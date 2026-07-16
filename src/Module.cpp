#define NOMINMAX

#include <fstream>
#include <filesystem>
#include <unordered_set>
#include <mutex>
#include <shared_mutex>
#include <algorithm>
#include <array>
#include <cstring>
#include <cctype>

#include <shlwapi.h>
#include <windows.h>
#include <winternl.h>

#include <utility/Logging.hpp>

#include <utility/String.hpp>
#include <utility/Thread.hpp>
#include <utility/Module.hpp>

#pragma comment (lib, "shlwapi.lib") // PathRemoveFileSpecW

using namespace std;

namespace utility {
    struct ModuleRange {
        uintptr_t begin;
        uintptr_t end;
        std::wstring path;
        std::optional<AnalysisContext> analysis;
    };

    std::vector<ModuleRange> g_module_ranges{};
    std::shared_mutex g_module_ranges_mutex{};

    namespace {
        struct ParsedPe {
            TargetArch arch{host_arch()};
            uint64_t preferred_image_base{};
            size_t image_size{};
            uint16_t number_of_sections{};
            size_t section_table_offset{};
            std::array<IMAGE_DATA_DIRECTORY, IMAGE_NUMBEROF_DIRECTORY_ENTRIES> directories{};
        };

        bool range_fits(size_t offset, size_t size, size_t available) {
            return offset <= available && size <= available - offset;
        }

        template <typename T>
        bool read_image_value(uintptr_t base, size_t available, size_t offset, T& value) {
            if (!range_fits(offset, sizeof(T), available)) {
                return false;
            }
            std::memcpy(&value, (const void*)(base + offset), sizeof(T));
            return true;
        }

        std::optional<ParsedPe> parse_pe_image(uintptr_t base, size_t available) {
            if (base == 0 || available < sizeof(IMAGE_DOS_HEADER)) {
                return std::nullopt;
            }

            IMAGE_DOS_HEADER dos{};
            if (!read_image_value(base, available, 0, dos) ||
                dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew <= 0) {
                return std::nullopt;
            }

            const auto nt_offset = (size_t)dos.e_lfanew;
            DWORD signature{};
            IMAGE_FILE_HEADER file_header{};
            if (!read_image_value(base, available, nt_offset, signature) ||
                signature != IMAGE_NT_SIGNATURE ||
                !read_image_value(base, available, nt_offset + sizeof(DWORD), file_header)) {
                return std::nullopt;
            }

            const auto optional_offset = nt_offset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
            WORD magic{};
            if (!read_image_value(base, available, optional_offset, magic)) {
                return std::nullopt;
            }

            ParsedPe result{};
            if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC &&
                file_header.Machine == IMAGE_FILE_MACHINE_I386 &&
                file_header.SizeOfOptionalHeader >= sizeof(IMAGE_OPTIONAL_HEADER32)) {
                IMAGE_OPTIONAL_HEADER32 optional{};
                if (!read_image_value(base, available, optional_offset, optional)) {
                    return std::nullopt;
                }
                result.arch = TargetArch::X86;
                result.preferred_image_base = optional.ImageBase;
                result.image_size = optional.SizeOfImage;
                const auto count = std::min<size_t>(optional.NumberOfRvaAndSizes, result.directories.size());
                std::copy_n(optional.DataDirectory, count, result.directories.begin());
            } else if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC &&
                       file_header.Machine == IMAGE_FILE_MACHINE_AMD64 &&
                       file_header.SizeOfOptionalHeader >= sizeof(IMAGE_OPTIONAL_HEADER64)) {
                IMAGE_OPTIONAL_HEADER64 optional{};
                if (!read_image_value(base, available, optional_offset, optional)) {
                    return std::nullopt;
                }
                result.arch = TargetArch::X64;
                result.preferred_image_base = optional.ImageBase;
                result.image_size = optional.SizeOfImage;
                const auto count = std::min<size_t>(optional.NumberOfRvaAndSizes, result.directories.size());
                std::copy_n(optional.DataDirectory, count, result.directories.begin());
            } else {
                return std::nullopt;
            }

            if (result.image_size == 0) {
                return std::nullopt;
            }

            result.number_of_sections = file_header.NumberOfSections;
            result.section_table_offset = optional_offset + file_header.SizeOfOptionalHeader;
            const auto section_bytes = (size_t)result.number_of_sections * sizeof(IMAGE_SECTION_HEADER);
            if (!range_fits(result.section_table_offset, section_bytes, available)) {
                return std::nullopt;
            }

            return result;
        }

        std::optional<ParsedPe> parse_pe_file(const std::filesystem::path& path) {
            std::ifstream file(path, std::ios::binary | std::ios::ate);
            if (!file) {
                return std::nullopt;
            }
            const auto length = file.tellg();
            if (length < (std::streamoff)sizeof(IMAGE_DOS_HEADER)) {
                return std::nullopt;
            }

            constexpr size_t kMaxPeHeaders = 1024 * 1024;
            const auto header_size = (size_t)std::min<std::streamoff>(length, kMaxPeHeaders);
            std::vector<uint8_t> headers(header_size);
            file.seekg(0, std::ios::beg);
            if (!file.read((char*)headers.data(), headers.size())) {
                return std::nullopt;
            }
            return parse_pe_image((uintptr_t)headers.data(), headers.size());
        }

        size_t module_header_span(uintptr_t base) {
            MEMORY_BASIC_INFORMATION mbi{};
            if (VirtualQuery((const void*)base, &mbi, sizeof(mbi)) == 0) {
                return 0;
            }
            const auto region_base = (uintptr_t)mbi.BaseAddress;
            if (base < region_base || base - region_base >= mbi.RegionSize) {
                return 0;
            }
            return mbi.RegionSize - (base - region_base);
        }
    }

    bool AnalysisContext::contains_host(uintptr_t address, size_t size) const noexcept {
        if (!mapped_image || address < host_base) {
            return false;
        }
        const auto offset = address - host_base;
        return offset <= image_size && size <= image_size - offset;
    }

    std::optional<uintptr_t> AnalysisContext::target_va_to_host(uint64_t address) const noexcept {
        if (!mapped_image) {
            if (address > std::numeric_limits<uintptr_t>::max()) {
                return std::nullopt;
            }
            return (uintptr_t)address;
        }
        if (address < preferred_image_base) {
            return std::nullopt;
        }
        const auto rva = address - preferred_image_base;
        if (rva >= image_size || rva > std::numeric_limits<uintptr_t>::max() - host_base) {
            return std::nullopt;
        }
        return host_base + (uintptr_t)rva;
    }

    std::optional<uint64_t> AnalysisContext::host_to_target_va(uintptr_t address) const noexcept {
        if (!mapped_image) {
            return (uint64_t)address;
        }
        if (!contains_host(address)) {
            return std::nullopt;
        }
        const auto rva = address - host_base;
        if (rva > std::numeric_limits<uint64_t>::max() - preferred_image_base) {
            return std::nullopt;
        }
        return preferred_image_base + rva;
    }

    std::optional<uint64_t> AnalysisContext::host_address_to_stored(
        uintptr_t address) const noexcept {
        const auto width_max = arch == TargetArch::X86
            ? (uint64_t)UINT32_MAX
            : std::numeric_limits<uint64_t>::max();
        if (!mapped_image) {
            return (uint64_t)address <= width_max
                ? std::optional<uint64_t>{(uint64_t)address}
                : std::nullopt;
        }
        if (contains_host(address)) {
            const auto rva = address - host_base;
            const auto stored_base = stored_image_base != 0
                ? stored_image_base
                : (relocations_applied
                    ? (uint64_t)host_base : preferred_image_base);
            if (rva > width_max || stored_base > width_max - rva) {
                return std::nullopt;
            }
            return stored_base + rva;
        }
        return (uint64_t)address <= width_max
            ? std::optional<uint64_t>{(uint64_t)address}
            : std::nullopt;
    }

    std::optional<uintptr_t> AnalysisContext::stored_address_to_host(
        uint64_t address) const noexcept {
        if (!mapped_image) {
            return target_va_to_host(address);
        }
        const auto stored_base = stored_image_base != 0
            ? stored_image_base
            : (relocations_applied
                ? (uint64_t)host_base : preferred_image_base);
        if (address >= stored_base) {
            const auto rva = address - stored_base;
            if (rva < image_size &&
                rva <= std::numeric_limits<uintptr_t>::max() - host_base) {
                return host_base + (uintptr_t)rva;
            }
        }
        return std::nullopt;
    }

    std::optional<AnalysisContext> get_analysis_context(HMODULE module) {
        if (module == nullptr) {
            return std::nullopt;
        }

        const auto base = (uintptr_t)module;
        {
            std::shared_lock _{g_module_ranges_mutex};
            for (const auto& range : g_module_ranges) {
                if (range.begin == base) {
                    if (range.analysis) {
                        return range.analysis;
                    }
                    return AnalysisContext{
                        .arch = host_arch(),
                        .host_base = range.begin,
                        .preferred_image_base = range.begin,
                        .stored_image_base = range.begin,
                        .image_size = range.end - range.begin,
                        .mapped_image = true,
                        .relocations_applied = true,
                    };
                }
            }
        }

        const auto parsed = parse_pe_image(base, module_header_span(base));
        if (!parsed) {
            return std::nullopt;
        }
        return AnalysisContext{
            .arch = parsed->arch,
            .host_base = base,
            .preferred_image_base = parsed->preferred_image_base,
            .stored_image_base = parsed->preferred_image_base,
            .image_size = parsed->image_size,
            .mapped_image = true,
            .relocations_applied = true,
        };
    }

    std::optional<AnalysisContext> get_analysis_context_within(Address address) {
        const auto module = get_module_within(address);
        return module ? get_analysis_context(*module) : std::nullopt;
    }

    optional<size_t> get_module_size(const string& module) {
        return get_module_size(get_module(module));
    }

    optional<size_t> get_module_size(const wstring& module) {
        return get_module_size(get_module(module));
    }

    optional<size_t> get_module_size(HMODULE module) {
        const auto context = get_analysis_context(module);
        return context ? std::optional<size_t>{context->image_size} : std::nullopt;
    }

    std::optional<HMODULE> get_module_within(Address address) {
        // For our fake modules
        {
            std::shared_lock _{g_module_ranges_mutex};
            for (const auto& range : g_module_ranges) {
                if (range.begin <= address.as<uintptr_t>() && address.as<uintptr_t>() < range.end) {
                    return (HMODULE)range.begin;
                }
            }
        }

        HMODULE module = nullptr;
        if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, address.as<LPCSTR>(), &module)) {
            return module;
        }

        if (!module) {
            return std::nullopt;
        }

        return module;
    }

    std::optional<uintptr_t> get_dll_imagebase(Address dll) {
        if (dll == nullptr) {
            return std::nullopt;
        }
        const auto context = get_analysis_context(dll.as<HMODULE>());
        if (!context || context->preferred_image_base > std::numeric_limits<uintptr_t>::max()) {
            return std::nullopt;
        }
        return (uintptr_t)context->preferred_image_base;
    }

    std::optional<uintptr_t> get_imagebase_va_from_ptr(Address dll, Address base, void* ptr) {
        auto file_imagebase = get_dll_imagebase(dll);

        if (!file_imagebase) {
            return {};
        }

        return *file_imagebase + ((uintptr_t)ptr - base.as<uintptr_t>());
    }


    std::optional<std::string> get_module_path(HMODULE module) {
        wchar_t filename[MAX_PATH]{0};
        if (auto res = GetModuleFileNameW(module, filename, MAX_PATH); res >= MAX_PATH || res == 0) {
            // Look in our module ranges
            {
                std::shared_lock _{g_module_ranges_mutex};
                for (const auto& range : g_module_ranges) {
                    if (range.begin == (uintptr_t)module) {
                        return utility::narrow(range.path);
                    }
                }
            }

            return {};
        }

        return utility::narrow(filename);
    }

    std::optional<std::wstring> get_module_pathw(HMODULE module) {
        wchar_t filename[MAX_PATH]{0};
        if (auto res = GetModuleFileNameW(module, filename, MAX_PATH); res >= MAX_PATH || res == 0) {
            // Look in our module ranges
            {
                std::shared_lock _{g_module_ranges_mutex};
                for (const auto& range : g_module_ranges) {
                    if (range.begin == (uintptr_t)module) {
                        return range.path;
                    }
                }
            }

            return {};
        }

        return filename;
    }

    std::optional<std::string> get_module_directory(HMODULE module) {
        wchar_t filename[MAX_PATH]{ 0 };
        if (auto res = GetModuleFileNameW(module, filename, MAX_PATH); res >= MAX_PATH || res == 0) {
            // Look in our module ranges
            {
                std::shared_lock _{g_module_ranges_mutex};
                for (const auto& range : g_module_ranges) {
                    if (range.begin == (uintptr_t)module) {
                        auto path = std::filesystem::path{ range.path };
                        path.remove_filename();
                        return utility::narrow(path.wstring());
                    }
                }
            }

            return {};
        }

        PathRemoveFileSpecW(filename);

        return utility::narrow(filename);
    }

    std::optional<std::wstring> get_module_directoryw(HMODULE module) {
        wchar_t filename[MAX_PATH]{ 0 };
        if (auto res = GetModuleFileNameW(module, filename, MAX_PATH); res >= MAX_PATH || res == 0) {
            // Look in our module ranges
            {
                std::shared_lock _{g_module_ranges_mutex};
                for (const auto& range : g_module_ranges) {
                    if (range.begin == (uintptr_t)module) {
                        auto path = std::filesystem::path{ range.path };
                        path.remove_filename();
                        return path.wstring();
                    }
                }
            }

            return {};
        }

        PathRemoveFileSpecW(filename);

        return filename;
    }

    HMODULE load_module_from_current_directory(const std::wstring& module) {
        const auto current_path = get_module_directoryw(get_executable());

        if (!current_path) {
            return nullptr;
        }

#if defined(_WIN32)
        auto fspath = std::filesystem::path{ *current_path } / module;
        return LoadLibraryW(fspath.c_str());
#else
        // No Win32 loader off Windows.
        (void)module;
        return nullptr;
#endif
    }

    std::vector<uint8_t> read_module_from_disk(HMODULE module) {
        auto path = get_module_path(module);

        if (!path) {
            return {};
        }
        
        // read using std utilities like ifstream and tellg, etc.
        auto file = std::ifstream{path->c_str(), std::ios::binary | std::ios::ate};

        if (!file.is_open()) {
            return {};
        }

        auto size = file.tellg();
        file.seekg(0, std::ios::beg);

        // don't brace initialize std::vector because it won't
        // call the right constructor.
        auto data = std::vector<uint8_t>((size_t)size);
        file.read((char*)data.data(), size);

        return data;
    }

    std::optional<std::vector<uint8_t>> get_original_bytes(Address address) {
        auto module_within = get_module_within(address);

        if (!module_within) {
            return {};
        }

        return get_original_bytes(*module_within, address);
    }

    std::optional<std::vector<uint8_t>> get_original_bytes(HMODULE module, Address address) {
        auto disk_data = read_module_from_disk(module);

        if (disk_data.empty()) {
            return std::nullopt;
        }

        auto module_base = get_dll_imagebase(module);

        if (!module_base) {
            return std::nullopt;
        }

        auto module_rva = address.as<uintptr_t>() - *module_base;

        // obtain the file offset of the address now
        auto disk_ptr = ptr_from_rva(disk_data.data(), module_rva);

        if (!disk_ptr) {
            return std::nullopt;
        }

        auto original_bytes = std::vector<uint8_t>{};

        auto module_bytes = address.as<uint8_t*>();
        auto disk_bytes = (uint8_t*)*disk_ptr;

        // copy the bytes from the disk data to the original bytes
        // copy only until the bytes start to match eachother
        for (auto i = 0; ; ++i) {
            if (module_bytes[i] == disk_bytes[i]) {
                bool actually_matches = true;

                // Lookahead 4 bytes to check if any other part is different before breaking out.
                for (auto j = 1; j <= 4; ++j) {
                    if (module_bytes[i + j] != disk_bytes[i + j]) {
                        actually_matches = false;
                        break;
                    }
                }

                if (actually_matches) {
                    break;
                }
            }

            original_bytes.push_back(disk_bytes[i]);
        }

        if (original_bytes.empty()) {
            return std::nullopt;
        }

        return original_bytes;
    }

    HMODULE get_executable() {
        return GetModuleHandle(nullptr);
    }

    HMODULE get_module(const std::string& module) {
        return GetModuleHandleA(module.c_str());
    }
    HMODULE get_module(const std::wstring& module) {
        return GetModuleHandleW(module.c_str());
    }

    std::mutex g_unlink_mutex{};

    HMODULE unlink(HMODULE module) {
        std::scoped_lock _{ g_unlink_mutex };

        const auto base = (uintptr_t)module;

        if (base == 0) {
            return module;
        }

        // this SHOULD be thread safe...?
        foreach_module([&](LIST_ENTRY* entry, _LDR_DATA_TABLE_ENTRY* ldr_entry) {
            if ((uintptr_t)ldr_entry->DllBase == base) {
                entry->Blink->Flink = entry->Flink;
                entry->Flink->Blink = entry->Blink;
            }
        });

        return module;
    }

    HMODULE safe_unlink(HMODULE module) {
        if (module == nullptr) {
            return nullptr;
        }

        utility::ThreadSuspender _{};

        unlink(module);
        return module;
    }

    HMODULE find_partial_module(std::wstring_view name) {
        HMODULE module = nullptr;

        foreach_module([&](LIST_ENTRY* entry, _LDR_DATA_TABLE_ENTRY* ldr_entry) {
            if (module != nullptr) {
                return;
            }

            if (std::wstring_view{ldr_entry->FullDllName.Buffer}.find(name) != std::wstring_view::npos) {
                module = (HMODULE)ldr_entry->DllBase;
            }
        });

        return module;
    }

    void foreach_module(std::function<void(LIST_ENTRY*, _LDR_DATA_TABLE_ENTRY*)> callback) try {
        if (!callback) {
            return;
        }

#if !defined(_WIN32)
        // No PEB / loader module list on non-Windows. Fake modules are tracked
        // in g_module_ranges rather than the loader list, so there is nothing to
        // walk here.
        (void)callback;
        return;
#else
#if defined(_M_X64)
        auto peb = (PEB*)__readgsqword(0x60);
#else
        auto peb = (PEB*)__readfsdword(0x30);
#endif

        if (peb == nullptr) {
            return;
        }

        typedef NTSTATUS (WINAPI* PFN_LdrLockLoaderLock)(ULONG Flags, ULONG *State, ULONG_PTR *Cookie);
        typedef NTSTATUS (WINAPI* PFN_LdrUnlockLoaderLock)(ULONG Flags, ULONG_PTR Cookie);

        const auto ntdll = get_module(L"ntdll.dll");
        auto lock_loader = ntdll != nullptr ? (PFN_LdrLockLoaderLock)GetProcAddress(ntdll, "LdrLockLoaderLock") : nullptr;
        auto unlock_loader = ntdll != nullptr ? (PFN_LdrUnlockLoaderLock)GetProcAddress(ntdll, "LdrUnlockLoaderLock") : nullptr;

        ULONG_PTR loader_magic = 0;

        if (lock_loader != nullptr && unlock_loader != nullptr) {
            lock_loader(0, NULL, &loader_magic);
        }
        
        for (auto entry = peb->Ldr->InMemoryOrderModuleList.Flink; entry != &peb->Ldr->InMemoryOrderModuleList && entry != nullptr; entry = entry->Flink) {
            if (IsBadReadPtr(entry, sizeof(LIST_ENTRY))) {
                SPDLOG_ERROR("[PEB] entry {:x} is a bad pointer", (uintptr_t)entry);
                break;
            }

            auto ldr_entry = (_LDR_DATA_TABLE_ENTRY*)CONTAINING_RECORD(entry, _LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

            if (IsBadReadPtr(ldr_entry, sizeof(_LDR_DATA_TABLE_ENTRY))) {
                SPDLOG_ERROR("[PEB] ldr entry {:x} is a bad pointer", (uintptr_t)ldr_entry);
                break;
            }
            
            callback(entry, ldr_entry);
        }

        if (lock_loader != nullptr && unlock_loader != nullptr) {
            unlock_loader(0, loader_magic);
        }
#endif // _WIN32
    } catch(std::exception& e) {
        SPDLOG_ERROR("[PEB] exception while iterating modules: {}", e.what());
    } catch(...) {
        SPDLOG_ERROR("[PEB] unexpected exception while iterating modules. Continuing...");
    }

    size_t get_module_count(std::wstring_view name) {
        size_t out{};

        wchar_t lower_name[MAX_PATH]{};
        std::transform(name.begin(), name.end(), lower_name, ::towlower);

        foreach_module([&](LIST_ENTRY* entry, _LDR_DATA_TABLE_ENTRY* ldr_entry) {
            wchar_t lower_dllname[MAX_PATH]{0};
            std::transform(ldr_entry->FullDllName.Buffer, ldr_entry->FullDllName.Buffer + ldr_entry->FullDllName.Length, lower_dllname, ::towlower);

            if (std::wstring_view{lower_dllname}.find(lower_name) != std::wstring_view::npos) {
                ++out;
            }
        });

        return out;
    }

    void unlink_duplicate_modules() {
        wchar_t system_dir[MAX_PATH]{0};
        GetSystemDirectoryW(system_dir, MAX_PATH);

        // to lower
        std::transform(system_dir, system_dir + wcslen(system_dir), system_dir, ::towlower);

        const auto current_exe = get_executable();

        foreach_module([&](LIST_ENTRY* entry, _LDR_DATA_TABLE_ENTRY* ldr_entry) {
            if (ldr_entry->DllBase == current_exe) {
                return;
            }

            wchar_t lower_name[MAX_PATH]{0};
            std::transform(ldr_entry->FullDllName.Buffer, ldr_entry->FullDllName.Buffer + ldr_entry->FullDllName.Length, lower_name, ::towlower);

            if (std::wstring_view{lower_name}.find(std::wstring_view{system_dir}) == 0) {
                return;
            }

            auto path = std::filesystem::path{lower_name};
            auto stripped_path = path.stem().wstring();

            if (get_module_count(stripped_path) > 1) {
                entry->Flink->Blink = entry->Blink;
                entry->Blink->Flink = entry->Flink;
                
                SPDLOG_INFO("{}", utility::narrow(lower_name));
            }
        });
    }

    std::unordered_set<std::wstring> g_skipped_paths{};
    std::mutex g_spoof_mutex{};

    void spoof_module_paths_in_exe_dir() try {
        std::scoped_lock _{g_spoof_mutex};

        wchar_t system_dir[MAX_PATH+1]{0};
        GetSystemDirectoryW(system_dir, MAX_PATH);

        // to lower
        std::transform(system_dir, system_dir + wcslen(system_dir), system_dir, ::towlower);

        std::wstring_view system_dir_view{system_dir};

        const auto current_exe = get_executable();
        auto current_dir = *utility::get_module_directoryw(current_exe);
        std::transform(current_dir.begin(), current_dir.end(), current_dir.begin(), ::towlower);

        const auto current_path = std::filesystem::path{current_dir};

        foreach_module([&](LIST_ENTRY* entry, _LDR_DATA_TABLE_ENTRY* ldr_entry) {
            if (ldr_entry == nullptr || IsBadReadPtr(ldr_entry, sizeof(_LDR_DATA_TABLE_ENTRY))) {
                SPDLOG_ERROR("[!] Failed to read module entry, continuing...", (uintptr_t)ldr_entry);
                return;
            }

            if (IsBadReadPtr(ldr_entry->FullDllName.Buffer, ldr_entry->FullDllName.Length)) {
                SPDLOG_ERROR("[!] Failed to read module name, continuing...", (uintptr_t)ldr_entry);
                return;
            }

            std::wstring previous_name{};

            try {
                if (ldr_entry != nullptr) {
                    previous_name = ldr_entry->FullDllName.Buffer;
                }
            } catch(...) {
                SPDLOG_ERROR("Could not determine name of module {:x}, continuing...", (uintptr_t)ldr_entry);
                return;
            }

            try {
                if (ldr_entry->DllBase == current_exe) {
                    return;
                }

                std::wstring lower_name = ldr_entry->FullDllName.Buffer;
                std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(), ::towlower);

                const auto path = std::filesystem::path{lower_name};

                //if (std::wstring_view{lower_name}.find(current_dir) == std::wstring_view::npos) {
                if (path.parent_path() != current_path) {
                    // only log it once so the log doesn't get polluted
                    if (g_skipped_paths.count(lower_name) == 0) {
                        SPDLOG_INFO("Skipping {}", utility::narrow(lower_name));
                        g_skipped_paths.insert(lower_name);
                    }

                    return;
                }

                const auto stripped_path = path.stem().wstring();
                auto new_path = (path.parent_path() / "_storage_" / stripped_path).wstring() + path.extension().wstring();

                try {
                    if (std::filesystem::exists(path)) {
                        std::filesystem::create_directory(std::filesystem::path{new_path}.parent_path());

                        std::error_code ec{};
                        std::filesystem::copy_file(path, new_path, std::filesystem::copy_options::overwrite_existing, ec);

                        if (ec) {
                            SPDLOG_ERROR("Failed to copy DLL file: {}", ec.message());
                        }

                        ec.clear();
                    }
                } catch(...) {
                    SPDLOG_ERROR("Failed to copy {} to {}", utility::narrow(path.wstring()), utility::narrow(new_path));
                    new_path = std::filesystem::path{system_dir_view}.append(stripped_path).wstring() + path.extension().wstring();
                }

                SPDLOG_INFO("Creating new node for {} (0x{:x})", utility::narrow(lower_name), (uintptr_t)ldr_entry->DllBase);

                const auto size = std::max<int32_t>(MAX_PATH+1, new_path.size()+1);
                auto final_chars = new wchar_t[size]{ 0 };

                memcpy(final_chars, new_path.data(), new_path.size() * sizeof(wchar_t));
                final_chars[new_path.size()] = 0;

                ldr_entry->FullDllName.Buffer = final_chars;
                ldr_entry->FullDllName.Length = new_path.size() * sizeof(wchar_t);
                ldr_entry->FullDllName.MaximumLength = size * sizeof(wchar_t);

                SPDLOG_INFO("Done {} -> {}", utility::narrow(path.wstring()), utility::narrow(new_path));
            } catch (...) {
                if (!previous_name.empty()) {
                    SPDLOG_ERROR("Failed {}", utility::narrow(previous_name));
                } else {
                    SPDLOG_ERROR("Failed to read module name (2), continuing...");
                }
            }
        });
    } catch(std::exception& e) {
        SPDLOG_ERROR("Exception in spoof_module_paths_in_exe_dir {}", e.what());
    } catch(...) {
        SPDLOG_ERROR("Unexpected error in spoof_module_paths_in_exe_dir. Continuing...");
    }

    optional<uintptr_t> ptr_from_rva(const uint8_t* dll, uintptr_t rva, bool memory_module) {
        if (memory_module) {
            return (uintptr_t)(dll + rva);
        }

        // Get the first section.
        auto dosHeader = (PIMAGE_DOS_HEADER)&dll[0];
        auto ntHeaders = (PIMAGE_NT_HEADERS)&dll[dosHeader->e_lfanew];
        auto section = IMAGE_FIRST_SECTION(ntHeaders);

        // Go through each section searching for where the rva lands.
        for (uint16_t i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i, ++section) {
            auto size = section->Misc.VirtualSize;

            if (size == 0) {
                size = section->SizeOfRawData;
            }

            if (rva >= section->VirtualAddress && rva < ((uintptr_t)section->VirtualAddress + size)) {
                auto delta = section->VirtualAddress - section->PointerToRawData;

                return (uintptr_t)(dll + (rva - delta));
            }
        }

        return {};
    }

    std::vector<std::wstring> get_loaded_module_names() {
        std::vector<HMODULE> modules{};
        std::vector<std::wstring> out{};
        
        foreach_module([&](LIST_ENTRY* entry, _LDR_DATA_TABLE_ENTRY* ldr_entry) {
            modules.push_back((HMODULE)ldr_entry->DllBase);
        });

        for (auto& module : modules) {
            if (module == nullptr) {
                continue;
            }

            const auto path = get_module_pathw(module);

            if (!path) {
                continue;
            }

            out.push_back(*path);
        }

        return out;
    }

    LoaderLockGuard::LoaderLockGuard() {
        const auto ntdll = get_module(L"ntdll.dll");
        auto lock_loader = ntdll != nullptr ? (PFN_LdrLockLoaderLock)GetProcAddress(ntdll, "LdrLockLoaderLock") : nullptr;
        auto unlock_loader = ntdll != nullptr ? (PFN_LdrUnlockLoaderLock)GetProcAddress(ntdll, "LdrUnlockLoaderLock") : nullptr;

        if (lock_loader != nullptr && unlock_loader != nullptr) {
            lock_loader(0, NULL, &this->cookie);
        }
    }

    LoaderLockGuard::~LoaderLockGuard() {
        const auto ntdll = get_module(L"ntdll.dll");
        auto lock_loader = ntdll != nullptr ? (PFN_LdrLockLoaderLock)GetProcAddress(ntdll, "LdrLockLoaderLock") : nullptr;
        auto unlock_loader = ntdll != nullptr ? (PFN_LdrUnlockLoaderLock)GetProcAddress(ntdll, "LdrUnlockLoaderLock") : nullptr;

        if (lock_loader != nullptr && unlock_loader != nullptr) {
            unlock_loader(0, this->cookie);
        }
    }

    std::optional<FakeModule> map_view_of_pe(const std::string& path) {
#if defined(_WIN32)
        auto fspath = std::filesystem::path{ path };
        const auto pe = parse_pe_file(fspath);
        if (!pe) {
            return std::nullopt;
        }

        auto file_handle = CreateFileW(fspath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

        if (file_handle == INVALID_HANDLE_VALUE) {
            return std::nullopt;
        }

        auto mapping_handle = CreateFileMappingW(file_handle, nullptr, PAGE_READONLY | SEC_IMAGE, 0, 0, nullptr);

        if (mapping_handle == nullptr) {
            CloseHandle(file_handle);
            return std::nullopt;
        }

        auto mapped_base = MapViewOfFile(mapping_handle, FILE_MAP_READ, 0, 0, 0);

        if (mapped_base == nullptr) {
            CloseHandle(mapping_handle);
            CloseHandle(file_handle);
            return std::nullopt;
        }

        // Create a fake PEB entry for this module so that utility::get_module_path and similar functions work with it.
        #ifdef _M_X64
        auto peb = (PEB*)__readgsqword(0x60);
        #else
        auto peb = (PEB*)__readfsdword(0x30);
        #endif

        // Lock the loader lock while we modify the module list to prevent
        // race conditions.
        LoaderLockGuard lock{};

        if (pe->image_size > UINT32_MAX ||
            pe->image_size > std::numeric_limits<uintptr_t>::max() - (uintptr_t)mapped_base) {
            UnmapViewOfFile(mapped_base);
            CloseHandle(mapping_handle);
            CloseHandle(file_handle);
            return std::nullopt;
        }

        const auto mapped_pe =
            parse_pe_image((uintptr_t)mapped_base, module_header_span((uintptr_t)mapped_base));
        if (!mapped_pe || mapped_pe->arch != pe->arch ||
            mapped_pe->image_size != pe->image_size) {
            UnmapViewOfFile(mapped_base);
            CloseHandle(mapping_handle);
            CloseHandle(file_handle);
            return std::nullopt;
        }

        // SEC_IMAGE can share already-relocated image pages. In that case the
        // mapped header's ImageBase is neither the file's preferred base nor
        // this view's address: it is the base whose relocation delta was
        // applied to stored pointers. Preserve it explicitly for translation.
        const auto stored_image_base = mapped_pe->preferred_image_base;
        const bool relocations_applied =
            stored_image_base != pe->preferred_image_base;

        auto fake_entry = new _LDR_DATA_TABLE_ENTRY{};
        std::memset(fake_entry, 0, sizeof(_LDR_DATA_TABLE_ENTRY));

        // _LDR_DATA_TABLE_ENTRY stores SizeOfImage in this reserved slot on the
        // compatibility definition used by kananlib.
        *(uint32_t*)&fake_entry->Reserved3[1] = (uint32_t)pe->image_size;

        fake_entry->DllBase = (PVOID)mapped_base;

        auto wpath = fspath.wstring();
        memset(&fake_entry->FullDllName, 0, sizeof(fake_entry->FullDllName));
        fake_entry->FullDllName.Buffer = (wchar_t*)malloc((wpath.size() + 1) * sizeof(wchar_t));
        fake_entry->FullDllName.Length = (USHORT)(wpath.size() * sizeof(wchar_t));
        fake_entry->FullDllName.MaximumLength = (USHORT)((wpath.size() + 1) * sizeof(wchar_t));
        memcpy(fake_entry->FullDllName.Buffer, wpath.c_str(), (wpath.size() + 1) * sizeof(wchar_t));
        
        fake_entry->InMemoryOrderLinks.Flink = peb->Ldr->InMemoryOrderModuleList.Flink;
        fake_entry->InMemoryOrderLinks.Blink = &peb->Ldr->InMemoryOrderModuleList;

        peb->Ldr->InMemoryOrderModuleList.Flink->Blink = &fake_entry->InMemoryOrderLinks;
        peb->Ldr->InMemoryOrderModuleList.Flink = &fake_entry->InMemoryOrderLinks;

        {
            const AnalysisContext analysis{
                .arch = pe->arch,
                .host_base = (uintptr_t)mapped_base,
                .preferred_image_base = pe->preferred_image_base,
                .stored_image_base = stored_image_base,
                .image_size = pe->image_size,
                .mapped_image = true,
                // Observed from the Magic-aware ImageBase in the mapped header.
                .relocations_applied = relocations_applied,
            };
            std::unique_lock _{ g_module_ranges_mutex };
            g_module_ranges.push_back({
                (uintptr_t)mapped_base,
                (uintptr_t)mapped_base + pe->image_size,
                wpath,
                analysis,
            });
        }

        return FakeModule{ (HMODULE)mapped_base, file_handle, mapping_handle };
#else
        // Non-Windows: there is no SEC_IMAGE mapping, so we emulate it by laying
        // out the PE sections at their RVAs in an anonymous mapping. The result
        // has RVA == offset-from-base, exactly like a loaded image, so every
        // scan/RTTI utility that walks the module by RVA works unchanged.
        std::ifstream file{ path, std::ios::binary | std::ios::ate };
        if (!file.is_open()) {
            return std::nullopt;
        }

        const auto file_size = (size_t)file.tellg();
        file.seekg(0, std::ios::beg);

        if (file_size < sizeof(IMAGE_DOS_HEADER)) {
            return std::nullopt;
        }

        std::vector<uint8_t> file_data(file_size);
        file.read((char*)file_data.data(), file_size);
        file.close();

        auto* dos = (PIMAGE_DOS_HEADER)file_data.data();
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
            return std::nullopt;
        }

        const auto nt_offset = (size_t)dos->e_lfanew;
        constexpr size_t optional_header_offset = offsetof(IMAGE_NT_HEADERS, OptionalHeader);

        if (dos->e_lfanew <= 0 || nt_offset > file_size || file_size - nt_offset < optional_header_offset + sizeof(WORD)) {
            return std::nullopt;
        }

        auto* nt = (PIMAGE_NT_HEADERS)(file_data.data() + nt_offset);
        if (nt->Signature != IMAGE_NT_SIGNATURE) {
            return std::nullopt;
        }

        const auto optional_magic = *(const WORD*)(file_data.data() + nt_offset + optional_header_offset);
        const bool pe32 = optional_magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC;
        const bool pe32_plus = optional_magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
        if (!pe32 && !pe32_plus) {
            return std::nullopt;
        }
        if ((pe32 && nt->FileHeader.Machine != IMAGE_FILE_MACHINE_I386) ||
            (pe32_plus && nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)) {
            return std::nullopt;
        }

        const size_t required_optional_size = pe32 ? sizeof(IMAGE_OPTIONAL_HEADER32) : sizeof(IMAGE_OPTIONAL_HEADER64);
        if (nt->FileHeader.SizeOfOptionalHeader < required_optional_size ||
            file_size - nt_offset < optional_header_offset + required_optional_size) {
            return std::nullopt;
        }

        const auto* opt32 = pe32 ? (const IMAGE_OPTIONAL_HEADER32*)(file_data.data() + nt_offset + optional_header_offset) : nullptr;
        const auto* opt64 = pe32_plus ? (const IMAGE_OPTIONAL_HEADER64*)(file_data.data() + nt_offset + optional_header_offset) : nullptr;
        const auto image_size = (size_t)(pe32 ? opt32->SizeOfImage : opt64->SizeOfImage);
        const auto headers_size = (size_t)(pe32 ? opt32->SizeOfHeaders : opt64->SizeOfHeaders);
        const auto image_base = (uint64_t)(pe32 ? opt32->ImageBase : opt64->ImageBase);
        const auto reloc_dir = pe32 ? opt32->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC] : opt64->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

        if (image_size == 0 || image_size > 0x100000000ULL) {
            return std::nullopt;
        }

        // e_lfanew was validated against the file above; also reject it against
        // the image so downstream consumers that re-read the NT headers from
        // mapped_base + e_lfanew can never read past the mapping.
        if (nt_offset + sizeof(IMAGE_NT_HEADERS) > image_size) {
            return std::nullopt;
        }

        // Validate section table is within file bounds. IMAGE_FIRST_SECTION
        // uses SizeOfOptionalHeader from the file. A malformed PE could set a
        // large SizeOfOptionalHeader or NumberOfSections, causing out-of-bounds
        // reads.
        if (file_size - nt_offset < optional_header_offset ||
            nt->FileHeader.SizeOfOptionalHeader > file_size - nt_offset - optional_header_offset) {
            return std::nullopt;
        }
        const auto section_table_offset = nt_offset + optional_header_offset + (size_t)nt->FileHeader.SizeOfOptionalHeader;
        const auto section_table_size = (size_t)nt->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
        if (section_table_offset > file_size || file_size - section_table_offset < section_table_size) {
            SPDLOG_WARN("[PE] Section table extends past end of file (offset={}, size={}, file_size={})",
                section_table_offset, section_table_size, file_size);
            return std::nullopt;
        }
        auto* first_section = (PIMAGE_SECTION_HEADER)(file_data.data() + section_table_offset);

        auto* mapped_base = (uint8_t*)VirtualAlloc(nullptr, image_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (mapped_base == nullptr) {
            SPDLOG_ERROR("[PE] VirtualAlloc failed for {} bytes", image_size);
            return std::nullopt;
        }

        // Copy the PE headers verbatim.
        std::memcpy(mapped_base, file_data.data(), std::min(std::min(headers_size, file_size), image_size));

        // Copy each section's raw data to its virtual address.
        auto* section = first_section;
        for (uint16_t i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section) {
            const auto va = (size_t)section->VirtualAddress;
            const auto raw_ptr = (size_t)section->PointerToRawData;
            auto raw_size = (size_t)section->SizeOfRawData;

            if (va >= image_size || raw_size == 0 || raw_ptr >= file_size) {
                continue;
            }
            if (raw_ptr + raw_size > file_size) {
                raw_size = file_size - raw_ptr;
            }
            if (va + raw_size > image_size) {
                raw_size = image_size - va;
            }

            std::memcpy(mapped_base + va, file_data.data() + raw_ptr, raw_size);
        }

        // Apply base relocations so absolute pointers (vtable -> RTTI locator,
        // import thunks, etc.) are valid at the actual load address. The Windows
        // loader does this; we must too since mmap will not honor the preferred
        // ImageBase. Done while the pages are still writable.
        const auto delta = (int64_t)((uint64_t)(uintptr_t)mapped_base - image_base);
        bool relocations_applied = delta == 0;
        const bool has_relocations =
            delta != 0 && reloc_dir.VirtualAddress != 0 && reloc_dir.Size != 0;
        const bool relocations_fit_target =
            !pe32 || (uintptr_t)mapped_base <= UINT32_MAX;
        if (has_relocations && relocations_fit_target) {
            const size_t reloc_begin = reloc_dir.VirtualAddress;
            if (!range_fits(reloc_begin, reloc_dir.Size, image_size)) {
                VirtualFree(mapped_base, 0, MEM_RELEASE);
                return std::nullopt;
            }

            const size_t reloc_end = reloc_begin + (size_t)reloc_dir.Size;
            auto walk_relocations = [&](bool apply) {
                size_t reloc_rva = reloc_begin;
                while (reloc_rva < reloc_end) {
                    if (!range_fits(reloc_rva, sizeof(IMAGE_BASE_RELOCATION), reloc_end)) {
                        return false;
                    }
                    auto* block = (IMAGE_BASE_RELOCATION*)(mapped_base + reloc_rva);
                    if (block->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION) ||
                        block->SizeOfBlock > reloc_end - reloc_rva ||
                        (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) % sizeof(uint16_t) != 0) {
                        return false;
                    }

                    const auto num_entries =
                        (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(uint16_t);
                    auto* entries = (uint16_t*)(block + 1);
                    for (uint32_t e = 0; e < num_entries; ++e) {
                        const auto type = entries[e] >> 12;
                        const size_t page_rva = (size_t)block->VirtualAddress;
                        const size_t page_offset = (size_t)(entries[e] & 0x0FFF);
                        if (page_rva > SIZE_MAX - page_offset) {
                            return false;
                        }
                        const size_t target = page_rva + page_offset;
                        if (type == IMAGE_REL_BASED_ABSOLUTE) {
                            continue;
                        }
                        if (pe32 && type == IMAGE_REL_BASED_HIGHLOW) {
                            if (!range_fits(target, sizeof(uint32_t), image_size)) {
                                return false;
                            }
                            if (apply) {
                                *(uint32_t*)(mapped_base + target) += (uint32_t)delta;
                            }
                            continue;
                        }
                        if (pe32_plus && type == IMAGE_REL_BASED_DIR64) {
                            if (!range_fits(target, sizeof(uint64_t), image_size)) {
                                return false;
                            }
                            if (apply) {
                                *(uint64_t*)(mapped_base + target) += (uint64_t)delta;
                            }
                            continue;
                        }
                        return false;
                    }
                    reloc_rva += block->SizeOfBlock;
                }
                return reloc_rva == reloc_end;
            };

            // Validate the complete table before mutating any slot. Publishing a
            // partially relocated image would make stored-pointer interpretation
            // ambiguous for every downstream scanner.
            if (!walk_relocations(false) || !walk_relocations(true)) {
                SPDLOG_WARN("[PE] Invalid or unsupported base relocation table");
                VirtualFree(mapped_base, 0, MEM_RELEASE);
                return std::nullopt;
            }
            relocations_applied = true;
        }
        if (has_relocations && !relocations_fit_target) {
            SPDLOG_INFO("[PE] Preserving PE32 target VAs because the host mapping is above 4 GiB");
        }

        // Apply per-section page protections so VirtualQuery reports executable
        // ranges (some scanners validate call targets against exec regions).
        section = first_section;
        for (uint16_t i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section) {
            const auto va = (size_t)section->VirtualAddress;
            auto vsize = (size_t)section->Misc.VirtualSize;
            if (vsize == 0) {
                vsize = (size_t)section->SizeOfRawData;
            }
            if (va >= image_size || vsize == 0) {
                continue;
            }
            if (va + vsize > image_size) {
                vsize = image_size - va;
            }

            const auto chars = section->Characteristics;
            DWORD prot = PAGE_READONLY;
            if (chars & IMAGE_SCN_MEM_EXECUTE) {
                prot = (chars & IMAGE_SCN_MEM_WRITE) ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
            } else if (chars & IMAGE_SCN_MEM_WRITE) {
                prot = PAGE_READWRITE;
            }

            DWORD old_prot = 0;
            VirtualProtect(mapped_base + va, vsize, prot, &old_prot);
        }

        SPDLOG_INFO("[PE] Mapped {} at {:x}, size 0x{:X}", path, (uintptr_t)mapped_base, image_size);

        {
            const AnalysisContext analysis{
                .arch = pe32 ? TargetArch::X86 : TargetArch::X64,
                .host_base = (uintptr_t)mapped_base,
                .preferred_image_base = image_base,
                .stored_image_base = relocations_applied
                    ? (uint64_t)(uintptr_t)mapped_base : image_base,
                .image_size = image_size,
                .mapped_image = true,
                .relocations_applied = relocations_applied,
            };
            std::unique_lock _{ g_module_ranges_mutex };
            g_module_ranges.push_back({
                (uintptr_t)mapped_base,
                (uintptr_t)mapped_base + image_size,
                std::filesystem::path{ path }.wstring(),
                analysis,
            });
        }

        // is_virtual_alloc = true: the destructor releases via VirtualFree and
        // never touches the (nonexistent) loader module list.
        return FakeModule{ (HMODULE)mapped_base, nullptr, nullptr, true };
#endif
    }

    std::optional<ImportMap> get_module_imports(HMODULE module) {
        const auto context = get_analysis_context(module);
        if (!context) {
            return std::nullopt;
        }

        const auto base = (uintptr_t)module;
        const auto pe = parse_pe_image(base, context->image_size);
        if (!pe) {
            return std::nullopt;
        }
        const auto module_size = context->image_size;
        auto rva_ok = [&](uintptr_t rva, size_t min_size = 1) {
            return rva >= 1 && range_fits((size_t)rva, min_size, module_size);
        };
        auto cstr_at = [&](uintptr_t rva) -> const char* {
            if (!rva_ok(rva)) {
                return nullptr;
            }
            const auto* value = (const char*)(base + rva);
            return std::memchr(value, '\0', module_size - (size_t)rva) ? value : nullptr;
        };

        const auto import_dir = pe->directories[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (import_dir.VirtualAddress == 0 ||
            import_dir.Size < sizeof(IMAGE_IMPORT_DESCRIPTOR) ||
            !rva_ok(import_dir.VirtualAddress, import_dir.Size)) {
            return std::nullopt;
        }

        ImportMap result{};
        const auto descriptor_end = (size_t)import_dir.VirtualAddress + import_dir.Size;
        for (size_t descriptor_rva = import_dir.VirtualAddress;
             range_fits(descriptor_rva, sizeof(IMAGE_IMPORT_DESCRIPTOR), descriptor_end);
             descriptor_rva += sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
            IMAGE_IMPORT_DESCRIPTOR descriptor{};
            std::memcpy(&descriptor, (const void*)(base + descriptor_rva), sizeof(descriptor));
            if (descriptor.Name == 0) {
                break;
            }

            const auto* dll_name = cstr_at(descriptor.Name);
            if (!dll_name) {
                continue;
            }
            std::string dll_lower = dll_name;
            std::transform(dll_lower.begin(), dll_lower.end(), dll_lower.begin(),
                [](unsigned char c) { return (char)std::tolower(c); });

            const auto int_rva = descriptor.OriginalFirstThunk
                ? descriptor.OriginalFirstThunk
                : descriptor.FirstThunk;
            auto walk_thunks = [&]<typename Thunk>() {
                for (size_t index = 0;; ++index) {
                    if (index > SIZE_MAX / sizeof(Thunk)) {
                        break;
                    }
                    const auto offset = index * sizeof(Thunk);
                    if ((size_t)int_rva > SIZE_MAX - offset ||
                        (size_t)descriptor.FirstThunk > SIZE_MAX - offset) {
                        break;
                    }
                    const auto int_entry_rva = (size_t)int_rva + offset;
                    const auto iat_entry_rva = (size_t)descriptor.FirstThunk + offset;
                    if (!rva_ok(int_entry_rva, sizeof(Thunk)) ||
                        !rva_ok(iat_entry_rva, sizeof(Thunk))) {
                        break;
                    }

                    Thunk int_entry{};
                    std::memcpy(&int_entry, (const void*)(base + int_entry_rva), sizeof(int_entry));
                    const auto value = (uint64_t)int_entry.u1.AddressOfData;
                    if (value == 0) {
                        break;
                    }

                    const auto iat_addr = base + iat_entry_rva;
                    constexpr uint64_t ordinal_flag =
                        sizeof(Thunk) == sizeof(IMAGE_THUNK_DATA32)
                            ? (uint64_t)IMAGE_ORDINAL_FLAG32
                            : (uint64_t)IMAGE_ORDINAL_FLAG64;
                    if ((value & ordinal_flag) != 0) {
                        const auto ordinal = (uint16_t)(value & 0xFFFF);
                        const auto key = dll_lower + "!#" + std::to_string(ordinal);
                        result.name_to_addr[key] = iat_addr;
                        result.addr_to_name[iat_addr] = key;
                        continue;
                    }

                    constexpr size_t name_offset = offsetof(IMAGE_IMPORT_BY_NAME, Name);
                    if (value > UINT32_MAX || value > SIZE_MAX - name_offset ||
                        !rva_ok((uintptr_t)value, sizeof(IMAGE_IMPORT_BY_NAME))) {
                        continue;
                    }
                    const auto* function_name = cstr_at((size_t)value + name_offset);
                    if (!function_name) {
                        continue;
                    }

                    const auto key = dll_lower + "!" + function_name;
                    result.name_to_addr[key] = iat_addr;
                    result.addr_to_name[iat_addr] = key;
                }
            };

            if (context->arch == TargetArch::X86) {
                walk_thunks.template operator()<IMAGE_THUNK_DATA32>();
            } else {
                walk_thunks.template operator()<IMAGE_THUNK_DATA64>();
            }
        }

        return result;
    }

    std::optional<ExportMap> get_module_exports(HMODULE module) {
        const auto context = get_analysis_context(module);
        if (!context) {
            return std::nullopt;
        }

        const auto base = (uintptr_t)module;
        const auto pe = parse_pe_image(base, context->image_size);
        if (!pe) {
            return std::nullopt;
        }
        const auto module_size = context->image_size;
        const auto module_end = base + module_size;

        auto rva_ok = [&](uintptr_t rva, size_t min_size = 1) -> bool {
            return rva >= 1 && range_fits((size_t)rva, min_size, module_size);
        };

        const auto export_dir_entry = pe->directories[IMAGE_DIRECTORY_ENTRY_EXPORT];

        if (export_dir_entry.VirtualAddress == 0 || export_dir_entry.Size == 0) {
            return std::nullopt;
        }

        if (!rva_ok(export_dir_entry.VirtualAddress, sizeof(IMAGE_EXPORT_DIRECTORY))) {
            return std::nullopt;
        }

        auto* exp = (PIMAGE_EXPORT_DIRECTORY)(base + export_dir_entry.VirtualAddress);

        // Forwarded exports store a string RVA inside the export directory region
        // instead of a real function RVA. We skip these (no local VA).
        const auto forward_begin = (uintptr_t)export_dir_entry.VirtualAddress;
        const auto forward_end = forward_begin + export_dir_entry.Size;

        if (!rva_ok(exp->AddressOfFunctions, sizeof(uint32_t)) ||
            !rva_ok(exp->AddressOfNames, sizeof(uint32_t)) ||
            !rva_ok(exp->AddressOfNameOrdinals, sizeof(uint16_t))) {
            return std::nullopt;
        }

        auto* functions = (const uint32_t*)(base + exp->AddressOfFunctions);
        auto* names = (const uint32_t*)(base + exp->AddressOfNames);
        auto* ordinals = (const uint16_t*)(base + exp->AddressOfNameOrdinals);

        ExportMap result{};

        for (uint32_t i = 0; i < exp->NumberOfNames; ++i) {
            // Bounds-check the name/ordinal array slots themselves.
            if (!rva_ok(exp->AddressOfNames + ((size_t)i + 1) * sizeof(uint32_t) - 1) ||
                !rva_ok(exp->AddressOfNameOrdinals + ((size_t)i + 1) * sizeof(uint16_t) - 1)) {
                break;
            }

            const auto name_rva = names[i];
            if (!rva_ok(name_rva)) {
                continue;
            }

            // Verify the name string is within bounds (scan for null terminator).
            auto* name = (const char*)(base + name_rva);
            bool name_valid = false;
            for (auto* p = name; (uintptr_t)p < module_end; ++p) {
                if (*p == '\0') { name_valid = true; break; }
            }
            if (!name_valid) {
                continue;
            }

            const auto ord = ordinals[i];
            if (ord >= exp->NumberOfFunctions) {
                continue;
            }

            if (!rva_ok(exp->AddressOfFunctions + ((size_t)ord + 1) * sizeof(uint32_t) - 1)) {
                continue;
            }

            const auto func_rva = functions[ord];
            if (func_rva == 0) {
                continue;
            }

            // Skip forwarders (RVA points inside the export directory).
            if (func_rva >= forward_begin && func_rva < forward_end) {
                continue;
            }

            const auto va = base + (uintptr_t)func_rva;

            std::string key = name;
            result.addr_to_name[va] = key;
            result.name_to_addr[std::move(key)] = va;
        }

        return result;
    }

    std::optional<std::vector<ModuleSection>> get_module_sections(HMODULE module) {
        const auto context = get_analysis_context(module);
        if (!context) {
            return std::nullopt;
        }

        const auto base = (uintptr_t)module;
        const auto pe = parse_pe_image(base, context->image_size);
        if (!pe) {
            return std::nullopt;
        }

        std::vector<ModuleSection> sections{};
        sections.reserve(pe->number_of_sections);
        for (uint16_t i = 0; i < pe->number_of_sections; ++i) {
            IMAGE_SECTION_HEADER section{};
            const auto offset = pe->section_table_offset + (size_t)i * sizeof(section);
            if (!read_image_value(base, context->image_size, offset, section)) {
                return std::nullopt;
            }

            ModuleSection result{};
            size_t name_len = 0;
            while (name_len < IMAGE_SIZEOF_SHORT_NAME && section.Name[name_len] != '\0') {
                ++name_len;
            }
            result.name.assign((const char*)section.Name, name_len);
            result.virtual_address = base + section.VirtualAddress;
            result.virtual_size = section.Misc.VirtualSize;
            result.raw_size = section.SizeOfRawData;
            result.raw_pointer = section.PointerToRawData;
            result.characteristics = section.Characteristics;
            sections.push_back(std::move(result));
        }
        return sections;
    }


    namespace {
        constexpr uint32_t MACHO_MH_MAGIC_64   = 0xFEEDFACF;
        constexpr uint32_t MACHO_FAT_MAGIC_BE   = 0xBEBAFECA; // big-endian FAT_MAGIC as read on little-endian
        constexpr uint32_t MACHO_CPU_TYPE_X86_64 = 0x01000007;
        constexpr uint32_t MACHO_LC_SEGMENT_64   = 0x19;

        struct macho_header_64 {
            uint32_t magic;
            uint32_t cputype;
            uint32_t cpusubtype;
            uint32_t filetype;
            uint32_t ncmds;
            uint32_t sizeofcmds;
            uint32_t flags;
            uint32_t reserved;
        };

        struct macho_load_command {
            uint32_t cmd;
            uint32_t cmdsize;
        };

        struct macho_segment_command_64 {
            uint32_t cmd;
            uint32_t cmdsize;
            char     segname[16];
            uint64_t vmaddr;
            uint64_t vmsize;
            uint64_t fileoff;
            uint64_t filesize;
            uint32_t maxprot;
            uint32_t initprot;
            uint32_t nsects;
            uint32_t flags;
        };

        struct macho_fat_header {
            uint32_t magic;
            uint32_t nfat_arch;
        };

        struct macho_fat_arch {
            uint32_t cputype;
            uint32_t cpusubtype;
            uint32_t offset;
            uint32_t size;
            uint32_t align;
        };

        constexpr uint32_t MACHO_VM_PROT_EXECUTE = 0x04;
    }

    std::optional<FakeModule> map_view_of_macho(const std::string& path) {
        // Read the entire file
        auto file = std::ifstream{path, std::ios::binary | std::ios::ate};
        if (!file.is_open()) {
            SPDLOG_ERROR("[Mach-O] Failed to open file: {}", path);
            return std::nullopt;
        }

        const auto file_size = (size_t)file.tellg();
        file.seekg(0, std::ios::beg);

        if (file_size < sizeof(macho_header_64)) {
            SPDLOG_ERROR("[Mach-O] File too small: {}", path);
            return std::nullopt;
        }

        auto file_data = std::vector<uint8_t>(file_size);
        file.read((char*)file_data.data(), file_size);
        file.close();

        // Determine offset to the x86_64 Mach-O within the file (0 for thin binaries)
        size_t macho_offset = 0;
        size_t macho_size = file_size;

        auto magic = *(uint32_t*)file_data.data();

        if (magic == MACHO_FAT_MAGIC_BE) {
            // Fat (universal) binary - headers are big-endian
            auto fat = (macho_fat_header*)file_data.data();
            uint32_t nfat_arch = _byteswap_ulong(fat->nfat_arch);

            if (file_size < sizeof(macho_fat_header) + nfat_arch * sizeof(macho_fat_arch)) {
                SPDLOG_ERROR("[Mach-O] Fat header extends past file end: {}", path);
                return std::nullopt;
            }

            auto archs = (macho_fat_arch*)(file_data.data() + sizeof(macho_fat_header));
            bool found = false;

            for (uint32_t i = 0; i < nfat_arch; ++i) {
                uint32_t cputype = _byteswap_ulong(archs[i].cputype);
                if (cputype == MACHO_CPU_TYPE_X86_64) {
                    macho_offset = _byteswap_ulong(archs[i].offset);
                    macho_size = _byteswap_ulong(archs[i].size);
                    found = true;
                    break;
                }
            }

            if (!found) {
                SPDLOG_ERROR("[Mach-O] No x86_64 slice found in fat binary: {}", path);
                return std::nullopt;
            }

            if (macho_offset + macho_size > file_size) {
                SPDLOG_ERROR("[Mach-O] x86_64 slice extends past file end: {}", path);
                return std::nullopt;
            }
        }

        // Validate the Mach-O header
        auto* base = file_data.data() + macho_offset;
        auto* header = (macho_header_64*)base;

        if (header->magic != MACHO_MH_MAGIC_64) {
            SPDLOG_ERROR("[Mach-O] Invalid magic: 0x{:08X} (expected 0x{:08X})", header->magic, MACHO_MH_MAGIC_64);
            return std::nullopt;
        }

        if (header->cputype != MACHO_CPU_TYPE_X86_64) {
            SPDLOG_ERROR("[Mach-O] Not x86_64 (cputype: 0x{:08X})", header->cputype);
            return std::nullopt;
        }

        // Walk load commands to collect segments
        struct SegmentInfo {
            uint64_t vmaddr;
            uint64_t vmsize;
            uint64_t fileoff;
            uint64_t filesize;
            uint32_t initprot;
            char     segname[16];
        };

        std::vector<SegmentInfo> segments{};
        auto* cmd_ptr = base + sizeof(macho_header_64);

        for (uint32_t i = 0; i < header->ncmds; ++i) {
            auto* lc = (macho_load_command*)cmd_ptr;

            if (lc->cmdsize == 0 || cmd_ptr + lc->cmdsize > base + macho_size) {
                break;
            }

            if (lc->cmd == MACHO_LC_SEGMENT_64) {
                auto* seg = (macho_segment_command_64*)cmd_ptr;

                // Skip __PAGEZERO (no file content, just reserves VA space)
                if (seg->filesize == 0 && seg->vmsize > 0 && seg->vmaddr == 0) {
                    cmd_ptr += lc->cmdsize;
                    continue;
                }

                SegmentInfo info{};
                info.vmaddr = seg->vmaddr;
                info.vmsize = seg->vmsize;
                info.fileoff = seg->fileoff;
                info.filesize = seg->filesize;
                info.initprot = seg->initprot;
                memcpy(info.segname, seg->segname, 16);

                segments.push_back(info);
            }

            cmd_ptr += lc->cmdsize;
        }

        if (segments.empty()) {
            SPDLOG_ERROR("[Mach-O] No segments found: {}", path);
            return std::nullopt;
        }

        // Compute virtual extent
        uint64_t min_vmaddr = UINT64_MAX;
        uint64_t max_vmend = 0;

        for (const auto& seg : segments) {
            if (seg.vmaddr < min_vmaddr) {
                min_vmaddr = seg.vmaddr;
            }
            uint64_t end = seg.vmaddr + seg.vmsize;
            if (end > max_vmend) {
                max_vmend = end;
            }
        }

        // Validate the extent in full 64-bit width BEFORE narrowing to size_t.
        // On 32-bit builds size_t is 4 bytes, so casting first would truncate a
        // >4GB extent (e.g. 0x100000010 -> 0x10) and silently pass this guard,
        // then overflow the undersized allocation in the copy loop below.
        const uint64_t virtual_extent = max_vmend - min_vmaddr;

        if (virtual_extent == 0 || virtual_extent > 0x100000000ULL) { // sanity check: max 4GB
            SPDLOG_ERROR("[Mach-O] Invalid virtual extent: 0x{:X}", virtual_extent);
            return std::nullopt;
        }

        const auto total_size = (size_t)virtual_extent;

        // Allocate memory for the mapped image
        auto* mapped_base = (uint8_t*)VirtualAlloc(nullptr, total_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        if (mapped_base == nullptr) {
            SPDLOG_ERROR("[Mach-O] VirtualAlloc failed for {} bytes", total_size);
            return std::nullopt;
        }

        // Copy each segment to its virtual address
        for (const auto& seg : segments) {
            auto dest_offset = (size_t)(seg.vmaddr - min_vmaddr);
            auto copy_size = (size_t)std::min(seg.filesize, seg.vmsize);

            if (seg.fileoff + copy_size > macho_size) {
                copy_size = (size_t)(macho_size - seg.fileoff);
            }

            if (copy_size > 0) {
                memcpy(mapped_base + dest_offset, base + seg.fileoff, copy_size);
            }
        }

        // Set page protections for executable segments
        for (const auto& seg : segments) {
            if (seg.initprot & MACHO_VM_PROT_EXECUTE) {
                auto dest_offset = (size_t)(seg.vmaddr - min_vmaddr);
                DWORD old_prot = 0;
                VirtualProtect(mapped_base + dest_offset, (size_t)seg.vmsize, PAGE_EXECUTE_READ, &old_prot);
            }
        }

        SPDLOG_INFO("[Mach-O] Mapped {} at {:x}, size 0x{:X} ({} segments)", path, (uintptr_t)mapped_base, total_size, segments.size());

        // Register in module ranges
        {
            std::unique_lock _{ g_module_ranges_mutex };
            g_module_ranges.push_back({ (uintptr_t)mapped_base, (uintptr_t)mapped_base + total_size, std::filesystem::path{path}.wstring() });
        }

        return FakeModule{ (HMODULE)mapped_base, nullptr, nullptr, true };
    }

    std::optional<FakeModule> map_view_of_file(const std::string& path) {
        // Read the first 4 bytes to determine file type
        auto file = std::ifstream{path, std::ios::binary};
        if (!file.is_open()) {
            return std::nullopt;
        }

        uint32_t magic = 0;
        file.read((char*)&magic, sizeof(magic));
        file.close();

        // Mach-O 64-bit or fat binary
        if (magic == MACHO_MH_MAGIC_64 || magic == MACHO_FAT_MAGIC_BE) {
            return map_view_of_macho(path);
        }

        // Assume PE otherwise (MZ signature = 0x5A4D)
        return map_view_of_pe(path);
    }

    FakeModule::~FakeModule() {
        if (module) {
            {
                std::unique_lock _{ g_module_ranges_mutex };
                g_module_ranges.erase(std::remove_if(g_module_ranges.begin(), g_module_ranges.end(),
                    [&](const ModuleRange& range) {
                        return range.begin == (uintptr_t)module;
                    }), g_module_ranges.end());
            }

            if (is_virtual_alloc) {
                VirtualFree(module, 0, MEM_RELEASE);
            } else {
                _LDR_DATA_TABLE_ENTRY* fake_entry = nullptr;
                // Find the entry in the list that matches our module and remove it.
                foreach_module([&](LIST_ENTRY* entry, _LDR_DATA_TABLE_ENTRY* ldr_entry) {
                    if (ldr_entry->DllBase == (PVOID)module) {
                        entry->Flink->Blink = entry->Blink;
                        entry->Blink->Flink = entry->Flink;
                        fake_entry = ldr_entry;
                    }
                });

                if (fake_entry != nullptr) {
                    free(fake_entry->FullDllName.Buffer);
                    delete fake_entry;
                }

                UnmapViewOfFile(module);
            }
        }

        if (mapping_handle) {
            CloseHandle(mapping_handle);
        }

        if (file_handle) {
            CloseHandle(file_handle);
        }
    }
}
