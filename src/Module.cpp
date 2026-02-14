#define NOMINMAX

#include <fstream>
#include <filesystem>
#include <unordered_set>
#include <mutex>
#include <shared_mutex>

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
    };

    std::vector<ModuleRange> g_module_ranges{};
    std::shared_mutex g_module_ranges_mutex{};

    optional<size_t> get_module_size(const string& module) {
        return get_module_size(GetModuleHandleA(module.c_str()));
    }

    optional<size_t> get_module_size(const wstring& module) {
        return get_module_size(GetModuleHandleW(module.c_str()));
    }

    optional<size_t> get_module_size(HMODULE module) {
        if (module == nullptr) {
            return {};
        }

        // Get the dos header and verify that it seems valid.
        auto dosHeader = (PIMAGE_DOS_HEADER)module;

        if (dosHeader->e_magic == IMAGE_DOS_SIGNATURE) {
            // Get the nt headers and verify that they seem valid.
            auto ntHeaders = (PIMAGE_NT_HEADERS)((uintptr_t)dosHeader + dosHeader->e_lfanew);

            if (ntHeaders->Signature == IMAGE_NT_SIGNATURE) {
                // OptionalHeader is not actually optional.
                return ntHeaders->OptionalHeader.SizeOfImage;
            }
        }

        // Fallback for non-PE fake modules (Mach-O, etc.)
        {
            std::shared_lock _{g_module_ranges_mutex};
            for (const auto& range : g_module_ranges) {
                if (range.begin == (uintptr_t)module) {
                    return range.end - range.begin;
                }
            }
        }

        return {};
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
            return {};
        }

        // Get the dos header and verify that it seems valid.
        auto dosHeader = dll.as<PIMAGE_DOS_HEADER>();

        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            return {};
        }

        // Get the nt headers and verify that they seem valid.
        auto ntHeaders = (PIMAGE_NT_HEADERS)((uintptr_t)dosHeader + dosHeader->e_lfanew);

        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
            return {};
        }

        return ntHeaders->OptionalHeader.ImageBase;
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
        if (GetModuleFileNameW(module, filename, MAX_PATH) >= MAX_PATH) {
            return {};
        }

        return utility::narrow(filename);
    }

    std::optional<std::wstring> get_module_pathw(HMODULE module) {
        wchar_t filename[MAX_PATH]{0};
        if (GetModuleFileNameW(module, filename, MAX_PATH) >= MAX_PATH) {
            return {};
        }

        return filename;
    }

    std::optional<std::string> get_module_directory(HMODULE module) {
        wchar_t filename[MAX_PATH]{ 0 };
        if (GetModuleFileNameW(module, filename, MAX_PATH) >= MAX_PATH) {
            return {};
        }

        PathRemoveFileSpecW(filename);

        return utility::narrow(filename);
    }

    std::optional<std::wstring> get_module_directoryw(HMODULE module) {
        wchar_t filename[MAX_PATH]{ 0 };
        if (GetModuleFileNameW(module, filename, MAX_PATH) >= MAX_PATH) {
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

        auto fspath = std::filesystem::path{ *current_path } / module;

        return LoadLibraryW(fspath.c_str());
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

        const auto ntdll = GetModuleHandleW(L"ntdll.dll");
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
        const auto ntdll = GetModuleHandleW(L"ntdll.dll");
        auto lock_loader = ntdll != nullptr ? (PFN_LdrLockLoaderLock)GetProcAddress(ntdll, "LdrLockLoaderLock") : nullptr;
        auto unlock_loader = ntdll != nullptr ? (PFN_LdrUnlockLoaderLock)GetProcAddress(ntdll, "LdrUnlockLoaderLock") : nullptr;

        if (lock_loader != nullptr && unlock_loader != nullptr) {
            lock_loader(0, NULL, &this->cookie);
        }
    }

    LoaderLockGuard::~LoaderLockGuard() {
        const auto ntdll = GetModuleHandleW(L"ntdll.dll");
        auto lock_loader = ntdll != nullptr ? (PFN_LdrLockLoaderLock)GetProcAddress(ntdll, "LdrLockLoaderLock") : nullptr;
        auto unlock_loader = ntdll != nullptr ? (PFN_LdrUnlockLoaderLock)GetProcAddress(ntdll, "LdrUnlockLoaderLock") : nullptr;

        if (lock_loader != nullptr && unlock_loader != nullptr) {
            unlock_loader(0, this->cookie);
        }
    }

    std::optional<FakeModule> map_view_of_pe(const std::string& path) {
        auto fspath = std::filesystem::path{ path };

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

        auto fake_entry = new _LDR_DATA_TABLE_ENTRY{};
        std::memset(fake_entry, 0, sizeof(_LDR_DATA_TABLE_ENTRY));

        // get size of image from pe header and assign to entry
        auto dosHeader = (PIMAGE_DOS_HEADER)mapped_base;
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            UnmapViewOfFile(mapped_base);
            CloseHandle(mapping_handle);
            CloseHandle(file_handle);
            return std::nullopt;
        }

        auto ntHeaders = (PIMAGE_NT_HEADERS)((uintptr_t)dosHeader + dosHeader->e_lfanew);

        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
            UnmapViewOfFile(mapped_base);
            CloseHandle(mapping_handle);
            CloseHandle(file_handle);
            return std::nullopt;
        }

        // SizeOfImage
        *(uint32_t*)&fake_entry->Reserved3[1] = ntHeaders->OptionalHeader.SizeOfImage;

        fake_entry->DllBase = (PVOID)mapped_base;

        auto wpath = fspath.wstring();
        memset(&fake_entry->FullDllName, 0, sizeof(fake_entry->FullDllName));
        fake_entry->FullDllName.Buffer = (wchar_t*)malloc((wpath.size() + 1) * sizeof(wchar_t));
        fake_entry->FullDllName.Length = (USHORT)(wpath.size() * sizeof(wchar_t));
        fake_entry->FullDllName.MaximumLength = (USHORT)((wpath.size() + 1) * sizeof(wchar_t));
        memcpy(fake_entry->FullDllName.Buffer, wpath.c_str(), (wpath.size() + 1) * sizeof(wchar_t));
        
        fake_entry->InMemoryOrderLinks.Flink = peb->Ldr->InMemoryOrderModuleList.Flink;
        fake_entry->InMemoryOrderLinks.Blink = &peb->Ldr->InMemoryOrderModuleList;

        //auto& InLoadOrderLinks = *(LIST_ENTRY*)&peb->Ldr->Reserved2[1];
        //auto& InLoadOrderLinksEntry = *(LIST_ENTRY*)(&fake_entry->Reserved1[0]);
        //InLoadOrderLinksEntry.Flink = InLoadOrderLinks.Flink;
        //InLoadOrderLinksEntry.Blink = &InLoadOrderLinksEntry;


        peb->Ldr->InMemoryOrderModuleList.Flink->Blink = &fake_entry->InMemoryOrderLinks;
        peb->Ldr->InMemoryOrderModuleList.Flink = &fake_entry->InMemoryOrderLinks;
        //InLoadOrderLinks.Flink->Blink = &InLoadOrderLinks;
        //InLoadOrderLinks.Flink = &InLoadOrderLinksEntry;

        {
            std::unique_lock _{ g_module_ranges_mutex };
            g_module_ranges.push_back({ (uintptr_t)mapped_base, (uintptr_t)mapped_base + ntHeaders->OptionalHeader.SizeOfImage });
        }

        return FakeModule{ (HMODULE)mapped_base, file_handle, mapping_handle };
    }

    std::optional<ImportMap> get_module_imports(HMODULE module) {
        if (module == nullptr) {
            return std::nullopt;
        }

        const auto base = (uintptr_t)module;
        auto* dos = (PIMAGE_DOS_HEADER)base;

        if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
            return std::nullopt;
        }

        auto* nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);

        if (nt->Signature != IMAGE_NT_SIGNATURE) {
            return std::nullopt;
        }

        const auto module_size = (size_t)nt->OptionalHeader.SizeOfImage;
        const auto module_end = base + module_size;

        auto rva_ok = [&](uintptr_t rva, size_t min_size = 1) -> bool {
            return rva >= 1 && rva + min_size <= module_size;
        };

        auto& import_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

        if (import_dir.VirtualAddress == 0 || import_dir.Size == 0) {
            return std::nullopt;
        }

        if (!rva_ok(import_dir.VirtualAddress, sizeof(IMAGE_IMPORT_DESCRIPTOR))) {
            return std::nullopt;
        }

        ImportMap result{};
        auto* desc = (PIMAGE_IMPORT_DESCRIPTOR)(base + import_dir.VirtualAddress);

        for (; rva_ok((uintptr_t)desc - base + sizeof(IMAGE_IMPORT_DESCRIPTOR) - 1) && desc->Name != 0; ++desc) {
            if (!rva_ok(desc->Name)) {
                continue;
            }

            auto* dll_name = (const char*)(base + desc->Name);

            // Ensure the string is within bounds (scan for null terminator)
            bool name_valid = false;
            for (auto* p = dll_name; (uintptr_t)p < module_end; ++p) {
                if (*p == '\0') { name_valid = true; break; }
            }
            if (!name_valid) {
                continue;
            }

            // Lowercase the DLL name for consistent keys
            std::string dll_lower = dll_name;
            std::transform(dll_lower.begin(), dll_lower.end(), dll_lower.begin(), ::tolower);

            auto int_rva = desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk;
            if (!rva_ok(int_rva, sizeof(IMAGE_THUNK_DATA)) || !rva_ok(desc->FirstThunk, sizeof(IMAGE_THUNK_DATA))) {
                continue;
            }

            // OriginalFirstThunk = Import Name Table (names), FirstThunk = IAT (addresses)
            auto* int_entry = (PIMAGE_THUNK_DATA)(base + int_rva);
            auto* iat_entry = (PIMAGE_THUNK_DATA)(base + desc->FirstThunk);

            for (; rva_ok((uintptr_t)int_entry - base, sizeof(IMAGE_THUNK_DATA)) && int_entry->u1.AddressOfData != 0; ++int_entry, ++iat_entry) {
                // Skip ordinal imports
                if (IMAGE_SNAP_BY_ORDINAL(int_entry->u1.Ordinal)) {
                    auto ordinal = IMAGE_ORDINAL(int_entry->u1.Ordinal);
                    auto key = dll_lower + "!#" + std::to_string(ordinal);
                    auto iat_addr = (uintptr_t)&iat_entry->u1.Function;

                    result.name_to_addr[std::move(key)] = iat_addr;
                    result.addr_to_name[iat_addr] = dll_lower + "!#" + std::to_string(ordinal);
                    continue;
                }

                if (!rva_ok((uintptr_t)int_entry->u1.AddressOfData, sizeof(IMAGE_IMPORT_BY_NAME))) {
                    continue;
                }

                auto* hint_name = (PIMAGE_IMPORT_BY_NAME)(base + int_entry->u1.AddressOfData);

                // Verify the name string is within bounds
                bool func_name_valid = false;
                for (auto* p = (const char*)hint_name->Name; (uintptr_t)p < module_end; ++p) {
                    if (*p == '\0') { func_name_valid = true; break; }
                }
                if (!func_name_valid) {
                    continue;
                }

                auto key = dll_lower + "!" + (const char*)hint_name->Name;
                auto iat_addr = (uintptr_t)&iat_entry->u1.Function;

                result.addr_to_name[iat_addr] = key;
                result.name_to_addr[std::move(key)] = iat_addr;
            }
        }

        return result;
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

        const auto total_size = (size_t)(max_vmend - min_vmaddr);

        if (total_size == 0 || total_size > 0x100000000ULL) { // sanity check: max 4GB
            SPDLOG_ERROR("[Mach-O] Invalid virtual extent: 0x{:X}", total_size);
            return std::nullopt;
        }

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
            g_module_ranges.push_back({ (uintptr_t)mapped_base, (uintptr_t)mapped_base + total_size });
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
