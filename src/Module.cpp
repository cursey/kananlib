#define NOMINMAX

#include <fstream>
#include <filesystem>
#include <unordered_set>
#include <mutex>

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

        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            return {};
        }

        // Get the nt headers and verify that they seem valid.
        auto ntHeaders = (PIMAGE_NT_HEADERS)((uintptr_t)dosHeader + dosHeader->e_lfanew);

        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
            return {};
        }

        // OptionalHeader is not actually optional.
        return ntHeaders->OptionalHeader.SizeOfImage;
    }

    std::optional<HMODULE> get_module_within(Address address) {
        HMODULE module = nullptr;
        if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, address.as<LPCSTR>(), &module)) {
            return module;
        }

        return {};
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

    optional<uintptr_t> ptr_from_rva(uint8_t* dll, uintptr_t rva) {
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
}
