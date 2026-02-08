#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>
#include <string_view>
#include <functional>

#include <Windows.h>
#include <winternl.h>

#include "Address.hpp"

struct _LIST_ENTRY;
typedef struct _LIST_ENTRY LIST_ENTRY;

struct _LDR_DATA_TABLE_ENTRY;

typedef NTSTATUS (WINAPI* PFN_LdrLockLoaderLock)(ULONG Flags, ULONG *State, ULONG_PTR *Cookie);
typedef NTSTATUS (WINAPI* PFN_LdrUnlockLoaderLock)(ULONG Flags, ULONG_PTR Cookie);

namespace utility {
    //
    // Module utilities.
    //
    std::optional<size_t> get_module_size(const std::string& module);
    std::optional<size_t> get_module_size(const std::wstring& module);
    std::optional<size_t> get_module_size(HMODULE module);
    std::optional<HMODULE> get_module_within(Address address);
    std::optional<uintptr_t> get_dll_imagebase(Address dll);
    std::optional<uintptr_t> get_imagebase_va_from_ptr(Address dll, Address base, void* ptr);

    std::optional<std::string> get_module_path(HMODULE module);
    std::optional<std::wstring> get_module_pathw(HMODULE module);
    std::optional<std::string> get_module_directory(HMODULE module);
    std::optional<std::wstring> get_module_directoryw(HMODULE module);
    HMODULE load_module_from_current_directory(const std::wstring& module);

    std::vector<uint8_t> read_module_from_disk(HMODULE module);

    // Returns the original bytes of the module at the given address.
    // useful for un-patching something.
    std::optional<std::vector<uint8_t>> get_original_bytes(Address address);
    std::optional<std::vector<uint8_t>> get_original_bytes(HMODULE module, Address address);

    // Note: This function doesn't validate the dll's headers so make sure you've
    // done so before calling it.
    std::optional<uintptr_t> ptr_from_rva(const uint8_t* dll, uintptr_t rva, bool memory_module = false);

    HMODULE get_executable();
    HMODULE get_module(const std::string& module);
    HMODULE unlink(HMODULE module);
    HMODULE safe_unlink(HMODULE module);
    HMODULE find_partial_module(std::wstring_view name);

    void foreach_module(std::function<void(LIST_ENTRY*, _LDR_DATA_TABLE_ENTRY*)> callback);
    size_t get_module_count(std::wstring_view name);
    void unlink_duplicate_modules();
    void spoof_module_paths_in_exe_dir();

    std::vector<std::wstring> get_loaded_module_names();

    struct LoaderLockGuard {
        LoaderLockGuard();
        ~LoaderLockGuard();
    
    private:
        ULONG_PTR cookie{};
    };

    struct FakeModule {
        HMODULE module{};
        HANDLE file_handle{};
        HANDLE mapping_handle{};

        FakeModule(HMODULE module, HANDLE file_handle, HANDLE mapping_handle)
            : module{ module }
            , file_handle{ file_handle }
            , mapping_handle{ mapping_handle }
        {}
        
        FakeModule(const FakeModule&) = delete;
        FakeModule& operator=(const FakeModule&) = delete;
        FakeModule(FakeModule&& other) noexcept
            : module{ other.module }
            , file_handle{ other.file_handle }
            , mapping_handle{ other.mapping_handle }
        {
            other.module = nullptr;
            other.file_handle = nullptr;
            other.mapping_handle = nullptr;
        }

        // Sets everything to null so the destructor won't clean up. 
        // Useful if you want to keep the module around after the FakeModule goes out of scope.
        void detach() {
            module = nullptr;
            file_handle = nullptr;
            mapping_handle = nullptr;
        }

        virtual ~FakeModule();
    };

    // Maps a PE into memory without loading it, and adds it to the module list with a fake entry.
    // Useful for being able to use our normal utilities on a PE that isn't actually loaded.
    // Especially useful on executables because we can't call LoadLibraryExA on them correctly.
    std::optional<FakeModule> map_view_of_pe(const std::string& path);
}
