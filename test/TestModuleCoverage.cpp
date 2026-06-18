// TestModuleCoverage.cpp -- deeper coverage of Module.cpp public API
// Focus: ptr_from_rva, get_imagebase_va_from_ptr, find_partial_module,
//        foreach_module, deeper imports/exports/sections, get_original_bytes
//        overloads, map_view_of_file/pe edge, path/directory edge cases.

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

#include <Windows.h>

#include <utility/Logging.hpp>
#include <utility/Module.hpp>
#include <utility/Address.hpp>

#include "TestHelpers.hpp"

// ============================================================================
// ptr_from_rva -- convert RVA in on-disk PE to a file-offset pointer
// ============================================================================

int test_ptr_from_rva_basic() {
    // Read kernel32 from disk and resolve the entry-point RVA.
    auto kernel32 = utility::get_module("kernel32.dll");
    TEST_ASSERT(kernel32 != nullptr);

    auto disk = utility::read_module_from_disk(kernel32);
    TEST_ASSERT(!disk.empty());

    // The e_lfanew offset tells us where NT headers live; the entry-point RVA
    // is at a fixed offset inside the OptionalHeader.
    auto dos = (PIMAGE_DOS_HEADER)disk.data();
    TEST_ASSERT(dos->e_magic == IMAGE_DOS_SIGNATURE);

    auto nt = (PIMAGE_NT_HEADERS)(disk.data() + dos->e_lfanew);
    TEST_ASSERT(nt->Signature == IMAGE_NT_SIGNATURE);

    auto entry_rva = nt->OptionalHeader.AddressOfEntryPoint;

    // Resolve through ptr_from_rva -- should succeed for any valid PE.
    auto result = utility::ptr_from_rva(disk.data(), entry_rva, false);
    TEST_ASSERT(result.has_value());
    // The returned pointer should land within the disk buffer.
    auto ptr_val = *result;
    auto buf_start = (uintptr_t)disk.data();
    auto buf_end   = buf_start + disk.size();
    TEST_ASSERT(ptr_val >= buf_start && ptr_val < buf_end);

    return 0;
}

int test_ptr_from_rva_rva0() {
    // Memory module mode: ptr_from_rva simply adds rva to base.
    auto kernel32 = utility::get_module("kernel32.dll");
    TEST_ASSERT(kernel32 != nullptr);

    auto disk = utility::read_module_from_disk(kernel32);
    TEST_ASSERT(!disk.empty());

    auto mem_result = utility::ptr_from_rva(disk.data(), 0, true);
    TEST_ASSERT(mem_result.has_value());
    TEST_ASSERT(*mem_result == (uintptr_t)disk.data());

    // On-disk mode: RVA 0 typically falls before the first section's VA,
    // so the function may return nullopt. We accept either outcome.
    auto disk_result = utility::ptr_from_rva(disk.data(), 0, false);
    (void)disk_result; // no crash

    return 0;
}

int test_ptr_from_rva_out_of_range() {
    // An absurdly large RVA should return nullopt in on-disk mode.
    auto kernel32 = utility::get_module("kernel32.dll");
    TEST_ASSERT(kernel32 != nullptr);

    auto disk = utility::read_module_from_disk(kernel32);
    TEST_ASSERT(!disk.empty());

    auto result = utility::ptr_from_rva(disk.data(), 0x7FFFFFFF, false);
    TEST_ASSERT(!result.has_value());

    return 0;
}

// ============================================================================
// get_imagebase_va_from_ptr
// ============================================================================

int test_get_imagebase_va_from_ptr() {
    // For a loaded module: get_imagebase_va_from_ptr reads OptionalHeader.ImageBase
    // from the pointer passed as `dll`, then computes: file_imagebase + (ptr - base).
    auto kernel32 = utility::get_module("kernel32.dll");
    TEST_ASSERT(kernel32 != nullptr);

    // Pick a known function in kernel32.
    auto* proc = (void*)GetProcAddress(kernel32, "GetProcAddress");
    TEST_ASSERT(proc != nullptr);

    // Use the in-memory module as the dll parameter (reads ImageBase from there).
    auto result = utility::get_imagebase_va_from_ptr(
        Address{kernel32},
        Address{(uintptr_t)kernel32},
        proc
    );
    TEST_ASSERT(result.has_value());

    // Verify via manual calculation: ImageBase + (proc - base).
    auto file_imagebase = utility::get_dll_imagebase(Address{kernel32});
    TEST_ASSERT(file_imagebase.has_value());

    uintptr_t expected = *file_imagebase + ((uintptr_t)proc - (uintptr_t)kernel32);
    TEST_ASSERT(*result == expected);

    // The result should be a plausible address (non-zero, different from raw ptr).
    TEST_ASSERT(*result != 0);

    return 0;
}

int test_get_imagebase_va_from_ptr_invalid() {
    // Pass a null/bad dll pointer -- should return nullopt gracefully.
    auto result = utility::get_imagebase_va_from_ptr(
        Address{nullptr}, Address{(uintptr_t)GetModuleHandleA("kernel32.dll")}, (void*)0x1000);
    TEST_ASSERT(!result.has_value());

    return 0;
}

// ============================================================================
// find_partial_module
// ============================================================================

int test_find_partial_module_kernel() {
    // find_partial_module searches FullDllName.Buffer with a case-sensitive match.
    // The PEB FullDllName is typically like C:\Windows\System32\KERNEL32.DLL.
    // Use a substring that will match regardless of casing differences.
    auto kernel32 = utility::get_module("kernel32.dll");
    TEST_ASSERT(kernel32 != nullptr);

    // Get the actual path to find the right casing.
    auto path = utility::get_module_pathw(kernel32);
    TEST_ASSERT(path.has_value());

    // Use the file name portion as the partial search string.
    std::filesystem::path fspath{*path};
    auto leaf = fspath.filename().wstring();

    auto mod = utility::find_partial_module(leaf);
    TEST_ASSERT(mod != nullptr);
    TEST_ASSERT(mod == kernel32);

    return 0;
}

int test_find_partial_module_garbage() {
    auto mod = utility::find_partial_module(L"zzz_nonexistent_dll_name_12345");
    TEST_ASSERT(mod == nullptr);
    return 0;
}

// ============================================================================
// foreach_module -- count modules and verify kernel32 appears
// ============================================================================

int test_foreach_module_count_and_kernel32() {
    size_t count = 0;
    bool found_kernel32 = false;
    bool found_ntdll = false;

    utility::foreach_module([&](LIST_ENTRY* entry, _LDR_DATA_TABLE_ENTRY* ldr_entry) {
        ++count;
        if (ldr_entry->FullDllName.Buffer) {
            std::wstring_view name{ldr_entry->FullDllName.Buffer};
            auto lower_pos = name.find_last_of(L'\\');
            std::wstring_view leaf = (lower_pos != std::wstring_view::npos)
                ? name.substr(lower_pos + 1) : name;

            // Case-insensitive compare for detection.
            std::wstring lower{leaf};
            std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
            if (lower.find(L"kernel32.dll") != std::wstring::npos) {
                found_kernel32 = true;
            }
            if (lower.find(L"ntdll.dll") != std::wstring::npos) {
                found_ntdll = true;
            }
        }
    });

    TEST_ASSERT(count >= 2); // at least kernel32 and ntdll
    TEST_ASSERT(found_kernel32);
    TEST_ASSERT(found_ntdll);

    return 0;
}

int test_foreach_module_null_callback() {
    // Passing a null/empty callback should not crash.
    utility::foreach_module(nullptr);
    utility::foreach_module(std::function<void(LIST_ENTRY*, _LDR_DATA_TABLE_ENTRY*)>{});
    return 0;
}

// ============================================================================
// get_module_exports -- deeper: specific export + addr_to_name round-trip
// ============================================================================

int test_exports_getprocaddress() {
    auto kernel32 = utility::get_module("kernel32.dll");
    TEST_ASSERT(kernel32 != nullptr);

    auto exports = utility::get_module_exports(kernel32);
    TEST_ASSERT(exports.has_value());

    // GetProcAddress must be exported.
    TEST_ASSERT(exports->name_to_addr.count("GetProcAddress") == 1);

    auto addr = exports->name_to_addr["GetProcAddress"];
    // addr must land inside kernel32's address space.
    auto size = utility::get_module_size(kernel32);
    TEST_ASSERT(size.has_value());
    TEST_ASSERT(addr >= (uintptr_t)kernel32);
    TEST_ASSERT(addr < (uintptr_t)kernel32 + *size);

    // addr_to_name round-trip.
    TEST_ASSERT(exports->addr_to_name.count(addr) == 1);
    TEST_ASSERT(exports->addr_to_name[addr] == "GetProcAddress");

    return 0;
}

int test_exports_ntdll() {
    auto ntdll = utility::get_module("ntdll.dll");
    TEST_ASSERT(ntdll != nullptr);

    auto exports = utility::get_module_exports(ntdll);
    TEST_ASSERT(exports.has_value());
    // ntdll has hundreds of exports.
    TEST_ASSERT(exports->name_to_addr.size() > 100);
    // NtCreateFile is a well-known ntdll export.
    TEST_ASSERT(exports->name_to_addr.count("NtCreateFile") == 1);

    return 0;
}

// ============================================================================
// get_module_imports -- deeper: verify specific import and ntdll imports
// ============================================================================

int test_imports_exe_specific() {
    auto exe = utility::get_executable();
    auto imports = utility::get_module_imports(exe);
    TEST_ASSERT(imports.has_value());
    TEST_ASSERT(!imports->name_to_addr.empty());

    // The test exe imports kernel32 functions. The keys are "kernel32.dll!<func>".
    // Look for at least one known import.
    bool found_any = false;
    for (const auto& [key, addr] : imports->name_to_addr) {
        if (key.find("kernel32.dll!") == 0) {
            found_any = true;
            // Verify round-trip.
            TEST_ASSERT(imports->addr_to_name.count(addr) == 1);
            TEST_ASSERT(imports->addr_to_name[addr] == key);
            break;
        }
    }
    TEST_ASSERT(found_any);

    return 0;
}

int test_imports_ntdll() {
    // ntdll itself has no IAT (it's the bottom of the import chain), so
    // get_module_imports should return either nullopt or an empty map.
    auto ntdll = utility::get_module("ntdll.dll");
    TEST_ASSERT(ntdll != nullptr);

    auto imports = utility::get_module_imports(ntdll);
    // ntdll imports nothing from other user-mode DLLs; either nullopt or empty.
    if (imports.has_value()) {
        // If it returns something, it should be nearly empty (only ntdll internals).
        // We just verify no crash.
        (void)imports->name_to_addr.size();
    }
    return 0;
}

// ============================================================================
// get_module_sections -- deeper: .text has EXECUTE, VA within bounds
// ============================================================================

int test_sections_text_execute() {
    auto kernel32 = utility::get_module("kernel32.dll");
    TEST_ASSERT(kernel32 != nullptr);

    auto sections = utility::get_module_sections(kernel32);
    TEST_ASSERT(sections.has_value());
    TEST_ASSERT(!sections->empty());

    auto size = utility::get_module_size(kernel32);
    TEST_ASSERT(size.has_value());

    bool found_text = false;
    for (const auto& sec : *sections) {
        // Every VA must fall within the module range.
        TEST_ASSERT(sec.virtual_address >= (uintptr_t)kernel32);
        TEST_ASSERT(sec.virtual_address < (uintptr_t)kernel32 + *size);

        if (sec.name == ".text") {
            found_text = true;
            // .text should have IMAGE_SCN_MEM_EXECUTE (0x20000000).
            TEST_ASSERT((sec.characteristics & IMAGE_SCN_MEM_EXECUTE) != 0);
            // .text should also have IMAGE_SCN_MEM_READ (0x40000000).
            TEST_ASSERT((sec.characteristics & IMAGE_SCN_MEM_READ) != 0);
            // Virtual size should be > 0.
            TEST_ASSERT(sec.virtual_size > 0);
        }
    }
    TEST_ASSERT(found_text);

    return 0;
}

int test_sections_ntdll() {
    auto ntdll = utility::get_module("ntdll.dll");
    TEST_ASSERT(ntdll != nullptr);

    auto sections = utility::get_module_sections(ntdll);
    TEST_ASSERT(sections.has_value());
    TEST_ASSERT(sections->size() >= 2); // at least .text and .rdata

    return 0;
}

// ============================================================================
// get_original_bytes -- both overloads
// ============================================================================

int test_get_original_bytes_single_arg() {
    // Use the single-arg overload on a kernel32 address.
    // For an unpatched kernel32, this should return nullopt (disk == memory).
    // We just verify no crash and reasonable behavior.
    auto kernel32 = utility::get_module("kernel32.dll");
    TEST_ASSERT(kernel32 != nullptr);

    auto bytes = utility::get_original_bytes(Address{(uintptr_t)kernel32});
    // For an unpatched module, bytes will be nullopt because disk matches memory.
    // That's fine -- the function didn't crash.
    if (bytes.has_value()) {
        TEST_ASSERT(!bytes->empty());
    }

    return 0;
}

int test_get_original_bytes_two_arg() {
    // Two-arg overload: pass HMODULE + address explicitly.
    auto kernel32 = utility::get_module("kernel32.dll");
    TEST_ASSERT(kernel32 != nullptr);

    auto bytes = utility::get_original_bytes(kernel32, Address{(uintptr_t)kernel32});
    if (bytes.has_value()) {
        TEST_ASSERT(!bytes->empty());
    }

    return 0;
}

int test_get_original_bytes_bad_address() {
    // An address that doesn't belong to any loaded module -> nullopt.
    auto result = utility::get_original_bytes(Address{(uintptr_t)0x1});
    TEST_ASSERT(!result.has_value());
    return 0;
}

// ============================================================================
// map_view_of_file / map_view_of_pe with non-existent path -> nullopt
// ============================================================================

int test_map_view_of_file_nonexistent() {
    auto result = utility::map_view_of_file("C:\\nonexistent_path_12345.dll");
    TEST_ASSERT(!result.has_value());
    return 0;
}

int test_map_view_of_pe_nonexistent() {
    auto result = utility::map_view_of_pe("C:\\nonexistent_path_12345.dll");
    TEST_ASSERT(!result.has_value());
    return 0;
}

// ============================================================================
// get_module_path / get_module_directory edge cases
// ============================================================================

int test_exe_path_ends_with_name() {
    auto exe = utility::get_executable();
    TEST_ASSERT(exe != nullptr);

    auto path = utility::get_module_path(exe);
    TEST_ASSERT(path.has_value());
    TEST_ASSERT(!path->empty());

    // The path should end with the exe filename (case-insensitive on Windows).
    wchar_t buf[MAX_PATH]{};
    GetModuleFileNameW(nullptr, buf, MAX_PATH);
    std::filesystem::path fspath{buf};
    auto leaf = fspath.filename().string();

    std::filesystem::path wmodpath{std::wstring{path->begin(), path->end()}};
    auto mod_leaf = wmodpath.filename().string();

    // Case-insensitive compare.
    std::string mod_lower = mod_leaf;
    std::string leaf_lower = leaf;
    std::transform(mod_lower.begin(), mod_lower.end(), mod_lower.begin(), ::tolower);
    std::transform(leaf_lower.begin(), leaf_lower.end(), leaf_lower.begin(), ::tolower);
    TEST_ASSERT(mod_lower == leaf_lower);

    return 0;
}

int test_exe_directory_is_prefix_of_path() {
    auto exe = utility::get_executable();
    TEST_ASSERT(exe != nullptr);

    auto path = utility::get_module_path(exe);
    TEST_ASSERT(path.has_value());

    auto dir = utility::get_module_directory(exe);
    TEST_ASSERT(dir.has_value());

    // The directory should be a prefix of the full path.
    TEST_ASSERT(path->size() > dir->size());
    TEST_ASSERT(path->substr(0, dir->size()) == *dir);

    return 0;
}

// ============================================================================
// read_module_from_disk -- additional checks
// ============================================================================

int test_read_module_from_disk_kernel32() {
    auto kernel32 = utility::get_module("kernel32.dll");
    TEST_ASSERT(kernel32 != nullptr);

    auto disk = utility::read_module_from_disk(kernel32);
    TEST_ASSERT(!disk.empty());
    TEST_ASSERT(disk[0] == 'M');
    TEST_ASSERT(disk[1] == 'Z');
    // Should be at least 4KB for any real DLL.
    TEST_ASSERT(disk.size() >= 4096);

    return 0;
}

int test_read_module_from_disk_nullptr() {
    // On Windows, GetModuleFileNameW(nullptr, ...) returns the exe path.
    // So read_module_from_disk(nullptr) reads the exe, which is valid.
    // We verify it returns a valid PE (the exe).
    auto disk = utility::read_module_from_disk(nullptr);
    TEST_ASSERT(!disk.empty());
    TEST_ASSERT(disk[0] == 'M');
    TEST_ASSERT(disk[1] == 'Z');
    return 0;
}

// ============================================================================
// get_dll_imagebase / get_module_size edge cases
// ============================================================================

int test_get_dll_imagebase_kernel32() {
    auto kernel32 = utility::get_module("kernel32.dll");
    TEST_ASSERT(kernel32 != nullptr);

    auto ib = utility::get_dll_imagebase(Address{kernel32});
    // Should have a valid image base from the PE OptionalHeader.
    TEST_ASSERT(ib.has_value());
    TEST_ASSERT(*ib != 0);

    return 0;
}

int test_get_module_size_ntdll() {
    auto ntdll = utility::get_module("ntdll.dll");
    TEST_ASSERT(ntdll != nullptr);

    auto sz = utility::get_module_size(ntdll);
    TEST_ASSERT(sz.has_value());
    // ntdll is always at least a few hundred KB.
    TEST_ASSERT(*sz > 0x10000);

    return 0;
}

// ============================================================================
// main
// ============================================================================

int main() try {
    std::cout << "===== kananlib module coverage test =====" << std::endl;

    // ptr_from_rva
    RUN_TEST(test_ptr_from_rva_basic);
    RUN_TEST(test_ptr_from_rva_rva0);
    RUN_TEST(test_ptr_from_rva_out_of_range);

    // get_imagebase_va_from_ptr
    RUN_TEST(test_get_imagebase_va_from_ptr);
    RUN_TEST(test_get_imagebase_va_from_ptr_invalid);

    // find_partial_module
    RUN_TEST(test_find_partial_module_kernel);
    RUN_TEST(test_find_partial_module_garbage);

    // foreach_module
    RUN_TEST(test_foreach_module_count_and_kernel32);
    RUN_TEST(test_foreach_module_null_callback);

    // Deeper exports
    RUN_TEST(test_exports_getprocaddress);
    RUN_TEST(test_exports_ntdll);

    // Deeper imports
    RUN_TEST(test_imports_exe_specific);
    RUN_TEST(test_imports_ntdll);

    // Deeper sections
    RUN_TEST(test_sections_text_execute);
    RUN_TEST(test_sections_ntdll);

    // get_original_bytes overloads
    RUN_TEST(test_get_original_bytes_single_arg);
    RUN_TEST(test_get_original_bytes_two_arg);
    RUN_TEST(test_get_original_bytes_bad_address);

    // map_view_of_file/pe non-existent
    RUN_TEST(test_map_view_of_file_nonexistent);
    RUN_TEST(test_map_view_of_pe_nonexistent);

    // Path/directory edge
    RUN_TEST(test_exe_path_ends_with_name);
    RUN_TEST(test_exe_directory_is_prefix_of_path);

    // read_module_from_disk additional
    RUN_TEST(test_read_module_from_disk_kernel32);
    RUN_TEST(test_read_module_from_disk_nullptr);

    // imagebase / module size edge
    RUN_TEST(test_get_dll_imagebase_kernel32);
    RUN_TEST(test_get_module_size_ntdll);

    return test_summary();
} catch (const std::exception& e) {
    std::cout << "Exception: " << e.what() << std::endl;
    return 1;
} catch (...) {
    std::cout << "Unknown exception." << std::endl;
    return 1;
}
