#include <algorithm>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

#include <windows.h>

#include <utility/Logging.hpp>
#include <utility/Module.hpp>
#include <utility/Address.hpp>

#include "TestHelpers.hpp"

// ============================================================================
// Basic module lookup tests
// ============================================================================

int test_get_executable() {
    auto exe = utility::get_executable();
    TEST_ASSERT(exe != nullptr);
    return 0;
}

int test_get_module_kernel32() {
    auto mod = utility::get_module("kernel32.dll");
    TEST_ASSERT(mod != nullptr);
    return 0;
}

int test_get_module_ntdll() {
    auto mod = utility::get_module("ntdll.dll");
    TEST_ASSERT(mod != nullptr);
    return 0;
}

int test_get_module_nonexistent() {
    auto mod = utility::get_module("this_does_not_exist.dll");
    TEST_ASSERT(mod == nullptr);
    return 0;
}

// ============================================================================
// Module size tests
// ============================================================================

int test_get_module_size_hmodule() {
    auto exe = utility::get_executable();
    auto size = utility::get_module_size(exe);
    TEST_ASSERT(size.has_value());
    TEST_ASSERT(*size > 0);
    // A test executable should be at least a few KB.
    TEST_ASSERT(*size >= 4096);
    return 0;
}

int test_get_module_size_by_string() {
    auto size = utility::get_module_size(std::string{"kernel32.dll"});
    TEST_ASSERT(size.has_value());
    TEST_ASSERT(*size > 0);
    return 0;
}

int test_get_module_size_by_wstring() {
    auto size = utility::get_module_size(std::wstring{L"kernel32.dll"});
    TEST_ASSERT(size.has_value());
    TEST_ASSERT(*size > 0);
    return 0;
}

int test_get_module_size_nullptr() {
    auto size = utility::get_module_size((HMODULE)nullptr);
    TEST_ASSERT(!size.has_value());
    return 0;
}

// ============================================================================
// get_module_within
// ============================================================================

int test_get_module_within() {
    // The address of this function should be within the test executable.
    auto fn_addr = (uintptr_t)&test_get_module_within;
    auto mod = utility::get_module_within(Address{fn_addr});
    TEST_ASSERT(mod.has_value());
    // Should match the executable module.
    TEST_ASSERT(*mod == utility::get_executable());
    return 0;
}

// ============================================================================
// get_dll_imagebase
// ============================================================================

int test_get_dll_imagebase() {
    auto exe = utility::get_executable();
    auto ib = utility::get_dll_imagebase(Address{exe});
    TEST_ASSERT(ib.has_value());
    // For a loaded module, the imagebase should be the module base itself.
    TEST_ASSERT(*ib == (uintptr_t)exe);
    return 0;
}

// ============================================================================
// get_module_path
// ============================================================================

int test_get_module_path() {
    auto exe = utility::get_executable();
    auto path = utility::get_module_path(exe);
    TEST_ASSERT(path.has_value());
    TEST_ASSERT(!path->empty());
    // Path should end with .exe (case-insensitive check via lowercase).
    std::string lower = *path;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    TEST_ASSERT(lower.find(".exe") != std::string::npos);
    return 0;
}

int test_get_module_pathw() {
    auto exe = utility::get_executable();
    auto path = utility::get_module_pathw(exe);
    TEST_ASSERT(path.has_value());
    TEST_ASSERT(!path->empty());
    std::wstring lower = *path;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
    TEST_ASSERT(lower.find(L".exe") != std::wstring::npos);
    return 0;
}

// ============================================================================
// get_module_directory
// ============================================================================

int test_get_module_directory() {
    auto exe = utility::get_executable();
    auto dir = utility::get_module_directory(exe);
    TEST_ASSERT(dir.has_value());
    TEST_ASSERT(!dir->empty());
    // Directory should not contain the filename itself.
    auto path = utility::get_module_path(exe);
    TEST_ASSERT(path.has_value());
    // The directory should be a prefix of the full path.
    TEST_ASSERT(path->find(*dir) == 0);
    return 0;
}

int test_get_module_directoryw() {
    auto exe = utility::get_executable();
    auto dir = utility::get_module_directoryw(exe);
    TEST_ASSERT(dir.has_value());
    TEST_ASSERT(!dir->empty());
    auto path = utility::get_module_pathw(exe);
    TEST_ASSERT(path.has_value());
    TEST_ASSERT(path->find(*dir) == 0);
    return 0;
}

// ============================================================================
// get_loaded_module_names
// ============================================================================

int test_get_loaded_module_names() {
    auto names = utility::get_loaded_module_names();
    TEST_ASSERT(!names.empty());
    // We should find at least ntdll and kernel32 in the list.
    bool found_ntdll = false;
    bool found_kernel32 = false;
    for (const auto& name : names) {
        std::wstring lower = name;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
        if (lower.find(L"ntdll.dll") != std::wstring::npos) found_ntdll = true;
        if (lower.find(L"kernel32.dll") != std::wstring::npos) found_kernel32 = true;
    }
    TEST_ASSERT(found_ntdll);
    TEST_ASSERT(found_kernel32);
    return 0;
}

// ============================================================================
// get_module_count
// ============================================================================

int test_get_module_count() {
    // kernel32.dll should always be loaded exactly once.
    auto count = utility::get_module_count(L"kernel32.dll");
    TEST_ASSERT(count >= 1);
    return 0;
}

// ============================================================================
// read_module_from_disk
// ============================================================================

int test_read_module_from_disk() {
    auto exe = utility::get_executable();
    auto data = utility::read_module_from_disk(exe);
    TEST_ASSERT(!data.empty());
    // Check MZ header.
    TEST_ASSERT(data[0] == 'M');
    TEST_ASSERT(data[1] == 'Z');
    return 0;
}

// ============================================================================
// get_original_bytes
// ============================================================================

int test_get_original_bytes() {
    // Read original bytes at the start of the executable's code.
    // This tests the full pipeline: read_module_from_disk -> ptr_from_rva -> compare.
    auto exe = utility::get_executable();
    auto bytes = utility::get_original_bytes(Address{exe});
    // May return nullopt if the loaded bytes match disk bytes (no patches).
    // That's expected for an unmodified test executable. We just verify
    // the function doesn't crash.
    (void)bytes;
    return 0;
}

// ============================================================================
// get_module_imports
// ============================================================================

int test_get_module_imports() {
    auto exe = utility::get_executable();
    auto imports = utility::get_module_imports(exe);
    TEST_ASSERT(imports.has_value());
    // The test executable imports from at least some DLLs.
    // Look for any kernel32 import (e.g., "kernel32.dll!..." key).
    bool found_kernel32 = false;
    for (const auto& [name, addr] : imports->name_to_addr) {
        if (name.find("kernel32.dll!") == 0) {
            found_kernel32 = true;
            break;
        }
    }
    TEST_ASSERT(found_kernel32);
    // Reverse map should also work.
    TEST_ASSERT(!imports->addr_to_name.empty());
    return 0;
}

// ============================================================================
// get_module_exports
// ============================================================================

int test_get_module_exports() {
    auto kernel32 = utility::get_module("kernel32.dll");
    auto exports = utility::get_module_exports(kernel32);
    TEST_ASSERT(exports.has_value());
    // kernel32 should export many functions.
    TEST_ASSERT(exports->name_to_addr.size() > 100);
    // Check for a well-known export.
    TEST_ASSERT(exports->name_to_addr.count("CreateFileW") == 1);
    // Reverse lookup should work.
    auto addr = exports->name_to_addr["CreateFileW"];
    TEST_ASSERT(exports->addr_to_name.count(addr) == 1);
    TEST_ASSERT(exports->addr_to_name[addr] == "CreateFileW");
    return 0;
}

// ============================================================================
// get_module_sections
// ============================================================================

int test_get_module_sections() {
    auto exe = utility::get_executable();
    auto sections = utility::get_module_sections(exe);
    TEST_ASSERT(sections.has_value());
    TEST_ASSERT(!sections->empty());
    // Should have at least .text and .rdata.
    bool found_text = false;
    bool found_rdata = false;
    for (const auto& sec : *sections) {
        if (sec.name == ".text") found_text = true;
        if (sec.name == ".rdata") found_rdata = true;
        // Virtual address should be non-zero (loaded module).
        TEST_ASSERT(sec.virtual_address != 0);
    }
    TEST_ASSERT(found_text);
    TEST_ASSERT(found_rdata);
    return 0;
}

// ============================================================================
// LoaderLockGuard RAII
// ============================================================================

int test_loader_lock_guard() {
    // Construct and immediately destroy. Should not crash or deadlock.
    {
        utility::LoaderLockGuard lock{};
    }
    // Nested locks should also be fine.
    {
        utility::LoaderLockGuard outer{};
        utility::LoaderLockGuard inner{};
    }
    return 0;
}

// ============================================================================
// FakeModule move semantics
// ============================================================================

int test_fake_module_move_construct() {
    // Create a FakeModule with null handles to test move semantics.
    // (We can't easily create a real FakeModule without map_view_of_pe.)
    utility::FakeModule fm1{nullptr, nullptr, nullptr, false};
    TEST_ASSERT(fm1.module == nullptr);
    TEST_ASSERT(fm1.file_handle == nullptr);
    TEST_ASSERT(fm1.mapping_handle == nullptr);

    // Move construct.
    utility::FakeModule fm2{std::move(fm1)};
    // fm2 should have the values (all null, but ownership transferred).
    TEST_ASSERT(fm2.module == nullptr);
    // fm1 should be zeroed out after move.
    TEST_ASSERT(fm1.module == nullptr);
    TEST_ASSERT(fm1.file_handle == nullptr);

    return 0;
}

int test_fake_module_detach() {
    // Create a FakeModule with VirtualAlloc'd memory to test detach.
    auto* page = (HMODULE)VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    TEST_ASSERT(page != nullptr);

    {
        utility::FakeModule fm{page, nullptr, nullptr, true};
        TEST_ASSERT(fm.module == page);

        // Detach: fm should no longer free the memory.
        fm.detach();
        TEST_ASSERT(fm.module == nullptr);
        TEST_ASSERT(fm.file_handle == nullptr);
        TEST_ASSERT(fm.mapping_handle == nullptr);
    }

    // After detach, page is still valid. Free it manually.
    TEST_ASSERT(VirtualFree(page, 0, MEM_RELEASE));

    return 0;
}

// ============================================================================
// map_view_of_pe / map_view_of_file
// ============================================================================

int test_map_view_of_pe() {
    // Get the path of our own executable, then map it as a PE.
    auto exe = utility::get_executable();
    auto path = utility::get_module_path(exe);
    TEST_ASSERT(path.has_value());
    TEST_ASSERT(!path->empty());

    auto mapped = utility::map_view_of_pe(*path);
    TEST_ASSERT(mapped.has_value());
    TEST_ASSERT(mapped->module != nullptr);
    TEST_ASSERT(mapped->file_handle != nullptr);
    TEST_ASSERT(mapped->mapping_handle != nullptr);

    // The mapped module should have valid PE headers.
    auto dos = (PIMAGE_DOS_HEADER)mapped->module;
    TEST_ASSERT(dos->e_magic == IMAGE_DOS_SIGNATURE);

    auto nt = (PIMAGE_NT_HEADERS)((uintptr_t)dos + dos->e_lfanew);
    TEST_ASSERT(nt->Signature == IMAGE_NT_SIGNATURE);

    // get_module_size should work on the mapped module.
    auto size = utility::get_module_size(mapped->module);
    TEST_ASSERT(size.has_value());
    TEST_ASSERT(*size > 0);

    // Cleanup happens automatically when FakeModule is destroyed.
    return 0;
}

int test_map_view_of_file_pe() {
    // map_view_of_file should auto-detect PE format.
    auto exe = utility::get_executable();
    auto path = utility::get_module_path(exe);
    TEST_ASSERT(path.has_value());

    auto mapped = utility::map_view_of_file(*path);
    TEST_ASSERT(mapped.has_value());
    TEST_ASSERT(mapped->module != nullptr);

    // Cleanup automatic.
    return 0;
}

// ============================================================================
// Negative / edge cases
// ============================================================================

int test_get_module_path_nullptr() {
    // Windows treats NULL HMODULE as "current executable" for GetModuleFileName.
    // Document that behavior explicitly so this test can fail if the wrapper changes.
    auto path = utility::get_module_path((HMODULE)nullptr);
    auto exe_path = utility::get_module_path(utility::get_executable());
    TEST_ASSERT(path.has_value());
    TEST_ASSERT(exe_path.has_value());
    TEST_ASSERT(*path == *exe_path);
    return 0;
}

int test_get_module_imports_nullptr() {
    auto imports = utility::get_module_imports((HMODULE)nullptr);
    TEST_ASSERT(!imports.has_value());
    return 0;
}

int test_get_module_exports_nullptr() {
    auto exports = utility::get_module_exports((HMODULE)nullptr);
    TEST_ASSERT(!exports.has_value());
    return 0;
}

int test_get_module_sections_nullptr() {
    auto sections = utility::get_module_sections((HMODULE)nullptr);
    TEST_ASSERT(!sections.has_value());
    return 0;
}

// ============================================================================
// main
// ============================================================================

int main() try {
    std::cout << "===== kananlib module test =====" << std::endl;

    // Basic lookup.
    RUN_TEST(test_get_executable);
    RUN_TEST(test_get_module_kernel32);
    RUN_TEST(test_get_module_ntdll);
    RUN_TEST(test_get_module_nonexistent);

    // Module size.
    RUN_TEST(test_get_module_size_hmodule);
    RUN_TEST(test_get_module_size_by_string);
    RUN_TEST(test_get_module_size_by_wstring);
    RUN_TEST(test_get_module_size_nullptr);

    // Module within / imagebase.
    RUN_TEST(test_get_module_within);
    RUN_TEST(test_get_dll_imagebase);

    // Module path.
    RUN_TEST(test_get_module_path);
    RUN_TEST(test_get_module_pathw);

    // Module directory.
    RUN_TEST(test_get_module_directory);
    RUN_TEST(test_get_module_directoryw);

    // Loaded module enumeration.
    RUN_TEST(test_get_loaded_module_names);
    RUN_TEST(test_get_module_count);

    // Disk reading.
    RUN_TEST(test_read_module_from_disk);
    RUN_TEST(test_get_original_bytes);

    // Imports / exports / sections.
    RUN_TEST(test_get_module_imports);
    RUN_TEST(test_get_module_exports);
    RUN_TEST(test_get_module_sections);

    // RAII helpers.
    RUN_TEST(test_loader_lock_guard);

    // FakeModule.
    RUN_TEST(test_fake_module_move_construct);
    RUN_TEST(test_fake_module_detach);

    // PE mapping.
    RUN_TEST(test_map_view_of_pe);
    RUN_TEST(test_map_view_of_file_pe);

    // Negative / edge cases.
    RUN_TEST(test_get_module_path_nullptr);
    RUN_TEST(test_get_module_imports_nullptr);
    RUN_TEST(test_get_module_exports_nullptr);
    RUN_TEST(test_get_module_sections_nullptr);

    return test_summary();
} catch (const std::exception& e) {
    std::cout << "Exception: " << e.what() << std::endl;
    return 1;
} catch (...) {
    std::cout << "Unknown exception." << std::endl;
    return 1;
}
