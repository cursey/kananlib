// Cross-platform PE-mapping + scanning test.
//
// This is the "reasonable on Linux" counterpart to the tests that introspect the
// running process (which assume a live PE host and so cannot work on an ELF
// process). It maps a committed, MSVC-compiled sample DLL (samples/kananlib_sample.dll)
// with utility::map_view_of_file -- which on non-Windows lays the PE sections out
// at their RVAs via mmap and applies base relocations -- then exercises the core
// scan / module / RTTI utilities against the sample's known, deterministic
// content. The same assertions hold on Windows.
//
// The sample exports kananlib_sample_{compute,add,make,call}, imports
// kernel32!GetCurrentProcessId, contains the string "kananlib_sample_marker"
// (referenced by kananlib_sample_compute), and defines a polymorphic class
// SampleVtableClass (RTTI TypeDescriptor ".?AVSampleVtableClass@@").

#include <cstdint>
#include <string>

#include <windows.h>

#include <utility/Module.hpp>
#include <utility/Scan.hpp>
#include <utility/RTTI.hpp>
#include <utility/Address.hpp>

#include "TestHelpers.hpp"

// KANANLIB_SAMPLE_DIR is passed unquoted by the build; stringize it here.
#define KANANLIB_STR2(x) #x
#define KANANLIB_STR(x) KANANLIB_STR2(x)
#ifndef KANANLIB_SAMPLE_DIR
#define KANANLIB_SAMPLE_DIR .
#endif

namespace {
constexpr const char* kMarker   = "kananlib_sample_marker";
constexpr const char* kRttiName = ".?AVSampleVtableClass@@";
constexpr uint32_t kComputeRva  = 0x1000; // kananlib_sample_compute (verified via exports)

std::string sample_path() {
    return std::string{ KANANLIB_STR(KANANLIB_SAMPLE_DIR) } + "/kananlib_sample.dll";
}
} // namespace

// Mapping a real PE yields a usable module handle and a plausible image size.
int test_map_pe() {
    auto mapped = utility::map_view_of_file(sample_path());
    TEST_ASSERT(mapped.has_value());
    TEST_ASSERT(mapped->module != nullptr);

    const auto size = utility::get_module_size(mapped->module);
    TEST_ASSERT(size.has_value());
    TEST_ASSERT(*size >= 0x1000);
    return 0;
}

// Sections are laid out at their RVAs (.text is executable).
int test_sections() {
    auto mapped = utility::map_view_of_file(sample_path());
    TEST_ASSERT(mapped.has_value());
    const auto base = reinterpret_cast<uintptr_t>(mapped->module);

    auto sections = utility::get_module_sections(mapped->module);
    TEST_ASSERT(sections.has_value());
    TEST_ASSERT(!sections->empty());

    bool found_text = false;
    for (const auto& s : *sections) {
        TEST_ASSERT(s.virtual_address >= base);
        if (s.name == ".text") {
            found_text = true;
            TEST_ASSERT((s.characteristics & IMAGE_SCN_MEM_EXECUTE) != 0);
        }
    }
    TEST_ASSERT(found_text);
    return 0;
}

// Export directory resolves the sample's exported functions to the right RVAs.
int test_exports() {
    auto mapped = utility::map_view_of_file(sample_path());
    TEST_ASSERT(mapped.has_value());
    const auto base = reinterpret_cast<uintptr_t>(mapped->module);

    auto exports = utility::get_module_exports(mapped->module);
    TEST_ASSERT(exports.has_value());

    const auto& n2a = exports->name_to_addr;
    TEST_ASSERT(n2a.count("kananlib_sample_compute") == 1);
    TEST_ASSERT(n2a.count("kananlib_sample_add") == 1);
    TEST_ASSERT(n2a.count("kananlib_sample_make") == 1);
    TEST_ASSERT(n2a.count("kananlib_sample_call") == 1);
    TEST_ASSERT(n2a.at("kananlib_sample_compute") == base + kComputeRva);
    return 0;
}

// Import directory exposes the kernel32 import the sample references.
int test_imports() {
    auto mapped = utility::map_view_of_file(sample_path());
    TEST_ASSERT(mapped.has_value());

    auto imports = utility::get_module_imports(mapped->module);
    TEST_ASSERT(imports.has_value());
    TEST_ASSERT(imports->name_to_addr.count("kernel32.dll!GetCurrentProcessId") == 1);
    return 0;
}

// scan_string finds the marker, which lives in a read-only data section.
int test_string_scan() {
    auto mapped = utility::map_view_of_file(sample_path());
    TEST_ASSERT(mapped.has_value());

    auto str = utility::scan_string(mapped->module, std::string{ kMarker });
    TEST_ASSERT(str.has_value());

    const auto base = reinterpret_cast<uintptr_t>(mapped->module);
    const auto size = *utility::get_module_size(mapped->module);
    TEST_ASSERT(*str >= base && *str < base + size);
    return 0;
}

// scan_displacement_reference resolves the RIP-relative LEA in
// kananlib_sample_compute that points at the marker string. This exercises
// displacement decoding plus .pdata-based function resolution.
int test_displacement_reference() {
    auto mapped = utility::map_view_of_file(sample_path());
    TEST_ASSERT(mapped.has_value());
    const auto base = reinterpret_cast<uintptr_t>(mapped->module);

    auto str = utility::scan_string(mapped->module, std::string{ kMarker });
    TEST_ASSERT(str.has_value());

    auto ref = utility::scan_displacement_reference(mapped->module, *str);
    TEST_ASSERT(ref.has_value());

    auto func = utility::find_function_start(*ref);
    TEST_ASSERT(func.has_value());
    TEST_ASSERT(*func == base + kComputeRva);
    return 0;
}

// .pdata-based function resolution: an address inside kananlib_sample_compute
// resolves back to its start.
int test_function_start() {
    auto mapped = utility::map_view_of_file(sample_path());
    TEST_ASSERT(mapped.has_value());
    const auto base = reinterpret_cast<uintptr_t>(mapped->module);

    auto start = utility::find_function_start(base + kComputeRva + 8);
    TEST_ASSERT(start.has_value());
    TEST_ASSERT(*start == base + kComputeRva);
    return 0;
}

// RTTI: find the vtable for SampleVtableClass by its decorated type name. This
// only works because the mapper applied base relocations (the vtable -> RTTI
// complete-object-locator pointer is absolute).
int test_rtti_find_vtable() {
    auto mapped = utility::map_view_of_file(sample_path());
    TEST_ASSERT(mapped.has_value());
    const auto base = reinterpret_cast<uintptr_t>(mapped->module);
    const auto size = *utility::get_module_size(mapped->module);

    auto vtable = utility::rtti::find_vtable(mapped->module, kRttiName);
    TEST_ASSERT(vtable.has_value());
    TEST_ASSERT(*vtable >= base && *vtable < base + size);
    return 0;
}

// A nonexistent path fails cleanly (no crash, no value).
int test_nonexistent_path() {
    auto mapped = utility::map_view_of_file("/nonexistent/kananlib/does_not_exist.dll");
    TEST_ASSERT(!mapped.has_value());
    return 0;
}

int main() {
    RUN_TEST(test_map_pe);
    RUN_TEST(test_sections);
    RUN_TEST(test_exports);
    RUN_TEST(test_imports);
    RUN_TEST(test_string_scan);
    RUN_TEST(test_displacement_reference);
    RUN_TEST(test_function_start);
    RUN_TEST(test_rtti_find_vtable);
    RUN_TEST(test_nonexistent_path);
    return test_summary();
}
