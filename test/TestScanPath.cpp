// ============================================================================
// Coverage tests for Scan.cpp path-finder family:
//   find_next_displacement, find_string_reference_in_path (char/wchar_t),
//   find_pointer_in_path, find_displacement_in_path,
//   find_mnemonic_in_path, find_register_usage_in_path,
//   find_pattern_in_path, find_encapsulating_function,
//   find_encapsulating_function_disp,
//   find_encapsulating_virtual_function, find_encapsulating_virtual_function_disp
// ============================================================================

#include <cstdint>
#include <string>
#include <iostream>
#include <cstring>

#include <Windows.h>

#include <bddisasm.h>
#include <utility/Scan.hpp>
#include <utility/Module.hpp>

#include "TestHelpers.hpp"

// ============================================================================
// Global volatile sinks — prevent optimizer from removing our test functions
// ============================================================================

volatile int g_path_sink = 0;

// These hold the address of strings so the compiler must actually embed them.
static const char    g_str_marker[]   = "COV_PATH_MARKER_STR";
static const wchar_t g_wstr_marker[]  = L"COV_PATH_MARKER_WIDE";

// A global integer whose address we can search for in tests.
int g_path_target_value = 42;

// A global pointer storing a known address. find_pointer_in_path reads
// *(void**)*disp from the resolved displacement address, so we need
// memory that CONTAINS the pointer value.
void* g_func_ptr_target = nullptr;

// ============================================================================
// Target functions: real code with known characteristics for path analysis
// ============================================================================

// Function that references a narrow string literal via RIP-relative LEA.
__declspec(noinline) void cov_path_uses_narrow_string() {
    volatile const char* s = g_str_marker;
    g_path_sink = s[0];
}

// Function that references a wide string literal.
__declspec(noinline) void cov_path_uses_wide_string() {
    volatile const wchar_t* ws = g_wstr_marker;
    g_path_sink = ws[0];
}

// Function that references the address of a global.
__declspec(noinline) void cov_path_uses_global_addr() {
    volatile int* p = &g_path_target_value;
    g_path_sink = *p;
}

// A leaf function called by cov_path_caller.
__declspec(noinline) int cov_path_leaf(int x) {
    volatile int y = x * 3 + 1;
    return y;
}

// A function that calls cov_path_leaf — used for find_encapsulating_function tests.
__declspec(noinline) int cov_path_caller(int x) {
    return cov_path_leaf(x) + cov_path_leaf(x + 1);
}

// A function with a known displacement (loads the address of g_path_target_value).
__declspec(noinline) void cov_path_has_displacement() {
    volatile int* p = &g_path_target_value;
    g_path_sink = *p + 1;
}

// Function that dereferences a global pointer — generates MOV from [rip+disp].
// find_pointer_in_path resolves disp -> &g_func_ptr_target, then reads
// *(void**)&g_func_ptr_target to compare with the searched pointer.
__declspec(noinline) void cov_path_loads_pointer() {
    volatile void* p = g_func_ptr_target;
    g_path_sink = p != nullptr ? 1 : 0;
}

// A function doing arithmetic — will have "ret", "mov", "imul", etc.
__declspec(noinline) int cov_path_arithmetic(int a, int b) {
    volatile int r = a * b + a - b;
    return r;
}

// ============================================================================
// Virtual function hierarchy for find_encapsulating_virtual_function
// ============================================================================

struct PathTestBase {
    virtual ~PathTestBase() {}
    virtual int virt_a(int x) = 0;
    virtual int virt_b(int x) = 0;
};

static volatile int g_virt_sink = 0;

struct PathTestDerived : PathTestBase {
    int data = 0;
    ~PathTestDerived() override {}
    int virt_a(int x) override {
        volatile int r = x * 7 + 3;
        g_virt_sink = r;
        return r;
    }
    int virt_b(int x) override {
        volatile int r = x + 100;
        g_virt_sink = r;
        return r;
    }
};

// ============================================================================
// Helper: ensure target functions are compiled & their addresses are valid
// ============================================================================

static void force_compile_targets() {
    // Initialize the stored-pointer global BEFORE calling the function.
    g_func_ptr_target = (void*)&g_path_target_value;

    // Call every function so the linker keeps them and the optimizer
    // can't eliminate them. Use volatile results to prevent folding.
    volatile int r1 = cov_path_leaf(1);
    volatile int r2 = cov_path_caller(2);
    volatile int r3 = cov_path_arithmetic(3, 4);
    (void)r1; (void)r2; (void)r3;
    cov_path_uses_narrow_string();
    cov_path_uses_wide_string();
    cov_path_uses_global_addr();
    cov_path_has_displacement();
    cov_path_loads_pointer();
}

// ============================================================================
// Test: find_next_displacement — find RIP-relative access in a real function
// ============================================================================

int test_find_next_displacement_narrow_str() {
    // cov_path_uses_narrow_string loads g_str_marker via RIP-relative LEA/MOV.
    auto result = utility::find_next_displacement((uintptr_t)&cov_path_uses_narrow_string, false);
    if (result) {
        TEST_EXPECT(result->displacement != 0);
        TEST_EXPECT(result->addr >= (uintptr_t)&cov_path_uses_narrow_string);
    }
    return 0;
}

int test_find_next_displacement_arithmetic() {
    // cov_path_arithmetic does pure arithmetic — may or may not have RIP-relative accesses.
    auto result = utility::find_next_displacement((uintptr_t)&cov_path_arithmetic, false);
    (void)result;
    return 0;
}

// ============================================================================
// Test: find_string_reference_in_path (narrow string)
// ============================================================================

int test_find_string_ref_narrow_hit() {
    auto result = utility::find_string_reference_in_path(
        (uintptr_t)&cov_path_uses_narrow_string,
        std::string_view{"COV_PATH_MARKER_STR"},
        false
    );
    TEST_ASSERT(result.has_value());
    TEST_ASSERT(result->displacement != 0);
    TEST_ASSERT(result->addr >= (uintptr_t)&cov_path_uses_narrow_string);
    TEST_ASSERT(std::string_view{(const char*)result->displacement} == "COV_PATH_MARKER_STR");
    return 0;
}

int test_find_string_ref_narrow_miss() {
    auto result = utility::find_string_reference_in_path(
        (uintptr_t)&cov_path_uses_narrow_string,
        std::string_view{"THIS_STRING_DOES_NOT_EXIST_ANYWHERE_12345"},
        false
    );
    TEST_ASSERT(!result.has_value());
    return 0;
}

int test_find_string_ref_empty() {
    auto result = utility::find_string_reference_in_path(
        (uintptr_t)&cov_path_uses_narrow_string,
        std::string_view{},
        false
    );
    TEST_ASSERT(!result.has_value());
    return 0;
}

// ============================================================================
// Test: find_string_reference_in_path (wide string)
// ============================================================================

int test_find_string_ref_wide_hit() {
    auto result = utility::find_string_reference_in_path(
        (uintptr_t)&cov_path_uses_wide_string,
        std::wstring_view{L"COV_PATH_MARKER_WIDE"},
        false
    );
    TEST_ASSERT(result.has_value());
    TEST_ASSERT(result->displacement != 0);
    TEST_ASSERT(result->addr >= (uintptr_t)&cov_path_uses_wide_string);
    TEST_ASSERT(std::wstring_view{(const wchar_t*)result->displacement} == L"COV_PATH_MARKER_WIDE");
    return 0;
}

int test_find_string_ref_wide_miss() {
    auto result = utility::find_string_reference_in_path(
        (uintptr_t)&cov_path_uses_wide_string,
        std::wstring_view{L"NO_SUCH_WIDE_STRING_XYZ"},
        false
    );
    TEST_ASSERT(!result.has_value());
    return 0;
}

// ============================================================================
// Test: find_pointer_in_path
// ============================================================================

int test_find_pointer_in_path_hit() {
    // cov_path_loads_pointer reads g_func_ptr_target which stores &g_path_target_value.
    // resolve_displacement -> &g_func_ptr_target, then *(void**)&g_func_ptr_target == &g_path_target_value.
    auto result = utility::find_pointer_in_path(
        (uintptr_t)&cov_path_loads_pointer,
        (const void*)&g_path_target_value,
        false
    );
    TEST_ASSERT(result.has_value());
    TEST_ASSERT(result->addr >= (uintptr_t)&cov_path_loads_pointer);
    return 0;
}

int test_find_pointer_in_path_miss() {
    int local_unused = 0xDEAD;
    auto result = utility::find_pointer_in_path(
        (uintptr_t)&cov_path_loads_pointer,
        (const void*)&local_unused,
        false
    );
    TEST_ASSERT(!result.has_value());
    return 0;
}

// ============================================================================
// Test: find_displacement_in_path
// ============================================================================

int test_find_displacement_in_path_self() {
    // cov_path_has_displacement references &g_path_target_value.
    // First, find the displacement to use as the target.
    auto disp = utility::find_next_displacement((uintptr_t)&cov_path_has_displacement, false);
    if (!disp) {
        std::printf("  SKIP: cov_path_has_displacement has no displacement\n");
        return 0;
    }
    auto result = utility::find_displacement_in_path(
        (uintptr_t)&cov_path_has_displacement,
        disp->displacement,
        false
    );
    TEST_ASSERT(result.has_value());
    TEST_ASSERT(result->displacement == disp->displacement);
    return 0;
}

int test_find_displacement_in_path_miss() {
    auto result = utility::find_displacement_in_path(
        (uintptr_t)&cov_path_arithmetic,
        0xDEADBEEFCAFEBABEULL,
        false
    );
    TEST_ASSERT(!result.has_value());
    return 0;
}

// ============================================================================
// Test: find_mnemonic_in_path
// ============================================================================

int test_find_mnemonic_ret() {
    auto result = utility::find_mnemonic_in_path(
        (uintptr_t)&cov_path_arithmetic,
        50,
        std::string_view{"RET"},
        false
    );
    TEST_ASSERT(result.has_value());
    TEST_ASSERT(result->addr >= (uintptr_t)&cov_path_arithmetic);
    return 0;
}

int test_find_mnemonic_impossible() {
    auto result = utility::find_mnemonic_in_path(
        (uintptr_t)&cov_path_arithmetic,
        50,
        std::string_view{"XYZZY_NONEXISTENT"},
        false
    );
    TEST_ASSERT(!result.has_value());
    return 0;
}

int test_find_mnemonic_mov() {
    auto result = utility::find_mnemonic_in_path(
        (uintptr_t)&cov_path_arithmetic,
        50,
        std::string_view{"MOV"},
        false
    );
    if (result) {
        TEST_ASSERT(result->addr >= (uintptr_t)&cov_path_arithmetic);
    }
    return 0;
}

// ============================================================================
// Test: find_register_usage_in_path
// ============================================================================

int test_find_register_usage_eax() {
    auto result = utility::find_register_usage_in_path(
        (uintptr_t)&cov_path_arithmetic,
        50,
        NDR_EAX,
        false
    );
    if (result) {
        TEST_ASSERT(result->addr >= (uintptr_t)&cov_path_arithmetic);
    }
    return 0;
}

int test_find_register_usage_rbx() {
    // RBX is callee-saved — may or may not appear in a leaf function.
    auto result = utility::find_register_usage_in_path(
        (uintptr_t)&cov_path_leaf,
        50,
        NDR_RBX,
        false
    );
    (void)result;
    return 0;
}

// ============================================================================
// Test: find_pattern_in_path
// ============================================================================

int test_find_pattern_in_path_first_bytes() {
    auto fn_addr = (uintptr_t)&cov_path_arithmetic;
    uint8_t* fn_bytes = (uint8_t*)fn_addr;
    char pattern_buf[16];
    std::snprintf(pattern_buf, sizeof(pattern_buf), "%02X %02X", fn_bytes[0], fn_bytes[1]);

    auto result = utility::find_pattern_in_path(
        fn_bytes,
        200,
        false,
        std::string{pattern_buf}
    );
    TEST_ASSERT(result.has_value());
    TEST_ASSERT(result->addr == fn_addr);
    return 0;
}

int test_find_pattern_in_path_miss() {
    auto result = utility::find_pattern_in_path(
        (uint8_t*)&cov_path_arithmetic,
        200,
        false,
        std::string{"FF FE FD FC FB FA F9 F8"}
    );
    TEST_ASSERT(!result.has_value());
    return 0;
}

// ============================================================================
// Test: find_encapsulating_function
// ============================================================================

int test_find_encapsulating_function_hit() {
    // cov_path_caller calls cov_path_leaf.
    // middle = address slightly into cov_path_leaf (past the prologue)
    uintptr_t middle = (uintptr_t)&cov_path_leaf + 8;

    auto result = utility::find_encapsulating_function(
        (uintptr_t)&cov_path_caller,
        middle
    );
    if (result) {
        TEST_ASSERT(*result <= middle);
    }
    return 0;
}

int test_find_encapsulating_function_bad_middle() {
    auto result = utility::find_encapsulating_function(
        (uintptr_t)&cov_path_caller,
        0
    );
    TEST_ASSERT(!result.has_value());
    return 0;
}

int test_find_encapsulating_function_bad_start() {
    auto result = utility::find_encapsulating_function(
        0,
        (uintptr_t)&cov_path_leaf
    );
    TEST_ASSERT(!result.has_value());
    return 0;
}

// ============================================================================
// Test: find_encapsulating_function_disp
// ============================================================================

int test_find_encapsulating_function_disp_hit() {
    auto disp = utility::find_next_displacement((uintptr_t)&cov_path_has_displacement, false);
    if (!disp) {
        std::printf("  SKIP: no displacement found in cov_path_has_displacement\n");
        return 0;
    }
    // Search from same function for its own displacement — no crash is the main check.
    auto result = utility::find_encapsulating_function_disp(
        (uintptr_t)&cov_path_has_displacement,
        disp->displacement,
        false
    );
    (void)result;
    return 0;
}

int test_find_encapsulating_function_disp_miss() {
    auto result = utility::find_encapsulating_function_disp(
        (uintptr_t)&cov_path_caller,
        0xDEADBEEFCAFEBABEULL,
        false
    );
    TEST_ASSERT(!result.has_value());
    return 0;
}

// ============================================================================
// Test: find_encapsulating_virtual_function
// ============================================================================

int test_find_encapsulating_virtual_func_hit() {
    PathTestDerived obj;
    uintptr_t vtable = *(uintptr_t*)&obj;
    TEST_ASSERT(vtable != 0);

    // vtable layout on MSVC x64: [0]=dtor, [1]=virt_a, [2]=virt_b
    uintptr_t virt_a_addr = ((uintptr_t*)vtable)[1];
    if (IsBadReadPtr((void*)virt_a_addr, 8)) {
        std::printf("  SKIP: vtable[1] not readable\n");
        return 0;
    }

    uintptr_t middle = virt_a_addr + 8;
    auto result = utility::find_encapsulating_virtual_function(vtable, 4, middle);
    if (result) {
        TEST_ASSERT(*result <= middle);
    }
    return 0;
}

int test_find_encapsulating_virtual_func_bad_args() {
    auto r1 = utility::find_encapsulating_virtual_function(0x1000, 0, 0x1000);
    TEST_ASSERT(!r1.has_value());

    auto r2 = utility::find_encapsulating_virtual_function(0x1000, 4, 0);
    TEST_ASSERT(!r2.has_value());

    auto r3 = utility::find_encapsulating_virtual_function(0, 4, 0x1000);
    TEST_ASSERT(!r3.has_value());
    return 0;
}

// ============================================================================
// Test: find_encapsulating_virtual_function_disp
// ============================================================================

int test_find_encapsulating_virtual_func_disp() {
    PathTestDerived obj;
    uintptr_t vtable = *(uintptr_t*)&obj;
    TEST_ASSERT(vtable != 0);

    uintptr_t virt_a_addr = ((uintptr_t*)vtable)[1];
    if (IsBadReadPtr((void*)virt_a_addr, 8)) {
        std::printf("  SKIP: vtable[1] not readable\n");
        return 0;
    }
    auto disp = utility::find_next_displacement(virt_a_addr, false);
    if (!disp) {
        std::printf("  SKIP: no displacement in virtual function\n");
        return 0;
    }
    auto result = utility::find_encapsulating_virtual_function_disp(vtable, 4, disp->displacement, false);
    if (result) {
        TEST_ASSERT(*result != 0);
    }
    return 0;
}

int test_find_encapsulating_virtual_func_disp_bad_args() {
    auto r1 = utility::find_encapsulating_virtual_function_disp(0, 4, 0x1234, false);
    TEST_ASSERT(!r1.has_value());
    return 0;
}

// ============================================================================
// Test: bad/edge inputs for path functions
// ============================================================================

int test_find_string_ref_bad_addr() {
    auto result = utility::find_string_reference_in_path(
        0, std::string_view{"test"}, false);
    TEST_ASSERT(!result.has_value());
    return 0;
}

int test_find_pointer_in_path_bad_addr() {
    auto result = utility::find_pointer_in_path(
        0, (const void*)0x12345, false);
    TEST_ASSERT(!result.has_value());
    return 0;
}

int test_find_mnemonic_bad_addr() {
    auto result = utility::find_mnemonic_in_path(
        0, 50, std::string_view{"MOV"}, false);
    TEST_ASSERT(!result.has_value());
    return 0;
}

int test_find_register_usage_bad_addr() {
    auto result = utility::find_register_usage_in_path(
        0, 50, NDR_RAX, false);
    TEST_ASSERT(!result.has_value());
    return 0;
}

int test_find_pattern_in_path_bad_addr() {
    auto result = utility::find_pattern_in_path(
        nullptr, 200, false, std::string{"90"});
    TEST_ASSERT(!result.has_value());
    return 0;
}

// ============================================================================
// main
// ============================================================================

int main() try {
    std::cout << "===== kananlib-scan-path-test =====" << std::endl;

    force_compile_targets();
    PathTestDerived vobj;
    g_virt_sink = vobj.virt_a(1);
    g_virt_sink = vobj.virt_b(2);

    std::cout << "Target functions compiled." << std::endl;

    // find_next_displacement
    RUN_TEST(test_find_next_displacement_narrow_str);
    RUN_TEST(test_find_next_displacement_arithmetic);

    // find_string_reference_in_path (narrow)
    RUN_TEST(test_find_string_ref_narrow_hit);
    RUN_TEST(test_find_string_ref_narrow_miss);
    RUN_TEST(test_find_string_ref_empty);

    // find_string_reference_in_path (wide)
    RUN_TEST(test_find_string_ref_wide_hit);
    RUN_TEST(test_find_string_ref_wide_miss);

    // find_pointer_in_path
    RUN_TEST(test_find_pointer_in_path_hit);
    RUN_TEST(test_find_pointer_in_path_miss);

    // find_displacement_in_path
    RUN_TEST(test_find_displacement_in_path_self);
    RUN_TEST(test_find_displacement_in_path_miss);

    // find_mnemonic_in_path
    RUN_TEST(test_find_mnemonic_ret);
    RUN_TEST(test_find_mnemonic_impossible);
    RUN_TEST(test_find_mnemonic_mov);

    // find_register_usage_in_path
    RUN_TEST(test_find_register_usage_eax);
    RUN_TEST(test_find_register_usage_rbx);

    // find_pattern_in_path
    RUN_TEST(test_find_pattern_in_path_first_bytes);
    RUN_TEST(test_find_pattern_in_path_miss);

    // find_encapsulating_function
    RUN_TEST(test_find_encapsulating_function_hit);
    RUN_TEST(test_find_encapsulating_function_bad_middle);
    RUN_TEST(test_find_encapsulating_function_bad_start);

    // find_encapsulating_function_disp
    RUN_TEST(test_find_encapsulating_function_disp_hit);
    RUN_TEST(test_find_encapsulating_function_disp_miss);

    // find_encapsulating_virtual_function
    RUN_TEST(test_find_encapsulating_virtual_func_hit);
    RUN_TEST(test_find_encapsulating_virtual_func_bad_args);

    // find_encapsulating_virtual_function_disp
    RUN_TEST(test_find_encapsulating_virtual_func_disp);
    RUN_TEST(test_find_encapsulating_virtual_func_disp_bad_args);

    // Edge / bad-address tests
    RUN_TEST(test_find_string_ref_bad_addr);
    RUN_TEST(test_find_pointer_in_path_bad_addr);
    RUN_TEST(test_find_mnemonic_bad_addr);
    RUN_TEST(test_find_register_usage_bad_addr);
    RUN_TEST(test_find_pattern_in_path_bad_addr);

    return test_summary();
} catch(const std::exception& e) {
    std::cout << "Exception caught: " << e.what() << std::endl;
    return 1;
} catch(...) {
    std::cout << "Unknown exception caught" << std::endl;
    return 1;
}
