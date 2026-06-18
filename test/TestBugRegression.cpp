// Regression tests for bugs found during API audit.
//
// Bug 1: Address::operator== and operator!= were not const-qualified,
//         preventing comparison on const Address objects.
//
// Bug 2: Patch::disable() corrupted m_enabled state when called on a patch
//         that was never enabled (m_original_bytes empty). VirtualProtect(addr, 0, ...)
//         fails, patch() returns false, m_enabled = !false = true.
//         Subsequent toggle() calls then take the wrong branch.

#include <cstdint>
#include <cstring>
#include <iostream>
#include <vector>

#include <Windows.h>
#include <utility/Address.hpp>
#include <utility/Patch.hpp>
#include <utility/ScopeGuard.hpp>

#include "TestHelpers.hpp"

// ============================================================================
// Bug 1: Address comparison operators must be const
// ============================================================================

// Helper: takes Address by const ref and exercises every comparison operator.
// Before the fix, this would fail to compile because the operators were non-const.
static bool exercise_const_address(const Address& a) {
    bool ok = true;
    ok = ok && (a == (uintptr_t)0x1000);
    ok = ok && (a != (uintptr_t)0x2000);
    ok = ok && (a == (void*)0x1000);
    ok = ok && (a != (void*)0x2000);
    ok = ok && (a == true);
    ok = ok && (a != false);
    return ok;
}

int test_address_const_operators() {
    const Address a(0x1000);
    TEST_ASSERT(exercise_const_address(a));

    const Address null_addr;
    TEST_ASSERT(null_addr == false);
    TEST_ASSERT(null_addr != true);
    TEST_ASSERT(null_addr == (uintptr_t)0);
    TEST_ASSERT(null_addr == (void*)nullptr);

    return 0;
}

// Also verify the return values are correct on non-const (existing usage).
int test_address_operators_return_values() {
    Address a(0x1000);

    TEST_ASSERT(a == (uintptr_t)0x1000);
    TEST_ASSERT(!(a == (uintptr_t)0x2000));
    TEST_ASSERT(a != (uintptr_t)0x2000);
    TEST_ASSERT(!(a != (uintptr_t)0x1000));

    TEST_ASSERT(a == (void*)0x1000);
    TEST_ASSERT(a != (void*)0x2000);

    TEST_ASSERT(a == true);
    TEST_ASSERT(a != false);

    Address null_addr;
    TEST_ASSERT(null_addr == false);
    TEST_ASSERT(null_addr != true);

    return 0;
}

// ============================================================================
// Bug 2: Patch::disable() state corruption when patch was never enabled
// ============================================================================

static uint8_t* alloc_page() {
    return (uint8_t*)VirtualAlloc(
        nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
}

// Reproducer: create a patch with should_enable=false, call disable(), then toggle().
// Before the fix:
//   disable() calls patch(addr, {}) with empty m_original_bytes
//   -> VirtualProtect(addr, 0, ...) fails
//   -> patch() returns false
//   -> m_enabled = !false = true  (CORRUPTED)
//   -> toggle() sees m_enabled=true, calls disable() instead of enable()
//   -> disable() fails again (empty m_original_bytes)
//   -> toggle() returns true but nothing was patched
//
// After the fix:
//   disable() sees m_enabled=false, returns true immediately
//   -> toggle() sees m_enabled=false, calls enable()
//   -> enable() backs up original bytes, patches
//   -> page has new bytes

int test_patch_disable_before_enable() {
    auto* page = alloc_page();
    TEST_ASSERT(page != nullptr);
    auto guard = utility::ScopeGuard([&]() { VirtualFree(page, 0, MEM_RELEASE); });

    page[0] = 0xAA;
    page[1] = 0xBB;

    std::vector<int16_t> new_bytes = {0xCC, 0xDD};
    auto p = Patch::create((uintptr_t)page, new_bytes, false);
    TEST_ASSERT(p != nullptr);

    // Page should still have original bytes.
    TEST_ASSERT(page[0] == 0xAA);
    TEST_ASSERT(page[1] == 0xBB);

    // Disable on a never-enabled patch should be a no-op returning true.
    TEST_ASSERT(p->disable());

    // Page should still have original bytes.
    TEST_ASSERT(page[0] == 0xAA);
    TEST_ASSERT(page[1] == 0xBB);

    // Now enable should work correctly.
    TEST_ASSERT(p->enable());
    TEST_ASSERT(page[0] == 0xCC);
    TEST_ASSERT(page[1] == 0xDD);

    // Disable should restore.
    TEST_ASSERT(p->disable());
    TEST_ASSERT(page[0] == 0xAA);
    TEST_ASSERT(page[1] == 0xBB);

    return 0;
}

int test_patch_toggle_after_disable_before_enable() {
    auto* page = alloc_page();
    TEST_ASSERT(page != nullptr);
    auto guard = utility::ScopeGuard([&]() { VirtualFree(page, 0, MEM_RELEASE); });

    page[0] = 0x11;
    page[1] = 0x22;

    std::vector<int16_t> new_bytes = {0x33, 0x44};
    auto p = Patch::create((uintptr_t)page, new_bytes, false);
    TEST_ASSERT(p != nullptr);

    // Call disable on never-enabled patch (should be harmless).
    TEST_ASSERT(p->disable());

    // toggle() should enable the patch (m_enabled is false after the fix).
    TEST_ASSERT(p->toggle());
    TEST_ASSERT(page[0] == 0x33);
    TEST_ASSERT(page[1] == 0x44);

    // toggle() again should disable.
    // toggle() returns the new state: false = disabled.
    TEST_ASSERT(!p->toggle());
    TEST_ASSERT(page[0] == 0x11);
    TEST_ASSERT(page[1] == 0x22);

    return 0;
}

// Also test: double disable on a never-enabled patch.
int test_patch_double_disable_before_enable() {
    auto* page = alloc_page();
    TEST_ASSERT(page != nullptr);
    auto guard = utility::ScopeGuard([&]() { VirtualFree(page, 0, MEM_RELEASE); });

    page[0] = 0xAA;

    std::vector<int16_t> new_bytes = {0xBB};
    auto p = Patch::create((uintptr_t)page, new_bytes, false);

    // Both calls should succeed (no-op).
    TEST_ASSERT(p->disable());
    TEST_ASSERT(p->disable());

    // Page unchanged.
    TEST_ASSERT(page[0] == 0xAA);

    // Enable should still work after double disable.
    TEST_ASSERT(p->enable());
    TEST_ASSERT(page[0] == 0xBB);

    return 0;
}

// ============================================================================
// main
// ============================================================================

int main() try {
    std::cout << "===== kananlib-bug-regression-test =====" << std::endl;

    // Bug 1: Address const operators
    RUN_TEST(test_address_const_operators);
    RUN_TEST(test_address_operators_return_values);

    // Bug 2: Patch::disable() state corruption
    RUN_TEST(test_patch_disable_before_enable);
    RUN_TEST(test_patch_toggle_after_disable_before_enable);
    RUN_TEST(test_patch_double_disable_before_enable);

    return test_summary();
} catch (const std::exception& e) {
    std::cout << "Exception caught: " << e.what() << std::endl;
    return 1;
} catch (...) {
    std::cout << "Unknown exception caught" << std::endl;
    return 1;
}
