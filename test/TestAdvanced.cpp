#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

#include <Windows.h>

#include <utility/Logging.hpp>
#include <utility/ScopeGuard.hpp>
#include <utility/Benchmark.hpp>
#include <utility/Memory.hpp>
#include <utility/Patch.hpp>
#include <utility/PointerHook.hpp>

#include "TestHelpers.hpp"

// ============================================================================
// ScopeGuard tests
// ============================================================================

int test_scope_guard_fires() {
    int counter = 0;
    {
        utility::ScopeGuard guard([&]() { ++counter; });
        TEST_ASSERT(counter == 0);
    }
    TEST_ASSERT(counter == 1);

    return 0;
}

int test_scope_guard_nested() {
    int counter = 0;
    {
        utility::ScopeGuard g1([&]() { counter += 10; });
        {
            utility::ScopeGuard g2([&]() { counter += 1; });
        }
        TEST_ASSERT(counter == 1);
    }
    TEST_ASSERT(counter == 11);

    return 0;
}

// ============================================================================
// Benchmark tests
// ============================================================================

int test_benchmark_no_crash() {
    // Construct and immediately destroy. Should not crash.
    { kananlib::Benchmark b("test_benchmark_no_crash"); }

    return 0;
}

int test_benchmark_print() {
    // Explicitly call print_elapsed_time before destruction.
    kananlib::Benchmark b("test_benchmark_print");
    b.print_elapsed_time();

    return 0;
}

// ============================================================================
// Memory tests
// ============================================================================

int test_is_good_read_ptr() {
    // Valid pointer to a stack variable.
    int x = 42;
    TEST_ASSERT(utility::isGoodReadPtr((uintptr_t)&x, sizeof(x)));

    // nullptr should not be a valid pointer.
    TEST_ASSERT(!utility::isGoodReadPtr(0, 1));

    // Very large address is likely invalid in user space.
    TEST_ASSERT(!utility::isGoodReadPtr(0x00000000FFFFFFFF, 4096));

    return 0;
}

int test_is_good_write_ptr() {
    int x = 0;
    TEST_ASSERT(utility::isGoodWritePtr((uintptr_t)&x, sizeof(x)));

    // Code section is not writable.
    auto fn_addr = (uintptr_t)&test_is_good_write_ptr;
    TEST_ASSERT(!utility::isGoodWritePtr(fn_addr, 1));

    return 0;
}

int test_is_good_code_ptr() {
    // The test function itself should be executable.
    auto fn_addr = (uintptr_t)&test_is_good_code_ptr;
    TEST_ASSERT(utility::isGoodCodePtr(fn_addr, 1));

    // A stack variable should not be executable.
    int x = 0;
    TEST_ASSERT(!utility::isGoodCodePtr((uintptr_t)&x, 1));

    return 0;
}

int test_is_stub_code() {
    // ret (single-byte stub).
    uint8_t ret_stub[] = {0xC3};
    TEST_ASSERT(utility::is_stub_code(ret_stub));

    // xor eax, eax; ret
    uint8_t xor_ret[] = {0x33, 0xC0, 0xC3};
    TEST_ASSERT(utility::is_stub_code(xor_ret));

    // Not a stub.
    uint8_t not_stub[] = {0x55, 0x48, 0x89, 0xE5};
    TEST_ASSERT(!utility::is_stub_code(not_stub));

    // nullptr.
    TEST_ASSERT(!utility::is_stub_code(nullptr));

    return 0;
}

int test_get_valid_regions() {
    // The test executable's own code should have at least one valid region.
    auto regions = utility::get_valid_regions(
        (uintptr_t)&test_get_valid_regions, 0x1000);
    TEST_ASSERT(!regions.empty());

    return 0;
}

// ============================================================================
// findInCache / isGoodReadPtr — length overflow must not report a bad read good
//
// BUG: findInCache() tests `start <= ptr && ptr + len < end`. `ptr + len` is
// uintptr_t arithmetic; when len is large enough that ptr + len wraps past
// UINTPTR_MAX, the wrapped (tiny) value compares < end and the cached region
// is returned -- so isGoodReadPtr() reports a read of nearly the whole address
// space as VALID. A pointer-safety predicate returning true for an impossible
// read is exactly the failure it exists to prevent.
//
// We first prime the thread-local cache with a real region (len=1 call), then
// probe the SAME base with a length chosen so base + len overflows to 0.
// ============================================================================

int test_is_good_read_ptr_length_overflow() {
    int x = 42;
    const uintptr_t base = (uintptr_t)&x;

    // Prime the cache with the region containing &x.
    TEST_ASSERT(utility::isGoodReadPtr(base, sizeof(x)));

    // Choose len so that base + len == 0 (mod 2^64): a read spanning almost the
    // entire address space. This can never be a valid readable range.
    const size_t overflow_len = (size_t)(0 - base);
    TEST_ASSERT(!utility::isGoodReadPtr(base, overflow_len));

    return 0;
}

// ============================================================================
// Patch tests (need PAGE_EXECUTE_READWRITE buffer)
// ============================================================================

static uint8_t* alloc_rw_page() {
    return (uint8_t*)VirtualAlloc(
        nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
}

int test_patch_enable_disable() {
    auto* page = alloc_rw_page();
    TEST_ASSERT(page != nullptr);
    auto guard_page = utility::ScopeGuard([&]() { VirtualFree(page, 0, MEM_RELEASE); });

    // Fill page with known bytes.
    memset(page, 0x90, 16);

    // Patch first 4 bytes.
    std::vector<int16_t> new_bytes = {0xCC, 0xCC, 0xCC, 0xCC};
    auto p = Patch::create((uintptr_t)page, new_bytes, false);
    TEST_ASSERT(p != nullptr);

    // Not enabled yet.
    TEST_ASSERT(page[0] == 0x90);

    // Enable.
    TEST_ASSERT(p->enable());
    TEST_ASSERT(page[0] == 0xCC);
    TEST_ASSERT(page[1] == 0xCC);
    TEST_ASSERT(page[2] == 0xCC);
    TEST_ASSERT(page[3] == 0xCC);

    // Disable restores originals.
    TEST_ASSERT(p->disable());
    TEST_ASSERT(page[0] == 0x90);
    TEST_ASSERT(page[1] == 0x90);

    return 0;
}

int test_patch_toggle() {
    auto* page = alloc_rw_page();
    TEST_ASSERT(page != nullptr);
    auto guard_page = utility::ScopeGuard([&]() { VirtualFree(page, 0, MEM_RELEASE); });

    memset(page, 0xAA, 8);

    std::vector<int16_t> new_bytes = {0xBB, 0xBB};
    auto p = Patch::create((uintptr_t)page, new_bytes, false);

    TEST_ASSERT(p->toggle(true));
    TEST_ASSERT(page[0] == 0xBB);
    TEST_ASSERT(page[1] == 0xBB);

    TEST_ASSERT(p->toggle(false));
    TEST_ASSERT(page[0] == 0xAA);
    TEST_ASSERT(page[1] == 0xAA);

    return 0;
}

int test_patch_nop() {
    auto* page = alloc_rw_page();
    TEST_ASSERT(page != nullptr);
    auto guard_page = utility::ScopeGuard([&]() { VirtualFree(page, 0, MEM_RELEASE); });

    memset(page, 0xFF, 8);

    auto p = Patch::create_nop((uintptr_t)page, 4, true);
    TEST_ASSERT(p != nullptr);
    TEST_ASSERT(page[0] == 0x90);
    TEST_ASSERT(page[1] == 0x90);
    TEST_ASSERT(page[2] == 0x90);
    TEST_ASSERT(page[3] == 0x90);
    TEST_ASSERT(page[4] == 0xFF); // Unchanged.

    return 0;
}

int test_patch_static_patch() {
    auto* page = alloc_rw_page();
    TEST_ASSERT(page != nullptr);
    auto guard_page = utility::ScopeGuard([&]() { VirtualFree(page, 0, MEM_RELEASE); });

    page[0] = 0x11;
    page[1] = 0x22;

    // Patch with wildcards: only first and third bytes are patched.
    std::vector<int16_t> bytes = {0xAA, -1, 0xBB};
    TEST_ASSERT(Patch::patch((uintptr_t)page, bytes));
    TEST_ASSERT(page[0] == 0xAA);
    TEST_ASSERT(page[1] == 0x22); // Wildcard: unchanged.
    TEST_ASSERT(page[2] == 0xBB);

    return 0;
}

int test_patch_auto_restore_on_destroy() {
    auto* page = alloc_rw_page();
    TEST_ASSERT(page != nullptr);
    auto guard_page = utility::ScopeGuard([&]() { VirtualFree(page, 0, MEM_RELEASE); });

    page[0] = 0xDE;
    page[1] = 0xAD;

    {
        std::vector<int16_t> new_bytes = {0x00, 0x00};
        auto p = Patch::create((uintptr_t)page, new_bytes, true);
        TEST_ASSERT(page[0] == 0x00);
    }
    // After p is destroyed, original bytes should be restored.
    TEST_ASSERT(page[0] == 0xDE);
    TEST_ASSERT(page[1] == 0xAD);

    return 0;
}

// ============================================================================
// PointerHook tests
// ============================================================================

// Must be global/heap so we can take address for VirtualProtect.
static void* g_hook_target = nullptr;

static void hook_fn_a() {}
static void hook_fn_b() {}

int test_pointer_hook_basic() {
    g_hook_target = (void*)hook_fn_a;
    TEST_ASSERT(g_hook_target == (void*)hook_fn_a);

    {
        PointerHook hook(&g_hook_target, (void*)hook_fn_b);
        TEST_ASSERT(g_hook_target == (void*)hook_fn_b);

        auto orig = hook.get_original<void(*)()>();
        TEST_ASSERT(orig == hook_fn_a);
    }
    // Destructor calls remove() which restores.
    TEST_ASSERT(g_hook_target == (void*)hook_fn_a);

    return 0;
}

int test_pointer_hook_remove_restore() {
    g_hook_target = (void*)hook_fn_a;

    PointerHook hook(&g_hook_target, (void*)hook_fn_b);
    TEST_ASSERT(g_hook_target == (void*)hook_fn_b);

    TEST_ASSERT(hook.remove());
    TEST_ASSERT(g_hook_target == (void*)hook_fn_a);

    TEST_ASSERT(hook.restore());
    TEST_ASSERT(g_hook_target == (void*)hook_fn_b);

    return 0;
}

// ============================================================================
// main
// ============================================================================

int main() try {
    std::cout << "===== kananlib advanced test =====" << std::endl;

    // ScopeGuard.
    RUN_TEST(test_scope_guard_fires);
    RUN_TEST(test_scope_guard_nested);

    // Benchmark.
    RUN_TEST(test_benchmark_no_crash);
    RUN_TEST(test_benchmark_print);

    // Memory.
    RUN_TEST(test_is_good_read_ptr);
    RUN_TEST(test_is_good_write_ptr);
    RUN_TEST(test_is_good_code_ptr);
    RUN_TEST(test_is_stub_code);
    RUN_TEST(test_get_valid_regions);
    RUN_TEST(test_is_good_read_ptr_length_overflow);

    // Patch.
    RUN_TEST(test_patch_enable_disable);
    RUN_TEST(test_patch_toggle);
    RUN_TEST(test_patch_nop);
    RUN_TEST(test_patch_static_patch);
    RUN_TEST(test_patch_auto_restore_on_destroy);

    // PointerHook.
    RUN_TEST(test_pointer_hook_basic);
    RUN_TEST(test_pointer_hook_remove_restore);

    return test_summary();
} catch (const std::exception& e) {
    std::cout << "Exception: " << e.what() << std::endl;
    return 1;
} catch (...) {
    std::cout << "Unknown exception." << std::endl;
    return 1;
}
