// Regression tests for scan bugs found via API audit.
//
// Bug 1: scan("nonexistent.dll", addr, pattern) wraps the length to near
//         SIZE_MAX when the module is not found. get_module_size(nullptr)
//         returns nullopt, value_or(0) gives 0, and (0 - start + 0) wraps.
//         The inner scan() then tries to scan a catastrophically large range
//         and crashes on unmapped memory.
//
// Bug 2: scan_reverse and scan_data_reverse use unsigned arithmetic in
//         their loop bound: `i >= start - length`. When length >= start,
//         the subtraction wraps and the loop either silently skips (length > start)
//         or wraps i past zero into UINTPTR_MAX (length == start). Fix: guard
//         against length > start before entering the loop.

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <thread>

#include <Windows.h>

#include <utility/Scan.hpp>

#include "TestHelpers.hpp"

// ============================================================================
// Bug 1: scan(module, start, pattern) crashes when module not found
// ============================================================================

// The crash is an access violation (SEH), not a C++ exception.
// We use __try/__except to catch it and report as a test failure.
// (The test target is built with /EHa, so SEH + C++ objects coexist.)

// The test target is compiled with /EHa, so SEH exceptions (access violations)
// are caught by C++ catch(...) blocks. Use that instead of __try/__except,
// which MSVC forbids in functions with C++ objects needing unwinding.
static int try_scan_string(const char* mod, uintptr_t start, const char* pattern) {
    // Returns: 0 = no crash, 1 = crash (SEH), 2 = unexpected match
    try {
        auto result = utility::scan(mod, start, pattern);
        return result.has_value() ? 2 : 0;
    } catch (...) {
        return 1;
    }
}

static int try_scan_wstring(const wchar_t* mod, uintptr_t start, const char* pattern) {
    try {
        auto result = utility::scan(mod, start, pattern);
        return result.has_value() ? 2 : 0;
    } catch (...) {
        return 1;
    }
}

int test_scan_nonexistent_module_does_not_crash() {
    const int rc = try_scan_string("nonexistent_module_xyzzy.dll", 0x10000, "48 89");
    if (rc == 1) {
        std::cout << "  BUG: scan(nonexistent_module, ...) crashed (SEH) — "
                     "unsigned length wrap on NULL module" << std::endl;
    }
    TEST_ASSERT(rc == 0);
    return 0;
}

// Same test for the wstring overload.
int test_scan_nonexistent_module_wstring_does_not_crash() {
    const int rc = try_scan_wstring(L"nonexistent_module_xyzzy.dll", 0x10000, "48 89");
    if (rc == 1) {
        std::cout << "  BUG: scan(L\"nonexistent_module\", ...) crashed (SEH) — "
                     "unsigned length wrap on NULL module" << std::endl;
    }
    TEST_ASSERT(rc == 0);
    return 0;
}

// ============================================================================
// Bug 2: scan_reverse / scan_data_reverse unsigned loop bound
// ============================================================================

// Helper: allocate a page of RW memory and fill it.
struct ScanTestPage {
    uint8_t* data{};
    size_t size{ 0x1000 };

    ScanTestPage() {
        data = (uint8_t*)VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (data) {
            memset(data, 0, size);
        }
    }
    ~ScanTestPage() {
        if (data) VirtualFree(data, 0, MEM_RELEASE);
    }
};

// Verify scan_reverse works on normal (non-overflowing) inputs.
int test_scan_reverse_basic() {
    ScanTestPage page;
    TEST_ASSERT(page.data != nullptr);

    // Place pattern at offset 0x100
    page.data[0x100] = 0xDE;
    page.data[0x101] = 0xAD;
    page.data[0x102] = 0xBE;
    page.data[0x103] = 0xEF;

    // Place same pattern at offset 0x200 (closer to scan start)
    page.data[0x200] = 0xDE;
    page.data[0x201] = 0xAD;
    page.data[0x202] = 0xBE;
    page.data[0x203] = 0xEF;

    // Scan backwards from offset 0x300, length 0x300 → should find 0x200 first
    const auto start = (uintptr_t)&page.data[0x300];
    const auto result = utility::scan_reverse(start, 0x300, "DE AD BE EF");

    TEST_ASSERT(result.has_value());
    TEST_ASSERT(*result == (uintptr_t)&page.data[0x200]);
    return 0;
}

// Verify scan_data_reverse works on normal inputs.
int test_scan_data_reverse_basic() {
    ScanTestPage page;
    TEST_ASSERT(page.data != nullptr);

    // Place a known 4-byte value at offset 0x100
    const uint8_t needle[] = { 0xCA, 0xFE, 0xBA, 0xBE };
    memcpy(&page.data[0x100], needle, sizeof(needle));

    // Place same value at offset 0x200
    memcpy(&page.data[0x200], needle, sizeof(needle));

    // Scan backwards from offset 0x300, length 0x300
    const auto start = (uintptr_t)&page.data[0x300];
    const auto result = utility::scan_data_reverse(start, 0x300, needle, sizeof(needle));

    TEST_ASSERT(result.has_value());
    TEST_ASSERT(*result == (uintptr_t)&page.data[0x200]);
    return 0;
}

// Verify scan_reverse returns nullopt when pattern is before the scan range.
int test_scan_reverse_not_found() {
    ScanTestPage page;
    TEST_ASSERT(page.data != nullptr);

    // Pattern at offset 0x50
    page.data[0x50] = 0xDE;
    page.data[0x51] = 0xAD;

    // Scan backwards from offset 0x200, length 0x100 → should NOT find offset 0x50
    const auto start = (uintptr_t)&page.data[0x200];
    const auto result = utility::scan_reverse(start, 0x100, "DE AD");

    TEST_ASSERT(!result.has_value());
    return 0;
}

// ============================================================================
// Bug 4: scan_reverse unsigned wraparound when length == start
// ============================================================================
//
// When length == start, the loop bound `start - length` is 0.
// The loop `for (uintptr_t i = start; i >= start - length; i--)` becomes
// `for (uintptr_t i = start; i >= 0; i--)`. Since i is unsigned, `i >= 0`
// is ALWAYS true. When i reaches 0 and decrements, it wraps to SIZE_MAX,
// and the loop runs forever.
//
// The existing guard `if (length > start)` only catches length > start,
// not length == start. The fix: use a loop structure that can't wrap.
//
// To trigger this without scanning billions of bytes, we VirtualAlloc a page
// at a LOW preferred address (e.g. 0x10000) so that `length == start` means
// scanning only ~64KB.
//
// We run the scan on a background thread with a timeout. If the scan hangs
// (bug present), the test fails after the timeout instead of hanging forever.

int test_scan_reverse_length_equals_start() {
    constexpr uintptr_t LOW_ADDR = 0x10000;
    auto* page = (uint8_t*)VirtualAlloc((void*)LOW_ADDR, 0x1000,
        MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN, PAGE_READWRITE);

    if (!page) {
        std::cout << "  SKIP: could not allocate at low address" << std::endl;
        return 0;
    }

    // Fill with zeros — no match for "DE AD".
    memset(page, 0, 0x1000);

    // Run scan_reverse on a background thread with a 5-second timeout.
    // With the bug, the loop wraps past 0 to SIZE_MAX and hangs.
    // With the fix, it returns nullopt in ~100ms.
    std::atomic<bool> done{false};
    std::optional<uintptr_t> result;

    std::thread worker([&] {
        result = utility::scan_reverse((uintptr_t)page, (uintptr_t)page, "DE AD");
        done.store(true, std::memory_order_release);
    });

    // Wait up to 5 seconds for the scan to complete.
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (!done.load(std::memory_order_acquire)) {
        if (std::chrono::steady_clock::now() >= deadline) {
            // Timed out — the scan is hanging (bug present).
            VirtualFree(page, 0, MEM_RELEASE);
            worker.detach(); // Leave the hung thread; can't safely cancel.
            std::cout << "  BUG: scan_reverse(length==start) hung for >5s — "
                         "unsigned wraparound in loop bound" << std::endl;
            TEST_ASSERT(false && "scan_reverse hung (unsigned wraparound)");
            return 1;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    worker.join();

    // Should return nullopt (pattern not found).
    TEST_ASSERT(!result.has_value());

    VirtualFree(page, 0, MEM_RELEASE);
    return 0;
}


// Bug 3: scan_strings unsigned wrap in `end` calculation
// ============================================================================

// When length < str.length() + 1, the expression `start + length - (str.length() + 1)`
// wraps to near SIZE_MAX. The function should return empty instead of scanning the
// entire address space.
int test_scan_strings_short_length_no_crash() {
    ScanTestPage page;

    // "hello world" is 11 chars, so str.length()+1 = 12.
    // length = 5 < 12, so end = start + 5 - 12 wraps.
    const auto results = utility::scan_strings((uintptr_t)page.data, 5, std::string{"hello world"}, false);

    // Should return empty, not crash or return garbage.
    TEST_ASSERT(results.empty());
    return 0;
}

// Same bug for the wstring variant: `start + length - (str.length()+1)*sizeof(wchar_t)`
int test_scan_strings_wstring_short_length_no_crash() {
    ScanTestPage page;

    // L"hello world" is 11 wchar_t, so (str.length()+1)*sizeof(wchar_t) = 24.
    // length = 10 < 24, so end wraps.
    const auto results = utility::scan_strings((uintptr_t)page.data, 10, std::wstring{L"hello world"}, false);

    TEST_ASSERT(results.empty());
    return 0;
}

// ============================================================================
// main
// ============================================================================

int main() try {
    std::cout << "=== Scan Bug Regression Tests ===" << std::endl;
    std::cout << "These tests demonstrate and verify fixes for bugs in scan functions.\n" << std::endl;

    RUN_TEST(test_scan_nonexistent_module_does_not_crash);
    RUN_TEST(test_scan_nonexistent_module_wstring_does_not_crash);
    RUN_TEST(test_scan_reverse_basic);
    RUN_TEST(test_scan_data_reverse_basic);
    RUN_TEST(test_scan_reverse_not_found);
    RUN_TEST(test_scan_strings_short_length_no_crash);
    RUN_TEST(test_scan_strings_wstring_short_length_no_crash);
    RUN_TEST(test_scan_reverse_length_equals_start);

    return test_summary();
} catch (const std::exception& e) {
    std::cout << "Exception: " << e.what() << std::endl;
    return 1;
} catch (...) {
    std::cout << "Unknown exception" << std::endl;
    return 1;
}
