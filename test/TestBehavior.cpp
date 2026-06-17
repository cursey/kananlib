// Behavior tests for modified functions: scan_strings (4 overloads),
// ThreadSuspender (mutex unlock), and for_each_uncached (via find_all_vtables).
//
// These verify that the functions still work correctly after defensive fixes.

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <future>
#include <chrono>
#include <Windows.h>

#include <utility/Scan.hpp>
#include <utility/Module.hpp>
#include <utility/Thread.hpp>
#include <utility/RTTI.hpp>

#include "TestHelpers.hpp"

// ============================================================================
// Marker strings embedded in the test binary for HMODULE scan_strings tests.
// These are guaranteed to exist in the .rdata section of this executable.
// ============================================================================

static const char MARKER_STRING[]   = "KANANLIB_BEHAVIOR_TEST_MARKER_7f3a";
static const wchar_t MARKER_WSTRING[] = L"KANANLIB_BEHAVIOR_WTEST_MARKER_9b2e";

// ============================================================================
// Helper: RW page for uintptr_t scan_strings tests
// ============================================================================

struct BehaviorTestPage {
    uint8_t* data;
    BehaviorTestPage() {
        data = (uint8_t*)VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!data) {
            std::printf("  FATAL: VirtualAlloc failed\n");
            std::abort();
        }
        memset(data, 0, 4096);
    }
    ~BehaviorTestPage() {
        if (data) VirtualFree(data, 0, MEM_RELEASE);
    }
};

// ============================================================================
// scan_strings — HMODULE string overload (line 327)
// ============================================================================

int test_scan_strings_hmodule_string_finds_marker() {
    auto* mod = GetModuleHandleA(nullptr);
    TEST_ASSERT(mod != nullptr);

    const auto results = utility::scan_strings(mod, std::string{MARKER_STRING});
    TEST_ASSERT(!results.empty());

    // Verify the address actually points to the marker string
    const auto addr = (const char*)results[0];
    TEST_ASSERT(strcmp(addr, MARKER_STRING) == 0);
    return 0;
}

// ============================================================================
// scan_strings — HMODULE wstring overload (line 354)
// ============================================================================

int test_scan_strings_hmodule_wstring_finds_marker() {
    auto* mod = GetModuleHandleA(nullptr);
    TEST_ASSERT(mod != nullptr);

    const auto results = utility::scan_strings(mod, std::wstring{MARKER_WSTRING});
    TEST_ASSERT(!results.empty());

    const auto addr = (const wchar_t*)results[0];
    TEST_ASSERT(wcscmp(addr, MARKER_WSTRING) == 0);
    return 0;
}

// ============================================================================
// scan_strings — uintptr_t string overload (line 382)
// Places a known string in a RW page and verifies it is found.
// ============================================================================

int test_scan_strings_uintptr_string_finds_placed() {
    BehaviorTestPage page;

    // Place the string at offset 64
    const char* marker = "SCAN_UINTPTR_STRING_MARKER_4c8d";
    const size_t marker_len = strlen(marker);
    memcpy(page.data + 64, marker, marker_len + 1);

    const auto results = utility::scan_strings(
        (uintptr_t)page.data, 4096, std::string{marker});
    TEST_ASSERT(results.size() == 1);
    TEST_ASSERT(results[0] == (uintptr_t)(page.data + 64));
    return 0;
}

// ============================================================================
// scan_strings — uintptr_t wstring overload (line 408)
// ============================================================================

int test_scan_strings_uintptr_wstring_finds_placed() {
    BehaviorTestPage page;

    const wchar_t* marker = L"SCAN_UINTPTR_WSTR_MARKER_5e7a";
    const size_t marker_wchars = wcslen(marker);
    const size_t marker_bytes = (marker_wchars + 1) * sizeof(wchar_t);
    memcpy(page.data + 128, marker, marker_bytes);

    const auto results = utility::scan_strings(
        (uintptr_t)page.data, 4096, std::wstring{marker});
    TEST_ASSERT(results.size() == 1);
    TEST_ASSERT(results[0] == (uintptr_t)(page.data + 128));
    return 0;
}

// ============================================================================
// scan_strings — verify multiple occurrences are found
// ============================================================================

int test_scan_strings_finds_multiple() {
    BehaviorTestPage page;

    const char* marker = "MULTI_MARKER_2f9a";
    const size_t len = strlen(marker) + 1;

    // Place the string at 3 locations
    memcpy(page.data + 100, marker, len);
    memcpy(page.data + 500, marker, len);
    memcpy(page.data + 900, marker, len);

    const auto results = utility::scan_strings(
        (uintptr_t)page.data, 4096, std::string{marker});
    TEST_ASSERT(results.size() == 3);
    return 0;
}

// ============================================================================
// ThreadSuspender — basic suspend/resume behavior
// Constructs one, destroys it, then constructs another. If the destructor
// failed to unlock the mutex, the second construction would deadlock.
// ============================================================================

int test_threadsuspender_double_construct() {
    // Run the double-construct in a future with a timeout.
    // If the mutex leaks, the second ThreadSuspender deadlocks.
    auto result = std::async(std::launch::async, []() -> int {
        {
            utility::ThreadSuspender suspender1;
            // The constructor locks the mutex and suspends threads.
            // Destructor resumes and unlocks.
        }
        {
            utility::ThreadSuspender suspender2;
            // If the first destructor didn't unlock, we never get here.
        }
        return 0; // success: no deadlock
    });

    auto status = result.wait_for(std::chrono::seconds(5));
    TEST_ASSERT(status == std::future_status::ready);
    TEST_ASSERT(result.get() == 0);
    return 0;
}

// ============================================================================
// ThreadSuspender — explicit suspend/resume cycle
// ============================================================================

int test_threadsuspender_suspend_resume() {
    auto result = std::async(std::launch::async, []() -> int {
        utility::ThreadSuspender suspender;

        // After construction, states should have at least the current thread
        // (which is NOT suspended — it's skipped) and possibly others.
        // We just verify the object was constructed without error.

        suspender.resume();
        // After resume(), states are cleared and mutex unlocked.

        // Construct another one to verify the mutex was released
        utility::ThreadSuspender suspender2;
        return 0;
    });

    auto status = result.wait_for(std::chrono::seconds(5));
    TEST_ASSERT(status == std::future_status::ready);
    TEST_ASSERT(result.get() == 0);
    return 0;
}

// ============================================================================
// for_each_uncached — via find_all_vtables on the executable module
// Exercises the full path: find_all_vtables -> populate -> for_each_uncached
// which is the function we guarded with get_module_size null check.
// ============================================================================

int test_find_all_vtables_executable() {
    auto* mod = GetModuleHandleA(nullptr);
    TEST_ASSERT(mod != nullptr);

    auto vtables = utility::rtti::find_all_vtables(mod);

    // This executable has polymorphic classes (PDBRTTITestBase/Derived
    // in TestPDBRTTI.cpp and any classes in kananlib itself), so at least
    // some vtables should be found.
    std::printf("  Found %zu vtable(s) in executable\n", vtables.size());
    TEST_ASSERT(!vtables.empty());
    return 0;
}

// ============================================================================
// for_each_uncached — null module returns empty (not crash)
// Verifies the get_module_size guard works.
// ============================================================================

int test_find_all_vtables_null_module_returns_empty() {
    // Passing nullptr should return empty, not crash.
    auto vtables = utility::rtti::find_all_vtables(nullptr);
    TEST_ASSERT(vtables.empty());
    return 0;
}

// ============================================================================
// main
// ============================================================================

int main() try {
    std::printf("=== Behavior Tests ===\n");

    // scan_strings — all 4 overloads
    RUN_TEST(test_scan_strings_hmodule_string_finds_marker);
    RUN_TEST(test_scan_strings_hmodule_wstring_finds_marker);
    RUN_TEST(test_scan_strings_uintptr_string_finds_placed);
    RUN_TEST(test_scan_strings_uintptr_wstring_finds_placed);
    RUN_TEST(test_scan_strings_finds_multiple);

    // ThreadSuspender
    RUN_TEST(test_threadsuspender_double_construct);
    RUN_TEST(test_threadsuspender_suspend_resume);

    // for_each_uncached (via find_all_vtables)
    RUN_TEST(test_find_all_vtables_executable);
    RUN_TEST(test_find_all_vtables_null_module_returns_empty);

    return test_summary();
} catch (const std::exception& e) {
    std::printf("EXCEPTION: %s\n", e.what());
    return 1;
} catch (...) {
    std::printf("UNKNOWN EXCEPTION\n");
    return 1;
}
