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
#include <thread>
#include <atomic>
#include <mutex>
#include <windows.h>

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
    if (mod == nullptr) { TEST_SKIP("current executable module unavailable (no Win32 PE host)"); }

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
    if (mod == nullptr) { TEST_SKIP("current executable module unavailable (no Win32 PE host)"); }

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

    const std::wstring marker = L"SCAN_UINTPTR_WSTR_MARKER_5e7a";
    const auto marker_bytes = utf16le_bytes(marker);
    memcpy(page.data + 128, marker_bytes.data(), marker_bytes.size());

    const auto results = utility::scan_strings(
        (uintptr_t)page.data, 4096, marker);
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
// ThreadSuspender — resume() followed by destructor must NOT double-unlock.
//
// BUG (now fixed): the ctor acquired g_suspend_mutex once, but BOTH resume()
// and ~ThreadSuspender() called g_suspend_mutex.unlock(). The sequence
// { ThreadSuspender s; s.resume(); } therefore unlocked the mutex TWICE while
// locking it ONCE. The second unlock releases a lock the object no longer
// owns -- undefined behavior (std::mutex::unlock by a non-owner). On MSVC's
// SRWLOCK-backed mutex this corrupts the lock and deadlocks the process.
//
// FIX: ThreadSuspender holds a std::unique_lock that tracks ownership. resume()
// and the destructor each release only if they still own the lock, so the
// mutex is unlocked exactly once no matter the call order.
//
// We can't safely demonstrate the *buggy* path in-process (it triggers UB that
// hangs the runner -- verified manually). Instead this regression test pins the
// ownership invariant that makes the bug impossible, and verifies the global
// mutex is left clean. A reintroduced double-unlock fails the owns_lock() check
// (or corrupts the mutex, caught by the surrounding timeout).
//
// Single worker thread only: ThreadSuspender::suspend_threads() suspends every
// OTHER thread, so a second thread contending on the mutex would be suspended
// while holding it and deadlock the test by construction. We keep all mutex
// access on the one worker thread.
// ============================================================================

namespace utility { namespace detail { extern std::mutex g_suspend_mutex; } }

int test_threadsuspender_resume_then_destruct_no_double_unlock() {
    struct Result { bool owned_after_ctor; bool released_after_resume; bool clean_after_scope; };

    auto fut = std::async(std::launch::async, []() -> Result {
        Result r{};
        {
            utility::ThreadSuspender s;
            // ctor must have taken ownership of the mutex.
            r.owned_after_ctor = s.lock.owns_lock();

            s.resume();
            // resume() must release ownership so the destructor does NOT
            // unlock a second time. This is the exact invariant the bug broke.
            r.released_after_resume = !s.lock.owns_lock();
            // scope end -> destructor runs; with the fix it is a no-op for the
            // already-released lock (no double-unlock).
        }

        // With the mutex released exactly once, it must be cleanly lockable.
        r.clean_after_scope = utility::detail::g_suspend_mutex.try_lock();
        if (r.clean_after_scope) {
            utility::detail::g_suspend_mutex.unlock();
        }
        return r;
    });

    // A reintroduced double-unlock corrupts the lock and can hang; bound it.
    if (fut.wait_for(std::chrono::seconds(10)) != std::future_status::ready) {
        std::printf("  TIMED OUT: resume()+destruct corrupted the mutex (double-unlock?)\n");
        TEST_ASSERT(false);
    }

    Result r = fut.get();
    TEST_ASSERT(r.owned_after_ctor);        // ctor acquired the lock
    TEST_ASSERT(r.released_after_resume);   // resume() released it (dtor won't re-unlock)
    TEST_ASSERT(r.clean_after_scope);       // mutex left in a clean, lockable state
    return 0;
}

// ============================================================================
// ThreadSuspender — actually FREEZES other threads (the core contract).
//
// The tests above only check that the mutex protocol doesn't deadlock/crash.
// This one verifies the behavior that gives ThreadSuspender its name: while a
// suspender is alive, every OTHER thread stops executing, and after resume()
// they run again.
//
// Method: a worker thread spins incrementing an atomic counter.
//   1. Wait until the counter is visibly advancing (worker is running).
//   2. Construct a ThreadSuspender on this thread -> worker gets SuspendThread'd.
//   3. Take two counter snapshots ~100ms apart, both AFTER a settle delay so
//      any in-flight increment has landed. They MUST be equal -> worker frozen.
//   4. resume() -> the counter MUST start advancing again.
// The whole thing is timeout-guarded so a regression can't wedge the runner.
// ============================================================================

int test_threadsuspender_actually_freezes_threads() {
#if !defined(_WIN32)
    TEST_SKIP("thread suspension is a no-op without a Win32 host");
#endif
    auto fut = std::async(std::launch::async, []() -> int {
        std::atomic<uint64_t> counter{0};
        std::atomic<bool> stop{false};

        std::thread worker([&]() {
            while (!stop.load(std::memory_order_relaxed)) {
                counter.fetch_add(1, std::memory_order_relaxed);
                std::this_thread::yield();
            }
        });

        auto wait_until_advances = [&](uint64_t from, std::chrono::milliseconds budget) -> bool {
            const auto deadline = std::chrono::steady_clock::now() + budget;
            while (std::chrono::steady_clock::now() < deadline) {
                if (counter.load(std::memory_order_relaxed) > from) {
                    return true;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
            return false;
        };

        int rc = 0;
        // 1. Worker must be running before we suspend it.
        if (!wait_until_advances(0, std::chrono::seconds(2))) {
            std::printf("  worker never started incrementing\n");
            rc = 1;
        } else {
            // 2. Suspend everything except this thread.
            utility::ThreadSuspender suspender;

            // 3. Settle, then take two snapshots while suspended.
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
            const uint64_t a = counter.load(std::memory_order_relaxed);
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            const uint64_t b = counter.load(std::memory_order_relaxed);

            std::printf("  while suspended: %llu -> %llu (delta %llu)\n",
                        (unsigned long long)a, (unsigned long long)b,
                        (unsigned long long)(b - a));
            if (a != b) {
                std::printf("  FAIL: worker kept running while suspended\n");
                rc = 1;
            }

            // 4. Resume and confirm it runs again.
            suspender.resume();
            if (!wait_until_advances(b, std::chrono::seconds(2))) {
                std::printf("  FAIL: worker did not resume after resume()\n");
                rc = 1;
            }
        }

        stop.store(true, std::memory_order_relaxed);
        worker.join();
        return rc;
    });

    if (fut.wait_for(std::chrono::seconds(15)) != std::future_status::ready) {
        std::printf("  TIMED OUT: suspend/resume wedged\n");
        TEST_ASSERT(false);
    }
    TEST_ASSERT(fut.get() == 0);
    return 0;
}

// ============================================================================
// ThreadSuspender — ThreadState::suspended must reflect reality.
//
// BUG: suspend_threads() sets `suspended = SuspendThread(handle) > 0`.
// SuspendThread returns the thread's PREVIOUS suspend count (0 on the first
// successful suspend) or (DWORD)-1 on failure. So a normal successful suspend
// of a running thread returns 0 -> `0 > 0` is false -> suspended=false, and a
// FAILED suspend returns 0xFFFFFFFF -> suspended=true. The flag is inverted /
// meaningless. Correct: success is `result != (DWORD)-1`.
//
// We already proved (test_threadsuspender_actually_freezes_threads) that the
// suspension genuinely happens, so at least one captured ThreadState must
// report suspended==true. The buggy `> 0` makes them all false.
// ============================================================================

int test_threadsuspender_suspended_flag_reflects_success() {
#if !defined(_WIN32)
    TEST_SKIP("thread suspension is a no-op without a Win32 host");
#endif
    auto fut = std::async(std::launch::async, []() -> int {
        std::atomic<uint64_t> counter{0};
        std::atomic<bool> stop{false};
        std::thread worker([&]() {
            while (!stop.load(std::memory_order_relaxed)) {
                counter.fetch_add(1, std::memory_order_relaxed);
                std::this_thread::yield();
            }
        });
        // Make sure the worker is alive and running.
        while (counter.load(std::memory_order_relaxed) == 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }

        bool any_suspended = false;
        size_t total = 0;
        {
            utility::ThreadSuspender suspender;
            total = suspender.states.size();
            for (const auto& s : suspender.states) {
                if (s && s->suspended) {
                    any_suspended = true;
                    break;
                }
            }
        }

        stop.store(true, std::memory_order_relaxed);
        worker.join();

        std::printf("  captured %zu thread state(s); any flagged suspended: %s\n",
                    total, any_suspended ? "yes" : "no");
        // We genuinely suspended at least the worker; the flag must say so.
        return (total > 0 && any_suspended) ? 0 : 1;
    });

    if (fut.wait_for(std::chrono::seconds(15)) != std::future_status::ready) {
        std::printf("  TIMED OUT\n");
        TEST_ASSERT(false);
    }
    TEST_ASSERT(fut.get() == 0);
    return 0;
}

// ============================================================================
// ThreadSuspender — repeated suspend() stays balanced (no leaked suspensions).
//
// BUG (now fixed): suspend() used to do `states = suspend_threads();`, blindly
// overwriting any batch the constructor already captured. The forgotten batch's
// SuspendThread calls were never undone, so the affected threads stayed frozen
// forever. The fix makes suspend() resume+clear the prior batch before taking a
// fresh one, keeping each thread's suspend count balanced.
//
// This is a FORWARD guard: it exercises ctor -> suspend() -> resume() and
// requires the worker to run again afterward. On fixed code that holds. (The
// buggy version leaks a suspend-the-world freeze that wedges the whole process
// rather than failing cleanly, so we don't run the buggy path here -- verified
// manually that reverting the fix makes this hang. We keep the safe direction
// as a regression tripwire: any change that breaks suspend()'s balance will
// either fail this assertion or, at worst, trip the timeout.)
// ============================================================================

int test_threadsuspender_suspend_balanced() {
    auto fut = std::async(std::launch::async, []() -> int {
        std::atomic<uint64_t> counter{0};
        std::atomic<bool> stop{false};
        std::thread worker([&]() {
            while (!stop.load(std::memory_order_relaxed)) {
                counter.fetch_add(1, std::memory_order_relaxed);
                std::this_thread::yield();
            }
        });
        while (counter.load(std::memory_order_relaxed) == 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }

        {
            utility::ThreadSuspender suspender; // ctor suspends (count 1)
            suspender.suspend();                // must resume prior batch, re-suspend (still net 1)
            suspender.resume();                 // back to 0
        }

        // Worker must run again -- no suspend count leaked.
        const uint64_t base = counter.load(std::memory_order_relaxed);
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
        bool resumed = false;
        while (std::chrono::steady_clock::now() < deadline) {
            if (counter.load(std::memory_order_relaxed) > base) { resumed = true; break; }
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }

        stop.store(true, std::memory_order_relaxed);
        worker.join();
        std::printf("  worker running after suspend()+resume(): %s\n", resumed ? "yes" : "no");
        return resumed ? 0 : 1;
    });

    if (fut.wait_for(std::chrono::seconds(15)) != std::future_status::ready) {
        std::printf("  TIMED OUT: suspend() leaked a suspension (worker stuck frozen)\n");
        TEST_ASSERT(false);
    }
    TEST_ASSERT(fut.get() == 0);
    return 0;
}

// ============================================================================
// for_each_uncached — via find_all_vtables on the executable module
// Exercises the full path: find_all_vtables -> populate -> for_each_uncached
// which is the function we guarded with get_module_size null check.
// ============================================================================

int test_find_all_vtables_executable() {
    auto* mod = GetModuleHandleA(nullptr);
    if (mod == nullptr) { TEST_SKIP("no live PE host (get_executable() is null on Linux)"); }

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
    RUN_TEST(test_threadsuspender_resume_then_destruct_no_double_unlock);
    RUN_TEST(test_threadsuspender_actually_freezes_threads);
    RUN_TEST(test_threadsuspender_suspended_flag_reflects_success);
    RUN_TEST(test_threadsuspender_suspend_balanced);

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
