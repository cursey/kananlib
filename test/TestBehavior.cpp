// Behavior tests for modified functions: scan_strings (4 overloads),
// ThreadSuspender (mutex unlock), and for_each_uncached (via find_all_vtables).
//
// These verify that the functions still work correctly after defensive fixes.

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <functional>
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
// ThreadSuspender — loader lock + PEB lock acquisition must not deadlock.
//
// Before freezing the world, suspend_world_locked() takes BOTH the loader lock
// and the PEB lock (RtlAcquirePebLock), so no thread can be suspended while
// owning either one. Two independent critical sections taken by one thread is
// an AB/BA deadlock waiting to happen, and real code takes them in both
// orders, so the implementation:
//
//   1. takes the PEB lock while owning no other NT lock (blocking is safe),
//   2. TRY-locks the loader lock (never blocks),
//   3. on failure RELEASES the PEB lock, backs off, and retries.
//
// Step 3 is the un-deadlocking step. The tests below build both halves of the
// cycle with real ntdll locks on real threads and require the suspender to get
// through them.
// ============================================================================

typedef void (WINAPI* PFN_RtlAcquirePebLock)(void);
typedef void (WINAPI* PFN_RtlReleasePebLock)(void);

namespace ntlocks {
struct Api {
    PFN_LdrLockLoaderLock lock_loader{nullptr};
    PFN_LdrUnlockLoaderLock unlock_loader{nullptr};
    PFN_RtlAcquirePebLock acquire_peb{nullptr};
    PFN_RtlReleasePebLock release_peb{nullptr};

    bool ok() const {
        return lock_loader != nullptr && unlock_loader != nullptr
            && acquire_peb != nullptr && release_peb != nullptr;
    }
};

static const Api& get() {
    static const Api api = []() {
        Api a{};
        auto ntdll = utility::get_module("ntdll.dll");

        if (ntdll == nullptr) {
            return a;
        }

        a.lock_loader = (PFN_LdrLockLoaderLock)GetProcAddress(ntdll, "LdrLockLoaderLock");
        a.unlock_loader = (PFN_LdrUnlockLoaderLock)GetProcAddress(ntdll, "LdrUnlockLoaderLock");
        a.acquire_peb = (PFN_RtlAcquirePebLock)GetProcAddress(ntdll, "RtlAcquirePebLock");
        a.release_peb = (PFN_RtlReleasePebLock)GetProcAddress(ntdll, "RtlReleasePebLock");
        return a;
    }();
    return api;
}

// Blocking loader-lock acquire. Returns false if ntdll refused.
static bool lock_loader_blocking(ULONG_PTR& cookie) {
    ULONG disposition = 0;
    cookie = 0;
    return get().lock_loader(0, &disposition, &cookie) >= 0;
}
}

// std::async on MSVC dispatches onto the PPL thread pool, which delays a second
// concurrent task by seconds when the first one blocks -- enough to dissolve the
// interleavings these tests are built to create. So spawn real OS threads, and
// keep a future alongside each one for bounded waits.
//
// A deadlock regression cannot be recovered from in-process: the wedged thread
// owns the loader and/or PEB lock, so joining it blocks forever. Waits therefore
// report the failure and kill the process, turning a would-be suite wedge into a
// suite failure.
//
// The exit path matters. exit(), abort() and even std::_Exit() all funnel into
// ExitProcess, which runs DLL_PROCESS_DETACH under the LOADER LOCK -- the very
// lock the deadlocked thread owns -- so the process hangs anyway. Measured with
// a deliberately wrong lock order: this message printed, then the process still
// had to be killed externally after 120s. TerminateProcess notifies no DLLs and
// takes no user-mode locks, so it is the only reliable escape here.
[[noreturn]] static void fail_fast(const char* what) {
    std::printf("  FAIL (fatal): %s -- lock acquisition deadlocked; killing the process so the suite cannot wedge\n", what);
    std::fflush(stdout);
    std::fflush(stderr);
#if defined(_WIN32)
    TerminateProcess(GetCurrentProcess(), 1);
#endif
    std::_Exit(1);
}

struct LockTask {
    std::thread thread{};
    std::future<int> future{};

    // Blocks up to `budget`. Never returns while the worker is still running --
    // that only happens on a real deadlock, which is unrecoverable.
    int join_within(std::chrono::seconds budget, const char* what) {
        if (future.wait_for(budget) != std::future_status::ready) {
            fail_fast(what);
        }

        thread.join();
        return future.get();
    }
};

static LockTask launch_lock_task(std::function<int()> body) {
    std::packaged_task<int()> packaged{std::move(body)};
    LockTask task{};
    task.future = packaged.get_future();
    task.thread = std::thread{std::move(packaged)};
    return task;
}

// Spins until `predicate` holds or the budget runs out. Every wait in these
// tests is bounded so a regression fails or times out instead of wedging.
template <typename Predicate>
static bool spin_until(Predicate predicate, std::chrono::milliseconds budget) {
    const auto deadline = std::chrono::steady_clock::now() + budget;
    while (!predicate()) {
        if (std::chrono::steady_clock::now() >= deadline) {
            return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    return true;
}

// Holds every worker at the starting line until all of them are genuinely
// running. Necessary because thread creation AND thread startup run
// DLL_THREAD_ATTACH under the loader lock: a thread that is still starting when
// a contender grabs the loader lock cannot execute a single instruction of its
// body until that lock is released, which dissolves the interleaving under test.
struct StartGate {
    std::atomic<uint32_t> running{0};
    std::atomic<bool> open{false};

    // Called first thing by each worker; false if the gate never opened.
    bool wait() {
        running.fetch_add(1, std::memory_order_release);
        return spin_until([this] { return open.load(std::memory_order_acquire); },
                          std::chrono::milliseconds(5000));
    }

    // Called by the test thread once every worker is spawned; false if some
    // worker never reached wait().
    bool release(uint32_t workers) {
        const bool all_running = spin_until(
            [&] { return running.load(std::memory_order_acquire) >= workers; },
            std::chrono::milliseconds(5000));
        open.store(true, std::memory_order_release);
        return all_running;
    }
};

// ============================================================================
// Half #1: a thread OWNS the loader lock and then WANTS the PEB lock.
//
// The suspender starts from the other end (PEB owned, loader wanted), so the
// two threads form a genuine cycle the moment the suspender blocks while still
// holding the PEB lock. It must instead notice the failed loader try, drop the
// PEB lock -- which is what lets the contender's blocking PEB acquire complete
// and its loader lock be released -- and then retry.
//
// Proof, not just "didn't hang":
//   * g_world_lock_retries MUST have advanced -> the drop-and-retry path ran.
//   * the contender MUST have obtained the PEB lock -> its blocked acquire was
//     released by the suspender backing out.
//
// The no-give-up half of the contract has its own test (a 6s loader hold); here
// the contention is short, so the loop is expected to win without stalling.
// ============================================================================

int test_threadsuspender_backs_out_when_loader_lock_is_held() {
#if !defined(_WIN32)
    TEST_SKIP("NT loader/PEB locks require a Win32 host");
#endif
    if (!ntlocks::get().ok()) { TEST_SKIP("ntdll lock exports unavailable"); }

    // Warm up the suspender's one-time ntdll resolution. GetModuleHandle and
    // GetProcAddress BLOCK on the loader lock, so an unresolved suspender would
    // stall inside the resolution step instead of reaching the try-lock loop we
    // are testing. Order-independent: this test must not rely on an earlier one.
    { utility::ThreadSuspender warmup; }

    const uint32_t retries_before = utility::detail::g_world_lock_retries.load();
    const uint32_t stalls_before = utility::detail::g_world_lock_stalls.load();

    StartGate gate{};
    std::atomic<bool> loader_owned{false};
    std::atomic<bool> contender_got_peb{false};

    auto contender = launch_lock_task([&]() -> int {
        if (!gate.wait()) {
            return 1;
        }

        ULONG_PTR cookie = 0;
        if (!ntlocks::lock_loader_blocking(cookie)) {
            return 1;
        }
        loader_owned.store(true, std::memory_order_release);

        // Keep the loader lock until the suspender has demonstrably backed out
        // of a partial lock, so the test exercises the retry path instead of
        // just winning a race. Bounded so a regression fails instead of hangs.
        const bool observed_backout = spin_until(
            [&] { return utility::detail::g_world_lock_retries.load() != retries_before; },
            std::chrono::milliseconds(5000));

        // Now complete the cycle: block on the PEB lock while still owning the
        // loader lock. This only returns because the suspender releases it.
        ntlocks::get().acquire_peb();
        contender_got_peb.store(true, std::memory_order_release);
        ntlocks::get().release_peb();

        ntlocks::get().unlock_loader(0, cookie);
        return observed_backout ? 0 : 1;
    });

    // Freeze the world only once the loader lock is genuinely taken.
    auto suspender = launch_lock_task([&]() -> int {
        if (!gate.wait()) {
            return 1;
        }

        if (!spin_until([&] { return loader_owned.load(std::memory_order_acquire); },
                        std::chrono::milliseconds(5000))) {
            return 1;
        }

        utility::ThreadSuspender s;
        const size_t captured = s.states.size();
        s.resume();
        return captured > 0 ? 0 : 1;
    });

    const bool started = gate.release(2);
    const bool armed = started && spin_until(
        [&] { return loader_owned.load(std::memory_order_acquire); },
        std::chrono::milliseconds(5000));

    // A wrong implementation (blocking on the loader lock while owning the PEB
    // lock) deadlocks here. join_within reports and kills the process rather
    // than joining a wedged thread, so a regression fails instead of hanging.
    const int suspender_rc = suspender.join_within(std::chrono::seconds(30), "suspender vs loader-lock owner");
    const int contender_rc = contender.join_within(std::chrono::seconds(30), "loader-lock owner vs suspender");

    const uint32_t retries = utility::detail::g_world_lock_retries.load() - retries_before;
    const uint32_t stalls = utility::detail::g_world_lock_stalls.load() - stalls_before;
    std::printf("  world-lock back-outs: %u, stall warnings: %u, contender got PEB lock: %s\n",
                retries, stalls, contender_got_peb.load() ? "yes" : "no");

    TEST_ASSERT(armed);                                         // contender really owned the loader lock
    TEST_ASSERT(suspender_rc == 0);                             // no deadlock, world actually frozen
    TEST_ASSERT(contender_rc == 0);                             // contender saw the back-out and finished
    TEST_ASSERT(retries > 0);                                   // the un-deadlock path ran
    TEST_ASSERT(contender_got_peb.load(std::memory_order_acquire)); // its blocked acquire was freed
    return 0;
}

// ============================================================================
// Half #2: a thread OWNS the PEB lock and then WANTS the loader lock.
//
// This pins the acquisition ORDER. With the correct order (PEB first, loader
// try-only) the suspender simply blocks on the PEB lock while owning nothing,
// and the contender -- which needs only the uncontended loader lock -- runs to
// completion and releases it.
//
// Reverse the order (loader first, then a blocking PEB acquire) and this test
// deadlocks for real: the suspender would own the loader lock and wait for the
// PEB lock while the contender owns the PEB lock and waits for the loader lock.
//
// Getting there requires the contender to request the loader lock only AFTER
// the suspender has entered its acquisition protocol; otherwise the contender
// could take and release the loader lock before a wrong-order suspender ever
// runs, and the broken implementation would pass. A fixed sleep cannot
// establish that on a loaded machine, so the contender waits on the
// g_world_lock_attempts counter, which the suspender bumps on entry before
// touching either lock. The short sleep after that only covers the handful of
// instructions between the bump and a wrong-order loader acquire.
// ============================================================================

int test_threadsuspender_waits_out_peb_lock_owner() {
#if !defined(_WIN32)
    TEST_SKIP("NT loader/PEB locks require a Win32 host");
#endif
    if (!ntlocks::get().ok()) { TEST_SKIP("ntdll lock exports unavailable"); }

    // See Half #1: resolve the suspender's ntdll pointers before the contention
    // starts, so it cannot stall on the loader lock during resolution.
    { utility::ThreadSuspender warmup; }

    const uint32_t stalls_before = utility::detail::g_world_lock_stalls.load();
    const uint32_t attempts_before = utility::detail::g_world_lock_attempts.load();

    StartGate gate{};
    std::atomic<bool> peb_owned{false};
    std::atomic<bool> contender_got_loader{false};
    std::atomic<bool> suspender_entered{false};

    auto contender = launch_lock_task([&]() -> int {
        if (!gate.wait()) {
            return 1;
        }

        ntlocks::get().acquire_peb();
        peb_owned.store(true, std::memory_order_release);

        // Wait until the suspender is actually inside the acquisition protocol,
        // so a wrong-order implementation has reached its loader acquire.
        const bool observed_entry = spin_until(
            [&] { return utility::detail::g_world_lock_attempts.load() != attempts_before; },
            std::chrono::milliseconds(5000));
        suspender_entered.store(observed_entry, std::memory_order_release);
        std::this_thread::sleep_for(std::chrono::milliseconds(20));

        ULONG_PTR cookie = 0;
        if (ntlocks::lock_loader_blocking(cookie)) {
            contender_got_loader.store(true, std::memory_order_release);
            ntlocks::get().unlock_loader(0, cookie);
        }
        ntlocks::get().release_peb();
        return observed_entry ? 0 : 1;
    });

    auto suspender = launch_lock_task([&]() -> int {
        if (!gate.wait()) {
            return 1;
        }

        if (!spin_until([&] { return peb_owned.load(std::memory_order_acquire); },
                        std::chrono::milliseconds(5000))) {
            return 1;
        }

        utility::ThreadSuspender s;
        const size_t captured = s.states.size();
        s.resume();
        return captured > 0 ? 0 : 1;
    });

    const bool started = gate.release(2);
    const bool armed = started && spin_until(
        [&] { return peb_owned.load(std::memory_order_acquire); },
        std::chrono::milliseconds(5000));

    const int suspender_rc = suspender.join_within(std::chrono::seconds(30), "suspender vs PEB-lock owner");
    const int contender_rc = contender.join_within(std::chrono::seconds(30), "PEB-lock owner vs suspender");

    const uint32_t stalls = utility::detail::g_world_lock_stalls.load() - stalls_before;
    std::printf("  stall warnings: %u, suspender entered before loader request: %s, contender got loader lock: %s\n",
                stalls, suspender_entered.load() ? "yes" : "no",
                contender_got_loader.load() ? "yes" : "no");

    TEST_ASSERT(armed);                                             // contender really owned the PEB lock
    TEST_ASSERT(suspender_rc == 0);                                 // order is deadlock-free
    TEST_ASSERT(contender_rc == 0);
    TEST_ASSERT(suspender_entered.load(std::memory_order_acquire)); // the interleaving was really set up
    TEST_ASSERT(contender_got_loader.load(std::memory_order_acquire));
    return 0;
}

// ============================================================================
// A long loader operation must be WAITED OUT, never frozen.
//
// This is the invariant that makes the whole protocol worth having: the
// acquisition loop has no give-up path. An earlier revision gave up after a
// fixed budget and suspended the world anyway -- which freezes the thread that
// owns the loader lock, deadlocking every later loader/PEB access (exactly what
// callers like safe_unlink() rely on not happening).
//
// Setup: a contender owns the loader lock for longer than the stall-warning
// interval, then sets `releasing` BEFORE unlocking. The suspender thread
// records that flag the instant its ThreadSuspender constructor returns.
//
// Because the constructor only returns while owning both locks, and the loader
// lock can only be owned after the contender started releasing it, the flag
// MUST be set. A give-up path makes the constructor return mid-hold, while the
// contender still owns the loader lock and the flag is still false -- no timing
// tolerance involved.
// ============================================================================

int test_threadsuspender_waits_out_long_loader_operation() {
#if !defined(_WIN32)
    TEST_SKIP("NT loader/PEB locks require a Win32 host");
#endif
    if (!ntlocks::get().ok()) { TEST_SKIP("ntdll lock exports unavailable"); }

    // See Half #1: resolve the suspender's ntdll pointers up front.
    { utility::ThreadSuspender warmup; }

    const uint32_t stalls_before = utility::detail::g_world_lock_stalls.load();

    // Deliberately longer than BOTH the current 1s stall-warning interval and
    // the 5s give-up budget the reviewed revision used, so re-introducing any
    // give-up path fails this test rather than silently passing it.
    constexpr auto k_hold = std::chrono::milliseconds(6000);

    StartGate gate{};
    std::atomic<bool> loader_owned{false};
    std::atomic<bool> releasing{false};
    std::atomic<bool> saw_releasing{false};

    auto contender = launch_lock_task([&]() -> int {
        if (!gate.wait()) {
            return 1;
        }

        ULONG_PTR cookie = 0;
        if (!ntlocks::lock_loader_blocking(cookie)) {
            return 1;
        }
        loader_owned.store(true, std::memory_order_release);

        // A legitimate long loader operation (a big DLL load, a slow disk).
        std::this_thread::sleep_for(k_hold);

        // Published before the unlock: whoever observes the loader lock as free
        // must also observe this.
        releasing.store(true, std::memory_order_release);
        ntlocks::get().unlock_loader(0, cookie);
        return 0;
    });

    auto suspender = launch_lock_task([&]() -> int {
        if (!gate.wait()) {
            return 1;
        }

        if (!spin_until([&] { return loader_owned.load(std::memory_order_acquire); },
                        std::chrono::milliseconds(5000))) {
            return 1;
        }

        utility::ThreadSuspender s;
        // Sampled before anything else: did the world freeze while the loader
        // lock was still owned by the contender?
        saw_releasing.store(releasing.load(std::memory_order_acquire), std::memory_order_release);
        const size_t captured = s.states.size();
        s.resume();
        return captured > 0 ? 0 : 1;
    });

    const bool started = gate.release(2);
    const auto t0 = std::chrono::steady_clock::now();

    const int suspender_rc = suspender.join_within(std::chrono::seconds(30), "suspender vs long loader operation");
    const int contender_rc = contender.join_within(std::chrono::seconds(30), "long loader operation");

    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - t0);
    const uint32_t stalls = utility::detail::g_world_lock_stalls.load() - stalls_before;
    std::printf("  held loader lock %lldms, freeze completed after %lldms, stall warnings: %u, froze only after release: %s\n",
                (long long)k_hold.count(), (long long)elapsed.count(), stalls,
                saw_releasing.load() ? "yes" : "no");

    TEST_ASSERT(started);
    TEST_ASSERT(suspender_rc == 0);
    TEST_ASSERT(contender_rc == 0);
    // The core invariant: no suspension happened while the loader lock was held.
    TEST_ASSERT(saw_releasing.load(std::memory_order_acquire));
    // And the wait really did outlive the stall-warning budget.
    TEST_ASSERT(stalls > 0);
    TEST_ASSERT(elapsed >= k_hold);
    return 0;
}

// ============================================================================
// Soak: both halves of the cycle running continuously while the world is
// repeatedly frozen. Every suspender must complete while owning both locks.
//
// The contenders take both NT locks in OPPOSITE orders, so they are serialized
// against each other by a test-local mutex -- otherwise they would deadlock
// each other and prove nothing about the suspender. The suspender is the only
// unserialized participant, which is exactly the contention we want to test.
// Each contender also holds the pair for a moment, so the freeze loop really
// collides with it instead of slipping through the gaps.
// ============================================================================

int test_threadsuspender_lock_order_soak() {
#if !defined(_WIN32)
    TEST_SKIP("NT loader/PEB locks require a Win32 host");
#endif
    if (!ntlocks::get().ok()) { TEST_SKIP("ntdll lock exports unavailable"); }

    // See Half #1: resolve the suspender's ntdll pointers up front.
    { utility::ThreadSuspender warmup; }

    const uint32_t retries_before = utility::detail::g_world_lock_retries.load();
    const uint32_t stalls_before = utility::detail::g_world_lock_stalls.load();

    StartGate gate{};
    std::atomic<bool> stop{false};
    std::atomic<uint32_t> contender_rounds{0};
    std::mutex both_locks_serializer{}; // keeps the contenders from cycling with each other

    // order == 0: loader then PEB.  order == 1: PEB then loader.
    auto contender_body = [&](int order) -> int {
        if (!gate.wait()) {
            return 1;
        }

        while (!stop.load(std::memory_order_relaxed)) {
            {
                std::scoped_lock guard{both_locks_serializer};
                ULONG_PTR cookie = 0;

                if (order == 0) {
                    if (!ntlocks::lock_loader_blocking(cookie)) { return 1; }
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                    ntlocks::get().acquire_peb();
                    ntlocks::get().release_peb();
                    ntlocks::get().unlock_loader(0, cookie);
                } else {
                    ntlocks::get().acquire_peb();
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                    if (!ntlocks::lock_loader_blocking(cookie)) {
                        ntlocks::get().release_peb();
                        return 1;
                    }
                    ntlocks::get().unlock_loader(0, cookie);
                    ntlocks::get().release_peb();
                }
            }

            contender_rounds.fetch_add(1, std::memory_order_relaxed);
            std::this_thread::yield();
        }
        return 0;
    };

    auto loader_first = launch_lock_task([&] { return contender_body(0); });
    auto peb_first = launch_lock_task([&] { return contender_body(1); });

    constexpr int k_iterations = 20;
    auto freezer = launch_lock_task([&]() -> int {
        // All three threads exist before any NT lock is taken; see Half #1.
        if (!gate.wait()) {
            return 1;
        }

        for (int i = 0; i < k_iterations; ++i) {
            utility::ThreadSuspender s;
            if (s.states.empty()) {
                return 1;
            }
            s.resume();
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        return 0;
    });

    const bool started = gate.release(3);

    const int freezer_rc = freezer.join_within(std::chrono::seconds(60), "freeze loop vs both-order contenders");

    stop.store(true, std::memory_order_relaxed);
    const int loader_first_rc = loader_first.join_within(std::chrono::seconds(30), "loader-first contender");
    const int peb_first_rc = peb_first.join_within(std::chrono::seconds(30), "PEB-first contender");

    const uint32_t retries = utility::detail::g_world_lock_retries.load() - retries_before;
    const uint32_t stalls = utility::detail::g_world_lock_stalls.load() - stalls_before;
    std::printf("  %d freezes vs %u contended lock rounds; back-outs: %u, stall warnings: %u\n",
                k_iterations, contender_rounds.load(), retries, stalls);

    TEST_ASSERT(started);
    TEST_ASSERT(freezer_rc == 0);
    TEST_ASSERT(loader_first_rc == 0 && peb_first_rc == 0);
    TEST_ASSERT(contender_rounds.load() > 0);
    // Collisions are overwhelmingly likely (contenders own the loader lock for
    // ~1ms per round) but not synchronized: a scheduler could in principle slot
    // every freeze between critical sections. Report it rather than assert it --
    // the deterministic back-out coverage lives in Half #1.
    TEST_EXPECT(retries > 0);
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

    // ThreadSuspender — loader lock + PEB lock (RtlAcquirePebLock) contention
    RUN_TEST(test_threadsuspender_backs_out_when_loader_lock_is_held);
    RUN_TEST(test_threadsuspender_waits_out_peb_lock_owner);
    RUN_TEST(test_threadsuspender_waits_out_long_loader_operation);
    RUN_TEST(test_threadsuspender_lock_order_soak);

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
