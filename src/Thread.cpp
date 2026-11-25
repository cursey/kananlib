#include <atomic>
#include <chrono>
#include <mutex>
#include <thread>

#include <windows.h>
#include <tlhelp32.h>

#include <utility/Logging.hpp>
#include <utility/Module.hpp>
#include <utility/Scan.hpp>
#include <utility/Thread.hpp>

namespace utility {
namespace detail {
std::mutex g_suspend_mutex{};
std::atomic<uint32_t> g_world_lock_attempts{0};
std::atomic<uint32_t> g_world_lock_retries{0};
std::atomic<uint32_t> g_world_lock_stalls{0};
}

typedef void (WINAPI* PFN_RtlAcquirePebLock)(void);
typedef void (WINAPI* PFN_RtlReleasePebLock)(void);

namespace {
constexpr ULONG k_ldr_lock_try_only = 0x2;
constexpr ULONG k_ldr_lock_acquired = 0x1;
constexpr auto k_world_lock_stall_warn_interval = std::chrono::seconds(1);
constexpr uint32_t k_world_lock_spin_attempts = 8;

struct NtLockApi {
    PFN_LdrLockLoaderLock lock_loader{nullptr};
    PFN_LdrUnlockLoaderLock unlock_loader{nullptr};
    PFN_RtlAcquirePebLock acquire_peb{nullptr};
    PFN_RtlReleasePebLock release_peb{nullptr};
};

const NtLockApi& nt_lock_api() {
    static const NtLockApi api = []() {
        NtLockApi resolved{};
        auto ntdll = get_module("ntdll.dll");

        if (ntdll == nullptr) {
            SPDLOG_WARN("ntdll.dll unavailable; freezing threads without the loader/PEB locks.");
            return resolved;
        }

        resolved.lock_loader = (PFN_LdrLockLoaderLock)GetProcAddress(ntdll, "LdrLockLoaderLock");
        resolved.unlock_loader = (PFN_LdrUnlockLoaderLock)GetProcAddress(ntdll, "LdrUnlockLoaderLock");
        resolved.acquire_peb = (PFN_RtlAcquirePebLock)GetProcAddress(ntdll, "RtlAcquirePebLock");
        resolved.release_peb = (PFN_RtlReleasePebLock)GetProcAddress(ntdll, "RtlReleasePebLock");

        if (resolved.lock_loader == nullptr || resolved.unlock_loader == nullptr) {
            SPDLOG_WARN("LdrLockLoaderLock/LdrUnlockLoaderLock unavailable.");
            resolved.lock_loader = nullptr;
            resolved.unlock_loader = nullptr;
        }

        if (resolved.acquire_peb == nullptr || resolved.release_peb == nullptr) {
            SPDLOG_WARN("RtlAcquirePebLock/RtlReleasePebLock unavailable.");
            resolved.acquire_peb = nullptr;
            resolved.release_peb = nullptr;
        }

        return resolved;
    }();

    return api;
}
}

ThreadStates suspend_threads() {
    ThreadStates states{};

    const auto pid = GetCurrentProcessId();
    const auto snapshot_handle = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, pid);

    if (snapshot_handle == nullptr || snapshot_handle == INVALID_HANDLE_VALUE) {
        return states;
    }

    THREADENTRY32 te{};
    te.dwSize = sizeof(THREADENTRY32);

    if (!Thread32First(snapshot_handle, &te)) {
        CloseHandle(snapshot_handle);
        return states;
    }

    const auto current_thread_id = GetCurrentThreadId();

    do {
        if (te.th32OwnerProcessID == pid && te.th32ThreadID != current_thread_id) {
            auto thread_handle = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);

            if (thread_handle != nullptr && snapshot_handle != INVALID_HANDLE_VALUE) {
                auto state = std::make_unique<ThreadState>();

                SPDLOG_INFO("Suspending {}", (uint32_t)te.th32ThreadID);

                state->thread_id = te.th32ThreadID;
                // SuspendThread returns the previous suspend count, or
                // (DWORD)-1 on failure. Success is "not -1", NOT "> 0".
                state->suspended = SuspendThread(thread_handle) != (DWORD)-1;
                states.emplace_back(std::move(state));

                CloseHandle(thread_handle);
            }
        }
    } while (Thread32Next(snapshot_handle, &te));

    CloseHandle(snapshot_handle);
    return states;
}

void resume_threads(const ThreadStates& states) {
    for (const ThreadState::Ptr& state : states) {
        auto thread_handle = OpenThread(THREAD_SUSPEND_RESUME, FALSE, state->thread_id);

        if (thread_handle != nullptr) {
            SPDLOG_INFO("Resuming {}", state->thread_id);

            ResumeThread(thread_handle);
            CloseHandle(thread_handle);
        }
    }
}

namespace detail {
// Holds the locks that must not be owned by a frozen thread:
//
//   * loader lock -- a thread suspended mid-DLL-load leaves the loader locked,
//     deadlocking anything that touches it afterwards.
//   * PEB lock    -- a thread suspended inside a PEB critical section (process
//     parameters, environment, current directory) deadlocks the PEB walkers
//     (utility::foreach_module and friends) that run while the world is frozen.
//   * process heap lock -- a thread suspended inside RtlAllocateHeap/RtlFreeHeap
//     while owning the heap's critical section deadlocks the next allocation:
//     suspend_threads() itself allocates between SuspendThread calls, and so do
//     logging and every caller's hook setup inside the frozen scope. (Seen as an
//     intermittent REFramework startup hang in a game that was loading, i.e.
//     allocating hard, while the world was frozen.)
//   * function-bucket lock (Scan.cpp) -- kananlib's own lock around the function
//     tables behind find_function_start and friends. A thread suspended while it
//     owns it deadlocks the first function lookup inside the frozen scope. (Seen
//     as a REFramework startup hang: a game thread was filling the buckets of a
//     DLL it had just loaded, waiting for the heap lock we held, and was frozen
//     there.)
//
// Lock-order hazard: the PEB and loader locks are two independent critical
// sections and real code takes them in both orders, so blocking on both invites
// a classic AB/BA deadlock against a thread that owns one and wants the other.
//
// Protocol that makes the cycle impossible:
//   1. Take the PEB lock while owning no other NT lock. Blocking here is safe:
//      its owner never waits on anything we hold.
//   2. TRY the loader lock (LDR_LOCK_LOADER_LOCK_FLAG_TRY_ONLY never blocks).
//   3. On failure, RELEASE the PEB lock, back off, and start over. That release
//      is the un-deadlock step: the loader-lock owner that was blocked on the
//      PEB lock now runs to completion and drops the loader lock for us.
//   4. Take the function-bucket lock, blocking. After the NT locks: code that
//      scans under the loader lock already owns that when it asks for this one,
//      and its owners take neither NT lock. Before the heap lock: its owners
//      allocate while holding it.
//   5. Only then take the process heap lock, blocking. It has to come last: PEB
//      and loader lock owners allocate while holding them (environment updates,
//      DLL loads), so taking the heap lock first would deadlock against them.
//      Last is safe because, with both NT locks ours, the heap lock can only be
//      owned by code inside the heap manager, which takes neither NT lock and
//      always finishes. (An explicit HeapLock() holder that then waits for the
//      PEB or loader lock would still deadlock us; no such caller is known.)
//
// So we never own one of the PEB/loader pair while blocking on the other, and
// every partially-locked state is unwound instead of waited on.
struct WorldLock {
    WorldLock() {
        acquire();
    }

    ~WorldLock() {
        release();
    }

    WorldLock(const WorldLock&) = delete;
    WorldLock& operator=(const WorldLock&) = delete;

private:
    void acquire() {
        acquire_nt_locks();

        // 4. Function-bucket lock (see above).
        detail::lock_function_buckets();
        m_buckets_held = true;

        // 5. Process heap lock, last and blocking (see above). Recursive, so our
        //    own allocations while suspending still work. Win32 only: the Linux
        //    port's suspender freezes nothing, and its compat layer has no heaps.
#if defined(_WIN32)
        m_heap = GetProcessHeap();
        m_heap_held = m_heap != nullptr && HeapLock(m_heap) != FALSE;
#endif
    }

    void acquire_nt_locks() {
        if (m_api.acquire_peb == nullptr && m_api.lock_loader == nullptr) {
            return;
        }

        g_world_lock_attempts.fetch_add(1, std::memory_order_relaxed);
        SPDLOG_INFO("Locking PEB + loader locks...");

        auto warn_at = std::chrono::steady_clock::now() + k_world_lock_stall_warn_interval;

        for (uint32_t attempt = 1;; ++attempt) {
            // 1. PEB lock first, owning nothing else. Recursive, so a nested
            //    suspender on this thread just bumps the count.
            if (m_api.acquire_peb != nullptr) {
                m_api.acquire_peb();
                m_peb_held = true;
            }

            if (m_api.lock_loader == nullptr) {
                return; // Nothing else to take.
            }

            // 2. Loader lock, never blocking.
            ULONG disposition = 0;
            ULONG_PTR cookie = 0;

            if (m_api.lock_loader(k_ldr_lock_try_only, &disposition, &cookie) >= 0 && disposition == k_ldr_lock_acquired) {
                m_loader_cookie = cookie;
                m_loader_held = true;
                SPDLOG_INFO("Locked PEB + loader locks.");
                return;
            }

            // 3. Couldn't get both: unwind so whoever owns the loader lock can
            //    finish (it may be waiting on the PEB lock we just took), then
            //    retry from scratch. There is deliberately no give-up path --
            //    suspending without the loader lock could freeze a thread that
            //    owns it, deadlocking every later loader/PEB access. A long
            //    legitimate loader operation must be waited out, not frozen.
            release_peb();
            g_world_lock_retries.fetch_add(1, std::memory_order_relaxed);

            const auto now = std::chrono::steady_clock::now();

            if (now >= warn_at) {
                g_world_lock_stalls.fetch_add(1, std::memory_order_relaxed);
                SPDLOG_WARN("Loader lock still unavailable after {} attempts; waiting (never suspending without it).", attempt);
                warn_at = now + k_world_lock_stall_warn_interval;
            }

            if (attempt <= k_world_lock_spin_attempts) {
                std::this_thread::yield();
            } else {
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
        }
    }

    void release_peb() {
        if (m_peb_held) {
            m_peb_held = false;
            m_api.release_peb();
        }
    }

    void release() {
        const bool held_any = m_loader_held || m_peb_held;

        // Reverse acquisition order.
#if defined(_WIN32)
        if (m_heap_held) {
            m_heap_held = false;
            HeapUnlock(m_heap);
        }
#endif

        if (m_buckets_held) {
            m_buckets_held = false;
            detail::unlock_function_buckets();
        }

        if (m_loader_held) {
            m_loader_held = false;
            m_api.unlock_loader(0, m_loader_cookie);
        }

        release_peb();

        if (held_any) {
            SPDLOG_INFO("Unlocked PEB + loader locks.");
        }
    }

    const NtLockApi& m_api{nt_lock_api()};
    ULONG_PTR m_loader_cookie{0};
    bool m_loader_held{false};
    bool m_peb_held{false};
    bool m_buckets_held{false};
    HANDLE m_heap{nullptr};
    bool m_heap_held{false};
};

// Suspends every other thread while holding the loader, PEB, function-bucket
// and process heap locks, so we never freeze a thread inside any of them (which
// would deadlock anything that later touches the loader, the PEB, the function
// tables or the heap). Returns the captured states.
static ThreadStates suspend_world_locked() {
    WorldLock world{};

    // All of these locks are dropped by ~WorldLock once the threads are frozen:
    // from here on nobody else can run, so they are ours to take again freely.
    return suspend_threads();
}
}

ThreadSuspender::ThreadSuspender()  {
    lock = std::unique_lock<std::mutex>(detail::g_suspend_mutex);
    states = detail::suspend_world_locked();
}

ThreadSuspender::~ThreadSuspender() {
    resume_threads(states);
    states.clear();
    if (lock.owns_lock()) {
        lock.unlock();
    }
}

void ThreadSuspender::suspend() {
    // Acquire the global suspend lock if we don't already hold it (e.g. when
    // suspend() is used standalone instead of via the constructor).
    if (!lock.owns_lock()) {
        lock = std::unique_lock<std::mutex>(detail::g_suspend_mutex);
    }
    // Resume any previously-captured batch first so repeated suspend() calls
    // don't leak suspend counts (which would freeze those threads forever).
    resume_threads(states);
    states.clear();
    states = detail::suspend_world_locked();
}

void ThreadSuspender::resume() {
    resume_threads(states);
    states.clear();
    if (lock.owns_lock()) {
        lock.unlock();
    }
}
}
