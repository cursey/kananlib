#include <mutex>

#include <Windows.h>
#include <TlHelp32.h>
#include <spdlog/spdlog.h>

#include <utility/Thread.hpp>

namespace utility {
namespace detail {
std::mutex g_suspend_mutex{};
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
                state->suspended = SuspendThread(thread_handle) > 0;
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

typedef NTSTATUS (WINAPI* PFN_LdrLockLoaderLock)(ULONG Flags, ULONG *State, ULONG_PTR *Cookie);
typedef NTSTATUS (WINAPI* PFN_LdrUnlockLoaderLock)(ULONG Flags, ULONG_PTR Cookie);

ThreadSuspender::ThreadSuspender()  {
    auto ntdll = GetModuleHandleA("ntdll.dll");
    
    auto lock_loader = ntdll != nullptr ? (PFN_LdrLockLoaderLock)GetProcAddress(ntdll, "LdrLockLoaderLock") : nullptr;
    auto unlock_loader = ntdll != nullptr ? (PFN_LdrUnlockLoaderLock)GetProcAddress(ntdll, "LdrUnlockLoaderLock") : nullptr;

    ULONG_PTR loader_magic = 0;
    if (lock_loader != nullptr && unlock_loader != nullptr) {
        SPDLOG_INFO("Locking loader lock...");
        lock_loader(0, NULL, &loader_magic);
    }

    detail::g_suspend_mutex.lock();
    states = suspend_threads();

    if (lock_loader != nullptr && unlock_loader != nullptr) {
        unlock_loader(0, loader_magic);
        SPDLOG_INFO("Unlocked loader lock.");
    }
}

ThreadSuspender::~ThreadSuspender() {
    resume_threads(states);
    
    if (!states.empty()) {
        detail::g_suspend_mutex.unlock();
    }
}

void ThreadSuspender::resume() {
    resume_threads(states);

    if (!states.empty()) {
        states.clear();
        detail::g_suspend_mutex.unlock();
    }
}
}
