#pragma once

#include <memory>
#include <mutex>
#include <vector>

namespace utility {
struct ThreadState {
    uint32_t thread_id{0};
    bool suspended{false};

    using Ptr = std::unique_ptr<ThreadState>;
};

using ThreadStates = std::vector<ThreadState::Ptr>;

ThreadStates suspend_threads();
void resume_threads(const ThreadStates& states);

namespace detail {
extern std::mutex g_suspend_mutex;
}

struct ThreadSuspender {
    ThreadSuspender();

    virtual ~ThreadSuspender();

    void suspend();

    void resume();

    ThreadStates states{};

    // Owns g_suspend_mutex while this suspender is active. Using unique_lock
    // (instead of a raw lock/unlock pair) tracks ownership so resume() and the
    // destructor can each safely release exactly once -- no double-unlock UB.
    std::unique_lock<std::mutex> lock{};
};
}