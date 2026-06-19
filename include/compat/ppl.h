// Non-Windows shim for <ppl.h> (Microsoft Parallel Patterns Library).
//
// kananlib only uses concurrency::parallel_for. The shim runs the range
// serially: correct and race-free (the callers write shared state without
// synchronization, mirroring how this code already behaves). Throughput is not
// needed for the Linux scenarios kananlib targets.
#pragma once

#if defined(_WIN32)
#error "compat/ppl.h is a non-Windows shim and must not be used on Windows"
#endif

namespace concurrency {
    template <typename Index, typename Func>
    void parallel_for(Index first, Index last, const Func& body) {
        for (Index i = first; i < last; ++i) {
            body(i);
        }
    }

    template <typename Index, typename Func>
    void parallel_for(Index first, Index last, Index step, const Func& body) {
        for (Index i = first; i < last; i += step) {
            body(i);
        }
    }
}
