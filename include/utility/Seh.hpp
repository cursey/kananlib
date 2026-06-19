// Portable structured-exception-handling wrappers.
//
// kananlib guards memory reads that may touch unmapped pages so an access
// violation becomes "skip this region" instead of a crash. On Windows that is
// native SEH (__try/__except). On other platforms we emulate it with a
// SIGSEGV/SIGBUS handler plus sigsetjmp/siglongjmp.
//
// The wrappers are spelled KANANLIB_SEH_TRY / KANANLIB_SEH_EXCEPT rather than
// __try / __except because libstdc++ uses __try/__catch internally -- defining
// __try as a macro corrupts every standard header that follows.
//
// WARNING (non-Windows): fault recovery uses siglongjmp, which does NOT unwind
// the stack or run C++ destructors; Windows /EHa (try/catch) does. The body of a
// KANANLIB_SEH_TRY / KANANLIB_AV_TRY block MUST therefore hold only trivially
// destructible locals (PODs, raw pointers/refs, SIMD registers). Do NOT place
// RAII types with side effects (locks, owning containers, file handles) inside a
// guarded body: on a fault they would leak on Linux while unwinding cleanly on
// Windows.
//
// Usage mirrors SEH exactly:
//
//     KANANLIB_SEH_TRY { ... } KANANLIB_SEH_EXCEPT(EXCEPTION_EXECUTE_HANDLER) { ... }
#pragma once

#if defined(_WIN32)

#define KANANLIB_SEH_TRY            __try
#define KANANLIB_SEH_EXCEPT(filter) __except(filter)

// AV-guard variant. On Windows access violations surface as C++ exceptions
// (under /EHa), so scanners catch them with try / catch(...). Elsewhere we route
// them through the same signal-based guard as the SEH wrappers.
#define KANANLIB_AV_TRY    try
#define KANANLIB_AV_EXCEPT catch (...)

#else

#include <csetjmp>

namespace kananlib::seh {
    struct Frame {
        sigjmp_buf buf;
        Frame* prev;
    };

    // Thread-local top of the active handler stack.
    Frame*& current() noexcept;

    // Installs the SIGSEGV/SIGBUS handlers exactly once.
    void ensure_installed() noexcept;

    struct Guard {
        Frame frame;

        Guard() noexcept {
            ensure_installed();
            frame.prev = current();
            current() = &frame;
        }

        ~Guard() noexcept {
            current() = frame.prev;
        }

        Guard(const Guard&) = delete;
        Guard& operator=(const Guard&) = delete;
    };
}

#ifndef EXCEPTION_EXECUTE_HANDLER
#define EXCEPTION_EXECUTE_HANDLER 1
#endif
#ifndef EXCEPTION_CONTINUE_SEARCH
#define EXCEPTION_CONTINUE_SEARCH 0
#endif

// __try/__except expand to an if/else whose condition arms a jump target:
//   KANANLIB_SEH_TRY { A } KANANLIB_SEH_EXCEPT(F) { B }
//     -> if (Guard g{}; sigsetjmp(g.frame.buf, 0) == 0) { A } else { B }
// A fault inside A longjmps back, sigsetjmp returns non-zero, and B runs. The
// Guard spans both branches and is popped on every exit path (including
// continue/break out of B). savesigs=0 keeps the per-iteration cost to a
// register save; SA_NODEFER on the handler keeps the signal catchable after a
// recovered fault, so the signal mask never needs restoring.
#define KANANLIB_SEH_TRY \
    if (::kananlib::seh::Guard _kananlib_seh_guard{}; sigsetjmp(_kananlib_seh_guard.frame.buf, 0) == 0)
#define KANANLIB_SEH_EXCEPT(filter) else

#define KANANLIB_AV_TRY \
    if (::kananlib::seh::Guard _kananlib_av_guard{}; sigsetjmp(_kananlib_av_guard.frame.buf, 0) == 0)
#define KANANLIB_AV_EXCEPT else

#endif // _WIN32
