// Non-Windows shim for <intrin.h>.
//
// clang on Linux ships an <intrin.h> that immediately does
// `#include_next <intrin.h>` and fails, so we provide the MSVC intrinsics
// kananlib uses, layered on the GCC/clang x86 intrinsic headers.
#pragma once

#if defined(_WIN32)
#error "compat/intrin.h is a non-Windows shim and must not be used on Windows"
#endif

#include <cstdint>
#include <x86intrin.h>   // pulls in immintrin/bmi/avx2 etc.

// __cpuid / __cpuidex are clang builtins on x86 with MSVC-compatible signatures,
// so they need no shim here. The _byteswap_* helpers live in winnt_compat.h
// (reached through <windows.h>) so they have a single definition even in
// translation units that include both <intrin.h> and <windows.h>.

// Bit scans (MSVC returns 0/1 and writes the index through a pointer).
// On LP64 Linux, unsigned long is 64-bit but MSVC's is 32-bit. Cast to
// uint32_t to preserve MSVC semantics and avoid UB from __builtin_clz(0)
// when the caller passes a value wider than 32 bits.
static inline unsigned char _BitScanForward(unsigned long* index, unsigned long mask) {
    if (mask == 0) return 0;
    *index = (unsigned long)__builtin_ctz((uint32_t)mask);
    return 1;
}
static inline unsigned char _BitScanReverse(unsigned long* index, unsigned long mask) {
    if (mask == 0) return 0;
    *index = (unsigned long)(31 - __builtin_clz((uint32_t)mask));
    return 1;
}
static inline unsigned char _BitScanForward64(unsigned long* index, unsigned long long mask) {
    if (mask == 0) return 0;
    *index = (unsigned long)__builtin_ctzll(mask);
    return 1;
}
static inline unsigned char _BitScanReverse64(unsigned long* index, unsigned long long mask) {
    if (mask == 0) return 0;
    *index = (unsigned long)(63 - __builtin_clzll(mask));
    return 1;
}

#ifndef __debugbreak
#define __debugbreak() __builtin_trap()
#endif

#ifndef _ReturnAddress
#define _ReturnAddress() __builtin_return_address(0)
#endif
