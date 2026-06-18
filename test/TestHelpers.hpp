#pragma once

//
// Lightweight test framework for kananlib tests.
//
// Usage:
//   1. Define test functions:  int test_foo() { TEST_ASSERT(...); return 0; }
//   2. Call from main:         RUN_TEST(test_foo);
//      With arguments:          RUN_TEST_NAMED("test_bar (arg=42)", test_bar(42));
//   3. Return summary:         return test_summary();
//
// TEST_ASSERT(expr)      -- hard failure: prints location and returns 1 from enclosing function.
// TEST_EXPECT(expr)      -- soft failure: prints location but continues the current function.
// RUN_TEST(fn)           -- runs a no-arg test function, tracks pass/fail, prints timing.
// RUN_TEST_NAMED(n, e)   -- runs an expression, tracks pass/fail, prints timing.
// test_summary()         -- prints totals and returns 0 (all pass) or 1 (any failure).
//

#include <chrono>
#include <cstdio>

namespace kananlib_test {
    inline int g_tests_passed = 0;
    inline int g_tests_failed = 0;

    inline int test_summary() {
        const int total = g_tests_passed + g_tests_failed;
        std::printf("\n===== Results: %d passed, %d failed (%d total) =====\n",
                    g_tests_passed, g_tests_failed, total);
        return g_tests_failed > 0 ? 1 : 0;
    }

    inline void run_test_impl(const char* name, int (*fn)(), const char* file, int line) {
        std::printf("\n[RUN ] %s (%s:%d)\n", name, file, line);
        std::fflush(stdout); // ensure the banner is visible even if fn() crashes
        const auto t0 = std::chrono::high_resolution_clock::now();
        const int rc = fn();
        const auto t1 = std::chrono::high_resolution_clock::now();
        const double ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
        if (rc == 0) {
            ++g_tests_passed;
            std::printf("[PASS] %s (%.1f ms)\n", name, ms);
        } else {
            ++g_tests_failed;
            std::printf("[FAIL] %s (%.1f ms)\n", name, ms);
        }
    }

    inline void run_named_impl(const char* name, int rc, double ms) {
        if (rc == 0) {
            ++g_tests_passed;
            std::printf("[PASS] %s (%.1f ms)\n", name, ms);
        } else {
            ++g_tests_failed;
            std::printf("[FAIL] %s (%.1f ms)\n", name, ms);
        }
    }
}

#define TEST_ASSERT(expr) do { \
    if (!(expr)) { \
        std::printf("  FAIL: %s  (%s:%d)\n", #expr, __FILE__, __LINE__); \
        return 1; \
    } \
} while (0)

#define TEST_EXPECT(expr) do { \
    if (!(expr)) { \
        std::printf("  EXPECT failed: %s  (%s:%d)\n", #expr, __FILE__, __LINE__); \
    } \
} while (0)

// Run a zero-argument test function.
#define RUN_TEST(fn) kananlib_test::run_test_impl(#fn, fn, __FILE__, __LINE__)

// Run an arbitrary expression as a test. name is a string literal; expr must evaluate to int.
// E.g.: RUN_TEST_NAMED("linear_correctness", test_linear_correctness(frozen.linear.addr()));
#define RUN_TEST_NAMED(name, expr) do { \
    std::printf("\n[RUN ] %s\n", name); \
    const auto _t0 = std::chrono::high_resolution_clock::now(); \
    const int _rc = (expr); \
    const auto _t1 = std::chrono::high_resolution_clock::now(); \
    const double _ms = std::chrono::duration<double, std::milli>(_t1 - _t0).count(); \
    kananlib_test::run_named_impl(name, _rc, _ms); \
} while (0)

inline int test_summary() { return kananlib_test::test_summary(); }
