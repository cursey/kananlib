#pragma once

#include <chrono>
#include <spdlog/spdlog.h>

//#define KANANLIB_DO_BENCHMARK

namespace kananlib {
class Benchmark {
public:
    Benchmark(const std::string& function_name)
        : m_function_name{ function_name }
        , m_start_time{ std::chrono::high_resolution_clock::now() }
    {
    }
    
    void print_elapsed_time() {
        const auto end_time = std::chrono::high_resolution_clock::now();
        const auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - m_start_time).count();
        SPDLOG_INFO("{} took {} microseconds", m_function_name, duration);
    }

    ~Benchmark() {
        print_elapsed_time();
    }

private:
    std::string m_function_name{};
    std::chrono::high_resolution_clock::time_point m_start_time{};
};
}

#ifdef KANANLIB_DO_BENCHMARK
#define KANANLIB_BENCH() \
    kananlib::Benchmark KANANLIB_BENCHMARK_INTERNAL_VARIABLE{ __FUNCTION__ }
#else
#define KANANLIB_BENCH()
#endif

#ifdef KANANLIB_LOG_HIGH_PERFORMANCE_CODE
#define KANANLIB_LOG_PERF_SENSITIVE(...) SPDLOG_INFO(__VA_ARGS__)
#else
#define KANANLIB_LOG_PERF_SENSITIVE(...)
#endif