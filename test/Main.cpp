#include <cstdint>
#include <string>
#include <iostream>
#include <random>

#include <spdlog/spdlog.h>

#include <utility/Scan.hpp>
#include <utility/Module.hpp>
#include <utility/RTTI.hpp>

#define KANANLIB_ASSERT(x) if (!(x)) { std::cout << "Assertion failed: " << #x << std::endl; return 1; }

constexpr char HELLO_WORLD[]{"Hello World!"};

class RTTITest {
public:
    static inline const size_t FOO_IDENTIFIER = 0xF00BA7;
    static consteval const char* FOO_STRING() {
        return "size_t RTTITest::foo()";
    }

    RTTITest() {
        std::cout << "RTTITest::RTTITest()" << std::endl;
    }
    virtual ~RTTITest() = default;

    __declspec(noinline) virtual size_t foo() try {
        printf("%s\n", FOO_STRING());
        return FOO_IDENTIFIER;
    } catch(const std::exception& e) {
        std::cout << "RTTITest::foo() threw exception: " << e.what() << std::endl;
        return 0;
    } catch(...) {
        std::cout << "RTTITest::foo() threw unknown exception" << std::endl;
        return 0;
    }

private:    
};

RTTITest* g_rtti_test{new RTTITest()};

int test_avx2_displacement_scan() {
    std::cout << "Testing AVX2 displacement scan..." << std::endl;

    // Make 1GB of data
    std::vector<uint8_t> huge_bytes{};
    huge_bytes.resize(1024 * 1024 * 1024);
    memset(huge_bytes.data(), 0, huge_bytes.size());

    std::cout << "Made 1GB of data..." << std::endl;

    double effective_throughput_scalar_gbs = 0.0;
    double effective_throughput_scalar = 0.0;
    size_t scan_time_scalar_ms{0};

    std::mt19937 rng{std::random_device{}()};

    constexpr size_t MAX_I = 128;

    // Slide a window up 32 bytes to make sure it can hit the reference at each possible alignment
    for (int32_t i = 0; i < MAX_I; ++i) {
        //std::cout << "I = " << i << std::endl;
        //const int32_t index_to_write_to = (int32_t)(huge_bytes.size() * 0.99f) + i;
        const int32_t index_to_write_to = ((int32_t)((rng() % (huge_bytes.size() - MAX_I - 4))) & ~7) + i;
        //const int32_t index_to_write_to = (int32_t)((huge_bytes.size() - 32 - 8) & ~7) + i;
        const uintptr_t address_to_write_to = (uintptr_t)&huge_bytes[index_to_write_to];
        const uintptr_t address_of_next_ip = address_to_write_to + 4;
        const uintptr_t address_to_rel32_reference = (uintptr_t)huge_bytes.data() + (rng() % (huge_bytes.size() - 32 - 4));

        const int32_t delta = (std::ptrdiff_t)address_to_rel32_reference - (std::ptrdiff_t)address_of_next_ip;
        *(int32_t*)(&huge_bytes[index_to_write_to]) = delta;

        if (index_to_write_to - 4 >= 0) {
            *(int32_t*)(&huge_bytes[index_to_write_to-4]) = delta + 5;
        }
        
        if (address_to_rel32_reference >= (uintptr_t)huge_bytes.data() + 4) {
            // We need to write something that isn't zero behind the reference so it doesn't falsely match
            *(int32_t*)(address_to_rel32_reference - 4) = 1 << 31;
        }

        std::cout << "Scanning for reference to: " << std::hex << address_to_rel32_reference << std::endl;

        const auto start = (uintptr_t)huge_bytes.data();
        const auto end = (uintptr_t)huge_bytes.data() + huge_bytes.size();
        const auto length = end - start;

        const auto scan_start_avx2 = std::chrono::high_resolution_clock::now();
        /*const auto scan_results = utility::scan_relative_references(start, length, address_to_rel32_reference);
        const auto scan_end_avx2 = std::chrono::high_resolution_clock::now();

        KANANLIB_ASSERT(scan_results.size() > 0);
        
        // print all results as we aren't supposed to find more than one
        if (scan_results.size() > 1) {
            for (const auto& result : scan_results) {
                std::cout << "Found reference at: " << std::hex << result << "(" << *(int32_t*)result << ")" << std::endl;
            }
        }

        KANANLIB_ASSERT(scan_results.size() == 1);
        const auto scan_result = scan_results[0];*/
        const auto scan_result = utility::scan_relative_reference(start, length, address_to_rel32_reference);
        const auto scan_end_avx2 = std::chrono::high_resolution_clock::now();
        KANANLIB_ASSERT(scan_result.has_value());
        KANANLIB_ASSERT(*scan_result == address_to_write_to);

        // Print the result
        std::cout << "Found reference at: " << std::hex << *scan_result << std::endl;
        std::cout << "Actual address: " << std::hex << address_to_write_to << std::endl;

        // Print the time taken
        std::cout << "AVX2 scan took: " << std::dec << std::chrono::duration_cast<std::chrono::milliseconds>(scan_end_avx2 - scan_start_avx2).count() << "ms" << std::endl;

        // Print the effective throughput rate (time it took to scan 1GB of data, given the time to arrive in the middle of the data)
        const auto scan_ratio = (double)(address_to_write_to - (uintptr_t)huge_bytes.data()) / (double)huge_bytes.size();
        const auto scan_time_avx2_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(scan_end_avx2 - scan_start_avx2).count();
        const auto scan_time_avx2_ms = (double)scan_time_avx2_ns / 1000000.0;

        const auto effective_throughput_avx2 = ((double)huge_bytes.size() * scan_ratio) / (scan_time_avx2_ms / 1000.0);
        const auto effective_throughput_avx2_gbs = effective_throughput_avx2 / (1024.0 * 1024.0 * 1024.0);

        std::cout << "Effective throughput (AVX2): " << effective_throughput_avx2_gbs << "GB/s" << std::endl;

        // Only check the scalar version once because it's ultra slow
        if (i == 0) {
            const auto scan_start_scalar = std::chrono::high_resolution_clock::now();
            const auto scan_result_scalar = utility::scan_relative_reference_scalar((uintptr_t)huge_bytes.data(), (uintptr_t)huge_bytes.size(), address_to_rel32_reference);
            const auto scan_end_scalar = std::chrono::high_resolution_clock::now();

            const auto scan_time_scalar_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(scan_end_scalar - scan_start_scalar).count();
            scan_time_scalar_ms = (double)scan_time_scalar_ns / 1000000.0;

            KANANLIB_ASSERT(scan_result_scalar.has_value());
            KANANLIB_ASSERT(*scan_result_scalar == address_to_write_to);

            effective_throughput_scalar = ((double)huge_bytes.size() * scan_ratio) / ((double)scan_time_scalar_ms / 1000.0);
            effective_throughput_scalar_gbs = effective_throughput_scalar / (1024.0 * 1024.0 * 1024.0);
        }

        std::cout << "Scalar scan took: " << std::dec << scan_time_scalar_ms << "ms" << std::endl;
        std::cout << "Effective throughput (Scalar): " << effective_throughput_scalar_gbs << "GB/s" << std::endl;

        // calculate percentage difference
        const auto percentage_difference = ((effective_throughput_avx2 - effective_throughput_scalar) / effective_throughput_scalar) * 100.0;
        //const auto times_faster = (double)scan_time_scalar_ms / (double)scan_time_avx2_ms;
        const auto times_faster = (double)effective_throughput_avx2 / (double)effective_throughput_scalar;
        const auto throughput_difference = effective_throughput_avx2_gbs - effective_throughput_scalar_gbs;
        std::cout << percentage_difference << "% (" << times_faster << "x) faster than scalar" << std::endl;
        std::cout << "Throughput difference: " << throughput_difference << "GB/s" << std::endl;

        // Erase the old data
        *(int32_t*)(&huge_bytes[index_to_write_to]) = 0;

        if (index_to_write_to - 4 >= 0) {
            *(int32_t*)(&huge_bytes[index_to_write_to-4]) = delta + 5;
        }

        if (address_to_rel32_reference >= (uintptr_t)huge_bytes.data() + 4) {
            *(int32_t*)(address_to_rel32_reference - 4) = 0;
        }
    }

    return 0;
}

int main() try {
    const auto hello_world_scan = utility::scan_string(utility::get_executable(), HELLO_WORLD);
    const auto hello_world_scans = utility::scan_strings(utility::get_executable(), HELLO_WORLD);

    KANANLIB_ASSERT(hello_world_scan.has_value());
    KANANLIB_ASSERT(*hello_world_scan == (uintptr_t)&HELLO_WORLD[0]);

    KANANLIB_ASSERT(hello_world_scans.size() > 0);

    std::cout << "Total number of strings found: " << hello_world_scans.size() << std::endl;

    const auto hello_world_string_reference = utility::scan_displacement_reference(utility::get_executable(), *hello_world_scan);

    KANANLIB_ASSERT(hello_world_string_reference.has_value());

    std::cout << "Found string reference at: " << std::hex << *hello_world_string_reference << std::endl;

    const auto resolved_instruction = utility::resolve_instruction(*hello_world_string_reference);

    if (resolved_instruction) {
        std::cout << "Resolved instruction: " << resolved_instruction->instrux.Mnemonic << std::endl;
    }

    const auto rtti_test_scan = utility::rtti::find_vtable(utility::get_executable(), "class RTTITest");

    KANANLIB_ASSERT(rtti_test_scan.has_value());
    KANANLIB_ASSERT(*rtti_test_scan == *(uintptr_t*)g_rtti_test);

    const auto rtti_object = utility::rtti::find_object_ptr(utility::get_executable(), "class RTTITest");

    KANANLIB_ASSERT(rtti_object.has_value());
    KANANLIB_ASSERT((uintptr_t)*rtti_object == (uintptr_t)&g_rtti_test);
    KANANLIB_ASSERT(**rtti_object == (uintptr_t)g_rtti_test);

    const auto foo_function = utility::find_function_from_string_ref(utility::get_executable(), RTTITest::FOO_STRING());

    KANANLIB_ASSERT(foo_function.has_value());

    using foo_t = size_t(__thiscall*)(RTTITest*);
    foo_t foo = (foo_t)*foo_function;
    KANANLIB_ASSERT(foo(g_rtti_test) == g_rtti_test->foo());
    
    KANANLIB_ASSERT(test_avx2_displacement_scan() == 0);

    SPDLOG_INFO("All tests passed.");

    return 0;
} catch(const std::exception& e) {
    std::cout << "Exception caught: " << e.what() << std::endl;
    return 1;
} catch(...) {
    std::cout << "Unknown exception caught" << std::endl;
    return 1;
}