#include <cstdint>
#include <cstring>
#include <iostream>
#include <random>
#include <vector>

#include <utility/Scan.hpp>

#include "TestHelpers.hpp"

// Stress scan_relative_reference over a large buffer with random alignments.
// The public dispatcher exercises the AVX2 implementation on AVX2-capable CPUs;
// the explicit scalar and byte-by-byte calls prove all three implementations agree
// on the same data. This used to live inside the Windows-only kananlib-test target,
// so Linux builds skipped it entirely.
int test_displacement_scan_large_random_alignments() {
    std::cout << "  Allocating 1 GB test buffer..." << std::endl;

    std::vector<uint8_t> huge_bytes{};
    try {
        huge_bytes.resize(1024 * 1024 * 1024);
    } catch (const std::bad_alloc&) {
        std::cout << "  SKIP: not enough memory for 1 GB buffer." << std::endl;
        return 0;
    }
    std::memset(huge_bytes.data(), 0, huge_bytes.size());
    std::cout << "  Allocated." << std::endl;

    std::mt19937 rng{0x4B414E41u};
    constexpr size_t MAX_I = 512;

    for (int32_t i = 0; i < (int32_t)MAX_I; ++i) {
        const int32_t index_to_write_to =
            ((int32_t)((rng() % (huge_bytes.size() - MAX_I - 4))) & ~7) + i;
        const uintptr_t address_to_write_to = (uintptr_t)&huge_bytes[index_to_write_to];
        const uintptr_t address_of_next_ip = address_to_write_to + 4;
        const uintptr_t address_to_rel32_reference =
            (uintptr_t)huge_bytes.data() + (rng() % (huge_bytes.size() - 32 - 4));

        const int32_t delta =
            (std::ptrdiff_t)address_to_rel32_reference - (std::ptrdiff_t)address_of_next_ip;
        *(int32_t*)(&huge_bytes[index_to_write_to]) = delta;

        if (index_to_write_to - 4 >= 0) {
            *(int32_t*)(&huge_bytes[index_to_write_to - 4]) = delta + 5;
        }

        if (address_to_rel32_reference >= (uintptr_t)huge_bytes.data() + 4) {
            *(int32_t*)(address_to_rel32_reference - 4) = 1 << 31;
        }

        const auto start = (uintptr_t)huge_bytes.data();
        const auto length = (uintptr_t)huge_bytes.size();

#if defined(KANANLIB_TESTING)
        utility::testing::reset_relative_reference_scan_implementation();
#endif
        const auto dispatch_result = utility::scan_relative_reference(start, length, address_to_rel32_reference);
        TEST_ASSERT(dispatch_result.has_value());
        TEST_ASSERT(*dispatch_result == address_to_write_to);
#if defined(KANANLIB_TESTING)
        const auto dispatch_impl = utility::testing::last_relative_reference_scan_implementation();
        if (i == 0) {
            std::cout << "  Dispatcher implementation: "
                      << (dispatch_impl == utility::testing::RelativeReferenceScanImplementation::Avx2 ? "AVX2" : "scalar")
                      << std::endl;
        }
        if (utility::testing::relative_reference_avx2_available_for_dispatch()) {
            TEST_ASSERT(dispatch_impl == utility::testing::RelativeReferenceScanImplementation::Avx2);
        } else {
            TEST_ASSERT(dispatch_impl == utility::testing::RelativeReferenceScanImplementation::Scalar);
        }
#endif

        // Scalar implementations are slow across 1 GB, so prove them once against
        // the same randomly aligned setup. The dispatcher path above runs every
        // iteration and covers the AVX2 implementation on AVX2-capable CPUs.
        if (i == 0) {
            const auto scalar = utility::scan_relative_reference_scalar(start, length, address_to_rel32_reference);
            TEST_ASSERT(scalar.has_value());
            TEST_ASSERT(*scalar == address_to_write_to);

            const auto byte_by_byte = utility::scan_relative_reference_scalar_byte_by_byte(start, length, address_to_rel32_reference);
            TEST_ASSERT(byte_by_byte.has_value());
            TEST_ASSERT(*byte_by_byte == address_to_write_to);
        }

        *(int32_t*)(&huge_bytes[index_to_write_to]) = 0;
        if (index_to_write_to - 4 >= 0) {
            *(int32_t*)(&huge_bytes[index_to_write_to - 4]) = 0;
        }
        if (address_to_rel32_reference >= (uintptr_t)huge_bytes.data() + 4) {
            *(int32_t*)(address_to_rel32_reference - 4) = 0;
        }
    }

    std::cout << "  " << MAX_I << " random-alignment iterations passed." << std::endl;
    return 0;
}

int main() try {
    std::cout << "===== kananlib-scan-stress-test =====" << std::endl;
    RUN_TEST(test_displacement_scan_large_random_alignments);
    return test_summary();
} catch (const std::exception& e) {
    std::cout << "Exception caught: " << e.what() << std::endl;
    return 1;
} catch (...) {
    std::cout << "Unknown exception caught" << std::endl;
    return 1;
}
