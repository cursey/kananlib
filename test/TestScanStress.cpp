#include <cstdint>
#include <cstdlib>
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
//
// The default run uses a modest buffer so it stays fast/reliable on CI while
// still exercising the AVX2 dispatch path (buffer >> the 128-byte AVX2 threshold
// and the 392-byte unrolled-path threshold). Set KANANLIB_SCAN_STRESS_FULL=1 for
// the heavy 1 GiB x 512-iteration run.
int test_displacement_scan_large_random_alignments() {
    const bool full = std::getenv("KANANLIB_SCAN_STRESS_FULL") != nullptr;
    const size_t buffer_size = full ? (size_t)1024 * 1024 * 1024 : (size_t)16 * 1024 * 1024;
    const size_t MAX_I = full ? 512 : 64;

    std::cout << "  Allocating " << (buffer_size >> 20) << " MiB test buffer"
              << (full ? " (KANANLIB_SCAN_STRESS_FULL)" : "") << "..." << std::endl;

    std::vector<uint8_t> huge_bytes{};
    try {
        huge_bytes.resize(buffer_size);
    } catch (const std::bad_alloc&) {
        std::cout << "  SKIP: not enough memory for the test buffer." << std::endl;
        return 0;
    }
    std::memset(huge_bytes.data(), 0, huge_bytes.size());
    std::cout << "  Allocated." << std::endl;

    std::mt19937 rng{0x4B414E41u};

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

// Stress the AVX2 sliding window for *stability*, not perf: place a single rel32
// match at EVERY byte offset in a buffer and confirm the dispatcher (AVX2),
// scalar, and byte-by-byte implementations all find it at exactly that offset.
// Sweeping every offset exercises matches that straddle the 32-byte vector-load
// boundaries, the 12x32-byte unrolled stride, and the main-loop/scalar-tail
// handoff -- the parts of the sliding window most likely to break. Sizes are
// chosen to drive both AVX2 branches: the small branch (length 128..391) and the
// big unrolled branch (length >= 392) across several outer iterations.
static int sweep_sliding_window(size_t size) {
    std::vector<uint8_t> buf(size, 0);
    const uintptr_t start = (uintptr_t)buf.data();
    const uintptr_t length = size;
    // Target just past the buffer: a default (zero) rel32 at any other position
    // references position+4, which can never equal target, so the placed offset
    // is the only match. (That AVX2 is actually used is asserted by
    // test_displacement_scan_large_random_alignments; here we only assert that
    // every offset is found correctly across all three implementations.)
    const uintptr_t target = start + size + 0x1000;

    for (size_t o = 0; o + 4 <= size; ++o) {
        const int32_t delta = (int32_t)((std::ptrdiff_t)target - (std::ptrdiff_t)(start + o + 4));
        *(int32_t*)&buf[o] = delta;
        const uintptr_t expected = start + o;

        const auto disp = utility::scan_relative_reference(start, length, target);
        TEST_ASSERT(disp.has_value());
        TEST_ASSERT(*disp == expected);

        const auto sca = utility::scan_relative_reference_scalar(start, length, target);
        TEST_ASSERT(sca.has_value() && *sca == expected);
        const auto bbb = utility::scan_relative_reference_scalar_byte_by_byte(start, length, target);
        TEST_ASSERT(bbb.has_value() && *bbb == expected);

        *(int32_t*)&buf[o] = 0; // reset for the next offset
    }
    return 0;
}

int test_displacement_scan_sliding_window_boundaries() {
    // 129..391 drive the small AVX2 branch; 392..4096 drive the big unrolled
    // branch (4096 = ~10 outer iterations). All sweep the scalar tail too.
    const size_t sizes[] = { 129, 200, 256, 391, 392, 393, 512, 1024, 4096 };
    for (size_t s : sizes) {
        if (sweep_sliding_window(s) != 0) {
            return 1;
        }
    }
    std::cout << "  sliding-window boundary sweep passed for all sizes" << std::endl;
    return 0;
}

int main() try {
    std::cout << "===== kananlib-scan-stress-test =====" << std::endl;
    RUN_TEST(test_displacement_scan_sliding_window_boundaries);
    RUN_TEST(test_displacement_scan_large_random_alignments);
    return test_summary();
} catch (const std::exception& e) {
    std::cout << "Exception caught: " << e.what() << std::endl;
    return 1;
} catch (...) {
    std::cout << "Unknown exception caught" << std::endl;
    return 1;
}
