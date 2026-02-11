#define NOMINMAX

#include <ppl.h>
#include <intrin.h>

#include <numeric>
#include <cwctype>
#include <cstdint>
#include <unordered_set>
#include <shared_mutex>

#include <utility/Logging.hpp>

#include <utility/Pattern.hpp>
#include <utility/String.hpp>
#include <utility/Module.hpp>
#include <utility/Scan.hpp>
#include <utility/thirdparty/parallel-util.hpp>
#include <utility/thirdparty/InstructionSet.hpp>
#include <utility/ScopeGuard.hpp>
#include <utility/Benchmark.hpp>

using namespace std;

namespace undocumented {
    // https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64?view=msvc-170
    union UNWIND_CODE {
        struct {
            BYTE CodeOffset;
            BYTE UnwindOp : 4;
            BYTE OpInfo   : 4;
        } u;
        USHORT FrameOffset;
    };

    struct UNWIND_INFO {
        BYTE Version       : 3;
        BYTE Flags         : 5;
        BYTE SizeOfProlog;
        BYTE CountOfCodes;
        BYTE FrameRegister : 4;
        BYTE FrameOffset   : 4;
        UNWIND_CODE UnwindCode[1];
    };
}

namespace utility {
    optional<uintptr_t> scan(const string& module, const string& pattern) {
        return scan(GetModuleHandleA(module.c_str()), pattern);
    }

    optional<uintptr_t> scan(const wstring& module, const string& pattern) {
        return scan(GetModuleHandleW(module.c_str()), pattern);
    }

    optional<uintptr_t> scan(const string& module, uintptr_t start, const string& pattern) {
        HMODULE mod = GetModuleHandleA(module.c_str());
        return scan(start, (get_module_size(mod).value_or(0) - start + (uintptr_t)mod), pattern);
    }

    optional<uintptr_t> scan(const wstring& module, uintptr_t start, const string& pattern) {
        HMODULE mod = GetModuleHandleW(module.c_str());
        return scan(start, (get_module_size(mod).value_or(0) - start + (uintptr_t)mod), pattern);
    }

    optional<uintptr_t> scan(HMODULE module, const string& pattern) {
        return scan((uintptr_t)module, get_module_size(module).value_or(0), pattern);
    }

    optional<uintptr_t> scan(uintptr_t start, size_t length, const string& pattern) {
        KANANLIB_BENCH();

        if (start == 0 || length == 0) {
            return {};
        }

        Pattern p{ pattern };

        return p.find(start, length);
    }

    std::optional<uintptr_t> scan_reverse(uintptr_t start, size_t length, const std::string& pattern) {
        KANANLIB_BENCH();

        if (start == 0 || length == 0) {
            return {};
        }

        Pattern p{ pattern };

        for (uintptr_t i = start; i >= start - length; i--) {
            if (p.find(i, p.pattern_len()).has_value()) {
                return i;
            }
        }

        return {};
    }

    optional<uintptr_t> scan_data(HMODULE module, const uint8_t* data, size_t size) {
        KANANLIB_BENCH();

        const auto module_size = get_module_size(module).value_or(0);
        auto it = (uint8_t*)module;
        const auto end = (uint8_t*)module + module_size;

        while (it < end) try {
            while (end != (it = std::find(it, end, *data))) try {
                if (memcmp(it, data, size) == 0) {
                    return (uintptr_t)it;
                } else {
                    it++;
                }
            } catch (...) {
                it++;
                continue;
            }
        } catch (...) {
            MEMORY_BASIC_INFORMATION mbi{};
            if (VirtualQuery(it, &mbi, sizeof(mbi)) != 0) {
                it = (uint8_t*)((uintptr_t)mbi.BaseAddress + mbi.RegionSize);
                SPDLOG_INFO("Caught exception during outer data scan, skipping to next memory region at {:x}", (uintptr_t)it);
            } else {
                it++;
            }
            continue;
        }

        return {};
    }

    optional<uintptr_t> scan_data(uintptr_t start, size_t length, const uint8_t* data, size_t size) {
        KANANLIB_BENCH();

        if (start == 0 || length == 0) {
            return {};
        }

        auto it = (uint8_t*)start;
        const auto end = (uint8_t*)start + length;
        while (it < end) try {
            while (end != (it = std::find(it, end, *data))) try {
                if (memcmp(it, data, size) == 0) {
                    return (uintptr_t)it;
                } else {
                    it++;
                }
            } catch (...) {
                it++;
                continue;
            }
        } catch (...) {
            MEMORY_BASIC_INFORMATION mbi{};
            if (VirtualQuery(it, &mbi, sizeof(mbi)) != 0) {
                it = (uint8_t*)((uintptr_t)mbi.BaseAddress + mbi.RegionSize);
                SPDLOG_INFO("Caught exception during outer data scan, skipping to next memory region at {:x}", (uintptr_t)it);
            } else {
                it++;
            }
            continue;
        }

        return {};
    }

    optional<uintptr_t> scan_data_reverse(uintptr_t start, size_t length, const uint8_t* data, size_t size) {
        KANANLIB_BENCH();

        if (start == 0 || length == 0) {
            return {};
        }

        for (auto i = start; i >= start - length; i -= sizeof(uint8_t)) {
            if (memcmp((void*)i, data, size) == 0) {
                return i;
            }
        }

        return {};
    }

    optional<uintptr_t> scan_ptr(HMODULE module, uintptr_t ptr) {
        KANANLIB_BENCH();

        const auto module_size = get_module_size(module).value_or(0);
        auto end = (uintptr_t*)((uintptr_t)module + module_size);
        auto it = (uintptr_t*)module;

        // just making use of the try catch + while to get through unreadable pages
        while (it < end) try {
            it = std::find(it, end, ptr);

            if (it != end) {
                return (uintptr_t)it;
            }

            ++it;
        } catch(...) {
            MEMORY_BASIC_INFORMATION mbi{};
            if (VirtualQuery(it, &mbi, sizeof(mbi)) != 0) {
                it = (uintptr_t*)((uintptr_t)mbi.BaseAddress + mbi.RegionSize);
            } else {
                ++it;
            }

            continue;
        }

        return std::nullopt;
    }

    std::optional<uintptr_t> scan_ptr(uintptr_t start, size_t length, uintptr_t ptr) {
        KANANLIB_BENCH();

        if (start == 0 || length == 0) {
            return {};
        }

        auto end = (uintptr_t*)(start + length);
        auto it = (uintptr_t*)start;

        // just making use of the try catch + while to get through unreadable pages
        while (it < end) try {
            it = std::find(it, end, ptr);

            if (it != end) {
                return (uintptr_t)it;
            }

            ++it;
        } catch(...) {
            MEMORY_BASIC_INFORMATION mbi{};
            if (VirtualQuery(it, &mbi, sizeof(mbi)) != 0) {
                it = (uintptr_t*)((uintptr_t)mbi.BaseAddress + mbi.RegionSize);
            } else {
                ++it;
            }
            
            continue;
        }

        return std::nullopt;
    }

    std::optional<uintptr_t> scan_ptr_noalign(HMODULE module, uintptr_t ptr) {
        KANANLIB_BENCH();

        return utility::scan_data(module, (uint8_t*)&ptr, sizeof(uintptr_t));
    }

    std::optional<uintptr_t> scan_ptr_noalign(uintptr_t start, size_t length, uintptr_t ptr) {
        KANANLIB_BENCH();

        return utility::scan_data(start, length, (uint8_t*)&ptr, sizeof(uintptr_t));
    }

    optional<uintptr_t> scan_string(HMODULE module, const string& str, bool zero_terminated) {
        KANANLIB_BENCH();

        if (str.empty()) {
            return {};
        }

        const auto data = (uint8_t*)str.c_str();
        const auto size = str.size() + (zero_terminated ? 1 : 0);

        return scan_data(module, data, size);
    }

    optional<uintptr_t> scan_string(HMODULE module, const wstring& str, bool zero_terminated) {
        KANANLIB_BENCH();

        if (str.empty()) {
            return {};
        }

        const auto data = (uint8_t*)str.c_str();
        const auto size = (str.size() + (zero_terminated ? 1 : 0)) * sizeof(wchar_t);

        return scan_data(module, data, size);
    }

    std::optional<uintptr_t> scan_string(uintptr_t start, size_t length, const std::string& str, bool zero_terminated) {
        KANANLIB_BENCH();

        if (str.empty()) {
            return {};
        }

        const auto data = (uint8_t*)str.c_str();
        const auto size = str.size() + (zero_terminated ? 1 : 0);

        return scan_data(start, length, data, size);
    }

    std::optional<uintptr_t> scan_string(uintptr_t start, size_t length, const std::wstring& str, bool zero_terminated) {
        KANANLIB_BENCH();

        if (str.empty()) {
            return {};
        }

        const auto data = (uint8_t*)str.c_str();
        const auto size = (str.size() + (zero_terminated ? 1 : 0)) * sizeof(wchar_t);

        return scan_data(start, length, data, size);
    }

    std::vector<uintptr_t> scan_strings(HMODULE module, const std::string& str, bool zero_terminated) {
        KANANLIB_BENCH();

        if (str.empty()) {
            return {};
        }

        const auto data = (uint8_t*)str.c_str();
        const auto size = str.size() + (zero_terminated ? 1 : 0);
        const auto module_size = get_module_size(module).value_or(0);
        const auto end = (uintptr_t)module + module_size - (str.length() + 1);

        std::vector<uintptr_t> results{};

        for (auto i = scan_data(module, data, size).value_or(0); 
            i > 0 && i < end; 
            i = scan_data(i + 1, end - i, data, size).value_or(0)) 
        {
            results.push_back(i);
        }

        return results;
    }

    std::vector<uintptr_t> scan_strings(HMODULE module, const std::wstring& str, bool zero_terminated) {
        KANANLIB_BENCH();

        if (str.empty()) {
            return {};
        }

        const auto data = (uint8_t*)str.c_str();
        const auto size = (str.size() + (zero_terminated ? 1 : 0)) * sizeof(wchar_t);
        const auto module_size = get_module_size(module).value_or(0);
        const auto end = (uintptr_t)module + module_size - (str.length() + 1) * sizeof(wchar_t);

        std::vector<uintptr_t> results{};

        for (auto i = scan_data(module, data, size).value_or(0); 
            i > 0 && i < end; 
            i = scan_data(i + 1, end - i, data, size).value_or(0)) 
        {
            results.push_back(i);
        }

        return results;
    }

    std::vector<uintptr_t> scan_strings(uintptr_t start, size_t length, const std::string& str, bool zero_terminated) {
        KANANLIB_BENCH();

        if (str.empty()) {
            return {};
        }

        const auto data = (uint8_t*)str.c_str();
        const auto size = str.size() + (zero_terminated ? 1 : 0);
        const auto end = start + length - (str.length() + 1);

        std::vector<uintptr_t> results{};

        for (auto i = scan_data(start, length, data, size).value_or(0); 
            i > 0 && i < end; 
            i = scan_data(i + 1, end - i, data, size).value_or(0)) 
        {
            results.push_back(i);
        }

        return results;
    }

    std::vector<uintptr_t> scan_strings(uintptr_t start, size_t length, const std::wstring& str, bool zero_terminated) {
        KANANLIB_BENCH();

        if (str.empty()) {
            return {};
        }

        const auto data = (uint8_t*)str.c_str();
        const auto size = (str.size() + (zero_terminated ? 1 : 0)) * sizeof(wchar_t);
        const auto end = start + length - (str.length() + 1) * sizeof(wchar_t);

        std::vector<uintptr_t> results{};

        for (auto i = scan_data(start, length, data, size).value_or(0); 
            i > 0 && i < end; 
            i = scan_data(i + 1, end - i, data, size).value_or(0)) 
        {
            results.push_back(i);
        }

        return results;
    }

    std::vector<uintptr_t> scan_relative_references(uintptr_t start, size_t length, uintptr_t ptr, std::function<bool(uintptr_t)> filter) {
        KANANLIB_BENCH();

        std::vector<uintptr_t> results{};
        std::mutex mutex{};

        struct Segment {
            uintptr_t start;
            size_t length;
        };

        std::vector<Segment> segments{};

        const size_t max_conc = std::max(std::thread::hardware_concurrency(), 1u);
        const size_t base_segment_length = length / max_conc;
        
        const auto end = start + length;

        if (base_segment_length <= 4 || max_conc == 1) {
            //SPDLOG_INFO("Falling back to scalar scan because base segment length is less than 4 bytes");
            for (auto result = scan_relative_reference(start, length, ptr, filter); result.has_value(); result = scan_relative_reference(result.value() + 1, end - (result.value() + 1), ptr, filter)) {
                results.push_back(*result);
            }

            return results;
        }

        for (auto i = 0; i < max_conc; i++) {
            const auto segment_start = start + (i * base_segment_length);
            const auto segment_length = (i == max_conc - 1 ? end - segment_start : base_segment_length);

            // Used for the last segment to make sure we don't go out of bounds
            const auto corrected_length = (segment_start + segment_length) > (start + length) ? (start + length) - segment_start : segment_length;

            segments.push_back({ segment_start, corrected_length });

            //SPDLOG_INFO("Segment {}: start: {:x}, length: {}", i, segment_start, corrected_length);
        }

        concurrency::parallel_for((size_t)0, segments.size(), [&](size_t i) {
            const auto& segment = segments[i];

            const auto len = i < segments.size() - 1 ? segment.length + 4 : segment.length; // +4 because scan_relative_reference_scalar checks if i + 4 < end

            if (auto result = scan_relative_reference(segment.start, len, ptr, filter); result.has_value()) {
                std::scoped_lock lock{ mutex };
                results.push_back(*result);
            }
        });

        std::sort(results.begin(), results.end());

        return results;
    }

    std::vector<uintptr_t> scan_relative_references(HMODULE module, uintptr_t ptr, std::function<bool(uintptr_t)> filter) {
        KANANLIB_BENCH();

        const auto module_size = get_module_size(module).value_or(0);

        if (module_size == 0) {
            return {};
        }

        return scan_relative_references((uintptr_t)module, module_size - sizeof(void*), ptr, filter);
    }

    // original, really stinky implementation
    std::optional<uintptr_t> scan_relative_reference_scalar_byte_by_byte(uintptr_t start, size_t length, uintptr_t ptr, std::function<bool(uintptr_t)> filter) {
        KANANLIB_BENCH();

        const auto end = start + length;

        for (auto i = start; i + 4 < end; i += sizeof(uint8_t)) {
            if (calculate_absolute(i, 4) == ptr) {
                if (filter == nullptr || filter(i)) {
                    return i;
                }
            }
        }

        return std::nullopt;
    }

    // This is in a separate funciton because it doesn't require unwinding for the __try/__except block
    std::optional<uintptr_t> scan_relative_reference_scalar_impl(uintptr_t start, size_t length, uintptr_t ptr, std::function<bool(uintptr_t)>& filter) {
        const auto end = start + length;

        constexpr int32_t INT32_MASK = 0xFFFFFFFF;
        constexpr size_t BYTE_BIT_SIZE = 8;
        constexpr int32_t POST_IP_CONSTANT = 4;

        // We can't make use of the full 8 bytes because we need to slide past sizeof(void*) / 2, which will end up going
        // past the end of the block when reading an int32 out of it. So we'll iterate forward by 4 byte intervals.
        for (uintptr_t i = start; i + sizeof(uint64_t) < end; i += sizeof(uint32_t)) __try {
            // Reading in 8 byte chunks at a time is significantly faster than byte-by-byte (0.6-0.7GB/s vs ~2GB/s in my testing)
            uint64_t block = *(uint64_t*)i;
            
            // Unrolled version of the loop, much faster (+ 1GB/s throughput in my testing)
            const auto offset0 = (int32_t)((block >> (0 * BYTE_BIT_SIZE)) & INT32_MASK);
            const auto offset1 = (int32_t)((block >> (1 * BYTE_BIT_SIZE)) & INT32_MASK);
            const auto offset2 = (int32_t)((block >> (2 * BYTE_BIT_SIZE)) & INT32_MASK);
            const auto offset3 = (int32_t)((block >> (3 * BYTE_BIT_SIZE)) & INT32_MASK);

            const auto landing_address0 = i + 0 + POST_IP_CONSTANT + offset0;
            const auto landing_address1 = i + 1 + POST_IP_CONSTANT + offset1;
            const auto landing_address2 = i + 2 + POST_IP_CONSTANT + offset2;
            const auto landing_address3 = i + 3 + POST_IP_CONSTANT + offset3;

            if (landing_address0 == ptr) {
                if (filter == nullptr || filter(i)) {
                    return i;
                }
            }

            if (landing_address1 == ptr) {
                if (filter == nullptr || filter(i + 1)) {
                    return i + 1;
                }
            }

            if (landing_address2 == ptr) {
                if (filter == nullptr || filter(i + 2)) {
                    return i + 2;
                }
            }

            if (landing_address3 == ptr) {
                if (filter == nullptr || filter(i + 3)) {
                    return i + 3;
                }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            // We don't care about access violations, just move on
            continue;
        }

        __try {
            // Need to read off the remaining nibble at the end
            const auto new_length = std::min<size_t>(length, 4);
            if (new_length < 4) {
                return std::nullopt;
            }

            const auto new_start = end - new_length;
            const auto offset = *(int32_t*)new_start;
            const auto landing_address = new_start + POST_IP_CONSTANT + offset;

            if (landing_address == ptr) {
                if (filter == nullptr || filter(new_start)) {
                    return new_start;
                }
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            // We don't care about access violations, just move on
        }

        return std::nullopt;
    }

    std::optional<uintptr_t> scan_relative_reference_scalar(uintptr_t start, size_t length, uintptr_t ptr, std::function<bool(uintptr_t)> filter) {
        KANANLIB_BENCH();
        
        const auto result = scan_relative_reference_scalar_impl(start, length, ptr, filter);

        if (!result.has_value()) {
            return std::nullopt;
        }

        return result;
    }

    std::optional<uintptr_t> scan_relative_reference(HMODULE module, uintptr_t ptr, std::function<bool(uintptr_t)> filter) {
        KANANLIB_BENCH();

        const auto module_size = get_module_size(module).value_or(0);

        if (module_size == 0) {
            return std::nullopt;
        }

        return scan_relative_reference((uintptr_t)module, module_size - sizeof(void*), ptr, filter);
    }

    /*std::optional<uintptr_t> scan_relative_reference_impl(uintptr_t start, size_t length, uintptr_t ptr, std::function<bool(uintptr_t)> filter) {
        KANANLIB_BENCH();

        const auto valid_regions = get_valid_regions(start, length);

        if (valid_regions.empty()) {
            return std::nullopt;
        }

        const auto end = start + length;

        for (const auto& region : valid_regions) {
            const auto new_start = start > region.start ? start : region.start;
            const auto region_end = region.start + region.length;
            size_t new_length = region.length;

            if (region_end > end) {
                new_length = end - new_start;
            }

            if (auto result = scan_relative_reference_impl(new_start, new_length, ptr, filter); result.has_value()) {
                return result;
            }
        }

        return std::nullopt;
    }*/

    std::optional<uintptr_t> check_candidate(uintptr_t real_i, int mask, int start_j_initial, uintptr_t ptr, std::function<bool(uintptr_t)>& filter) {
        static constexpr int mask_0 = 0b1111;
        static constexpr int mask_1 = mask_0 << 4;
        static constexpr int mask_2 = mask_1 << 4;
        static constexpr int mask_3 = mask_2 << 4;
        static constexpr int mask_4 = mask_3 << 4;
        static constexpr int mask_5 = mask_4 << 4;
        static constexpr int mask_6 = mask_5 << 4;
        static constexpr int mask_7 = mask_6 << 4;
        static constexpr int masks[] = { mask_0, mask_1, mask_2, mask_3, mask_4, mask_5, mask_6, mask_7 };

        for (int j_counter = 0; j_counter < 8; j_counter++) {
            const auto start_j = start_j_initial + (j_counter > 3 ? 16 : 0);
            const auto j = j_counter > 3 ? j_counter - 4 : j_counter;
            if (mask & masks[j_counter]) {
                KANANLIB_LOG_PERF_SENSITIVE("Mask at offset {} ({} corrected) (real {:x}): {:x}", start_j + j, start_j + j + byte_index, real_i + j + start_j, (uint32_t)masks[j_counter]);
            }

            if (mask & masks[j_counter] && calculate_absolute(real_i + j + start_j, 4) == ptr) {
                const uintptr_t candidate_addr = real_i + j + start_j;

                if (filter == nullptr || filter(candidate_addr)) {
                    return candidate_addr;
                }
            }
        }

        return std::nullopt;
    };

    // This is in a separate funciton because it doesn't require unwinding for the __try/__except block
    #ifdef __clang__
    __attribute__((target("avx,avx2,bmi")))
    #endif
    std::optional<uintptr_t> scan_relative_reference_avx2(uintptr_t start, size_t length, uintptr_t ptr, std::function<bool(uintptr_t)>& filter) {
        // if ptr - start > 2GB, fallback to scalar
        const int64_t dist = (int64_t)((intptr_t)ptr - (intptr_t)start);
        if (dist > INT32_MAX || dist < INT32_MIN) {
            return scan_relative_reference_scalar_impl(start, length, ptr, filter);
        }
                
        const auto end = (start + length);

        constexpr auto SHIFT_SCALAR = 8;

        const __m256i post_ip_constant32 = _mm256_set1_epi32(4); // Usually true most of the time. *rel32 + &rel32 + 4 = target unless it's some weird instruction

        const __m256i shuffle_mask_lo = _mm256_set_epi8(
            22, 21, 20, 19,
            21, 20, 19, 18,
            20, 19, 18, 17,
            19, 18, 17, 16,
            6, 5, 4, 3,
            5, 4, 3, 2,
            4, 3, 2, 1,
            3, 2, 1, 0
        );

        const __m256i shuffle_mask_hi = _mm256_set_epi8(
            26, 25, 24, 23,
            25, 24, 23, 22,
            24, 23, 22, 21,
            23, 22, 21, 20,
            10, 9, 8, 7,
            9, 8, 7, 6,
            8, 7, 6, 5,
            7, 6, 5, 4
        );

        const __m256i addition_mask32 = _mm256_add_epi32(_mm256_set_epi32(19, 18, 17, 16, 3, 2, 1, 0), post_ip_constant32);
        
        size_t lookahead_size = (sizeof(__m256i) * 4) + (sizeof(__m256i) / 4); // 32 + 32 (unrolled loop) + 8 (for the sliding window when we do a 256 load on the next iteration)

        const int32_t rva_scalar = (int32_t)((intptr_t)ptr - (intptr_t)start);
        const __m256i rva = _mm256_set1_epi32(rva_scalar);

        // Add 8 bytes to the addresses at every interval
        // First iteration (lo) 0 - 4, 4 - 8
        // First iteration (hi) 16 - 20, 20 - 24
        // Second iteration (lo) 8 - 12, 12 - 16
        // Second iteration (hi) 24 - 28, 28 - 32
        // Basically a sliding window
        
        // So I know this macro is really ugly but it's a good way to unroll the loop and make it easier to read
        // Unrolling the loop gets us an extra 1-1.5GB/s throughput
        #define PROCESS_AVX2_BLOCK() \
        { \
            const uint32_t byte_index = (uint32_t)((mask_index >> 1) * sizeof(__m256i) + (mask_index & 1) * SHIFT_SCALAR); \
            const uintptr_t real_i = start_i + byte_index;\
            const __m256i addressesN = _mm256_add_epi32(addresses_base, _mm256_set1_epi32(byte_index)); \
\
            const __m256i data = _mm256_loadu_si256((__m256i*)(real_i));\
\
            const __m256i displacement_lo = _mm256_shuffle_epi8(data, shuffle_mask_lo);\
            const __m256i displacement_hi = _mm256_shuffle_epi8(data, shuffle_mask_hi);\
\
            /* Resolve the addresses */ \
            const __m256i vaddresses1 = _mm256_add_epi32(addressesN, displacement_lo);\
            const __m256i vaddresses2 = _mm256_add_epi32(_mm256_add_epi32(addressesN, post_ip_constant32), displacement_hi);\
\
            /* Compare addresses to the target */ \
            const __m256i cmp_result1 = _mm256_cmpeq_epi32(vaddresses1, rva);\
            const __m256i cmp_result2 = _mm256_cmpeq_epi32(vaddresses2, rva);\
\
            const uint32_t mm1 = (uint32_t)_mm256_movemask_epi8(cmp_result1);\
            const uint32_t mm2 = (uint32_t)_mm256_movemask_epi8(cmp_result2);\
            masks[mask_index++] = (uint64_t)mm1 | ((uint64_t)mm2 << 32);\
        }

        #define PROCESS_4_MASKS_FINAL(IN, mask) \
        {\
            constexpr size_t j = IN;\
            constexpr size_t maskindex = IN / 4;\
            while (mask != 0) {\
                /* Find index of first set bit*/\
                unsigned long index = _tzcnt_u32(mask);\
\
                /* Get the actual mask value */\
                const auto jindex = j + index;\
                const uint64_t actual_mask = masks[jindex];\
                const auto real_i = start_i + (sizeof(__m256i) * (jindex / 2)) + ((jindex % 2) * SHIFT_SCALAR);\
\
                const uint32_t mask2 = (uint32_t)(actual_mask >> 32);\
                if (mask2 != 0) {\
                    if (auto result = check_candidate(real_i, mask2, 4, ptr, filter); result.has_value()) {\
                        return result;\
                    }\
                }\
\
                const uint32_t mask1 = (uint32_t)actual_mask;\
                if (mask1 != 0) {\
                    if (auto result = check_candidate(real_i, mask1, 0, ptr, filter); result.has_value()) {\
                        return result;\
                    }\
                }\
\
                /* clear the lowest set bit */\
                mask = _blsr_u32(mask);\
            }\
        }

        #define PROCESS_AVX2_BLOCKS()\
            PROCESS_AVX2_BLOCK();\
            /* Second half, 8-12, 12 - 16, 24 - 28, 28 - 32 */ \
            PROCESS_AVX2_BLOCK();\
            i += sizeof(__m256i);
        
        constexpr size_t LOOKAHEAD_AMOUNT = 12;
        // Each 64-bit mask holds two 32-bit values
        constexpr size_t NUM_64BIT_MASKS = LOOKAHEAD_AMOUNT * 2;

        alignas(__m256i) uint64_t masks[NUM_64BIT_MASKS]{};

        if (length >= (sizeof(__m256i) * 12) + 8) {
            lookahead_size = (sizeof(__m256i) * LOOKAHEAD_AMOUNT) + 8;
            const __m256i zero = _mm256_setzero_si256();

            // Loop unrolled a bunch of times to increase throughput
            for (auto i = start; i + lookahead_size < end;) __try {
                const int32_t base = (int32_t)(i - start);
                const auto addresses_base = _mm256_add_epi32(_mm256_set1_epi32(base), addition_mask32);

                size_t mask_index{0};
                const size_t start_i = i;

                PROCESS_AVX2_BLOCKS();
                PROCESS_AVX2_BLOCKS();
                PROCESS_AVX2_BLOCKS();
                PROCESS_AVX2_BLOCKS();

                PROCESS_AVX2_BLOCKS();
                PROCESS_AVX2_BLOCKS();
                PROCESS_AVX2_BLOCKS();
                PROCESS_AVX2_BLOCKS();

                PROCESS_AVX2_BLOCKS();
                PROCESS_AVX2_BLOCKS();
                PROCESS_AVX2_BLOCKS();
                PROCESS_AVX2_BLOCKS();

                // Process 4 masks at a time using AVX2
                // Literally increases speed from 10GB/s to almost 20GB/s
                const auto load0 = _mm256_load_si256((__m256i*)&masks[0]);
                const auto load4 = _mm256_load_si256((__m256i*)&masks[4]);
                const auto load8 = _mm256_load_si256((__m256i*)&masks[8]);
                const auto load12 = _mm256_load_si256((__m256i*)&masks[12]);
                const auto load16 = _mm256_load_si256((__m256i*)&masks[16]);
                const auto load20 = _mm256_load_si256((__m256i*)&masks[20]);
            
                // The testz instruction is way faster than movemask + cmpeq when most masks are zero
                uint32_t mask0 = _mm256_testz_si256(load0, load0) == 0 ? ~_mm256_movemask_pd(_mm256_castsi256_pd(_mm256_cmpeq_epi64(load0, zero))) & 0b1111 : 0;
                uint32_t mask4 = _mm256_testz_si256(load4, load4) == 0 ? ~_mm256_movemask_pd(_mm256_castsi256_pd(_mm256_cmpeq_epi64(load4, zero))) & 0b1111 : 0;
                uint32_t mask8 = _mm256_testz_si256(load8, load8) == 0 ? ~_mm256_movemask_pd(_mm256_castsi256_pd(_mm256_cmpeq_epi64(load8, zero))) & 0b1111 : 0;
                uint32_t mask12 = _mm256_testz_si256(load12, load12) == 0 ? ~_mm256_movemask_pd(_mm256_castsi256_pd(_mm256_cmpeq_epi64(load12, zero))) & 0b1111 : 0;
                uint32_t mask16 = _mm256_testz_si256(load16, load16) == 0 ? ~_mm256_movemask_pd(_mm256_castsi256_pd(_mm256_cmpeq_epi64(load16, zero))) & 0b1111 : 0;
                uint32_t mask20 = _mm256_testz_si256(load20, load20) == 0 ? ~_mm256_movemask_pd(_mm256_castsi256_pd(_mm256_cmpeq_epi64(load20, zero))) & 0b1111 : 0;

                PROCESS_4_MASKS_FINAL(0, mask0);
                PROCESS_4_MASKS_FINAL(4, mask4);
                PROCESS_4_MASKS_FINAL(8, mask8);
                PROCESS_4_MASKS_FINAL(12, mask12);
                PROCESS_4_MASKS_FINAL(16, mask16);
                PROCESS_4_MASKS_FINAL(20, mask20);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                //SPDLOG_INFO("Exception caught at {:x}", i);
                i += sizeof(__m256i);
                continue;
            }
        } else {
            lookahead_size = (sizeof(__m256i)) + 8;
            const __m256i zero = _mm256_setzero_si256();

            for (auto i = start; i + lookahead_size < end;) __try {
                const int32_t base = (int32_t)(i - start);
                const auto addresses_base = _mm256_add_epi32(_mm256_set1_epi32(base), addition_mask32);

                size_t start_i = i;
                size_t mask_index{0};

                PROCESS_AVX2_BLOCKS();
                auto mask0 = ~_mm256_movemask_pd(_mm256_castsi256_pd(_mm256_cmpeq_epi64( _mm256_load_si256((__m256i*)&masks[0]), zero))) & 0b1111; \
                PROCESS_4_MASKS_FINAL(0, mask0);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                //SPDLOG_INFO("Exception caught at {:x}", i);
                i += sizeof(__m256i);
                continue;
            }
        }

        return std::nullopt;
    }

    std::optional<uintptr_t> scan_relative_reference(uintptr_t start, size_t length, uintptr_t ptr, std::function<bool(uintptr_t)> filter) {
        KANANLIB_BENCH();

        if (!kananlib::utility::thirdparty::InstructionSet::AVX2() || length <= sizeof(__m256i) * 4) {
            return scan_relative_reference_scalar(start, length, ptr, filter);
        }

        const auto result = scan_relative_reference_avx2(start, length, ptr, filter);

        if (!result.has_value()) {
            const auto new_length = std::min<size_t>(length, (sizeof(__m256i) * 12) + 8);
            const auto end = start + length;
            return scan_relative_reference_scalar(end - new_length, new_length, ptr, filter);
        }

        return result;
    }

    optional<uintptr_t> scan_reference(HMODULE module, uintptr_t ptr, bool relative) {
        KANANLIB_BENCH();

        if (!relative) {
            return scan_ptr(module, ptr);
        }

        const auto module_size = get_module_size(module).value_or(0);

        if (module_size == 0) {
            return {};
        }

        return scan_relative_reference((uintptr_t)module, module_size - sizeof(void*), ptr, nullptr);
    }

    optional<uintptr_t> scan_reference(uintptr_t start, size_t length, uintptr_t ptr, bool relative) {
        KANANLIB_BENCH();

        if (!relative) {
            return scan_ptr(start, length, ptr);
        }

        return scan_relative_reference(start, length, ptr, nullptr);
    }

    optional<uintptr_t> scan_relative_reference_strict(HMODULE module, uintptr_t ptr, const string& preceded_by) {
        KANANLIB_BENCH();

        if (preceded_by.empty()) {
            return {};
        }

        const auto module_size = get_module_size(module).value_or(0);

        // convert preceded_by (IDA style string) to bytes
        auto pat = utility::Pattern{ preceded_by };
        const auto pat_len = pat.pattern_len();

        return scan_relative_reference((uintptr_t)module, module_size - sizeof(void*), ptr, [&](uintptr_t candidate_addr) {
            if (pat.find(candidate_addr - pat_len, pat_len)) {
                return true;
            }

            return false;
        });
    }

    std::optional<uintptr_t> scan_relative_reference_strict(uintptr_t start, size_t length, uintptr_t ptr, const std::string& preceded_by) {
        KANANLIB_BENCH();

        if (preceded_by.empty()) {
            return {};
        }

        // convert preceded_by (IDA style string) to bytes
        auto pat = utility::Pattern{ preceded_by };
        const auto pat_len = pat.pattern_len();

        return scan_relative_reference((uintptr_t)start, length, ptr, [&](uintptr_t candidate_addr) {
            if (pat.find(candidate_addr - pat_len, pat_len)) {
                return true;
            }

            return false;
        });
    }

    std::optional<uintptr_t> scan_displacement_reference(HMODULE module, uintptr_t ptr, std::function<bool(uintptr_t)> filter) {
        KANANLIB_BENCH();

        const auto module_size = get_module_size(module);

        if (!module_size) {
            return {};
        }

        return scan_displacement_reference((uintptr_t)module, *module_size, ptr, filter);
    }

    std::vector<uintptr_t> scan_displacement_references(HMODULE module, uintptr_t ptr) {
        KANANLIB_BENCH();

        const auto module_size = get_module_size(module);

        if (!module_size) {
            return {};
        }

        return scan_displacement_references((uintptr_t)module, *module_size, ptr);
    }

    std::vector<uintptr_t> scan_displacement_references(uintptr_t start, size_t length, uintptr_t ptr) {
        KANANLIB_BENCH();

        std::vector<uintptr_t> results{};
        const auto end = (start + length) - sizeof(void*);

        /*for (auto i = (uintptr_t)start; i + 4 < end; i += sizeof(uint8_t)) {
            if (calculate_absolute(i, 4) == ptr) {
                const auto resolved = utility::resolve_instruction(i);

                if (resolved) {
                    const auto displacement = utility::resolve_displacement(resolved->addr);

                    if (displacement && *displacement == ptr) {
                        results.push_back(i);
                    }
                }
            }
        }*/

        for (auto ref = scan_displacement_reference(start, length, ptr); ref; ref = scan_displacement_reference(*ref + 4, end - (*ref + 4), ptr)) {
            results.push_back(*ref);
        }

        return results;
    }

    std::optional<uintptr_t> scan_displacement_reference(uintptr_t start, size_t length, uintptr_t ptr, std::function<bool(uintptr_t)> filter) {
        KANANLIB_BENCH();

        return scan_relative_reference(start, length, ptr, [ptr, filter](uintptr_t candidate_addr) {
            const auto resolved = utility::resolve_instruction(candidate_addr);

            if (resolved) {
                const auto displacement = utility::resolve_displacement(resolved->addr, &resolved->instrux);

                if (displacement && *displacement == ptr) {
                    if (filter == nullptr || filter(candidate_addr)) {
                        return true;
                    }
                }
            }

            return false;
        });
    }
    
    std::optional<uintptr_t> scan_opcode(uintptr_t ip, size_t num_instructions, uint8_t opcode) {
        KANANLIB_BENCH();

        for (size_t i = 0; i < num_instructions; ++i) {
            INSTRUX ix{};
            const auto status = NdDecodeEx(&ix, (uint8_t*)ip, 1000, ND_CODE_64, ND_DATA_64);

            if (!ND_SUCCESS(status)) {
                break;
            }

            if (ix.PrimaryOpCode == opcode) {
                return ip;
            }

            ip += ix.Length;
        }

        return std::nullopt;
    }

    std::optional<uintptr_t> scan_disasm(uintptr_t ip, size_t num_instructions, const string& pattern) {
        KANANLIB_BENCH();

        for (size_t i = 0; i < num_instructions; ++i) {
            INSTRUX ix{};
            const auto status = NdDecodeEx(&ix, (uint8_t*)ip, 1000, ND_CODE_64, ND_DATA_64);

            if (!ND_SUCCESS(status)) {
                break;
            }

            if (auto result = scan(ip, ix.Length, pattern); result && *result == ip) {
                return ip;
            }

            ip += ix.Length;
        }

        return std::nullopt;
    }

    std::optional<uintptr_t> scan_mnemonic(uintptr_t ip, size_t num_instructions, const string& mnemonic) {
        KANANLIB_BENCH();

        for (size_t i = 0; i < num_instructions; ++i) {
            INSTRUX ix{};
            const auto status = NdDecodeEx(&ix, (uint8_t*)ip, 1000, ND_CODE_64, ND_DATA_64);

            if (!ND_SUCCESS(status)) {
                break;
            }

            if (std::string_view{ix.Mnemonic} == mnemonic) {
                return ip;
            }

            ip += ix.Length;
        }

        return std::nullopt;
    }

    uint32_t get_insn_size(uintptr_t ip) {
        INSTRUX ix{};
        const auto status = NdDecodeEx(&ix, (uint8_t*)ip, 1000, ND_CODE_64, ND_DATA_64);

        if (!ND_SUCCESS(status)) {
            return 0;
        }

        return ix.Length;
    }

    uintptr_t calculate_absolute(uintptr_t address, uint8_t customOffset /*= 4*/) {
        auto offset = *(int32_t*)address;

        return address + customOffset + offset;
    }

    std::optional<INSTRUX> decode_one(uint8_t* ip, size_t max_size) {
        INSTRUX ix{};
        const auto status = NdDecodeEx(&ix, ip, max_size, ND_CODE_64, ND_DATA_64);

        if (!ND_SUCCESS(status)) {
            return {};
        }

        return ix;
    }

    void linear_decode(uint8_t* ip, size_t max_size, std::function<bool(ExhaustionContext&)> callback) {
        ExhaustionContext ctx{};
        ctx.branch_start = (uintptr_t)ip;

        for (size_t i = 0; i < max_size;) try {
            INSTRUX ix{};
            const auto status = NdDecodeEx(&ix, ip, 64, ND_CODE_64, ND_DATA_64);

            if (!ND_SUCCESS(status)) {
                break;
            }

            ctx.addr = (uintptr_t)ip;
            ctx.instrux = ix;

            if (!callback(ctx)) {
                break;
            }

            i += ix.Length;
            ip += ix.Length;
        } catch (...) {
            SPDLOG_ERROR("Exception caught during linear_decode at {:x}", (uintptr_t)ip);
            break;
        }
    }

    std::vector<BasicBlock> collect_basic_blocks(uintptr_t start, const BasicBlockCollectOptions& options) {
        std::vector<BasicBlock> blocks{};
        blocks.reserve(1024);
        uintptr_t previous_branch_start = start;

        BasicBlock last_block{};
        last_block.start = start;
        last_block.end = start;

        const auto should_copy_instructions = options.copy_instructions;

        utility::exhaustive_decode((uint8_t*)start, options.max_size, [&](utility::ExhaustionContext& ctx) {
            if (ctx.instrux.BranchInfo.IsBranch && ctx.instrux.Category != ND_CAT_CALL) {
                if (ctx.instrux.BranchInfo.IsConditional) {
                    if (ctx.resolved_target != 0) {
                        last_block.branches.push_back(ctx.resolved_target);
                    }

                    last_block.branches.push_back(ctx.addr + ctx.instrux.Length); // Fallthrough
                } else {
                    if (ctx.resolved_target != 0) {
                        last_block.branches.push_back(ctx.resolved_target);
                    }
                }
            }

            if (ctx.branch_start != previous_branch_start) {
                blocks.push_back(last_block);
                //SPDLOG_INFO("Found basic block from {:x} to {:x}", last_block.start, last_block.end);

                previous_branch_start = ctx.branch_start;
                last_block.instructions.clear();
                last_block.branches.clear();
                last_block.start = ctx.branch_start;
                last_block.end = ctx.branch_start + ctx.instrux.Length;
                last_block.instruction_count = 0;
            }

            last_block.end = ctx.addr + ctx.instrux.Length;
            ++last_block.instruction_count;
            
            if (should_copy_instructions) {
                last_block.instructions.push_back({ ctx.addr, ctx.instrux });
            }

            // Skip over calls
            if (ctx.instrux.Category == ND_CAT_CALL) {
                return utility::ExhaustionResult::STEP_OVER;
            }

            return ExhaustionResult::CONTINUE;
        });

        // Push the last block if it's not equal to the last one we pushed (can happen if the last instruction is a ret or int3, etc)
        if (blocks.empty() || blocks.back().start != last_block.start || blocks.back().end != last_block.end) {
            blocks.push_back(last_block);
            //SPDLOG_INFO("Found basic block from {:x} to {:x}", last_block.start, last_block.end);
        }

        if (options.sort || options.merge_call_blocks) {
            std::sort(blocks.begin(), blocks.end(), [](const BasicBlock& a, const BasicBlock& b) {
                return a.start < b.start;
            });

            // merge blocks together that are separated by call instructions
            // just a side effect of how exhaustive_decode works
            if (options.merge_call_blocks) {
                for (auto it = blocks.begin(); it != blocks.end(); ++it) {
                    if (!it->instructions.empty() && it->instructions.back().instrux.Category == ND_CAT_CALL) {
                        auto next = std::next(it);
                        if (next != blocks.end() && !next->instructions.empty() && next->instructions.front().addr == it->end) {
                            it->end = next->end;
                            it->branches = next->branches;
                            it->instructions.insert(it->instructions.end(), next->instructions.begin(), next->instructions.end());
                            it->instruction_count += next->instruction_count;
                            blocks.erase(next);
                        }
                    }
                }
            }
        }

        return blocks;
    }

    std::vector<BasicBlock>::const_iterator get_highest_contiguous_block(const std::vector<BasicBlock>& blocks) {
        if (blocks.empty()) {
            return blocks.end();
        }

        const auto start_absolute = blocks.front().start;
        uintptr_t highest_block_end = blocks.begin()->end;
        auto highest_block = blocks.begin();

        for (size_t i = 1; i < blocks.size(); ++i) {
            const auto& block = blocks[i];

            if (block.start != highest_block_end) {
                //SPDLOG_INFO("{} contiguous blocks found for function starting at {:x}", i, start_absolute);
                break;
            }

            highest_block_end = block.end;
            highest_block = blocks.begin() + i;
        }

        if (highest_block_end > start_absolute) {
            uintptr_t old_block_end = highest_block_end;
            size_t num_decoded = 0;
            // Check if we can linearly connect the "highest" block we found to the
            // highest block in the actual array of blocks.
            // this should fix issues where we have dead instructions/padding somewhere
            // the CFG does not account for, but we can still linearly decode through it.
            if (highest_block_end < blocks.back().end) {
                INSTRUX ix{};
                const auto status = NdDecodeEx(&ix, (uint8_t*)highest_block_end, 16, ND_CODE_64, ND_DATA_64);

                if (ND_SUCCESS(status)) {
                    // If the disassembly is successful, we can assume it's a valid instruction
                    // and continue sliding the end forward until we hit an invalid instruction
                    while (true && num_decoded < 16) {
                        const auto next_status = NdDecodeEx(&ix, (uint8_t*)highest_block_end + ix.Length, 16, ND_CODE_64, ND_DATA_64);

                        if (!ND_SUCCESS(next_status)) {
                            break;
                        }

                        highest_block_end += ix.Length;
                        ++num_decoded;

                        // If decoded instruction is:
                        // ret, int3, jmp, or similar, we can assume it's the end of the function and stop sliding
                        if (ix.Instruction == ND_INS_RETN || ix.Instruction == ND_INS_INT3 || ix.BranchInfo.IsBranch) {
                            break;
                        }

                        // If instruction pointer lands on:
                        // Any known function start,
                        // a range within our known basic blocks
                        // then we can assume it's the end of the function and stop sliding
                        //if (function_starts_set.contains((uint32_t)(highest_block_end - module))) {
                            //break;
                        //}

                        auto it = std::find_if(blocks.begin(), blocks.end(), [highest_block_end](const BasicBlock& b) {
                            return highest_block_end >= b.start && highest_block_end < b.end;
                        });

                        if (it != blocks.end()) {
                            highest_block_end = it->end;
                            break;
                        }
                    }
                }
            }

            //if (old_block_end != highest_block_end) {
                //SPDLOG_INFO("Slid function end from {:x} to {:x} for function starting at {:x} after decoding {} instructions", old_block_end, highest_block_end, start_absolute, num_decoded);
            //}
        }
        
        return highest_block;
    }
    
    std::vector<LinearBlock> collect_linear_blocks(uintptr_t fn_start, uintptr_t fn_end) {
        std::vector<LinearBlock> blocks;
        if (fn_start >= fn_end) {
            return blocks;
        }

        // gather all split points (block starts) first, then we will build blocks in pass 2
        std::unordered_set<uintptr_t> split_set;
        split_set.reserve(64);

        split_set.insert(fn_start);
        split_set.insert(fn_end);

        utility::linear_decode((uint8_t*)fn_start, fn_end - fn_start,
            [&](const utility::ExhaustionContext& ctx)
        {
            const auto ip   = ctx.addr;
            const auto& ix  = ctx.instrux;
            const auto next = ip + ix.Length;

            if (ip >= fn_end) {
                return false;
            }

            if (ix.BranchInfo.IsBranch) {
                // fallthrough always starts new block
                if (next >= fn_start && next <= fn_end) {
                    split_set.insert(next);
                }

                // direct branch target
                if (!ix.BranchInfo.IsIndirect) {
                    if (auto dest = utility::resolve_displacement(ip, &ix); dest) {
                        if (*dest >= fn_start && *dest <= fn_end) {
                            split_set.insert(*dest);
                        }
                    }
                }
            }

            // terminators also split
            if (ix.Instruction == ND_INS_RETN || ix.Instruction == ND_INS_INT3) {
                if (next >= fn_start && next <= fn_end) {
                    split_set.insert(next);
                }
            }

            return true;
        });

        // sort split points
        std::vector<uintptr_t> splits(split_set.begin(), split_set.end());
        std::sort(splits.begin(), splits.end());

        if (splits.size() < 2) {
            return blocks;
        }

        blocks.reserve(splits.size());

        // pass 2, build blocks from split points
        for (size_t i = 0; i + 1 < splits.size(); ++i) {
            uintptr_t start = splits[i];
            uintptr_t end   = splits[i + 1];

            if (start >= fn_end) {
                break;
            }

            LinearBlock bb{};
            bb.start = start;
            bb.end   = start;

            utility::linear_decode((uint8_t*)start, end - start,
                [&](const utility::ExhaustionContext& ctx)
            {
                const auto ip   = ctx.addr;
                const auto& ix  = ctx.instrux;
                const auto next = ip + ix.Length;

                if (ip >= end) {
                    return false;
                }

                // record branches
                if (ix.BranchInfo.IsBranch) {
                    if (!ix.BranchInfo.IsIndirect) {
                        if (auto dest = utility::resolve_displacement(ip, &ix); dest) {
                            bb.branches.push_back(*dest);
                        }
                    }

                    if (ix.BranchInfo.IsConditional) {
                        bb.branches.push_back(next);
                    }
                }

                bb.end = next;

                if (ix.Category == ND_CAT_CALL) {
                    return true;
                }

                return true;
            });

            blocks.push_back(bb);
        }

        return blocks;
    }

    static std::shared_mutex bucket_mtx{};
    static std::unordered_map<uintptr_t, std::vector<Bucket>> module_buckets{};

    template<typename T, typename GetBegin, typename GetEnd>
    void fill_generic(
        uintptr_t module,
        size_t module_size,
        const std::vector<T>& sorted_entries,
        std::vector<Bucket>& buckets,
        GetBegin get_begin,
        GetEnd get_end
    )
    {
        constexpr size_t NUM_BUCKETS = 2048;
        size_t total_added_entries = 0;

        for (auto i = 0; i < std::max<size_t>(sorted_entries.size() / NUM_BUCKETS, 1); ++i) {
            Bucket bucket{};
            const auto bucket_index = i * NUM_BUCKETS;
            bucket.start_range = get_begin(sorted_entries[bucket_index]);
            const auto next_index = std::min<size_t>((i + 1) * NUM_BUCKETS, sorted_entries.size());

            uint32_t highest_end = 0;
            for (size_t j = bucket_index; j < next_index; ++j) {
                bucket.end_range = std::max<uint32_t>(highest_end, get_end(sorted_entries[j]));
                bucket.entries.emplace_back(sorted_entries[j]);
                highest_end = bucket.end_range;

                ++total_added_entries;
            }

            buckets.push_back(bucket);
        }

        // Can happen, but can also happen if the number of entries is less than NUM_BUCKETS
        if (total_added_entries < sorted_entries.size()) {
            if (buckets.empty()) {
                SPDLOG_INFO("Adding all entries to one bucket for module {:x}", module);

                buckets.push_back(Bucket{
                    .start_range = 0,
                    .end_range = (uint32_t)module_size,
                    .entries = {}
                });
            } else {
                buckets.push_back(Bucket{
                    .start_range = get_begin(sorted_entries[total_added_entries]),
                    .end_range = (uint32_t)module_size,
                    .entries = {}
                });
            }

            SPDLOG_INFO("Adding remaining {} entries to last bucket for module {:x}", sorted_entries.size() - total_added_entries, module);
            // Add the remaining entries to the last bucket
            auto& last_bucket = buckets.back();

            for (size_t i = total_added_entries; i < sorted_entries.size(); ++i) {
                last_bucket.entries.push_back(sorted_entries[i]);
            }
        }

        // Re-sort the buckets because of the last minute additions
        std::sort(buckets.begin(), buckets.end(), [](const Bucket& a, const Bucket& b) {
            return a.start_range < b.start_range;
        });
    }

    void populate_function_buckets_heuristic(uintptr_t module) {
        KANANLIB_BENCH();

        const auto module_size = utility::get_module_size((HMODULE)module).value_or(0xDEADBEEF);
        const auto module_end = module + module_size;

        constexpr size_t NUM_BUCKETS = 2048;
        bool needs_insert = false;

        {
            std::shared_lock _{bucket_mtx};

            if (auto it = module_buckets.find(module); it != module_buckets.end()) {
                if (it->second.empty()) {
                    needs_insert = true;
                }
            } else {
                needs_insert = true;
            }
        }

        if (!needs_insert) {
            return;
        }

        SPDLOG_INFO("Populating function buckets heuristically for module {:x}", module);

        // VirtualQuery and look for all executable regions
        MEMORY_BASIC_INFORMATION mbi{};
        std::vector<MEMORY_BASIC_INFORMATION> exec_regions{};
        std::vector<MEMORY_BASIC_INFORMATION> readable_regions{};

        for (auto addr = module; addr < module_end; ) {
            if (VirtualQuery((LPCVOID)addr, &mbi, sizeof(mbi)) == 0) {
                break;
            }

            if ((mbi.Protect & PAGE_EXECUTE) || (mbi.Protect & PAGE_EXECUTE_READ) || (mbi.Protect & PAGE_EXECUTE_READWRITE) || (mbi.Protect & PAGE_EXECUTE_WRITECOPY)) {
                exec_regions.push_back(mbi);
            }

            if ((mbi.Protect & PAGE_READONLY) || (mbi.Protect & PAGE_READWRITE) || (mbi.Protect & PAGE_WRITECOPY) || (mbi.Protect & PAGE_EXECUTE_READ) || (mbi.Protect & PAGE_EXECUTE_READWRITE) || (mbi.Protect & PAGE_EXECUTE_WRITECOPY)) {
                readable_regions.push_back(mbi);
            }

            addr += mbi.RegionSize;
        }

        SPDLOG_INFO("Found {} executable regions in module {:x}", exec_regions.size(), module);
        SPDLOG_INFO("Found {} readable regions in module {:x}", readable_regions.size(), module);

        // Continuously use scan_data to find all E8 xx xx xx xx patterns in the executable regions
        std::vector<uint32_t> function_starts{};
        for (const auto& region : exec_regions) {
            const auto region_start = (uintptr_t)region.BaseAddress;
            const auto region_size = region.RegionSize;
            const auto region_end = region_start + region_size;

            for (auto addr = region_start; addr + 5 < region_end; ) {
                const auto result = scan_data(addr, region_end - addr - 5, (uint8_t*)"\xE8", 1);

                if (!result.has_value()) {
                    break;
                }

                const auto call_target = utility::calculate_absolute(*result + 1);

                if (call_target >= module && call_target < module_end) {
                    // now also check if it's within the executable regions
                    auto it = std::find_if(exec_regions.begin(), exec_regions.end(), [call_target](const MEMORY_BASIC_INFORMATION& r) {
                        const auto r_start = (uintptr_t)r.BaseAddress;
                        const auto r_end = r_start + r.RegionSize;

                        return call_target >= r_start && call_target < r_end;
                    });

                    if (it != exec_regions.end()) {
                        function_starts.push_back((uint32_t)(call_target - module));
                    }
                }

                addr = *result + 5;
            }
        }

        SPDLOG_INFO("Found {} potential function starts in module {:x}", function_starts.size(), module);

        std::sort(function_starts.begin(), function_starts.end());
        function_starts.erase(std::unique(function_starts.begin(), function_starts.end()), function_starts.end());
        SPDLOG_INFO("Filtered down to {} unique function starts in module {:x}", function_starts.size(), module);

        // Look for functions that start with E9, and sled into other E9s.
        // these are functions that don't always have references but can be considered functions.
        std::unordered_set<uint32_t> additional_function_starts{};
        std::unordered_set<uint32_t> visited_sleds{};

        for (const auto& start : function_starts) {
            const auto absolute = module + start;

            if (*(uint8_t*)absolute != 0xE9) {
                continue;
            }

            uint32_t slide_count = 0;
            auto sled_addr = absolute;

            if (visited_sleds.contains(sled_addr - module)) {
                continue;
            }

            while (*(uint8_t*)sled_addr == 0xE9) {
                const auto dest = utility::calculate_absolute(sled_addr + 1);

                if (dest < module || dest >= module_end) {
                    break;
                }

                const auto dest_rva = (uint32_t)(dest - module);

                if (!additional_function_starts.contains(dest_rva) || !additional_function_starts.contains((uint32_t)(sled_addr - module)))
                {
                    if (std::binary_search(function_starts.begin(), function_starts.end(), dest_rva) &&
                        !additional_function_starts.contains((uint32_t)(sled_addr - module)))
                    {
                        additional_function_starts.insert(dest_rva);
                        additional_function_starts.insert(sled_addr - module);
                    }

                    ++slide_count;
                }

                visited_sleds.insert(sled_addr - module);
                sled_addr += 5;
            }
        }

        SPDLOG_INFO("Found {} additional function starts via sledding in module {:x}", additional_function_starts.size(), module);

        // Filter out which ones already belong to function_starts
        // and log how many actually got added
        size_t added_count = 0;
        for (const auto& add_start : additional_function_starts) {
            if (std::find(function_starts.begin(), function_starts.end(), add_start) == function_starts.end()) {
                function_starts.push_back(add_start);
                ++added_count;
            }
        }

        SPDLOG_INFO("Added {} new function starts after filtering in module {:x}", added_count, module);
        SPDLOG_INFO("Total function starts before disassembly check: {}", function_starts.size());

        std::sort(function_starts.begin(), function_starts.end());
        function_starts.erase(std::unique(function_starts.begin(), function_starts.end()), function_starts.end());

        // Quickly disassemble to make sure they look like function starts
        // Remove any that don't
        std::erase_if(function_starts, [module](uint32_t rva) {
            const auto absolute = module + rva;

            INSTRUX ix{};
            const auto status = NdDecodeEx(&ix, (uint8_t*)absolute, 16, ND_CODE_64, ND_DATA_64);

            if (!ND_SUCCESS(status)) {
                return true;
            }

            return false;
        });

        SPDLOG_INFO("Filtered down to {} function starts after disassembly check in module {:x}", function_starts.size(), module);

        // Remove any function starts that land on int3, 0x00, or similar
        std::erase_if(function_starts, [module](uint32_t rva) {
            const auto absolute = module + rva;

            if (*(uint8_t*)absolute == 0xCC || *(uint8_t*)absolute == 0x00) {
                return true;
            }

            if (*(uint8_t*)absolute == 0xFF && (*(uint8_t*)(absolute + 1) == 0xFF)) {
                return true;
            }

            return false;
        });

        std::unordered_set<uint32_t> function_starts_set(function_starts.begin(), function_starts.end());

        SPDLOG_INFO("Filtered down to {} function starts after int3 check in module {:x}", function_starts.size(), module);

        std::unordered_set<uint32_t> function_starts_set_final(function_starts.begin(), function_starts.end());

        const auto function_starts_before = function_starts.size();

        // Walk readable regions and look for valid function pointers that aren't in our current list, and add them if they look like they could be valid function pointers (point to executable section, etc)
        for (const auto& region : readable_regions) {
            const auto region_start = (uintptr_t)region.BaseAddress;
            const auto region_size = region.RegionSize;
            const auto region_end = region_start + region_size;

            for (auto addr = region_start; addr + 8 < region_end; addr += 8) {
                const auto potential_fn_ptr = *(uint64_t*)addr;

                // make sure aligned on sizeof(void*)
                if ((addr & (sizeof(void*) - 1)) != 0) {
                    continue;
                }

                if (potential_fn_ptr >= module && potential_fn_ptr < module_end) {
                    if (function_starts_set_final.contains((uint32_t)(potential_fn_ptr - module))) {
                        continue;
                    }

                    // Check if it points to an executable region
                    auto it = std::find_if(exec_regions.begin(), exec_regions.end(), [potential_fn_ptr](const MEMORY_BASIC_INFORMATION& r) {
                        const auto r_start = (uintptr_t)r.BaseAddress;
                        const auto r_end = r_start + r.RegionSize;

                        return potential_fn_ptr >= r_start && potential_fn_ptr < r_end;
                    });

                    if (it != exec_regions.end()) {
                        function_starts.push_back((uint32_t)(potential_fn_ptr - module));
                    }
                }
            }
        }

        SPDLOG_INFO("Added {} new function starts from pointer scan in module {:x}", function_starts.size() - function_starts_before, module);
        std::sort(function_starts.begin(), function_starts.end());
        function_starts.erase(std::unique(function_starts.begin(), function_starts.end()), function_starts.end());

        // Sort function starts by gap to next function (proxy for complexity)
        std::vector<size_t> indices(function_starts.size());
        std::iota(indices.begin(), indices.end(), 0);
        std::sort(indices.begin(), indices.end(), [&](size_t a, size_t b) {
            auto gap_a = (a + 1 < function_starts.size()) 
                ? function_starts[a + 1] - function_starts[a] : 0x10000;
            auto gap_b = (b + 1 < function_starts.size()) 
                ? function_starts[b + 1] - function_starts[b] : 0x10000;
            return gap_a > gap_b; // biggest first
        });

        struct BlacklistEntry {
            std::atomic<uintptr_t> start{0};
            std::atomic<uintptr_t> end{0};
        };
        std::vector<BlacklistEntry> blacklisted(function_starts.size());

        std::vector<uint32_t> function_ends(function_starts.size(), 0); // Heuristically determined via basic block
        std::vector<uint8_t> functions_populated(function_starts.size(), 0);
        //for (const auto& start_rva : function_starts) {
        concurrency::parallel_for(size_t(0), indices.size(), [&](size_t j) {
            const auto i = indices[j];
            const auto& start_rva = function_starts[i];
            const auto start_absolute = module + start_rva;

            auto in_blacklisted_region = [&](uintptr_t addr) {
                for (const auto& bl : blacklisted) {
                    auto s = bl.start.load(std::memory_order_relaxed);
                    if (s == 0) continue;
                    if (addr >= s && addr < bl.end.load(std::memory_order_relaxed)) return true;
                }
                return false;
            };

            /*if (in_blacklisted_region(start_absolute)) {
                SPDLOG_WARN("Skipping function at {:x} because it is in a blacklisted region", start_absolute);
                function_ends[i] = start_rva + utility::get_insn_size(start_absolute); // fallback
                functions_populated[i] = 1;
                return;
            }*/

            auto t0 = std::chrono::high_resolution_clock::now();

            const auto blocks = utility::collect_basic_blocks(start_absolute, BasicBlockCollectOptions{ 
                .max_size = 8192, .sort = true, .merge_call_blocks = true, .copy_instructions = false
            });

            functions_populated[i] = 1;

            auto t1 = std::chrono::high_resolution_clock::now();
            auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
            
            if (ms > 1000) {
                const auto populated_pct = std::count(functions_populated.begin(), functions_populated.end(), 1) * 100 / functions_populated.size();
                SPDLOG_WARN("collect_basic_blocks took {}ms for function at {:x} (progress: {}%)", ms, start_absolute, populated_pct);

                if (ms >= 2000) {
                    SPDLOG_WARN("Function at {:x} is taking a very long time to analyze, blacklisting the region {:x}-{:x}", start_absolute, start_absolute, start_absolute + 8192);
                    blacklisted[i].start.store(start_absolute, std::memory_order_relaxed);
                    blacklisted[i].end.store(start_absolute + 8192, std::memory_order_relaxed);
                    function_ends[i] = start_rva + utility::get_insn_size(start_absolute); // fallback
                    return;
                }
            }

            if (blocks.empty()) {
                function_ends[i] = start_rva + utility::get_insn_size(start_absolute); // fallback
                return;
            }

            // Find the highest basic block that is > than the start
            // and is also reachable contiguously (cur.start == prev.end)
            uintptr_t highest_block_end = blocks.begin()->end;

            for (size_t i = 1; i < blocks.size(); ++i) {
                const auto& block = blocks[i];

                if (block.start != highest_block_end) {
                    //SPDLOG_INFO("{} contiguous blocks found for function starting at {:x}", i, start_absolute);
                    break;
                }

                highest_block_end = block.end;
            }

            if (highest_block_end > start_absolute) {
                uintptr_t old_block_end = highest_block_end;
                size_t num_decoded = 0;
                // Check if we can linearly connect the "highest" block we found to the
                // highest block in the actual array of blocks.
                // this should fix issues where we have dead instructions/padding somewhere
                // the CFG does not account for, but we can still linearly decode through it.
                if (highest_block_end < blocks.back().end) {
                    INSTRUX ix{};
                    const auto status = NdDecodeEx(&ix, (uint8_t*)highest_block_end, 16, ND_CODE_64, ND_DATA_64);

                    if (ND_SUCCESS(status)) {
                        // If the disassembly is successful, we can assume it's a valid instruction
                        // and continue sliding the end forward until we hit an invalid instruction
                        while (true && num_decoded < 16) {
                            const auto next_status = NdDecodeEx(&ix, (uint8_t*)highest_block_end + ix.Length, 16, ND_CODE_64, ND_DATA_64);

                            if (!ND_SUCCESS(next_status)) {
                                break;
                            }

                            highest_block_end += ix.Length;
                            ++num_decoded;

                            // If decoded instruction is:
                            // ret, int3, jmp, or similar, we can assume it's the end of the function and stop sliding
                            if (ix.Instruction == ND_INS_RETN || ix.Instruction == ND_INS_INT3 || ix.BranchInfo.IsBranch) {
                                break;
                            }

                            // If instruction pointer lands on:
                            // Any known function start,
                            // a range within our known basic blocks
                            // then we can assume it's the end of the function and stop sliding
                            if (function_starts_set.contains((uint32_t)(highest_block_end - module))) {
                                break;
                            }

                            auto it = std::find_if(blocks.begin(), blocks.end(), [highest_block_end](const BasicBlock& b) {
                                return highest_block_end >= b.start && highest_block_end < b.end;
                            });

                            if (it != blocks.end()) {
                                highest_block_end = it->end;
                                break;
                            }
                        }
                    }
                }

                //if (old_block_end != highest_block_end) {
                    //SPDLOG_INFO("Slid function end from {:x} to {:x} for function starting at {:x} after decoding {} instructions", old_block_end, highest_block_end, start_absolute, num_decoded);
                //}

                function_ends[i] = highest_block_end - module;
            } else {
                function_ends[i] = start_rva + utility::get_insn_size(start_absolute); // fallback
            }
        });

        // log all RVAs
        /*for (const auto& start : function_starts) {
            const auto rva = start;
            SPDLOG_INFO("Function start RVA: {:x}->{:X} (size {:X})", rva, rva + function_ends[&start - &function_starts[0]] - rva, function_ends[&start - &function_starts[0]] - rva);
        }*/

        /*for (size_t i = 0; i < function_starts.size(); ++i) {
            const auto rva = function_starts[i];
            SPDLOG_INFO("Function start RVA: {:x}->{:X} (size {:X})", rva, function_ends[i], function_ends[i] - rva);
        }*/

        std::unique_lock _{bucket_mtx};
        auto& buckets = module_buckets[module];
        
        std::vector<Bucket::IMAGE_RUNTIME_FUNCTION_ENTRY_KANANLIB> entries{};
        for (size_t i = 0; i < function_starts.size(); ++i) {
            Bucket::IMAGE_RUNTIME_FUNCTION_ENTRY_KANANLIB entry{};
            entry.BeginAddress = function_starts[i];
            entry.EndAddress = function_ends[i];
            entries.push_back(entry);
        }

        fill_generic<Bucket::IMAGE_RUNTIME_FUNCTION_ENTRY_KANANLIB>(module, module_size, entries, buckets,
            [](const Bucket::IMAGE_RUNTIME_FUNCTION_ENTRY_KANANLIB& entry) {
                return entry.BeginAddress;
            },
            [](const Bucket::IMAGE_RUNTIME_FUNCTION_ENTRY_KANANLIB& entry) {
                return entry.EndAddress;
            }
        );

        return;
    }

    void populate_function_buckets(uintptr_t module) {
        KANANLIB_BENCH();

#ifdef _M_X86
        return populate_function_buckets_heuristic(module);
#else

        const auto module_size = utility::get_module_size((HMODULE)module).value_or(0xDEADBEEF);
        const auto module_end = module + module_size;

        bool needs_insert = false;

        {
            std::shared_lock _{bucket_mtx};

            if (auto it = module_buckets.find(module); it != module_buckets.end()) {
                if (it->second.empty()) {
                    needs_insert = true;
                }
            } else {
                needs_insert = true;
            }
        }

        if (!needs_insert) {
            return;
        }

        // This function abuses the fact that most non-obfuscated binaries have
        // an exception directory containing a list of function start and end addresses.
        // Get the PE header, and then the exception directory
        const auto dos_header = (PIMAGE_DOS_HEADER)module;
        const auto nt_header = (PIMAGE_NT_HEADERS)((uintptr_t)dos_header + dos_header->e_lfanew);
        const auto exception_directory = (PIMAGE_DATA_DIRECTORY)&nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];

        // Get the exception directory RVA and size
        const auto exception_directory_rva = exception_directory->VirtualAddress;
        const auto exception_directory_size = exception_directory->Size;

        // Get the exception directory
        const auto exception_directory_ptr = (PIMAGE_RUNTIME_FUNCTION_ENTRY)((uintptr_t)dos_header + exception_directory_rva);

        // Get the number of entries in the exception directory
        const auto exception_directory_entries = exception_directory_size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);

        std::unique_lock _{bucket_mtx};
        auto& buckets = module_buckets[module];

        if (buckets.empty() && exception_directory_entries > 0) {
            SPDLOG_INFO("Adding {} entries for module {:x}", exception_directory_entries, module);

            std::vector<PIMAGE_RUNTIME_FUNCTION_ENTRY> sorted_entries{};
            sorted_entries.resize(exception_directory_entries);

            for (size_t i = 0; i < exception_directory_entries; ++i) {
                sorted_entries[i] = &exception_directory_ptr[i];
            }

            std::sort(sorted_entries.begin(), sorted_entries.end(), [](const PIMAGE_RUNTIME_FUNCTION_ENTRY a, const PIMAGE_RUNTIME_FUNCTION_ENTRY b) {
                return a->BeginAddress < b->BeginAddress;
            });

            std::erase_if(sorted_entries, [module, module_end](const PIMAGE_RUNTIME_FUNCTION_ENTRY entry) {
                return module + entry->EndAddress > module_end || module + entry->BeginAddress > module_end || entry->EndAddress < entry->BeginAddress;
            });

            SPDLOG_INFO("Filtered and sorted entries down to {} for module {:x}", sorted_entries.size(), module);

            fill_generic<PIMAGE_RUNTIME_FUNCTION_ENTRY>(module, module_size, sorted_entries, buckets,
                [](const PIMAGE_RUNTIME_FUNCTION_ENTRY entry) {
                    return entry->BeginAddress;
                },
                [](const PIMAGE_RUNTIME_FUNCTION_ENTRY entry) {
                    return entry->EndAddress;
                }
            );
        }
#endif
    }

    std::optional<Bucket::IMAGE_RUNTIME_FUNCTION_ENTRY_KANANLIB> find_function_entry(uintptr_t middle) {
        KANANLIB_BENCH();

        const auto module = (uintptr_t)utility::get_module_within(middle).value_or(nullptr);

        if (module == 0 || middle == 0) {
            return {};
        }

        populate_function_buckets(module);

        const auto middle_rva = middle - module;

        // For the case where there's weird obfuscation or something
        std::vector<Bucket*> candidates{};

        {
            std::shared_lock _{bucket_mtx};

            for (auto& bucket : module_buckets[module]) {
                // Buckets are sorted so we can break early
                if (bucket.start_range > middle_rva) {
                    break;
                }

                if (bucket.start_range <= middle_rva && middle_rva <= bucket.end_range) {
                    candidates.push_back(&bucket);
                }
            }
        }

        if (candidates.empty()) {
            SPDLOG_ERROR("Failed to find candidates for function entry");
            return std::nullopt;
        }

        if (candidates.size() > 1) {
            SPDLOG_DEBUG("Found {} candidates for function entry", candidates.size());
        }

        const Bucket::IMAGE_RUNTIME_FUNCTION_ENTRY_KANANLIB* last = nullptr;
        uint32_t nearest_distance = 0xFFFFFFFF;

        for (auto& bucket : candidates) {
            if (nearest_distance == 0) {
                break;
            }

            for (const auto& entry : bucket->entries) {
                if (nearest_distance == 0) {
                    break;
                }

                if (entry.BeginAddress == middle_rva) {
                    last = &entry;
                    nearest_distance = 0;
                    break;
                }

                // Check if the middle address is within the range of the function
                if (entry.BeginAddress <= middle_rva && middle_rva <= entry.EndAddress) {
                    const auto distance = middle_rva - entry.BeginAddress;

                    if (distance < nearest_distance) {
                        nearest_distance = distance;

                        // Return the start address of the function
                        last = &entry;
                    }
                }
            }
        }

        return last != nullptr ? std::optional<Bucket::IMAGE_RUNTIME_FUNCTION_ENTRY_KANANLIB>{*last} : std::nullopt;
    }

    std::vector<FunctionBounds> find_all_function_bounds(HMODULE module) {
        populate_function_buckets((uintptr_t)module);
        
        std::vector<FunctionBounds> functions{};

        const auto module_base = (uintptr_t)module;
        const auto module_size = utility::get_module_size(module).value_or(0);

        std::shared_lock _{bucket_mtx};

        if (auto it = module_buckets.find(module_base); it != module_buckets.end()) {
            for (const auto& bucket : it->second) {
                for (const auto& entry : bucket.entries) {
                    functions.push_back(FunctionBounds{
                        .start = module_base + entry.BeginAddress,
                        .end = module_base + entry.EndAddress
                    });
                }
            }
        }

        return functions;
    }

    std::optional<FunctionBounds> determine_function_bounds(uintptr_t addr) {
        const auto blocks = utility::collect_basic_blocks(addr, BasicBlockCollectOptions{ .max_size = 8192, .sort = true, .merge_call_blocks = true, .copy_instructions = false });

        if (blocks.empty()) {
            return std::nullopt;
        }

        auto it = get_highest_contiguous_block(blocks);

        if (it == blocks.end()) {
            return std::nullopt;
        }

        return FunctionBounds{
            .start = blocks.front().start,
            .end = it->end,
            .instruction_count = 1
        };
    }

    std::optional<uintptr_t> find_function_start(uintptr_t middle) {
        const auto entry = find_function_entry(middle);

        if (entry) {
            SPDLOG_DEBUG("Found function start for {:x} at {:x}", middle, entry->BeginAddress);
            return (uintptr_t)entry->BeginAddress + (uintptr_t)utility::get_module_within(middle).value_or(nullptr);
        }

        return std::nullopt;
    }

    std::optional<uintptr_t> find_function_start_unwind(uintptr_t middle) {
#if defined(_M_AMD64)
        auto entry = find_function_entry(middle);

        if (entry) {
            const auto module = utility::get_module_within(middle).value_or(nullptr);

            if (module != nullptr) {
                auto ui = (undocumented::UNWIND_INFO*)((uintptr_t)module + entry->UnwindData);
                
                while (ui->Flags & UNW_FLAG_CHAININFO) {
                    // The chained RUNTIME_FUNCTION follows the unwind codes array
                    // Array must be DWORD aligned, hence the (Count + 1) & ~1
                    entry = (RUNTIME_FUNCTION*)(&ui->UnwindCode[(ui->CountOfCodes + 1) & ~1]);
                    ui = (undocumented::UNWIND_INFO*)((uintptr_t)module + entry->UnwindData);
                }

                return (uintptr_t)entry->BeginAddress + (uintptr_t)module;
            }
        }
#endif

        return std::nullopt;
    }

    std::optional<uintptr_t> find_function_start_with_call(uintptr_t middle) {
        KANANLIB_BENCH();

        const auto module = utility::get_module_within(middle).value_or(nullptr);
        
        if (module == nullptr) {
            return std::nullopt;
        }

        for (auto func = find_function_start_unwind(middle); func.has_value(); func = find_function_start_unwind(*func - 1)) {
            SPDLOG_INFO(" Checking if {:x} is a real function", *func);

            const auto ref = utility::scan_displacement_reference(module, *func, [&](uintptr_t ref) {
                const auto resolved = utility::resolve_instruction(ref);

                if (!resolved) {
                    SPDLOG_ERROR(" Could not resolve instruction");
                    return false;
                }

                if (std::string_view{resolved->instrux.Mnemonic}.starts_with("CALL")) {
                    return true;
                }

                return false;
            });

            if (ref) {
                return func;
            }
        }

        return std::nullopt;
    }

    std::optional<uintptr_t> find_function_from_string_ref(HMODULE module, std::string_view str, bool zero_terminated) {
        KANANLIB_BENCH();

        SPDLOG_INFO("Scanning module {} for string reference {}", utility::get_module_path(module).value_or("UNKNOWN"), str);

        const auto str_data = utility::scan_string(module, str.data(), zero_terminated);

        if (!str_data) {
            SPDLOG_ERROR("Failed to find string for {}", str.data());
            return std::nullopt;
        }

        const auto str_ref = utility::scan_displacement_reference(module, *str_data);

        if (!str_ref) {
            SPDLOG_ERROR("Failed to find reference to string for {}", str.data());
            return std::nullopt;
        }

        const auto func_start = find_function_start(*str_ref);

        if (!func_start) {
            SPDLOG_ERROR("Failed to find function start for {}", str.data());
            return std::nullopt;
        }

        return func_start;
    }

    std::optional<uintptr_t> find_function_from_string_ref(HMODULE module, std::wstring_view str, bool zero_terminated) {
        KANANLIB_BENCH();

        SPDLOG_INFO("Scanning module {} for string reference {}", utility::get_module_path(module).value_or("UNKNOWN"), utility::narrow(str));

        const auto str_data = utility::scan_string(module, str.data(), zero_terminated);

        if (!str_data) {
            SPDLOG_ERROR("Failed to find string for {}", utility::narrow(str.data()));
            return std::nullopt;
        }

        const auto str_ref = utility::scan_displacement_reference(module, *str_data);

        if (!str_ref) {
            SPDLOG_ERROR("Failed to find reference to string for {}", utility::narrow(str.data()));
            return std::nullopt;
        }

        const auto func_start = find_function_start(*str_ref);

        if (!func_start) {
            SPDLOG_ERROR("Failed to find function start for {}", utility::narrow(str.data()));
            return std::nullopt;
        }

        return func_start;
    }

    std::optional<uintptr_t> find_function_with_string_refs(HMODULE module, std::wstring_view a, std::wstring_view b, bool follow_calls) {
        KANANLIB_BENCH();

        SPDLOG_INFO("Scanning module {} for string references {} and {}", utility::get_module_path(module).value_or("UNKNOWN"), utility::narrow(a), utility::narrow(b));

        // We're not going to bother finding the b strings, we will just disassemble the function that contains the a string
        // until we run into a reference to the b string
        const auto a_datas = utility::scan_strings(module, a.data(), false);

        if (a_datas.empty()) {
            SPDLOG_ERROR("Failed to find strings for {}", utility::narrow(a.data()));
            return std::nullopt;
        }

        std::unordered_set<uintptr_t> seen_ips{};

        for (auto a_data : a_datas) {
            const auto a_refs = utility::scan_displacement_references(module, a_data);

            if (a_refs.empty()) {
                SPDLOG_ERROR("Failed to find references to string for {}", utility::narrow(a.data()));
                continue;
            }

            for (auto a_ref : a_refs) {
                const auto func_start = find_function_start(a_ref);

                if (!func_start) {
                    SPDLOG_ERROR("Failed to find function start for {}", utility::narrow(a.data()));
                    continue;
                }

                bool is_correct_function = false;

                utility::exhaustive_decode((uint8_t*)*func_start, 1000, [&](INSTRUX& ix, uintptr_t ip) -> ExhaustionResult {
                    if (!follow_calls && std::string_view{ix.Mnemonic}.starts_with("CALL")) {
                        return ExhaustionResult::STEP_OVER;
                    }

                    if (seen_ips.contains(ip) || is_correct_function) {
                        return ExhaustionResult::BREAK;
                    }

                    seen_ips.insert(ip);

                    const auto displacement = utility::resolve_displacement(ip);

                    if (!displacement) {
                        return ExhaustionResult::CONTINUE;
                    }

                    try {
                        const auto potential_string = (wchar_t*)*displacement;

                        if (IsBadReadPtr(potential_string, b.length() * sizeof(wchar_t))) {
                            return ExhaustionResult::CONTINUE;
                        }

                        if (std::memcmp(potential_string, b.data(), b.length() * sizeof(wchar_t)) == 0) {
                            SPDLOG_INFO("Found correct displacement at 0x{:x}", ip);
                            is_correct_function = true;
                            return ExhaustionResult::BREAK;
                        }
                    } catch(...) {

                    }

                    return ExhaustionResult::CONTINUE;
                });

                if (is_correct_function) {
                    return func_start;
                }
            }
        }

        SPDLOG_ERROR("Failed to find function for {} and {}", utility::narrow(a.data()), utility::narrow(b.data()));
        return std::nullopt;
    }

    std::optional<uintptr_t> find_function_with_refs(HMODULE module, std::vector<uintptr_t> ptrs) {
        KANANLIB_BENCH();

        if (ptrs.size() < 2) {
            return std::nullopt;
        }

        std::vector<std::vector<uintptr_t>> refs_all{};

        for (auto ptr : ptrs) {
            const auto refs = utility::scan_displacement_references(module, ptr);

            if (refs.empty()) {
                SPDLOG_ERROR("Failed to find references to 0x{:x}", ptr);
                return std::nullopt;
            }

            auto& back = refs_all.emplace_back();
            back = refs;
        }

        std::vector<std::vector<uintptr_t>> func_starts_all{};

        for (auto& refs : refs_all) {
            auto& back = func_starts_all.emplace_back();

            for (auto ref : refs) {
                const auto func_start = find_function_start_unwind(ref);

                if (!func_start) {
                    SPDLOG_ERROR("Failed to find function start for 0x{:x}", ref);
                    continue;
                }

                back.push_back(*func_start);
            }

            func_starts_all.push_back(back);
        }

        // Find commonalities
        for (auto& func_starts : func_starts_all) {
            for (auto func_start : func_starts) {
                bool is_common = true;

                for (auto& other_func_starts : func_starts_all) {
                    if (std::find(other_func_starts.begin(), other_func_starts.end(), func_start) == other_func_starts.end()) {
                        is_common = false;
                        break;
                    }
                }

                if (is_common) {
                    return func_start;
                }
            }
        }

        return std::nullopt;
    }


    // Same as the previous, but it keeps going upwards until utility::scan_ptr returns something
    std::optional<uintptr_t> find_virtual_function_start(uintptr_t middle) {
        KANANLIB_BENCH();

        auto module = utility::get_module_within(middle).value_or(nullptr);

        if (module == nullptr) {
            return {};
        }

        auto func_start = find_function_start(middle);

        do {
            if (!func_start) {
                return std::nullopt;
            }

            if (utility::scan_ptr(module, *func_start)) {
                return func_start;
            }

            func_start = find_function_start(*func_start - 1);
        } while(func_start);

        return std::nullopt;
    }

    // Same as the previous, but it keeps going upwards until utility::scan_ptr returns something
    std::optional<uintptr_t> find_virtual_function_from_string_ref(HMODULE module, std::wstring_view str, bool zero_terminated) {
        KANANLIB_BENCH();

        SPDLOG_INFO("Scanning module {} for string reference {}", utility::get_module_path(module).value_or("UNKNOWN"), utility::narrow(str));

        const auto str_data = utility::scan_string(module, str.data(), zero_terminated);

        if (!str_data) {
            SPDLOG_ERROR("Failed to find string for {}", utility::narrow(str.data()));
            return std::nullopt;
        }

        const auto str_ref = utility::scan_displacement_reference(module, *str_data);

        if (!str_ref) {
            SPDLOG_ERROR("Failed to find reference to string for {}", utility::narrow(str.data()));
            return std::nullopt;
        }

        return find_virtual_function_start(*str_ref);
    }
    
    std::optional<uintptr_t> find_encapsulating_virtual_function(uintptr_t vtable, size_t walk_amount, uintptr_t middle) {
        if (middle == 0 || walk_amount == 0 || vtable == 0 || IsBadReadPtr((void*)vtable, sizeof(void*) * walk_amount)) {
            return std::nullopt;
        }

        std::optional<uintptr_t> result{};
        std::unordered_set<uintptr_t> seen{};

        for (size_t i = 0; i < walk_amount; ++i) {
            const auto fn = *(uintptr_t*)(vtable + (sizeof(void*) * i));
            if (fn == 0 || IsBadReadPtr((void*)fn, 8)) {
                continue;
            }

            if (result) {
                break;
            }

            utility::exhaustive_decode((uint8_t*)fn, 200, [&](INSTRUX& ix, uintptr_t ip) -> utility::ExhaustionResult {
                if (result) {
                    return utility::ExhaustionResult::BREAK;
                }

                // We don't treat every new function as a valid path, we need to check if we've seen it before
                // or else execution times will balloon
                if (seen.contains(ip)) {
                    return utility::ExhaustionResult::BREAK;
                }

                seen.insert(ip);

                if (middle >= ip && middle < ip + ix.Length) {
                    result = fn;
                    SPDLOG_INFO("Found encapsulating function at 0x{:x} for {:x} within vtable {:x} (index {})", fn, middle, vtable, i);
                    return utility::ExhaustionResult::BREAK;
                }

                return utility::ExhaustionResult::CONTINUE;
            });
        }

        return result;
    }

    std::optional<uintptr_t> find_encapsulating_virtual_function_disp(uintptr_t vtable, size_t walk_amount, uintptr_t disp, bool follow_calls) {
        if (walk_amount == 0 || vtable == 0 || IsBadReadPtr((void*)vtable, sizeof(void*) * walk_amount)) {
            return std::nullopt;
        }

        std::optional<uintptr_t> result{};
        std::unordered_set<uintptr_t> seen{};

        for (size_t i = 0; i < walk_amount; ++i) {
            const auto fn = *(uintptr_t*)(vtable + (sizeof(void*) * i));
            if (fn == 0 || IsBadReadPtr((void*)fn, 8)) {
                continue;
            }

            if (result) {
                break;
            }

            utility::exhaustive_decode((uint8_t*)fn, 200, [&](INSTRUX& ix, uintptr_t ip) -> utility::ExhaustionResult {
                if (result) {
                    return utility::ExhaustionResult::BREAK;
                }

                // We don't treat every new function as a valid path, we need to check if we've seen it before
                // or else execution times will balloon
                if (seen.contains(ip)) {
                    return utility::ExhaustionResult::BREAK;
                }

                if (!follow_calls && std::string_view{ix.Mnemonic}.starts_with("CALL")) {
                    return utility::ExhaustionResult::STEP_OVER;
                }

                seen.insert(ip);

                const auto displacement = utility::resolve_displacement(ip);

                if (!displacement) {
                    return utility::ExhaustionResult::CONTINUE;
                }

                if (*displacement == disp) {
                    result = fn;
                    SPDLOG_INFO("Found encapsulating virtual function at 0x{:x} for {:x} (displacement)", fn, disp);
                    return utility::ExhaustionResult::BREAK;
                }

                return utility::ExhaustionResult::CONTINUE;
            });
        }

        return result;
    }

    std::optional<uintptr_t> find_encapsulating_function(uintptr_t start_instruction, uintptr_t middle) {
        if (middle == 0 || start_instruction == 0 || IsBadReadPtr((void*)start_instruction, sizeof(void*))) {
            return std::nullopt;
        }

        std::optional<uintptr_t> result{};
        std::unordered_set<uintptr_t> seen{};

        utility::exhaustive_decode((uint8_t*)start_instruction, 200, [&](INSTRUX& top_ix, uintptr_t top_ip) -> utility::ExhaustionResult {
            if (result) {
                return utility::ExhaustionResult::BREAK;
            }

            if (!std::string_view{top_ix.Mnemonic}.starts_with("CALL")) {
                return utility::ExhaustionResult::CONTINUE;
            }

            const auto possible_fn = utility::resolve_displacement(top_ip);

            if (!possible_fn) {
                return utility::ExhaustionResult::CONTINUE;
            }

            utility::exhaustive_decode((uint8_t*)*possible_fn, 500, [&](INSTRUX& ix, uintptr_t ip) -> utility::ExhaustionResult {
                if (result) {
                    return utility::ExhaustionResult::BREAK;
                }

                // We don't treat every new function as a valid path, we need to check if we've seen it before
                // or else execution times will balloon
                if (seen.contains(ip)) {
                    return utility::ExhaustionResult::BREAK;
                }

                seen.insert(ip);

                if (middle >= ip && middle < ip + ix.Length) {
                    result = *possible_fn;
                    SPDLOG_INFO("Found encapsulating function at 0x{:x} for {:x}", *possible_fn, middle);
                    return utility::ExhaustionResult::BREAK;
                }

                return utility::ExhaustionResult::CONTINUE;
            });

            if (result) {
                return utility::ExhaustionResult::BREAK;
            }

            // Step over the call we just analyzed.
            return utility::ExhaustionResult::STEP_OVER;
        });

        return result;
    }

    std::optional<uintptr_t> find_encapsulating_function_disp(uintptr_t start_instruction, uintptr_t disp, bool follow_calls) {
        if (disp == 0 || start_instruction == 0 || IsBadReadPtr((void*)start_instruction, sizeof(void*))) {
            return std::nullopt;
        }

        std::optional<uintptr_t> result{};
        std::unordered_set<uintptr_t> seen{};

        utility::exhaustive_decode((uint8_t*)start_instruction, 200, [&](INSTRUX& top_ix, uintptr_t top_ip) -> utility::ExhaustionResult {
            if (result) {
                return utility::ExhaustionResult::BREAK;
            }

            if (!std::string_view{top_ix.Mnemonic}.starts_with("CALL")) {
                return utility::ExhaustionResult::CONTINUE;
            }

            const auto possible_fn = utility::resolve_displacement(top_ip);

            if (!possible_fn) {
                return utility::ExhaustionResult::CONTINUE;
            }

            utility::exhaustive_decode((uint8_t*)*possible_fn, 500, [&](INSTRUX& ix, uintptr_t ip) -> utility::ExhaustionResult {
                if (result) {
                    return utility::ExhaustionResult::BREAK;
                }

                // We don't treat every new function as a valid path, we need to check if we've seen it before
                // or else execution times will balloon
                if (seen.contains(ip)) {
                    return utility::ExhaustionResult::BREAK;
                }

                if (!follow_calls && std::string_view{ix.Mnemonic}.starts_with("CALL")) {
                    return utility::ExhaustionResult::STEP_OVER;
                }

                seen.insert(ip);

                const auto displacement = utility::resolve_displacement(ip);

                if (!displacement) {
                    return utility::ExhaustionResult::CONTINUE;
                }

                if (*displacement == disp) {
                    result = *possible_fn;
                    SPDLOG_INFO("Found encapsulating function at 0x{:x} for {:x} (displacement)", *possible_fn, disp);
                    return utility::ExhaustionResult::BREAK;
                }

                return utility::ExhaustionResult::CONTINUE;
            });

            if (result) {
                return utility::ExhaustionResult::BREAK;
            }

            // Step over the call we just analyzed.
            return utility::ExhaustionResult::STEP_OVER;
        });

        return result;
    }

    std::optional<uintptr_t> resolve_displacement(uintptr_t ip, const INSTRUX* ix_in) {
        INSTRUX ix_local{};
        const INSTRUX* ix;
        
        if (ix_in) {
            ix = ix_in;
        } else {
            auto decoded = decode_one((uint8_t*)ip);
            if (!decoded) {
                return std::nullopt;
            }
            ix_local = *decoded;
            ix = &ix_local;
        }

        for (auto i = 0; i < ix->OperandsCount; ++i) {
            const auto& operand = ix->Operands[i];
            if (operand.Type == ND_OP_MEM) {
                const auto& mem = operand.Info.Memory;
                if (mem.HasDisp && mem.IsRipRel) {
                    return ip + ix->Length + (intptr_t)mem.Disp;
                }
            } else if (operand.Type == ND_OP_OFFS) {
                const auto& offs = operand.Info.RelativeOffset;
                return ip + ix->Length + (intptr_t)offs.Rel;
            }
        }

        if (ix->HasDisp && ix->IsRipRelative) {
            return ip + ix->Length + ix->Displacement;
        }

        return std::nullopt;
    }

    std::optional<ResolvedDisplacement> find_next_displacement(uintptr_t start, bool follow_calls) {
        KANANLIB_BENCH();

        std::optional<ResolvedDisplacement> result{};

        utility::exhaustive_decode((uint8_t*)start, 100, [&](INSTRUX& ix, uintptr_t ip) -> utility::ExhaustionResult {
            if (result) {
                return utility::ExhaustionResult::BREAK;
            }

            if (!follow_calls && std::string_view{ix.Mnemonic}.starts_with("CALL")) {
                return utility::ExhaustionResult::STEP_OVER;
            }

            const auto displacement = utility::resolve_displacement(ip);

            if (displacement) {
                result = { { ip, ix }, *displacement };
                return utility::ExhaustionResult::BREAK;
            }

            return utility::ExhaustionResult::CONTINUE;
        });

        return result;
    }

    std::optional<Resolved> resolve_instruction(uintptr_t middle) {
        KANANLIB_BENCH();

        const auto reference_point = find_function_start(middle);

        if (!reference_point) {
            SPDLOG_ERROR("Failed to find function start for 0x{:x}, cannot resolve instruction", middle);
            return std::nullopt;
        }

        SPDLOG_INFO("Reference point for {:x}: {:x}", middle, *reference_point);

        // Now keep disassembling forward until we run into an instruction
        // whose address is <= middle or address + size > middle
        for (auto ip = (uint8_t*)*reference_point;;) {
            const auto ix = decode_one(ip);

            if (!ix) {
                SPDLOG_ERROR("Failed to decode instruction at 0x{:x}, cannot resolve instruction", (uintptr_t)ip);
                return std::nullopt;
            }

            if (middle >= (uintptr_t)ip && middle < (uintptr_t)ip + ix->Length) {
                return Resolved{(uintptr_t)ip, *ix};
            }

            ip += ix->Length;
        }

        return std::nullopt;
    }


    std::optional<ResolvedDisplacement> find_string_reference_in_path(uintptr_t start_instruction, std::string_view str, bool follow_calls) {
        KANANLIB_BENCH();

        if (str.empty() || IsBadReadPtr((void*)start_instruction, sizeof(void*))) {
            return std::nullopt;
        }

        std::optional<ResolvedDisplacement> result{};

        utility::exhaustive_decode((uint8_t*)start_instruction, 200, [&](INSTRUX& ix, uintptr_t ip) -> utility::ExhaustionResult {
            if (result) {
                return utility::ExhaustionResult::BREAK;
            }

            if (!follow_calls && std::string_view{ix.Mnemonic}.starts_with("CALL")) {
                return utility::ExhaustionResult::STEP_OVER;
            }

            const auto disp = utility::resolve_displacement(ip, &ix);

            if (!disp) {
                return utility::ExhaustionResult::CONTINUE;
            }

            if (IsBadReadPtr((void*)*disp, str.length() * sizeof(wchar_t))) {
                return utility::ExhaustionResult::CONTINUE;
            }

            if (str == (const char*)*disp) {
                result = ResolvedDisplacement{ { ip, ix }, *disp };
                return utility::ExhaustionResult::BREAK;
            }

            return utility::ExhaustionResult::CONTINUE;
        });

        return result;
    }

    std::optional<ResolvedDisplacement> find_string_reference_in_path(uintptr_t start_instruction, std::wstring_view str, bool follow_calls) {
        KANANLIB_BENCH();

        if (str.empty() || IsBadReadPtr((void*)start_instruction, sizeof(void*))) {
            return std::nullopt;
        }

        std::optional<ResolvedDisplacement> result{};

        utility::exhaustive_decode((uint8_t*)start_instruction, 200, [&](INSTRUX& ix, uintptr_t ip) -> utility::ExhaustionResult {
            if (result) {
                return utility::ExhaustionResult::BREAK;
            }

            if (!follow_calls && std::string_view{ix.Mnemonic}.starts_with("CALL")) {
                return utility::ExhaustionResult::STEP_OVER;
            }

            const auto disp = utility::resolve_displacement(ip, &ix);

            if (!disp) {
                return utility::ExhaustionResult::CONTINUE;
            }

            if (IsBadReadPtr((void*)*disp, str.length() * sizeof(wchar_t))) {
                return utility::ExhaustionResult::CONTINUE;
            }

            if (str == (const wchar_t*)*disp) {
                result = ResolvedDisplacement{ { ip, ix }, *disp };
                return utility::ExhaustionResult::BREAK;
            }

            return utility::ExhaustionResult::CONTINUE;
        });

        return result;
    }

    std::optional<ResolvedDisplacement> find_pointer_in_path(uintptr_t start_instruction, const void* pointer, bool follow_calls) {
        KANANLIB_BENCH();

        if (IsBadReadPtr((void*)start_instruction, sizeof(void*))) {
            return std::nullopt;
        }

        std::optional<ResolvedDisplacement> result{};

        utility::exhaustive_decode((uint8_t*)start_instruction, 200, [&](INSTRUX& ix, uintptr_t ip) -> utility::ExhaustionResult {
            if (result) {
                return utility::ExhaustionResult::BREAK;
            }

            auto check_if_pointer = [&]() -> bool {
                const auto disp = utility::resolve_displacement(ip, &ix);

                if (!disp) {
                    return false;
                }

                if (IsBadReadPtr((void*)*disp, sizeof(void*))) {
                    return false;
                }

                if (pointer == *(void**)*disp) {
                    result = ResolvedDisplacement{ { ip, ix }, *disp };
                    return true;
                }

                return false;
            };

            if (!follow_calls && std::string_view{ix.Mnemonic}.starts_with("CALL")) {
                if (check_if_pointer()) {
                    return utility::ExhaustionResult::BREAK;
                }

                return utility::ExhaustionResult::STEP_OVER;
            }

            if (check_if_pointer()) {
                return utility::ExhaustionResult::BREAK;
            }

            return utility::ExhaustionResult::CONTINUE;
        });

        return result;
    }

    std::optional<ResolvedDisplacement> find_displacement_in_path(uintptr_t start_instruction, uintptr_t displacement, bool follow_calls) {
        KANANLIB_BENCH();

        if (IsBadReadPtr((void*)start_instruction, sizeof(void*))) {
            return std::nullopt;
        }

        std::optional<ResolvedDisplacement> result{};

        utility::exhaustive_decode((uint8_t*)start_instruction, 200, [&](INSTRUX& ix, uintptr_t ip) -> utility::ExhaustionResult {
            if (result) {
                return utility::ExhaustionResult::BREAK;
            }

            auto check_if_pointer = [&]() -> bool {
                const auto disp = utility::resolve_displacement(ip, &ix);

                if (!disp) {
                    return false;
                }

                if (*disp == displacement) {
                    result = ResolvedDisplacement{ { ip, ix }, *disp };
                    return true;
                }

                return false;
            };

            if (!follow_calls && std::string_view{ix.Mnemonic}.starts_with("CALL")) {
                if (check_if_pointer()) {
                    return utility::ExhaustionResult::BREAK;
                }

                return utility::ExhaustionResult::STEP_OVER;
            }

            if (check_if_pointer()) {
                return utility::ExhaustionResult::BREAK;
            }

            return utility::ExhaustionResult::CONTINUE;
        });

        return result;
    }

    std::optional<Resolved> find_mnemonic_in_path(uintptr_t start_instruction, uint32_t num_instructions, std::string_view mnemonic, bool follow_calls) {
        KANANLIB_BENCH();

        if (mnemonic.empty() || IsBadReadPtr((void*)start_instruction, sizeof(void*))) {
            return std::nullopt;
        }

        std::optional<Resolved> result{};

        utility::exhaustive_decode((uint8_t*)start_instruction, num_instructions, [&](INSTRUX& ix, uintptr_t ip) -> utility::ExhaustionResult {
            if (result) {
                return utility::ExhaustionResult::BREAK;
            }

            if (std::string_view{ix.Mnemonic}.starts_with(mnemonic)) {
                result = Resolved{ ip, ix };
                return utility::ExhaustionResult::BREAK;
            }

            if (!follow_calls && std::string_view{ix.Mnemonic}.starts_with("CALL")) {
                return utility::ExhaustionResult::STEP_OVER;
            }

            return utility::ExhaustionResult::CONTINUE;
        });

        return result;
    }

    std::optional<Resolved> find_register_usage_in_path(uintptr_t start_instruction, uint32_t num_instructions, uint32_t reg, bool follow_calls) {
        KANANLIB_BENCH();

        if (IsBadReadPtr((void*)start_instruction, sizeof(void*))) {
            return std::nullopt;
        }

        std::optional<Resolved> result{};

        utility::exhaustive_decode((uint8_t*)start_instruction, num_instructions, [&](INSTRUX& ix, uintptr_t ip) -> utility::ExhaustionResult {
            if (result) {
                return utility::ExhaustionResult::BREAK;
            }

            for (auto i = 0; i < ix.OperandsCount; ++i) {
                const auto& operand = ix.Operands[i];

                if (operand.Type == ND_OP_REG && operand.Info.Register.Reg == reg) {
                    result = Resolved{ ip, ix };
                    return utility::ExhaustionResult::BREAK;
                }

                if (operand.Type == ND_OP_MEM && operand.Info.Memory.HasBase && operand.Info.Memory.Base == reg) {
                    result = Resolved{ ip, ix };
                    return utility::ExhaustionResult::BREAK;
                }
            }

            if (!follow_calls && std::string_view{ix.Mnemonic}.starts_with("CALL")) {
                return utility::ExhaustionResult::STEP_OVER;
            }

            return utility::ExhaustionResult::CONTINUE;
        });

        return result;
    }

    std::optional<Resolved> find_pattern_in_path(uint8_t* ip, size_t max_size, bool follow_calls, const std::string& pattern) {
        KANANLIB_BENCH();

        if (IsBadReadPtr(ip, sizeof(void*))) {
            return std::nullopt;
        }

        std::optional<Resolved> result{};

        exhaustive_decode(ip, max_size, [&](INSTRUX& instrux, uintptr_t addr) {
            if (result.has_value()) {
                return BREAK;
            }

            if (const auto s = utility::scan(addr, 64, pattern); s.has_value() && *s == addr) {
                result = Resolved{ addr, instrux };
                return BREAK;
            }

            if (!follow_calls && std::string_view{instrux.Mnemonic}.starts_with("CALL")) {
                return STEP_OVER;
            }

            return CONTINUE;
        });

        return result;
    }

    std::optional<Resolved> find_landmark_sequence(HMODULE module, const std::string& initial_pattern, const std::vector<std::string>& patterns, bool follow_calls) {
        KANANLIB_BENCH();

        return find_landmark_sequence((uintptr_t)module, utility::get_module_size(module).value_or(0), initial_pattern, patterns, follow_calls);
    }

    std::optional<Resolved> find_landmark_sequence(uintptr_t start, size_t size, const std::string& initial_pattern, const std::vector<std::string>& patterns, bool follow_calls) {
        const auto end = start + size;

        for (auto initial = utility::scan(start, size, initial_pattern); initial.has_value(); initial = utility::scan(*initial + 1, end - (*initial + 1), initial_pattern)) {
            const auto initial_instruction = utility::decode_one((uint8_t*)*initial);
            if (!initial_instruction) {
                continue;
            }

            const auto initial_size = initial_instruction->Length;

            bool all_found = true;


            for (const auto& pattern : patterns) {
                auto resolved = utility::find_pattern_in_path((uint8_t*)(*initial + initial_size), 100, follow_calls, pattern);
                if (!resolved) {
                    all_found = false;
                    break;
                }
            }

            if (all_found) {
                return Resolved{ *initial, *initial_instruction };
            }
        }

        return std::nullopt;
    }

    std::vector<Resolved> get_disassembly_behind(uintptr_t middle) {
        KANANLIB_BENCH();

        const auto reference_point = find_function_start(middle);

        if (!reference_point) {
            SPDLOG_ERROR("Failed to find function start for 0x{:x}, cannot resolve instruction", middle);
            return {};
        }

        std::vector<Resolved> out{};

        SPDLOG_INFO("Reference point for {:x}: {:x}", middle, *reference_point);

        for (auto ip = (uint8_t*)*reference_point;;) {
            const auto ix = decode_one(ip);

            if (!ix) {
                SPDLOG_ERROR("Failed to decode instruction at 0x{:x}, cannot resolve instruction", (uintptr_t)ip);
                return {};
            }

            if (middle >= (uintptr_t)ip && middle < (uintptr_t)ip + ix->Length) {
                break;
            }
            
            out.push_back(Resolved{(uintptr_t)ip, *ix});

            ip += ix->Length;
        }

        return out;
    }

    std::vector<StringReference> collect_ascii_string_references(uintptr_t start, size_t max_size, const StringReferenceOptions& options) {
        std::vector<StringReference> out{};

        utility::exhaustive_decode((uint8_t*)start, max_size, [&](ExhaustionContext& ctx) -> ExhaustionResult { 
            try {
                if (!options.follow_calls && std::string_view{ctx.instrux.Mnemonic}.starts_with("CALL")) {
                    return ExhaustionResult::STEP_OVER;
                }

                const auto disp = utility::resolve_displacement(ctx.addr, &ctx.instrux);

                if (!disp) {
                    return ExhaustionResult::CONTINUE;
                }

                if (IsBadReadPtr((void*)*disp, 2)) {
                    return ExhaustionResult::CONTINUE;
                }

                auto c = (char*)*disp;

                while (std::isprint(*c) && *c != '\0') {
                    const auto len = (uintptr_t)c - (uintptr_t)*disp;

                    if (len >= options.max_length) {
                        return ExhaustionResult::CONTINUE;
                    }

                    ++c;
                }

                if (*c == '\0' && c != (char*)*disp) {
                    const auto len = (uintptr_t)c - (uintptr_t)*disp;

                    if (len >= options.min_length) {
                        out.emplace_back(Resolved{ctx.addr, ctx.instrux}, (char*)*disp);
                    }
                }
            } catch(...) {
            }

            return ExhaustionResult::CONTINUE;
        });

        return out;
    }

    std::vector<StringReference> collect_unicode_string_references(uintptr_t start, size_t max_size, const StringReferenceOptions& options) {
        std::vector<StringReference> out{};

        utility::exhaustive_decode((uint8_t*)start, max_size, [&](ExhaustionContext& ctx) -> ExhaustionResult { 
            try {
                if (!options.follow_calls && std::string_view{ctx.instrux.Mnemonic}.starts_with("CALL")) {
                    return ExhaustionResult::STEP_OVER;
                }

                const auto disp = utility::resolve_displacement(ctx.addr, &ctx.instrux);

                if (!disp) {
                    return ExhaustionResult::CONTINUE;
                }

                if (IsBadReadPtr((void*)*disp, sizeof(wchar_t) * 2)) {
                    return ExhaustionResult::CONTINUE;
                }

                auto wc = (wchar_t*)*disp;

                while (std::iswprint(*wc) && *wc != L'\0' && *wc >= 0x20 && *wc <= 0x7E) {
                    const auto len = ((uintptr_t)wc - (uintptr_t)*disp) / sizeof(wchar_t);

                    if (len >= options.max_length) {
                        return ExhaustionResult::CONTINUE;
                    }

                    ++wc;
                }

                if (*wc == L'\0' && wc != (wchar_t*)*disp) {
                    const auto len = ((uintptr_t)wc - (uintptr_t)*disp) / sizeof(wchar_t);

                    if (len >= options.min_length) {
                        out.emplace_back(Resolved{ctx.addr, ctx.instrux}, (wchar_t*)*disp);
                    }
                }
            } catch(...) {
            }

            return ExhaustionResult::CONTINUE;
        });

        return out;
    }
}
