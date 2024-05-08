#define NOMINMAX

#include <ppl.h>
#include <intrin.h>

#include <cstdint>
#include <unordered_set>
#include <deque>
#include <shared_mutex>

#include <spdlog/spdlog.h>

#include <utility/Pattern.hpp>
#include <utility/String.hpp>
#include <utility/Module.hpp>
#include <utility/Scan.hpp>
#include <utility/thirdparty/parallel-util.hpp>
#include <utility/thirdparty/InstructionSet.hpp>
#include <utility/ScopeGuard.hpp>

using namespace std;

//#define KANANLIB_DO_BENCHMARK

#ifdef KANANLIB_DO_BENCHMARK
#define KANANLIB_BENCH() \
    const auto KANANLIB_START_TIME = std::chrono::high_resolution_clock::now();\
    const auto KANANLIB_FUNCTION_NAME = __FUNCTION__;\
    utility::ScopeGuard guard{[KANANLIB_START_TIME, KANANLIB_FUNCTION_NAME] {\
        const auto end_time = std::chrono::high_resolution_clock::now();\
        const auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - KANANLIB_START_TIME).count();\
        SPDLOG_INFO("{} took {} microseconds", KANANLIB_FUNCTION_NAME, duration);\
    }};
#else
#define KANANLIB_BENCH()
#endif

namespace utility {
    optional<uintptr_t> scan(const string& module, const string& pattern) {
        return scan(GetModuleHandle(module.c_str()), pattern);
    }

    optional<uintptr_t> scan(const string& module, uintptr_t start, const string& pattern) {
        HMODULE mod = GetModuleHandle(module.c_str());
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

        while (end != (it = std::find(it, end, *data))) {
            if (memcmp(it, data, size) == 0) {
                return (uintptr_t)it;
            } else {
                it++;
            }
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
        while (end != (it = std::find(it, end, *data))) {
            if (memcmp(it, data, size) == 0) {
                return (uintptr_t)it;
            } else {
                it++;
            }
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
        const auto end = (uintptr_t)module + module_size;

        for (auto i = (uintptr_t)module; i < end; i += sizeof(void*)) {
            if (*(uintptr_t*)i == ptr) {
                return i;
            }
        }

        return std::nullopt;
    }

    std::optional<uintptr_t> scan_ptr(uintptr_t start, size_t length, uintptr_t ptr) {
        KANANLIB_BENCH();

        if (start == 0 || length == 0) {
            return {};
        }

        for (auto i = start; i < start + length; i += sizeof(void*)) {
            if (*(uintptr_t*)i == ptr) {
                return i;
            }
        }

        return std::nullopt;
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

    std::optional<uintptr_t> scan_relative_reference_scalar(uintptr_t start, size_t length, uintptr_t ptr, std::function<bool(uintptr_t)> filter) {
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

    std::optional<uintptr_t> scan_relative_reference(HMODULE module, uintptr_t ptr, std::function<bool(uintptr_t)> filter) {
        KANANLIB_BENCH();

        const auto module_size = get_module_size(module).value_or(0);

        if (module_size == 0) {
            return std::nullopt;
        }

        return scan_relative_reference((uintptr_t)module, module_size - sizeof(void*), ptr, filter);
    }

    std::optional<uintptr_t> scan_relative_reference(uintptr_t start, size_t length, uintptr_t ptr, std::function<bool(uintptr_t)> filter) {
        KANANLIB_BENCH();

        if (!kananlib::utility::thirdparty::InstructionSet::AVX2() || length <= sizeof(__m256i) * 4) {
            return scan_relative_reference_scalar(start, length, ptr, filter);
        }

        const auto end = (start + length);

        constexpr auto SHIFT_SCALAR = 8;
        constexpr auto GRANULARITY = sizeof(__m256i) / SHIFT_SCALAR; // 4

        const __m256i target = _mm256_set1_epi64x(ptr);
        const __m256i post_ip_constant = _mm256_set1_epi64x(4); // Usually true most of the time. *rel32 + &rel32 + 4 = target unless it's some weird instruction
        const __m256i shift_amount_interval = _mm256_set1_epi64x(SHIFT_SCALAR);
        const __m256i shift_amount_upper_initial = _mm256_set1_epi64x(SHIFT_SCALAR * 2);
        const __m256i shift_amount_after = _mm256_set1_epi64x(sizeof(__m256i) - SHIFT_SCALAR);

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

        const __m256i upper_addition_mask = _mm256_add_epi64(_mm256_set_epi64x(7, 6, 5, 4), post_ip_constant);
        const __m256i lower_addition_mask = _mm256_add_epi64(_mm256_set_epi64x(3, 2, 1, 0), post_ip_constant);
        //const __m256i indices = _mm256_set_epi32(7, 6, 5, 4, 3, 2, 1, 0);

        constexpr int mask_0 = 0b11111111;
        constexpr int mask_1 = mask_0 << 8;
        constexpr int mask_2 = mask_1 << 8;
        constexpr int mask_3 = mask_2 << 8;

        constexpr int masks[] = { mask_0, mask_1, mask_2, mask_3 };
        constexpr size_t lookahead_size = sizeof(__m256i) + (sizeof(__m256i) / 4); // 32 + 8 (for the sliding window when we do a 256 load on the next iteration)
        const size_t remaining_bytes = std::min<size_t>((length % lookahead_size) == 0 ? 0 : sizeof(__m256i), length);

        const __m256i start_vectorized = _mm256_set1_epi64x(start);

        // These will be added onto every loop.
        // The lower 0 - 8 bytes
        __m256i addresses1 = _mm256_add_epi64(start_vectorized, lower_addition_mask);
        __m256i addresses2 = _mm256_add_epi64(start_vectorized, upper_addition_mask);

        // The upper 16 - 24 bytes
        __m256i addresses3 = _mm256_add_epi64(addresses1, shift_amount_upper_initial);
        __m256i addresses4 = _mm256_add_epi64(addresses2, shift_amount_upper_initial);

        for (auto i = start; i + lookahead_size < end; i += sizeof(__m256i)) {
            // Add 8 bytes to the addresses at every interval
            // First iteration (lo) 0 - 4, 4 - 8
            // First iteration (hi) 16 - 20, 20 - 24
            // Second iteration (lo) 8 - 12, 12 - 16
            // Second iteration (hi) 24 - 28, 28 - 32
            // Basically a sliding window
            for (auto shr_i = 0; shr_i < GRANULARITY / 2; ++shr_i) {
                const auto byte_index = shr_i * SHIFT_SCALAR;
                const auto real_i = i + byte_index;

                if (shr_i > 0) {
                    addresses1 = _mm256_add_epi64(addresses1, shift_amount_interval);
                    addresses2 = _mm256_add_epi64(addresses2, shift_amount_interval);
                    addresses3 = _mm256_add_epi64(addresses3, shift_amount_interval);
                    addresses4 = _mm256_add_epi64(addresses4, shift_amount_interval);
                }

                const __m256i data = _mm256_loadu_si256((__m256i*)(real_i));

                const __m256i shuffled_lo = _mm256_shuffle_epi8(data, shuffle_mask_lo);
                const __m256i shuffled_hi = _mm256_shuffle_epi8(data, shuffle_mask_hi);

                // Move upper and lower 128-bit lanes to separate registers
                const __m256i displacement_lo = _mm256_cvtepi32_epi64(_mm256_extracti128_si256(shuffled_lo, 0));
                const __m256i displacement_hi = _mm256_cvtepi32_epi64(_mm256_extracti128_si256(shuffled_hi, 0));
                const __m256i displacement_lo_lo = _mm256_cvtepi32_epi64(_mm256_extracti128_si256(shuffled_lo, 1));
                const __m256i displacement_hi_hi = _mm256_cvtepi32_epi64(_mm256_extracti128_si256(shuffled_hi, 1));

                // Alternative way of doing the above (much slower, for reference)
                //const __m256i gathered = _mm256_i32gather_epi32((int32_t*)real_i, indices, 1);
                //const __m256i displacement_lo = _mm256_cvtepi32_epi64(_mm256_extracti128_si256(gathered, 0));
                //const __m256i displacement_hi = _mm256_cvtepi32_epi64(_mm256_extracti128_si256(gathered, 1));

                // Resolve the addresses
                const __m256i vaddresses1 = _mm256_add_epi64(addresses1, displacement_lo);
                const __m256i vaddresses2 = _mm256_add_epi64(addresses2, displacement_hi);
                const __m256i vaddresses3 = _mm256_add_epi64(addresses3, displacement_lo_lo);
                const __m256i vaddresses4 = _mm256_add_epi64(addresses4, displacement_hi_hi);

                // Compare addresses to the target
                const __m256i cmp_result1 = _mm256_cmpeq_epi64(vaddresses1, target);
                const __m256i cmp_result2 = _mm256_cmpeq_epi64(vaddresses2, target);
                const __m256i cmp_result3 = _mm256_cmpeq_epi64(vaddresses3, target);
                const __m256i cmp_result4 = _mm256_cmpeq_epi64(vaddresses4, target);

                const int mask1 = _mm256_movemask_epi8(cmp_result1);
                const int mask2 = _mm256_movemask_epi8(cmp_result2);
                const int mask3 = _mm256_movemask_epi8(cmp_result3);
                const int mask4 = _mm256_movemask_epi8(cmp_result4);

                auto check_candidate = [&](int mask, int start_j) -> std::optional<uintptr_t> {
                    for (int j = 0; j < 4; j++) {
                        if (mask & masks[j]) {
                            SPDLOG_INFO("Mask at offset {} ({} corrected) (real {:x}): {:x}", start_j + j, start_j + j + byte_index, real_i + j + start_j, (uint32_t)masks[j]);
                        }

                        if (mask & masks[j] && calculate_absolute(real_i + j + start_j, 4) == ptr) {
                            const uintptr_t candidate_addr = real_i + j + start_j;

                            if (filter == nullptr || filter(candidate_addr)) {
                                return candidate_addr;
                            }
                        }
                    }

                    return std::nullopt;
                };

                if (mask4 != 0) {
                    SPDLOG_INFO("Mask 4 is not zero @ {:x} (real {:x}): {:x}", i, real_i, (uint32_t)mask4);

                    if (auto result = check_candidate(mask4, 20); result) {
                        SPDLOG_INFO("Found fourth candidate at (block {:x}) {:x}->{:x} (mask {:x})", i, *result, ptr, (uint32_t)mask4);
                        return result;
                    }
                }

                if (mask3 != 0) {
                    SPDLOG_INFO("Mask 3 is not zero @ {:x} (real {:x}): {:x}", i, real_i, (uint32_t)mask3);

                    if (auto result = check_candidate(mask3, 16); result) {
                        SPDLOG_INFO("Found third candidate at (block {:x}) {:x}->{:x} (mask {:x})", i, *result, ptr, (uint32_t)mask3);
                        return result;
                    }
                }

                if (mask2 != 0) {
                    SPDLOG_INFO("Mask 2 is not zero @ {:x} (real {:x}): {:x}", i, real_i, (uint32_t)mask2);

                    if (auto result = check_candidate(mask2, 4); result) {
                        SPDLOG_INFO("Found second candidate at (block {:x}) {:x}->{:x} (mask {:x})", i, *result, ptr, (uint32_t)mask2);
                        return result;
                    }
                } 

                if (mask1 != 0) {
                    SPDLOG_INFO("Mask 1 is not zero @ {:x} (real {:x}): {:x}", i, real_i, (uint32_t)mask1);

                    if (auto result = check_candidate(mask1, 0); result) {
                        SPDLOG_INFO("Found first candidate at (block {:x}) {:x}->{:x} (mask {:x})", i, *result, ptr, (uint32_t)mask1);
                        return result;
                    }
                }
            }

            addresses1 = _mm256_add_epi64(addresses1, shift_amount_after); // 32 - 8 = 24
            addresses2 = _mm256_add_epi64(addresses2, shift_amount_after);
            addresses3 = _mm256_add_epi64(addresses3, shift_amount_after);
            addresses4 = _mm256_add_epi64(addresses4, shift_amount_after);
        }

        // Remaining bytes is always 0 or sizeof(__m256i)
        // because AVX2 requires 32 bytes for a load
        if (remaining_bytes > 0) {
            SPDLOG_INFO("Remaining bytes: {}", remaining_bytes);
            return scan_relative_reference_scalar(end - remaining_bytes, remaining_bytes, ptr, filter);
        }

        return std::nullopt;
    }

    optional<uintptr_t> scan_reference(HMODULE module, uintptr_t ptr, bool relative) {
        KANANLIB_BENCH();

        if (!relative) {
            return scan_ptr(module, ptr);
        }

        const auto module_size = get_module_size(module).value_or(0);
        const auto end = (uintptr_t)module + module_size;

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
        const auto end = (uintptr_t)module + module_size;

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

    std::optional<uintptr_t> scan_displacement_reference(HMODULE module, uintptr_t ptr) {
        KANANLIB_BENCH();

        const auto module_size = get_module_size(module);

        if (!module_size) {
            return {};
        }

        return scan_displacement_reference((uintptr_t)module, *module_size, ptr);
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

    std::optional<uintptr_t> scan_displacement_reference(uintptr_t start, size_t length, uintptr_t ptr) {
        KANANLIB_BENCH();

        return scan_relative_reference(start, length, ptr, [ptr](uintptr_t candidate_addr) {
            const auto resolved = utility::resolve_instruction(candidate_addr);

            if (resolved) {
                const auto displacement = utility::resolve_displacement(resolved->addr);

                if (displacement && *displacement == ptr) {
                    return true;
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

    // exhaustive_decode decodes until it hits something like a return, int3, fails, etc
    // except when it notices a conditional jmp, it will decode both branches separately
    void exhaustive_decode(uint8_t* start, size_t max_size, std::function<ExhaustionResult(ExhaustionContext&)> callback) {
        SPDLOG_INFO("Running exhaustive_decode on {:x}", (uintptr_t)start);

        std::unordered_set<uint8_t*> seen_addresses{};
        std::deque<uint8_t*> branches{};

        uint32_t total_branches_seen = 0;

        auto decode_branch = [&](uint8_t* ip) {
            const auto branch_start = (uintptr_t)ip;

            ExhaustionContext ctx{};
            ctx.branch_start = branch_start;

            for (size_t i = 0; i < max_size; ++i) {
                if (seen_addresses.contains(ip)) {
                    break;
                }

                seen_addresses.insert(ip);

                if (IsBadReadPtr(ip, 16)) {
                    break;
                }

                INSTRUX ix{};
                const auto status = NdDecodeEx(&ix, ip, 64, ND_CODE_64, ND_DATA_64);

                if (!ND_SUCCESS(status)) {
                    break;
                }

                ctx.addr = (uintptr_t)ip;
                ctx.instrux = ix;
                const auto result = callback(ctx);

                if (result == ExhaustionResult::BREAK) {
                    return;
                }

                // Allows the callback to at least process that we hit a ret or int3, but we will stop here.
                if (ix.Instruction == ND_INS_RETN || ix.Instruction == ND_INS_INT3) {
                    break;
                }

                const auto prev_branches_count = total_branches_seen;

                // We dont want to follow indirect branches, we aren't emulating
                if (ix.IsRipRelative && !ix.BranchInfo.IsIndirect) {
                    if (ix.BranchInfo.IsBranch && ix.BranchInfo.IsConditional) {
                        // Determine how to get the destination address from the ix
                        // and push it to the branches deque
                        SPDLOG_DEBUG("Conditional Branch detected: {:x}", (uintptr_t)ip);

                        if (auto dest = utility::resolve_displacement((uintptr_t)ip); dest) {
                            if (result != ExhaustionResult::STEP_OVER) {
                                branches.push_back((uint8_t*)*dest);
                                ++total_branches_seen;
                            }
                        } else {
                            SPDLOG_ERROR("Failed to resolve displacement for {:x}", (uintptr_t)ip);
                            SPDLOG_ERROR(" TODO: Fix this");
                        }
                    } else if (ix.BranchInfo.IsBranch && !ix.BranchInfo.IsConditional) {
                        SPDLOG_DEBUG("Unconditional Branch detected: {:x}", (uintptr_t)ip);

                        if (auto dest = utility::resolve_displacement((uintptr_t)ip); dest) {
                            if (std::string_view{ix.Mnemonic}.starts_with("JMP")) {
                                ip = (uint8_t*)*dest;
                                ctx.branch_start = (uintptr_t)*dest;
                                ++total_branches_seen;
                                continue;
                            } else {
                                if (result != ExhaustionResult::STEP_OVER) {
                                    branches.push_back((uint8_t*)*dest);
                                    ++total_branches_seen;
                                }
                            }
                        } else {
                            SPDLOG_ERROR("Failed to resolve displacement for {:x}", (uintptr_t)ip);
                            SPDLOG_ERROR(" TODO: Fix this");
                        }
                    }
                } else if (ix.IsRipRelative && ip[0] == 0xFF && ip[1] == 0x25) { // jmp qword ptr [rip+0xdeadbeef]
                    SPDLOG_DEBUG("Indirect jmp detected: {:x}", (uintptr_t)ip);
                    const auto dest = utility::calculate_absolute((uintptr_t)ip + 2);

                    if (dest != 0 && dest != (uintptr_t)ip && !IsBadReadPtr((void*)dest, sizeof(void*))) {
                        const auto real_dest = *(uintptr_t*)dest;

                        // Cannot step over jmps
                        if (real_dest != 0 && real_dest != (uintptr_t)ip && !IsBadReadPtr((void*)real_dest, sizeof(void*))) {
                            //branches.push_back((uint8_t*)real_dest);
                            SPDLOG_DEBUG("Indirect jmp destination: {:x}", (uintptr_t)real_dest);
                            ip = (uint8_t*)real_dest;
                            ctx.branch_start = (uintptr_t)real_dest;
                            ++total_branches_seen;
                            continue;
                        }
                    }

                    SPDLOG_ERROR("Failed to resolve indirect jmp destination: {:x}", (uintptr_t)ip);
                    break;
                } else if (ix.IsRipRelative && ip[0] == 0xFF && ip[1] == 0x15) { // call qword ptr [rip+0xdeadbeef]
                    SPDLOG_DEBUG("Indirect call detected: {:x}", (uintptr_t)ip);

                    const auto dest = utility::calculate_absolute((uintptr_t)ip + 2);

                    if (dest != 0 && dest != (uintptr_t)ip && !IsBadReadPtr((void*)dest, sizeof(void*))) {
                        const auto real_dest = *(uintptr_t*)dest;

                        if (real_dest != 0 && real_dest != (uintptr_t)ip && !IsBadReadPtr((void*)real_dest, sizeof(void*)) && result != ExhaustionResult::STEP_OVER) {
                            branches.push_back((uint8_t*)real_dest);
                            ++total_branches_seen;
                            SPDLOG_DEBUG("Indirect call destination: {:x}", (uintptr_t)real_dest);
                        }
                    }
                } else if (ix.BranchInfo.IsBranch && !ix.BranchInfo.IsConditional) {
                    if (!std::string_view{ix.Mnemonic}.starts_with("CALL")) {
                        break;
                    }
                }

                ip += ix.Length;

                if (total_branches_seen != prev_branches_count) {
                    ctx.branch_start = (uintptr_t)ip;
                }
            }
        };

        branches.push_back(start);

        while(true) {
            const auto branch = branches.front();
            branches.pop_front();

            decode_branch(branch);

            if (branches.empty()) {
                break;
            }
        }
    }

    void exhaustive_decode(uint8_t* start, size_t max_size, std::function<ExhaustionResult(INSTRUX&, uintptr_t)> callback) {
        return exhaustive_decode(start, max_size, [&](ExhaustionContext& ctx) {
            return callback(ctx.instrux, ctx.addr);
        });
    }

    std::vector<BasicBlock> collect_basic_blocks(uintptr_t start, const BasicBlockCollectOptions& options) {
        std::vector<BasicBlock> blocks{};
        uintptr_t previous_branch_start = start;

        BasicBlock last_block{};
        last_block.start = start;
        last_block.end = start;

        utility::exhaustive_decode((uint8_t*)start, options.max_size, [&](utility::ExhaustionContext& ctx) {
            if (ctx.branch_start != previous_branch_start) {
                blocks.push_back(last_block);
                SPDLOG_INFO("Found basic block from {:x} to {:x}", last_block.start, last_block.end);

                previous_branch_start = ctx.branch_start;
                last_block.instructions.clear();
                last_block.start = ctx.branch_start;
                last_block.end = ctx.branch_start;
            }

            last_block.end = ctx.addr;
            last_block.instructions.push_back({ ctx.addr, ctx.instrux });

            const auto ip = (uint8_t*)ctx.addr;

            // Skip over calls
            if (std::string_view{ctx.instrux.Mnemonic}.starts_with("CALL")) {
                return utility::ExhaustionResult::STEP_OVER;
            }

            return ExhaustionResult::CONTINUE;
        });

        if (options.sort) {
            std::sort(blocks.begin(), blocks.end(), [](const BasicBlock& a, const BasicBlock& b) {
                return a.start < b.start;
            });
        }

        return blocks;
    }

    PIMAGE_RUNTIME_FUNCTION_ENTRY find_function_entry(uintptr_t middle) {
        KANANLIB_BENCH();

        const auto module = (uintptr_t)utility::get_module_within(middle).value_or(nullptr);

        if (module == 0 || middle == 0) {
            return {};
        }

        const auto module_size = utility::get_module_size((HMODULE)module).value_or(0xDEADBEEF);
        const auto module_end = module + module_size;

        const auto middle_rva = middle - module;

        // We are storing a list of ranges inside buckets, so we can quickly find the correct bucket
        // Doing this with multithreading was much slower and inefficient
        struct Bucket {
            uint32_t start_range{};
            uint32_t end_range{};
            std::vector<PIMAGE_RUNTIME_FUNCTION_ENTRY> entries{};
        };
        
        static std::shared_mutex bucket_mtx{};
        static std::unordered_map<uintptr_t, std::vector<Bucket>> module_buckets{};

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

        if (needs_insert) {
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

                size_t total_added_entries = 0;

                for (auto i = 0; i < std::max<size_t>(sorted_entries.size() / NUM_BUCKETS, 1); ++i) {
                    Bucket bucket{};
                    const auto bucket_index = i * NUM_BUCKETS;
                    bucket.start_range = sorted_entries[bucket_index]->BeginAddress;
                    const auto next_index = std::min<size_t>((i + 1) * NUM_BUCKETS, sorted_entries.size());

                    uint32_t highest_end = 0;
                    for (size_t j = bucket_index; j < next_index; ++j) {
                        bucket.end_range = std::max<uint32_t>(highest_end, sorted_entries[j]->EndAddress);

                        bucket.entries.push_back(sorted_entries[j]);
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
                    }

                    SPDLOG_INFO("Adding remaining {} entries to last bucket for module {:x}", sorted_entries.size() - total_added_entries, module);
                    // Add the remaining entries to the last bucket
                    auto& last_bucket = buckets.back();

                    for (size_t i = total_added_entries; i < sorted_entries.size(); ++i) {
                        last_bucket.entries.push_back(sorted_entries[i]);
                    }
                }
            }
        }

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
            return nullptr;
        }

        if (candidates.size() > 1) {
            SPDLOG_INFO("Found {} candidates for function entry", candidates.size());
        }

        PIMAGE_RUNTIME_FUNCTION_ENTRY last = nullptr;
        uint32_t nearest_distance = 0xFFFFFFFF;

        for (auto& bucket : candidates) {
            if (nearest_distance == 0) {
                break;
            }

            for (const auto& entry : bucket->entries) {
                if (nearest_distance == 0) {
                    break;
                }

                if (entry->BeginAddress == middle_rva) {
                    last = entry;
                    nearest_distance = 0;
                    break;
                }

                // Check if the middle address is within the range of the function
                if (entry->BeginAddress <= middle_rva && middle_rva <= entry->EndAddress) {
                    const auto distance = middle_rva - entry->BeginAddress;

                    if (distance < nearest_distance) {
                        nearest_distance = distance;

                        // Return the start address of the function
                        last = entry;
                    }
                }
            }
        }

        return last;
    }

    std::optional<uintptr_t> find_function_start(uintptr_t middle) {
        const auto entry = find_function_entry(middle);

        if (entry != nullptr) {
            SPDLOG_INFO("Found function start for {:x} at {:x}", middle, entry->BeginAddress);
            return (uintptr_t)entry->BeginAddress + (uintptr_t)utility::get_module_within(middle).value_or(nullptr);
        }

        return std::nullopt;
    }

    std::optional<uintptr_t> find_function_start_with_call(uintptr_t middle) {
        KANANLIB_BENCH();

        const auto module = utility::get_module_within(middle).value_or(nullptr);
        
        if (module == nullptr) {
            return std::nullopt;
        }

        for (auto func = find_function_start(middle); func.has_value(); func = find_function_start(*func - 1)) {
            SPDLOG_INFO(" Checking if {:x} is a real function", *func);

            const auto ref = utility::scan_displacement_reference(module, *func);

            if (!ref) {
                continue;
            }

            const auto resolved = utility::resolve_instruction(*ref);

            if (!resolved) {
                SPDLOG_ERROR(" Could not resolve instruction");
                continue;
            }

            if (std::string_view{resolved->instrux.Mnemonic}.starts_with("CALL")) {
                return *func;
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

    std::optional<uintptr_t> resolve_displacement(uintptr_t ip) {
        const auto ix = decode_one((uint8_t*)ip);

        if (!ix) {
            SPDLOG_ERROR("Failed to decode instruction at 0x{:x}", ip);
            return std::nullopt;
        }

        for (auto i = 0; i < ix->OperandsCount; ++i) {
            const auto& operand = ix->Operands[i];

            if (operand.Type == ND_OP_MEM) {
                const auto& mem = operand.Info.Memory;
                if (mem.HasDisp && mem.IsRipRel) {
                    return ip + ix->Length + mem.Disp;
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
                result = { ip, ix, *displacement };
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

            const auto disp = utility::resolve_displacement(ip);

            if (!disp) {
                return utility::ExhaustionResult::CONTINUE;
            }

            if (IsBadReadPtr((void*)*disp, str.length() * sizeof(wchar_t))) {
                return utility::ExhaustionResult::CONTINUE;
            }

            if (str == (const char*)*disp) {
                result = ResolvedDisplacement{ ip, ix, *disp };
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

            const auto disp = utility::resolve_displacement(ip);

            if (!disp) {
                return utility::ExhaustionResult::CONTINUE;
            }

            if (IsBadReadPtr((void*)*disp, str.length() * sizeof(wchar_t))) {
                return utility::ExhaustionResult::CONTINUE;
            }

            if (str == (const wchar_t*)*disp) {
                result = ResolvedDisplacement{ ip, ix, *disp };
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
                const auto disp = utility::resolve_displacement(ip);

                if (!disp) {
                    return false;
                }

                if (IsBadReadPtr((void*)*disp, sizeof(void*))) {
                    return false;
                }

                if (pointer == *(void**)*disp) {
                    result = ResolvedDisplacement{ ip, ix, *disp };
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
                const auto disp = utility::resolve_displacement(ip);

                if (!disp) {
                    return false;
                }

                if (*disp == displacement) {
                    result = ResolvedDisplacement{ ip, ix, *disp };
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

            if (!follow_calls && std::string_view{instrux.Mnemonic}.starts_with("CALL")) {
                return STEP_OVER;
            }

            if (const auto s = utility::scan(addr, 64, pattern); s.has_value() && *s == addr) {
                result = Resolved{ addr, instrux };
                return BREAK;
            }

            return CONTINUE;
        });

        return result;
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
}
