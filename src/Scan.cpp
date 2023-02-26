#include <cstdint>
#include <unordered_set>
#include <deque>
#include <omp.h>
#include <ppl.h>

#include <spdlog/spdlog.h>

#include <utility/Pattern.hpp>
#include <utility/String.hpp>
#include <utility/Module.hpp>
#include <utility/Scan.hpp>

using namespace std;

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
        if (start == 0 || length == 0) {
            return {};
        }

        Pattern p{ pattern };

        return p.find(start, length);
    }

    std::optional<uintptr_t> scan_reverse(uintptr_t start, size_t length, const std::string& pattern) {
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
        const auto module_size = get_module_size(module).value_or(0);
        const auto end = (uintptr_t)module + module_size;

        for (auto i = (uintptr_t)module; i < end; i += sizeof(uint8_t)) {
            if (memcmp((void*)i, data, size) == 0) {
                return i;
            }
        }

        return {};
    }

    optional<uintptr_t> scan_data(uintptr_t start, size_t length, const uint8_t* data, size_t size) {
        if (start == 0 || length == 0) {
            return {};
        }

        for (auto i = start; i < start + length; i += sizeof(uint8_t)) {
            if (memcmp((void*)i, data, size) == 0) {
                return i;
            }
        }

        return {};
    }

    optional<uintptr_t> scan_data_reverse(uintptr_t start, size_t length, const uint8_t* data, size_t size) {
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
        if (str.empty()) {
            return {};
        }

        const auto data = (uint8_t*)str.c_str();
        const auto size = str.size() + (zero_terminated ? 1 : 0);

        return scan_data(module, data, size);
    }

    optional<uintptr_t> scan_string(HMODULE module, const wstring& str, bool zero_terminated) {
        if (str.empty()) {
            return {};
        }

        const auto data = (uint8_t*)str.c_str();
        const auto size = (str.size() + (zero_terminated ? 1 : 0)) * sizeof(wchar_t);

        return scan_data(module, data, size);
    }

    std::optional<uintptr_t> scan_string(uintptr_t start, size_t length, const std::string& str, bool zero_terminated) {
        if (str.empty()) {
            return {};
        }

        const auto data = (uint8_t*)str.c_str();
        const auto size = str.size() + (zero_terminated ? 1 : 0);

        return scan_data(start, length, data, size);
    }

    std::optional<uintptr_t> scan_string(uintptr_t start, size_t length, const std::wstring& str, bool zero_terminated) {
        if (str.empty()) {
            return {};
        }

        const auto data = (uint8_t*)str.c_str();
        const auto size = (str.size() + (zero_terminated ? 1 : 0)) * sizeof(wchar_t);

        return scan_data(start, length, data, size);
    }

    std::vector<uintptr_t> scan_strings(HMODULE module, const std::string& str, bool zero_terminated) {
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

    optional<uintptr_t> scan_reference(HMODULE module, uintptr_t ptr, bool relative) {
        if (!relative) {
            return scan_ptr(module, ptr);
        }

        const auto module_size = get_module_size(module).value_or(0);
        const auto end = (uintptr_t)module + module_size;
        
        for (auto i = (uintptr_t)module; i < end - sizeof(void*); i += sizeof(uint8_t)) {
            if (calculate_absolute(i, 4) == ptr) {
                return i;
            }
        }

        return {};
    }

    optional<uintptr_t> scan_reference(uintptr_t start, size_t length, uintptr_t ptr, bool relative) {
        if (!relative) {
            return scan_ptr(start, length, ptr);
        }

        const auto end = start + length;

        for (auto i = start; i < end; i += sizeof(uint8_t)) {
            if (calculate_absolute(i, 4) == ptr) {
                return i;
            }
        }

        return {};
    }

    optional<uintptr_t> scan_relative_reference_strict(HMODULE module, uintptr_t ptr, const string& preceded_by) {
        if (preceded_by.empty()) {
            return {};
        }

        const auto module_size = get_module_size(module).value_or(0);
        const auto end = (uintptr_t)module + module_size;

        // convert preceded_by (IDA style string) to bytes
        auto pat = utility::Pattern{ preceded_by };
        const auto pat_len = pat.pattern_len();

        for (auto i = (uintptr_t)module; i < end; i += sizeof(uint8_t)) {
            if (calculate_absolute(i, 4) == ptr) {
                if (pat.find(i - pat_len, pat_len)) {
                    return i;
                }
            }
        }

        return {};
    }

    std::optional<uintptr_t> scan_displacement_reference(HMODULE module, uintptr_t ptr) {
        const auto module_size = get_module_size(module);

        if (!module_size) {
            return {};
        }

        return scan_displacement_reference((uintptr_t)module, *module_size, ptr);
    }

    std::optional<uintptr_t> scan_displacement_reference(uintptr_t start, size_t length, uintptr_t ptr) {
        const auto end = (start + length) - sizeof(void*);

        for (auto i = (uintptr_t)start; i < end; i += sizeof(uint8_t)) {
            if (calculate_absolute(i, 4) == ptr) {
                const auto resolved = utility::resolve_instruction(i);

                if (resolved) {
                    const auto displacement = utility::resolve_displacement(resolved->addr);

                    if (displacement && *displacement == ptr) {
                        return i;
                    }
                }
            }
        }

        return {};
    }
    
    std::optional<uintptr_t> scan_opcode(uintptr_t ip, size_t num_instructions, uint8_t opcode) {
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
    void exhaustive_decode(uint8_t* start, size_t max_size, std::function<ExhaustionResult(INSTRUX&, uintptr_t)> callback) {
        std::unordered_set<uint8_t*> seen_addresses{};
        std::deque<uint8_t*> branches{};

        auto decode_branch = [&](uint8_t* ip) {
            for (size_t i = 0; i < max_size; ++i) {
                if (seen_addresses.contains(ip)) {
                    break;
                }

                seen_addresses.insert(ip);

                if (IsBadReadPtr(ip, 16)) {
                    break;
                }

                INSTRUX ix{};
                const auto status = NdDecodeEx(&ix, ip, 1000, ND_CODE_64, ND_DATA_64);

                if (!ND_SUCCESS(status)) {
                    break;
                }

                if (ix.Instruction == ND_INS_RETN || ix.Instruction == ND_INS_INT3) {
                    break;
                }

                const auto result = callback(ix, (uintptr_t)ip);

                if (result == ExhaustionResult::BREAK) {
                    return;
                }

                // We dont want to follow indirect branches, we aren't emulating
                if (ix.IsRipRelative && !ix.BranchInfo.IsIndirect) {
                    if (ix.BranchInfo.IsBranch && ix.BranchInfo.IsConditional) {
                        // Determine how to get the destination address from the ix
                        // and push it to the branches deque
                        SPDLOG_INFO("Conditional Branch detected: {:x}", (uintptr_t)ip);

                        if (auto dest = utility::resolve_displacement((uintptr_t)ip); dest) {
                            if (result != ExhaustionResult::STEP_OVER) {
                                branches.push_back((uint8_t*)*dest);
                            }
                        } else {
                            SPDLOG_ERROR("Failed to resolve displacement for {:x}", (uintptr_t)ip);
                            SPDLOG_ERROR(" TODO: Fix this");
                        }
                    } else if (ix.BranchInfo.IsBranch && !ix.BranchInfo.IsConditional) {
                        SPDLOG_INFO("Unconditional Branch detected: {:x}", (uintptr_t)ip);

                        if (auto dest = utility::resolve_displacement((uintptr_t)ip); dest) {
                            if (std::string_view{ix.Mnemonic}.starts_with("JMP")) {
                                ip = (uint8_t*)*dest;
                                continue;
                            } else {
                                if (result != ExhaustionResult::STEP_OVER) {
                                    branches.push_back((uint8_t*)*dest);
                                }
                            }
                        } else {
                            SPDLOG_ERROR("Failed to resolve displacement for {:x}", (uintptr_t)ip);
                            SPDLOG_ERROR(" TODO: Fix this");
                        }
                    }
                } else if (ix.BranchInfo.IsIndirect) {
                    break; // We dont want to disassemble anything after an indirect branch
                }

                ip += ix.Length;
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

    std::optional<uintptr_t> find_function_start(uintptr_t middle) {
        const auto module = (uintptr_t)utility::get_module_within(middle).value_or(nullptr);

        if (module == 0) {
            return {};
        }

        const auto module_size = utility::get_module_size((HMODULE)module).value_or(0xDEADBEEF);
        const auto module_end = module + module_size;

        const auto middle_rva = middle - module;

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

        std::optional<uintptr_t> last{};
        uint32_t nearest_distance = 0xFFFFFFFF;

        std::mutex mtx{};

        concurrency::parallel_for<size_t>(0, exception_directory_entries, [&](size_t i) {
            const auto entry = exception_directory_ptr[i];

            if (module + entry.EndAddress >= module_end || entry.EndAddress >= module_size) {
                SPDLOG_ERROR("Bad end address at {:x} {:x}", module + entry.EndAddress, module_end);
                return;
            }

            // Check if the middle address is within the range of the function
            if (entry.BeginAddress <= middle_rva && middle_rva <= entry.EndAddress) {
                const auto distance = middle_rva - entry.BeginAddress;

                std::scoped_lock _{mtx};
                if (distance < nearest_distance) {
                    nearest_distance = distance;

                    // Return the start address of the function
                    last = module + entry.BeginAddress;
                }
            }
        });

        if (last) {
            SPDLOG_INFO("Found function start for {:x} at {:x}", middle, *last);
            return last;
        }

        return std::nullopt;
    }

    std::optional<uintptr_t> find_function_start_with_call(uintptr_t middle) {
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

    std::optional<uintptr_t> find_function_from_string_ref(HMODULE module, std::wstring_view str, bool zero_terminated) {
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

    // Same as the previous, but it keeps going upwards until utility::scan_ptr returns something
    std::optional<uintptr_t> find_virtual_function_start(uintptr_t middle) {
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

    std::optional<Resolved> resolve_instruction(uintptr_t middle) {
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
}
