#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <functional>

#include <bddisasm.h>
#include <Windows.h>

namespace utility {
    std::optional<uintptr_t> scan(const std::string& module, const std::string& pattern);
    std::optional<uintptr_t> scan(const std::string& module, uintptr_t start, const std::string& pattern);
    std::optional<uintptr_t> scan(HMODULE module, const std::string& pattern);
    std::optional<uintptr_t> scan(uintptr_t start, size_t length, const std::string& pattern);
    std::optional<uintptr_t> scan_reverse(uintptr_t start, size_t length, const std::string& pattern);
    
    std::optional<uintptr_t> scan_data(HMODULE, const uint8_t* data, size_t size);
    std::optional<uintptr_t> scan_data(uintptr_t start, size_t length, const uint8_t* data, size_t size);
    std::optional<uintptr_t> scan_data_reverse(uintptr_t start, size_t length, const uint8_t* data, size_t size);
    std::optional<uintptr_t> scan_ptr(HMODULE module, uintptr_t ptr);
    std::optional<uintptr_t> scan_ptr(uintptr_t start, size_t length, uintptr_t ptr);
    std::optional<uintptr_t> scan_string(HMODULE module, const std::string& str, bool zero_terminated = false);
    std::optional<uintptr_t> scan_string(HMODULE module, const std::wstring& str, bool zero_terminated = false);
    std::optional<uintptr_t> scan_string(uintptr_t start, size_t length, const std::string& str, bool zero_terminated = false);
    std::optional<uintptr_t> scan_string(uintptr_t start, size_t length, const std::wstring& str, bool zero_terminated = false);
    std::vector<uintptr_t> scan_strings(HMODULE module, const std::string& str, bool zero_terminated = false);
    std::vector<uintptr_t> scan_strings(HMODULE module, const std::wstring& str, bool zero_terminated = false);
    std::vector<uintptr_t> scan_strings(uintptr_t start, size_t length, const std::string& str, bool zero_terminated = false);
    std::vector<uintptr_t> scan_strings(uintptr_t start, size_t length, const std::wstring& str, bool zero_terminated = false);

    std::optional<uintptr_t> scan_relative_reference_scalar(uintptr_t start, size_t length, uintptr_t ptr, std::function<bool(uintptr_t)> filter = nullptr);

    std::optional<uintptr_t> scan_relative_reference(uintptr_t start, size_t length, uintptr_t ptr, std::function<bool(uintptr_t)> filter = nullptr);
    std::optional<uintptr_t> scan_relative_reference(HMODULE module, uintptr_t ptr, std::function<bool(uintptr_t)> filter = nullptr);
    std::vector<uintptr_t> scan_relative_references(uintptr_t start, size_t length, uintptr_t ptr, std::function<bool(uintptr_t)> filter = nullptr);
    std::vector<uintptr_t> scan_relative_references(HMODULE module, uintptr_t ptr, std::function<bool(uintptr_t)> filter = nullptr);


    std::optional<uintptr_t> scan_reference(HMODULE module, uintptr_t ptr, bool relative = true);
    std::optional<uintptr_t> scan_reference(uintptr_t start, size_t length, uintptr_t ptr, bool relative = true);
    std::optional<uintptr_t> scan_relative_reference_strict(HMODULE module, uintptr_t ptr, const std::string& preceded_by);
    std::optional<uintptr_t> scan_displacement_reference(HMODULE module, uintptr_t ptr);
    std::optional<uintptr_t> scan_displacement_reference(uintptr_t start, size_t length, uintptr_t ptr);
    std::vector<uintptr_t> scan_displacement_references(HMODULE module, uintptr_t ptr);
    std::vector<uintptr_t> scan_displacement_references(uintptr_t start, size_t length, uintptr_t ptr);

    std::optional<uintptr_t> scan_opcode(uintptr_t ip, size_t num_instructions, uint8_t opcode);
    std::optional<uintptr_t> scan_disasm(uintptr_t ip, size_t num_instructions, const std::string& pattern);
    std::optional<uintptr_t> scan_mnemonic(uintptr_t ip, size_t num_instructions, const std::string& mnemonic);

    uint32_t get_insn_size(uintptr_t ip);

    uintptr_t calculate_absolute(uintptr_t address, uint8_t custom_offset = 4);

    std::optional<INSTRUX> decode_one(uint8_t* ip, size_t max_size = 1000);
    // exhaustive_decode decodes until it hits something like a return, int3, etc
    // except when it notices a conditional jmp, it will decode both branches separately
    enum ExhaustionResult {
        CONTINUE,
        BREAK,
        STEP_OVER
    };
    struct ExhaustionContext {
        uintptr_t addr{};
        INSTRUX instrux{};

        uintptr_t branch_start{};
    };
    void exhaustive_decode(uint8_t* ip, size_t max_size, std::function<ExhaustionResult(ExhaustionContext&)> callback);
    void exhaustive_decode(uint8_t* ip, size_t max_size, std::function<ExhaustionResult(INSTRUX&, uintptr_t)> callback);

    struct BasicBlock {
        struct Instruction {
            uintptr_t addr{};
            INSTRUX instrux{};
        };

        uintptr_t start{};
        uintptr_t end{};
        std::vector<Instruction> instructions{};
        std::vector<uintptr_t> branches{}; // the addresses they branch to, not the addresses of the instructions themselves
    };
    struct BasicBlockCollectOptions {
        size_t max_size{1000};
        bool sort{false};
    };
    std::vector<BasicBlock> collect_basic_blocks(uintptr_t start, const BasicBlockCollectOptions& options = {});

    PIMAGE_RUNTIME_FUNCTION_ENTRY find_function_entry(uintptr_t middle);
    std::optional<uintptr_t> find_function_start(uintptr_t middle);
    // same as prev, but keeps going backwards until the "function" it lands on
    // is actually called somewhere within the module
    std::optional<uintptr_t> find_function_start_with_call(uintptr_t middle);
    std::optional<uintptr_t> find_function_from_string_ref(HMODULE module, std::string_view str, bool zero_terminated = false);
    std::optional<uintptr_t> find_function_from_string_ref(HMODULE module, std::wstring_view str, bool zero_terminated = false);

    // finds the function(s) containing the A string, and then
    // disassembles each one looking for a reference to data that contains the B string
    std::optional<uintptr_t> find_function_with_string_refs(HMODULE module, std::wstring_view a, std::wstring_view b, bool follow_calls = false);

    // Same as the previous, but it keeps going upwards until utility::scan_ptr returns something
    std::optional<uintptr_t> find_virtual_function_start(uintptr_t middle);
    std::optional<uintptr_t> find_virtual_function_from_string_ref(HMODULE module, std::wstring_view str, bool zero_terminated = false);

    // Given any address/instruction within a function, walk a virtual table and disassemble to see if
    // any of the given functions contain the address/instruction
    std::optional<uintptr_t> find_encapsulating_virtual_function(uintptr_t vtable, size_t walk_amount, uintptr_t middle);
    std::optional<uintptr_t> find_encapsulating_virtual_function_disp(uintptr_t vtable, size_t walk_amount, uintptr_t disp, bool follow_calls = true);

    // Given any address/instruction within a function, disassemble forwards until we hit a call
    // then disassemble the called function's instructions to see if any of them contain the address/instruction
    // Is a bit naive, it could be improved by checking the function calls within the function too,
    // but it only finds the top level function that contains the address/instruction
    // It DOES check the function calls within the function, but it doesn't treat those as the encapsulating function, only the top level one
    std::optional<uintptr_t> find_encapsulating_function(uintptr_t start_instruction, uintptr_t middle);
    std::optional<uintptr_t> find_encapsulating_function_disp(uintptr_t start_instruction, uintptr_t disp, bool follow_calls = true);

    std::optional<uintptr_t> resolve_displacement(uintptr_t ip);

    struct Resolved {
        uintptr_t addr{};
        INSTRUX instrux{};
    };

    struct ResolvedDisplacement : Resolved {
        uintptr_t displacement{};
    };

    std::optional<ResolvedDisplacement> find_next_displacement(uintptr_t ip, bool follow_calls = false); // stops if ret, int3
    std::optional<Resolved> resolve_instruction(uintptr_t middle); // finds the start of the instruction given an address in the middle of the instruction 

    std::optional<ResolvedDisplacement> find_string_reference_in_path(uintptr_t start_instruction, std::string_view str, bool follow_calls = true);
    std::optional<ResolvedDisplacement> find_string_reference_in_path(uintptr_t start_instruction, std::wstring_view str, bool follow_calls = true);
    std::optional<ResolvedDisplacement> find_pointer_in_path(uintptr_t start_instruction, const void* pointer, bool follow_calls = true);
    std::optional<ResolvedDisplacement> find_displacement_in_path(uintptr_t start_instruction, uintptr_t disp, bool follow_calls = true);
    std::optional<Resolved> find_mnemonic_in_path(uintptr_t start_instruction, uint32_t num_instructions, std::string_view mnemonic, bool follow_calls = true);
    std::optional<Resolved> find_register_usage_in_path(uintptr_t start_instruction, uint32_t num_instructions, uint32_t reg, bool follow_calls = true);

    // This is scan_disasm but it will stop whenever execution fully exhausts all branches and hits a return, int3, etc
    std::optional<Resolved> find_pattern_in_path(uint8_t* ip, size_t max_size, bool follow_calls, const std::string& pattern);

    // Finds the function start given the middle, and then disassembles and stores all instructions until it hits the middle
    // We can use this to "disassemble" backwards from the middle of an instruction
    std::vector<Resolved> get_disassembly_behind(uintptr_t middle);
}
