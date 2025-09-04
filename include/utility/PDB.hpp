#pragma once

#include <string>
#include <string_view>
#include <optional>
#include <cstdint>
#include <vector>
#include <unordered_map>


namespace utility::pdb {
    // Structure member information
    struct StructMember {
        std::string name;
        std::string type;
        uint32_t offset = 0;
        uint32_t size = 0;
        bool is_pointer = false;
        bool is_array = false;
        uint32_t array_count = 0;
        bool is_bitfield = false;
        uint32_t bit_position = 0;
        uint32_t bit_length = 0;
    };

    // Structure information
    struct StructInfo {
        std::string name;
        uint32_t size;
        std::vector<StructMember> members;
    };

    std::optional<std::string> get_pdb_path(const uint8_t* module);
    std::optional<uintptr_t> get_symbol_address(const uint8_t* module, std::string_view symbol_name);
    std::optional<std::string> get_symbol_name(const uint8_t* module, uintptr_t rva);
    std::unordered_map<uintptr_t, std::string> get_symbol_map(const uint8_t* module);
    std::vector<std::string> enumerate_symbols(const uint8_t* module, size_t max_symbols = 100);
    
    // Structure analysis functions (requires KANANLIB_USE_DIA_SDK to be defined)
    std::optional<StructInfo> get_struct_info(const uint8_t* module, std::string_view struct_name);
    std::vector<std::string> enumerate_structs(const uint8_t* module, size_t max_structs = 50);
    std::string generate_c_struct(const StructInfo& struct_info);
}