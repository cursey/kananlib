#pragma once

#include <string>
#include <string_view>
#include <optional>
#include <cstdint>
#include <vector>


namespace utility::pdb {
    std::optional<std::string> get_pdb_path(const uint8_t* module);
    std::optional<uintptr_t> get_symbol_address(const uint8_t* module, std::string_view symbol_name);
    std::vector<std::string> enumerate_symbols(const uint8_t* module, size_t max_symbols = 100);
}