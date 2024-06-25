#pragma once

#include <cstdint>
#include <vector>

namespace utility {
    bool isGoodPtr(uintptr_t ptr, size_t len, uint32_t access);
    bool isGoodReadPtr(uintptr_t ptr, size_t len);
    bool isGoodWritePtr(uintptr_t ptr, size_t len);
    bool isGoodCodePtr(uintptr_t ptr, size_t len);

    bool is_stub_code(uint8_t* code);

    struct ValidRegion {
        uintptr_t start;
        size_t length;
    };

    std::vector<ValidRegion> get_valid_regions(uintptr_t start, size_t length);
}
