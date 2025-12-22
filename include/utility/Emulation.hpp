#pragma once

#include <memory>
#include <vector>
#include <cstdint>
#include <functional>

#include <windows.h>

#include "Scan.hpp"

struct _SHEMU_CONTEXT;
typedef struct _SHEMU_CONTEXT SHEMU_CONTEXT;

namespace utility {
struct ShemuContext {
    ShemuContext(uintptr_t base, size_t buffer_size, size_t stack_size = 0x2000);
    ShemuContext(HMODULE module, size_t stack_size = 0x2000);

    uint32_t emulate(uintptr_t ip, size_t num_instructions);
    uint32_t emulate(); // emulate one instruction from the current IP

    std::unique_ptr<SHEMU_CONTEXT> ctx;
    std::vector<uint8_t> stack{};
    std::vector<uint8_t> internal_buffer{};
    uint32_t status{};
};

ShemuContext emulate(uintptr_t base, size_t size, uintptr_t ip, size_t num_instructions);
ShemuContext emulate(HMODULE module, uintptr_t ip, size_t num_instructions);

struct ShemuContextExtended {
    ShemuContext* ctx;

    struct {
        INSTRUX ix{};
        bool writes_to_memory{false};
    } next;
};

void emulate(HMODULE module, uintptr_t ip, size_t num_instructions, std::function<ExhaustionResult(const ShemuContextExtended& ctx)> callback);
void emulate(HMODULE module, uintptr_t ip, size_t num_instructions, ShemuContext& start_ctx, std::function<ExhaustionResult(const ShemuContextExtended& ctx)> callback);
}