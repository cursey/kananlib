#include <cstdint>
#include <cstdio>
#include <iostream>

#include <windows.h>
#include <bdshemu.h>

#include "TestHelpers.hpp"

#include <utility/Emulation.hpp>

// ============================================================================
// Emulation Tests
// ============================================================================

// x86-64 instruction bytes
static const uint8_t NOP = 0x90;
// mov eax, imm32 = B8 xx xx xx xx
static const uint8_t MOV_EAX_IMM32[] = { 0xB8, 0x01, 0x00, 0x00, 0x00 }; // mov eax, 1
// xor eax, eax = 31 C0
static const uint8_t XOR_EAX_EAX[] = { 0x31, 0xC0 };
// add eax, imm8 = 83 C0 xx
static const uint8_t ADD_EAX_5[] = { 0x83, 0xC0, 0x05 };
// ret = C3
static const uint8_t RET = 0xC3;

// Helper: allocate RWX buffer and copy bytes
struct RWXBuffer {
    uint8_t* data;
    size_t size;

    RWXBuffer(size_t sz) : size(sz) {
        data = (uint8_t*)VirtualAlloc(nullptr, sz, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    }

    ~RWXBuffer() {
        if (data) VirtualFree(data, 0, MEM_RELEASE);
    }

    RWXBuffer(const RWXBuffer&) = delete;
    RWXBuffer& operator=(const RWXBuffer&) = delete;
};

// Test: ShemuContext construction with VirtualAlloc'd buffer
int test_shemu_construction() {
    RWXBuffer buf(0x1000);
    TEST_ASSERT(buf.data != nullptr);

    // Fill with NOPs
    memset(buf.data, NOP, buf.size);

    // Construct ShemuContext
    utility::ShemuContext ctx{(uintptr_t)buf.data, buf.size};

    // Verify internal state
    TEST_ASSERT(ctx.ctx != nullptr);
    TEST_ASSERT(ctx.stack.size() > 0);
    TEST_ASSERT(ctx.internal_buffer.size() > 0);
    TEST_ASSERT(ctx.ctx->Shellcode == buf.data);
    TEST_ASSERT(ctx.ctx->ShellcodeBase == (uintptr_t)buf.data);
    TEST_ASSERT(ctx.ctx->ShellcodeSize == buf.size);

    return 0;
}

// Test: simple NOP emulation
int test_shemu_nop_emulation() {
    RWXBuffer buf(0x1000);
    TEST_ASSERT(buf.data != nullptr);

    // Fill with NOPs
    memset(buf.data, NOP, buf.size);

    utility::ShemuContext ctx{(uintptr_t)buf.data, buf.size};

    // Disable NOP sled detection — we're testing emulation mechanics, not shellcode detection
    ctx.ctx->NopThreshold = 101;

    // Emulate 10 NOPs
    const auto status = ctx.emulate((uintptr_t)buf.data, 10);
    TEST_ASSERT(status == SHEMU_SUCCESS);

    // RIP should have advanced by 10 bytes (each NOP is 1 byte)
    TEST_ASSERT(ctx.ctx->Registers.RegRip == (uintptr_t)buf.data + 10);

    return 0;
}

// Test: mov eax, 1 emulation — verify register update
int test_shemu_mov_eax() {
    RWXBuffer buf(0x1000);
    TEST_ASSERT(buf.data != nullptr);

    // Fill with NOPs first
    memset(buf.data, NOP, buf.size);

    // Write: mov eax, 1 (5 bytes) at offset 0
    memcpy(buf.data, MOV_EAX_IMM32, sizeof(MOV_EAX_IMM32));

    utility::ShemuContext ctx{(uintptr_t)buf.data, buf.size};

    // Clear RAX to ensure the emulation actually sets it
    ctx.ctx->Registers.RegRax = 0;

    // Emulate 1 instruction (the mov)
    const auto status = ctx.emulate((uintptr_t)buf.data, 1);
    TEST_ASSERT(status == SHEMU_SUCCESS);

    // RAX should now be 1 (lower 32 bits)
    TEST_ASSERT((uint32_t)ctx.ctx->Registers.RegRax == 1);

    return 0;
}

// Test: multi-instruction emulation — mov eax,1; add eax,5
int test_shemu_multi_instruction() {
    RWXBuffer buf(0x1000);
    TEST_ASSERT(buf.data != nullptr);

    memset(buf.data, NOP, buf.size);

    // Write: mov eax, 1 (5 bytes) then add eax, 5 (3 bytes)
    size_t offset = 0;
    memcpy(buf.data + offset, MOV_EAX_IMM32, sizeof(MOV_EAX_IMM32));
    offset += sizeof(MOV_EAX_IMM32);
    memcpy(buf.data + offset, ADD_EAX_5, sizeof(ADD_EAX_5));

    utility::ShemuContext ctx{(uintptr_t)buf.data, buf.size};
    ctx.ctx->Registers.RegRax = 0;

    // Emulate 2 instructions
    const auto status = ctx.emulate((uintptr_t)buf.data, 2);
    TEST_ASSERT(status == SHEMU_SUCCESS);

    // RAX should be 1 + 5 = 6
    TEST_ASSERT((uint32_t)ctx.ctx->Registers.RegRax == 6);

    return 0;
}

// Test: free function emulate(base, size, ip, num_instructions)
int test_shemu_free_function() {
    RWXBuffer buf(0x1000);
    TEST_ASSERT(buf.data != nullptr);

    // Fill with NOPs, then put mov eax, 0xBEEF at the start
    memset(buf.data, NOP, buf.size);
    const uint8_t mov_eax_beef[] = { 0xB8, 0xEF, 0xBE, 0x00, 0x00 }; // mov eax, 0xBEEF
    memcpy(buf.data, mov_eax_beef, sizeof(mov_eax_beef));

    // Use the convenience free function
    auto ctx = utility::emulate((uintptr_t)buf.data, buf.size, (uintptr_t)buf.data, 1);

    TEST_ASSERT(ctx.ctx != nullptr);
    TEST_ASSERT(ctx.status == SHEMU_SUCCESS);
    TEST_ASSERT((uint32_t)ctx.ctx->Registers.RegRax == 0xBEEF);
    return 0;
}

// Test: single-step emulation (emulate() with no args)
// Note: bdshemu may execute slightly more instructions than requested per step
// due to internal counting, so we verify that each call succeeds and RIP advances.
int test_shemu_single_step() {
    RWXBuffer buf(0x1000);
    TEST_ASSERT(buf.data != nullptr);

    memset(buf.data, NOP, buf.size);

    utility::ShemuContext ctx{(uintptr_t)buf.data, buf.size};
    ctx.ctx->Registers.RegRip = (uintptr_t)buf.data;

    // Disable NOP sled detection
    ctx.ctx->NopThreshold = 101;

    // Single-step 3 times — each call should advance RIP and increase instruction count
    auto status = ctx.emulate();
    TEST_ASSERT(status == SHEMU_SUCCESS);
    const auto count1 = ctx.ctx->InstructionsCount;
    const auto rip1 = ctx.ctx->Registers.RegRip;
    TEST_ASSERT(count1 > 0);
    TEST_ASSERT(rip1 > (uintptr_t)buf.data);  // RIP must advance past start

    status = ctx.emulate();
    TEST_ASSERT(status == SHEMU_SUCCESS);
    TEST_ASSERT(ctx.ctx->InstructionsCount > count1);
    TEST_ASSERT(ctx.ctx->Registers.RegRip > rip1);

    status = ctx.emulate();
    TEST_ASSERT(status == SHEMU_SUCCESS);
    TEST_ASSERT(ctx.ctx->Registers.RegRip > rip1);

    return 0;
}

// Test: construction with HMODULE (use kernel32.dll which is always loaded)
int test_shemu_hmodule_construction() {
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    TEST_ASSERT(hKernel32 != nullptr);

    utility::ShemuContext ctx{hKernel32};

    TEST_ASSERT(ctx.ctx != nullptr);
    TEST_ASSERT(ctx.ctx->Shellcode == (uint8_t*)hKernel32);
    TEST_ASSERT(ctx.ctx->ShellcodeSize > 0);
    TEST_ASSERT(ctx.stack.size() > 0);

    return 0;
}

// ============================================================================
// main
// ============================================================================

int main() {
    std::cout << "===== kananlib-emulation-test =====" << std::endl;

    RUN_TEST(test_shemu_construction);
    RUN_TEST(test_shemu_nop_emulation);
    RUN_TEST(test_shemu_mov_eax);
    RUN_TEST(test_shemu_multi_instruction);
    RUN_TEST(test_shemu_free_function);
    RUN_TEST(test_shemu_single_step);
    RUN_TEST(test_shemu_hmodule_construction);

    return test_summary();
}
