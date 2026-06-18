#include <cstdint>
#include <string>
#include <iostream>
#include <cstring>

#include <Windows.h>

#include <utility/Scan.hpp>
#include <utility/Module.hpp>

#include "TestHelpers.hpp"

// ============================================================================
// Helper: VirtualAlloc RWX page with ScopeGuard-like cleanup
// ============================================================================

struct RWXPage {
    uint8_t* data{};
    size_t size{0x1000};

    RWXPage() {
        data = (uint8_t*)VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    }
    ~RWXPage() {
        if (data) VirtualFree(data, 0, MEM_RELEASE);
    }
    RWXPage(const RWXPage&) = delete;
    RWXPage& operator=(const RWXPage&) = delete;
};

// ============================================================================
// Known x86-64 instruction bytes for testing
// ============================================================================
// mov eax, 1       -> B8 01 00 00 00   (5 bytes)
// ret              -> C3               (1 byte)
// nop              -> 90               (1 byte)
// xor eax, eax     -> 31 C0            (2 bytes)
// push rbp         -> 55               (1 byte)
// pop rbp          -> 5D               (1 byte)
// mov eax, 0x12345678 -> B8 78 56 34 12 (5 bytes)

static constexpr uint8_t CODE_MOV_EAX_1[]   = {0xB8, 0x01, 0x00, 0x00, 0x00};
static constexpr uint8_t CODE_RET[]          = {0xC3};
static constexpr uint8_t CODE_NOP[]          = {0x90};
static constexpr uint8_t CODE_XOR_EAX[]      = {0x31, 0xC0};
static constexpr uint8_t CODE_PUSH_RBP[]     = {0x55};
static constexpr uint8_t CODE_POP_RBP[]      = {0x5D};

// ============================================================================
// Test: scan_reverse — reverse direction scan in a buffer
// ============================================================================

int test_scan_reverse() {
    RWXPage page;
    TEST_ASSERT(page.data != nullptr);

    // Fill page with zeros
    memset(page.data, 0, page.size);

    // Place a known byte pattern at offset 0x100
    constexpr size_t TARGET_OFFSET = 0x100;
    page.data[TARGET_OFFSET]     = 0xDE;
    page.data[TARGET_OFFSET + 1] = 0xAD;
    page.data[TARGET_OFFSET + 2] = 0xBE;
    page.data[TARGET_OFFSET + 3] = 0xEF;

    // Also place the same pattern at offset 0x200 (closer to scan start)
    page.data[0x200]     = 0xDE;
    page.data[0x200 + 1] = 0xAD;
    page.data[0x200 + 2] = 0xBE;
    page.data[0x200 + 3] = 0xEF;

    // Scan backwards from offset 0x300 — should find offset 0x200 first
    const auto start = (uintptr_t)&page.data[0x300];
    const size_t length = 0x300; // scan back 0x300 bytes
    const auto result = utility::scan_reverse(start, length, "DE AD BE EF");

    TEST_ASSERT(result.has_value());
    // scan_reverse scans backwards from start, so first match going backwards from 0x300 should be 0x200
    TEST_ASSERT(*result == (uintptr_t)&page.data[0x200]);
    std::cout << "  Found pattern at offset 0x" << std::hex << (*result - (uintptr_t)page.data) << std::dec << std::endl;

    return 0;
}

// ============================================================================
// Test: scan_data — raw byte scan in a buffer
// ============================================================================

int test_scan_data() {
    RWXPage page;
    TEST_ASSERT(page.data != nullptr);

    memset(page.data, 0, page.size);

    // Place known data at offset 0x80
    const uint8_t needle[] = {0xCA, 0xFE, 0xBA, 0xBE};
    memcpy(&page.data[0x80], needle, sizeof(needle));

    // Test the start/length overload
    const auto result = utility::scan_data((uintptr_t)page.data, page.size, needle, sizeof(needle));
    TEST_ASSERT(result.has_value());
    TEST_ASSERT(*result == (uintptr_t)&page.data[0x80]);
    std::cout << "  scan_data found at offset 0x" << std::hex << (*result - (uintptr_t)page.data) << std::dec << std::endl;

    // Test scan_data_t (typed version)
    const uint32_t typed_val = 0xBEBAFECA; // little-endian representation
    const auto result_typed = utility::scan_data_t((uintptr_t)page.data, page.size, typed_val);
    TEST_ASSERT(result_typed.has_value());
    TEST_ASSERT(*result_typed == (uintptr_t)&page.data[0x80]);

    // Negative: scan for data that doesn't exist
    const uint8_t missing[] = {0x12, 0x34, 0x56, 0x78};
    const auto no_result = utility::scan_data((uintptr_t)page.data, page.size, missing, sizeof(missing));
    TEST_ASSERT(!no_result.has_value());

    // Test HMODULE overload by scanning own module for a known string
    const auto* exe = utility::get_executable();
    if (exe) {
        const uint8_t test_byte = 'T'; // ASCII 'T'
        const auto module_result = utility::scan_data((HMODULE)exe, &test_byte, 1);
        TEST_ASSERT(module_result.has_value());
        std::cout << "  scan_data (HMODULE) found 'T' at " << std::hex << *module_result << std::dec << std::endl;
    }

    return 0;
}

// ============================================================================
// Test: scan_ptr — pointer value scan
// ============================================================================

int test_scan_ptr() {
    RWXPage page;
    TEST_ASSERT(page.data != nullptr);

    memset(page.data, 0, page.size);

    // Store a pointer value at a known location (8-byte aligned). Use memcpy:
    // the backing storage is uint8_t[], so writing through uintptr_t* would be
    // type-punning UB (and alignment-sensitive if the offset changes).
    const uintptr_t test_ptr = 0xDEADBEEFCAFEBABE;
    constexpr size_t PTR_OFFSET = 0x100;
    memcpy(page.data + PTR_OFFSET, &test_ptr, sizeof(test_ptr));
    // scan_ptr (start/length overload) — scans for aligned pointer
    const auto result = utility::scan_ptr((uintptr_t)page.data, page.size, test_ptr);
    TEST_ASSERT(result.has_value());
    TEST_ASSERT(*result == (uintptr_t)&page.data[PTR_OFFSET]);
    std::cout << "  scan_ptr found at offset 0x" << std::hex << (*result - (uintptr_t)page.data) << std::dec << std::endl;

    // scan_ptr_noalign — can find unaligned pointers.
    // Place pointer bytes at an intentionally unaligned offset; memcpy avoids
    // unaligned uintptr_t stores and strict-aliasing UB.
    constexpr size_t UNALIGNED_OFFSET = 0x83;
    memcpy(page.data + UNALIGNED_OFFSET, &test_ptr, sizeof(test_ptr));
    const auto noalign_result = utility::scan_ptr_noalign((uintptr_t)page.data, page.size, test_ptr);
    TEST_ASSERT(noalign_result.has_value());
    // Should find the first occurrence (either aligned or unaligned)
    std::cout << "  scan_ptr_noalign found at offset 0x" << std::hex << (*noalign_result - (uintptr_t)page.data) << std::dec << std::endl;

    // Negative: scan for pointer that doesn't exist
    const auto no_result = utility::scan_ptr((uintptr_t)page.data, page.size, 0x12345678);
    TEST_ASSERT(!no_result.has_value());

    return 0;
}

// ============================================================================
// Test: scan_opcode — find instruction by opcode byte
// ============================================================================

int test_scan_opcode() {
    RWXPage page;
    TEST_ASSERT(page.data != nullptr);

    memset(page.data, 0xCC, page.size); // fill with int3

    // Write: nop; nop; mov eax,1; ret
    size_t offset = 0;
    page.data[offset++] = 0x90; // nop
    page.data[offset++] = 0x90; // nop
    page.data[offset++] = 0xB8; // mov eax, imm32
    page.data[offset++] = 0x01;
    page.data[offset++] = 0x00;
    page.data[offset++] = 0x00;
    page.data[offset++] = 0x00;
    page.data[offset++] = 0xC3; // ret

    // Search for ret opcode (0xC3) — should find it at offset 7
    const auto result = utility::scan_opcode((uintptr_t)page.data, 10, 0xC3);
    TEST_ASSERT(result.has_value());
    TEST_ASSERT(*result == (uintptr_t)&page.data[7]);
    std::cout << "  Found RET (0xC3) at offset 7" << std::endl;

    // Search for mov eax,imm32 opcode (0xB8) — should find at offset 2
    const auto mov_result = utility::scan_opcode((uintptr_t)page.data, 10, 0xB8);
    TEST_ASSERT(mov_result.has_value());
    TEST_ASSERT(*mov_result == (uintptr_t)&page.data[2]);
    std::cout << "  Found MOV EAX (0xB8) at offset 2" << std::endl;

    // Search for opcode that doesn't exist in the sequence
    const auto no_result = utility::scan_opcode((uintptr_t)page.data, 10, 0x48); // no REX.W prefix
    TEST_ASSERT(!no_result.has_value());

    return 0;
}

// ============================================================================
// Test: scan_mnemonic — find instruction by mnemonic string
// ============================================================================

int test_scan_mnemonic() {
    RWXPage page;
    TEST_ASSERT(page.data != nullptr);

    memset(page.data, 0xCC, page.size); // fill with int3

    // Write: nop; xor eax, eax; mov eax, 1; ret
    size_t offset = 0;
    page.data[offset++] = 0x90; // nop
    page.data[offset++] = 0x31; // xor eax, eax
    page.data[offset++] = 0xC0;
    page.data[offset++] = 0xB8; // mov eax, imm32
    page.data[offset++] = 0x01;
    page.data[offset++] = 0x00;
    page.data[offset++] = 0x00;
    page.data[offset++] = 0x00;
    page.data[offset++] = 0xC3; // ret

    // Search for NOP mnemonic
    const auto nop_result = utility::scan_mnemonic((uintptr_t)page.data, 10, "NOP");
    TEST_ASSERT(nop_result.has_value());
    TEST_ASSERT(*nop_result == (uintptr_t)&page.data[0]);
    std::cout << "  Found NOP at offset 0" << std::endl;

    // Search for XOR mnemonic
    const auto xor_result = utility::scan_mnemonic((uintptr_t)page.data, 10, "XOR");
    TEST_ASSERT(xor_result.has_value());
    TEST_ASSERT(*xor_result == (uintptr_t)&page.data[1]);
    std::cout << "  Found XOR at offset 1" << std::endl;

    // Search for RET mnemonic
    const auto ret_result = utility::scan_mnemonic((uintptr_t)page.data, 10, "RETN");
    TEST_ASSERT(ret_result.has_value());
    TEST_ASSERT(*ret_result == (uintptr_t)&page.data[8]);
    std::cout << "  Found RETN at offset 8" << std::endl;

    // Negative: search for mnemonic not present
    const auto no_result = utility::scan_mnemonic((uintptr_t)page.data, 10, "PUSH");
    TEST_ASSERT(!no_result.has_value());

    return 0;
}

// ============================================================================
// Test: get_insn_size — get instruction length at address
// ============================================================================

int test_get_insn_size() {
    RWXPage page;
    TEST_ASSERT(page.data != nullptr);

    // Write known instructions at offset 0
    // nop (1 byte), xor eax, eax (2 bytes), mov eax, 1 (5 bytes), ret (1 byte)
    size_t offset = 0;
    page.data[offset++] = 0x90; // nop           — 1 byte
    page.data[offset++] = 0x31; // xor eax, eax  — 2 bytes
    page.data[offset++] = 0xC0;
    page.data[offset++] = 0xB8; // mov eax, 1    — 5 bytes
    page.data[offset++] = 0x01;
    page.data[offset++] = 0x00;
    page.data[offset++] = 0x00;
    page.data[offset++] = 0x00;
    page.data[offset++] = 0xC3; // ret           — 1 byte

    // Test each instruction size
    const uint32_t nop_size = utility::get_insn_size((uintptr_t)&page.data[0]);
    TEST_ASSERT(nop_size == 1);
    std::cout << "  NOP size: " << nop_size << std::endl;

    const uint32_t xor_size = utility::get_insn_size((uintptr_t)&page.data[1]);
    TEST_ASSERT(xor_size == 2);
    std::cout << "  XOR EAX, EAX size: " << xor_size << std::endl;

    const uint32_t mov_size = utility::get_insn_size((uintptr_t)&page.data[3]);
    TEST_ASSERT(mov_size == 5);
    std::cout << "  MOV EAX, 1 size: " << mov_size << std::endl;

    const uint32_t ret_size = utility::get_insn_size((uintptr_t)&page.data[8]);
    TEST_ASSERT(ret_size == 1);
    std::cout << "  RET size: " << ret_size << std::endl;

    // Test on push rbp (1 byte) and 2-byte instruction
    page.data[0x20] = 0x55; // push rbp — 1 byte
    page.data[0x21] = 0x48; // REX.W prefix
    page.data[0x22] = 0x89; // mov [rsp+8], rcx
    page.data[0x23] = 0x4C;
    page.data[0x24] = 0x24;
    page.data[0x25] = 0x08;

    const uint32_t push_size = utility::get_insn_size((uintptr_t)&page.data[0x20]);
    TEST_ASSERT(push_size == 1);
    std::cout << "  PUSH RBP size: " << push_size << std::endl;

    const uint32_t mov_rsp_size = utility::get_insn_size((uintptr_t)&page.data[0x21]);
    TEST_ASSERT(mov_rsp_size == 5); // 48 89 4C 24 08 = 5 bytes
    std::cout << "  MOV [RSP+8], RCX size: " << mov_rsp_size << std::endl;

    return 0;
}

// ============================================================================
// Test: calculate_absolute — resolve relative offset to absolute
// ============================================================================

int test_calculate_absolute() {
    RWXPage page;
    TEST_ASSERT(page.data != nullptr);

    memset(page.data, 0, page.size);

    // Place a known 32-bit relative offset at offset 0x100
    // We want: calculate_absolute(&page.data[0x100], 4) == &page.data[0x200]
    // So offset should be: target - (address + 4) = 0x200 - 0x104 = 0xFC
    const uintptr_t addr = (uintptr_t)&page.data[0x100];
    const uintptr_t expected_target = (uintptr_t)&page.data[0x200];
    const int32_t rel_offset = (int32_t)(expected_target - (addr + 4));
    *(int32_t*)&page.data[0x100] = rel_offset;

    const uintptr_t result = utility::calculate_absolute(addr);
    TEST_ASSERT(result == expected_target);
    std::cout << "  calculate_absolute: 0x" << std::hex << addr << " + 4 + " << rel_offset << " = 0x" << result << std::dec << std::endl;

    // Test with custom offset
    // We want: calculate_absolute(&page.data[0x300], 2) == &page.data[0x400]
    // offset = target - (address + 2) = 0x400 - 0x302 = 0xFE
    const uintptr_t addr2 = (uintptr_t)&page.data[0x300];
    const uintptr_t expected_target2 = (uintptr_t)&page.data[0x400];
    const int32_t rel_offset2 = (int32_t)(expected_target2 - (addr2 + 2));
    *(int32_t*)&page.data[0x300] = rel_offset2;

    const uintptr_t result2 = utility::calculate_absolute(addr2, 2);
    TEST_ASSERT(result2 == expected_target2);
    std::cout << "  calculate_absolute (custom_offset=2): 0x" << std::hex << addr2 << " + 2 + " << rel_offset2 << " = 0x" << result2 << std::dec << std::endl;

    // Test negative offset (backwards jump)
    // We want: calculate_absolute(&page.data[0x200], 4) == &page.data[0x100]
    // offset = target - (address + 4) = 0x100 - 0x204 = -0x104
    const uintptr_t addr3 = (uintptr_t)&page.data[0x200];
    const uintptr_t expected_target3 = (uintptr_t)&page.data[0x100];
    const int32_t rel_offset3 = (int32_t)(expected_target3 - (addr3 + 4));
    *(int32_t*)&page.data[0x200] = rel_offset3;

    const uintptr_t result3 = utility::calculate_absolute(addr3);
    TEST_ASSERT(result3 == expected_target3);
    std::cout << "  calculate_absolute (negative): 0x" << std::hex << addr3 << " + 4 + " << rel_offset3 << " = 0x" << result3 << std::dec << std::endl;

    return 0;
}

// ============================================================================
// Test: decode_one — decode a single instruction
// ============================================================================

int test_decode_one() {
    RWXPage page;
    TEST_ASSERT(page.data != nullptr);

    // Write: nop (90) at offset 0
    page.data[0] = 0x90;

    const auto nop = utility::decode_one(&page.data[0]);
    TEST_ASSERT(nop.has_value());
    TEST_ASSERT(nop->Length == 1);
    std::cout << "  NOP decoded: length=" << nop->Length << std::endl;

    // Write: mov eax, 1 (B8 01 00 00 00) at offset 0x10
    page.data[0x10] = 0xB8;
    page.data[0x11] = 0x01;
    page.data[0x12] = 0x00;
    page.data[0x13] = 0x00;
    page.data[0x14] = 0x00;

    const auto mov = utility::decode_one(&page.data[0x10]);
    TEST_ASSERT(mov.has_value());
    TEST_ASSERT(mov->Length == 5);
    std::cout << "  MOV EAX,1 decoded: length=" << mov->Length << std::endl;

    // Write: ret (C3) at offset 0x20
    page.data[0x20] = 0xC3;

    const auto ret = utility::decode_one(&page.data[0x20]);
    TEST_ASSERT(ret.has_value());
    TEST_ASSERT(ret->Length == 1);
    std::cout << "  RET decoded: length=" << ret->Length << std::endl;

    // Write: xor eax, eax (31 C0) at offset 0x30
    page.data[0x30] = 0x31;
    page.data[0x31] = 0xC0;

    const auto xor_eax = utility::decode_one(&page.data[0x30]);
    TEST_ASSERT(xor_eax.has_value());
    TEST_ASSERT(xor_eax->Length == 2);
    std::cout << "  XOR EAX,EAX decoded: length=" << xor_eax->Length << std::endl;

    // Negative: decode from an invalid location (should return nullopt)
    // Writing 0xFF 0xFF is an invalid two-byte sequence
    page.data[0x40] = 0xFF;
    page.data[0x41] = 0xFF;
    page.data[0x42] = 0xFF;
    page.data[0x43] = 0xFF;
    page.data[0x44] = 0xFF;

    // Actually 0xFF /7 (0xFF 0xFF) is a valid instruction (jmp qword ptr [...])
    // Let's just check that decode_one handles zero-length gracefully
    const auto zero_decode = utility::decode_one(&page.data[0], 0);
    // With max_size=0, the decoder should fail
    TEST_EXPECT(!zero_decode.has_value());

    return 0;
}

// ============================================================================
// main
// ============================================================================

int main() try {
    std::cout << "===== kananlib-scan-test =====" << std::endl;

    RUN_TEST(test_scan_reverse);
    RUN_TEST(test_scan_data);
    RUN_TEST(test_scan_ptr);
    RUN_TEST(test_scan_opcode);
    RUN_TEST(test_scan_mnemonic);
    RUN_TEST(test_get_insn_size);
    RUN_TEST(test_calculate_absolute);
    RUN_TEST(test_decode_one);

    return test_summary();
} catch(const std::exception& e) {
    std::cout << "Exception caught: " << e.what() << std::endl;
    return 1;
} catch(...) {
    std::cout << "Unknown exception caught" << std::endl;
    return 1;
}
