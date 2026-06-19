// ============================================================================
// Coverage tests for Scan.hpp public APIs NOT covered by TestScan.cpp
// or TestBehavior.cpp.
//
// Functions covered:
//   scan_data_reverse, scan_ptr_noalign, scan_string (buffer overloads),
//   scan_relative_reference_scalar, scan_relative_reference_scalar_byte_by_byte,
//   scan_relative_reference (buffer overload), scan_relative_references,
//   scan_reference, scan_relative_reference_strict,
//   resolve_displacement, exhaustive_decode, linear_decode,
//   collect_basic_blocks_into, scan_disasm
// ============================================================================

#include <cstdint>
#include <string>
#include <iostream>
#include <cstring>
#include <vector>
#include <functional>

#include <windows.h>

#include <utility/Scan.hpp>
#include <utility/Module.hpp>

#include "TestHelpers.hpp"

// ============================================================================
// Helper: VirtualAlloc RWX page
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
// x86-64 instruction byte constants
// ============================================================================

// XOR EAX, EAX (2 bytes)
static constexpr uint8_t CODE_XOR_EAX[]     = {0x31, 0xC0};
// NOP (1 byte)
static constexpr uint8_t CODE_NOP[]          = {0x90};
// RET (1 byte)
static constexpr uint8_t CODE_RET[]          = {0xC3};
// INT3 (1 byte)
static constexpr uint8_t CODE_INT3[]         = {0xCC};
// MOV EAX, 1 (5 bytes)
static constexpr uint8_t CODE_MOV_EAX_1[]    = {0xB8, 0x01, 0x00, 0x00, 0x00};
// PUSH RBP (1 byte)
static constexpr uint8_t CODE_PUSH_RBP[]     = {0x55};
// POP RBP (1 byte)
static constexpr uint8_t CODE_POP_RBP[]      = {0x5D};

// ============================================================================
// scan_data_reverse — finds data scanning backwards
// ============================================================================

int test_scan_data_reverse_finds_match() {
    RWXPage page;
    TEST_ASSERT(page.data != nullptr);

    // Place a unique marker near the end of the page
    const uint8_t marker[] = {0xDE, 0xAD, 0xBE, 0xEF};
    const size_t marker_offset = 0xF00;
    memcpy(page.data + marker_offset, marker, sizeof(marker));

    // Scan backwards from marker_offset (start) searching for the marker
    // scan_data_reverse(start, length, data, size) scans from `start` backwards `length` bytes
    auto result = utility::scan_data_reverse(
        (uintptr_t)(page.data + marker_offset), 0x100, marker, sizeof(marker));

    TEST_ASSERT(result.has_value());
    TEST_ASSERT(*result == (uintptr_t)(page.data + marker_offset));
    return 0;
}

int test_scan_data_reverse_not_found() {
    RWXPage page;
    TEST_ASSERT(page.data != nullptr);

    // Fill page with 0x00, search for non-existent pattern
    memset(page.data, 0x00, page.size);
    const uint8_t needle[] = {0xDE, 0xAD};
    auto result = utility::scan_data_reverse(
        (uintptr_t)(page.data + 0x100), 0x100, needle, sizeof(needle));

    TEST_ASSERT(!result.has_value());
    return 0;
}

int test_scan_data_reverse_zero_length() {
    RWXPage page;
    TEST_ASSERT(page.data != nullptr);

    const uint8_t data[] = {0x42};
    auto result = utility::scan_data_reverse((uintptr_t)(page.data + 0x100), 0, data, 1);
    TEST_ASSERT(!result.has_value());
    return 0;
}

// ============================================================================
// scan_ptr_noalign — byte-level pointer search (no alignment)
// ============================================================================

int test_scan_ptr_noalign_finds_unaligned() {
    RWXPage page;
    TEST_ASSERT(page.data != nullptr);

    memset(page.data, 0x00, page.size);

    // Place a uintptr_t at an unaligned offset (offset 5)
    const uintptr_t needle = 0xDEADBEEFCAFEBABEULL;
    memcpy(page.data + 5, &needle, sizeof(needle));

    auto result = utility::scan_ptr_noalign((uintptr_t)page.data, page.size, needle);
    TEST_ASSERT(result.has_value());
    TEST_ASSERT(*result == (uintptr_t)(page.data + 5));
    return 0;
}

int test_scan_ptr_noalign_not_found() {
    RWXPage page;
    TEST_ASSERT(page.data != nullptr);

    memset(page.data, 0x00, page.size);
    auto result = utility::scan_ptr_noalign((uintptr_t)page.data, page.size, 0x12345678);
    TEST_ASSERT(!result.has_value());
    return 0;
}

// ============================================================================
// scan_string — buffer overloads (string and wstring)
// ============================================================================

int test_scan_string_finds_ascii() {
    RWXPage page;
    TEST_ASSERT(page.data != nullptr);

    memset(page.data, 0x00, page.size);
    const char* marker = "HELLO_WORLD";
    memcpy(page.data + 0x100, marker, strlen(marker));

    auto result = utility::scan_string((uintptr_t)page.data, page.size, std::string{marker});
    TEST_ASSERT(result.has_value());
    TEST_ASSERT(*result == (uintptr_t)(page.data + 0x100));
    return 0;
}

int test_scan_string_wchar_finds_wide() {
    RWXPage page;
    TEST_ASSERT(page.data != nullptr);

    memset(page.data, 0x00, page.size);
    const wchar_t* marker = L"WIDE_TEST";
    size_t marker_bytes = wcslen(marker) * sizeof(wchar_t);
    memcpy(page.data + 0x200, marker, marker_bytes);

    auto result = utility::scan_string((uintptr_t)page.data, page.size, std::wstring{marker});
    TEST_ASSERT(result.has_value());
    TEST_ASSERT(*result == (uintptr_t)(page.data + 0x200));
    return 0;
}

int test_scan_string_empty_returns_nullopt() {
    RWXPage page;
    TEST_ASSERT(page.data != nullptr);

    auto result = utility::scan_string((uintptr_t)page.data, page.size, std::string{});
    TEST_ASSERT(!result.has_value());

    auto result2 = utility::scan_string((uintptr_t)page.data, page.size, std::wstring{});
    TEST_ASSERT(!result2.has_value());
    return 0;
}

int test_scan_string_zero_terminated() {
    RWXPage page;
    TEST_ASSERT(page.data != nullptr);

    memset(page.data, 0x00, page.size);
    const char* marker = "ZZTERM";
    size_t len = strlen(marker);
    // Copy marker + null terminator
    memcpy(page.data + 0x300, marker, len + 1);

    // With zero_terminated=true, the search includes the trailing 0x00
    auto result = utility::scan_string((uintptr_t)page.data, page.size, std::string{marker}, true);
    TEST_ASSERT(result.has_value());
    TEST_ASSERT(*result == (uintptr_t)(page.data + 0x300));
    return 0;
}

// ============================================================================
// scan_relative_reference_scalar — finds rel32 displacement
// ============================================================================

// Helper: compute a 4-byte relative displacement for scan_relative_reference.
// The functions use: landing = pos + 4 + *(int32_t*)pos
// So: disp32 = target - pos - 4
static void place_rel32(uint8_t* page_data, size_t offset, uintptr_t target) {
    uintptr_t pos = (uintptr_t)(page_data + offset);
    int32_t disp = (int32_t)(target - pos - 4);
    memcpy(page_data + offset, &disp, sizeof(disp));
}

int test_scan_relative_reference_scalar_finds_match() {
    RWXPage page;
    TEST_ASSERT(page.data != nullptr);
    memset(page.data, 0x00, page.size);

    // Place rel32 at offset 0x100 pointing to offset 0x500
    const uintptr_t target = (uintptr_t)(page.data + 0x500);
    place_rel32(page.data, 0x100, target);

    // Use scalar variant directly (length < 128 triggers scalar anyway)
    auto result = utility::scan_relative_reference_scalar(
        (uintptr_t)page.data, page.size, target, nullptr);

    TEST_ASSERT(result.has_value());
    TEST_ASSERT(*result == (uintptr_t)(page.data + 0x100));
    return 0;
}

int test_scan_relative_reference_scalar_not_found() {
    RWXPage page;
    TEST_ASSERT(page.data != nullptr);
    // Fill with 0xCC so no displacement accidentally matches the target
    memset(page.data, 0xCC, page.size);

    const uintptr_t target = (uintptr_t)(page.data + 0x500);
    auto result = utility::scan_relative_reference_scalar(
        (uintptr_t)page.data, page.size, target, nullptr);

    TEST_ASSERT(!result.has_value());
    return 0;
}

// ============================================================================
// scan_relative_reference_scalar_byte_by_byte — byte-by-byte rel32 search
// ============================================================================

int test_scan_relative_reference_bbb_finds_match() {
    RWXPage page;
    TEST_ASSERT(page.data != nullptr);
    memset(page.data, 0x00, page.size);

    const uintptr_t target = (uintptr_t)(page.data + 0x500);
    place_rel32(page.data, 0x100, target);

    auto result = utility::scan_relative_reference_scalar_byte_by_byte(
        (uintptr_t)page.data, page.size, target, nullptr);

    TEST_ASSERT(result.has_value());
    TEST_ASSERT(*result == (uintptr_t)(page.data + 0x100));
    return 0;
}

int test_scan_relative_reference_bbb_not_found() {
    RWXPage page;
    TEST_ASSERT(page.data != nullptr);
    memset(page.data, 0xCC, page.size);

    const uintptr_t target = (uintptr_t)(page.data + 0x500);
    auto result = utility::scan_relative_reference_scalar_byte_by_byte(
        (uintptr_t)page.data, page.size, target, nullptr);

    TEST_ASSERT(!result.has_value());
    return 0;
}

// ============================================================================
// scan_relative_reference — main dispatch (AVX2 if available, else scalar)
// ============================================================================

int test_scan_relative_reference_finds_match() {
    RWXPage page;
    TEST_ASSERT(page.data != nullptr);
    memset(page.data, 0x00, page.size);

    const uintptr_t target = (uintptr_t)(page.data + 0x500);
    place_rel32(page.data, 0x100, target);

    // Full-size page (>128 bytes) may trigger AVX2 path
    auto result = utility::scan_relative_reference(
        (uintptr_t)page.data, page.size, target, nullptr);

    TEST_ASSERT(result.has_value());
    TEST_ASSERT(*result == (uintptr_t)(page.data + 0x100));
    return 0;
}

int test_scan_relative_reference_with_filter() {
    RWXPage page;
    TEST_ASSERT(page.data != nullptr);
    memset(page.data, 0x00, page.size);

    const uintptr_t target = (uintptr_t)(page.data + 0x500);
    place_rel32(page.data, 0x100, target);

    // Filter that rejects all candidates
    auto result = utility::scan_relative_reference(
        (uintptr_t)page.data, page.size, target,
        [](uintptr_t) { return false; });

    TEST_ASSERT(!result.has_value());
    return 0;
}

int test_scan_relative_reference_not_found() {
    RWXPage page;
    TEST_ASSERT(page.data != nullptr);
    memset(page.data, 0xCC, page.size);

    auto result = utility::scan_relative_reference(
        (uintptr_t)page.data, page.size, (uintptr_t)(page.data + 0x500), nullptr);

    TEST_ASSERT(!result.has_value());
    return 0;
}

// ============================================================================
// scan_relative_references — finds all instances
// ============================================================================

int test_scan_relative_references_finds_all() {
    RWXPage page;
    TEST_ASSERT(page.data != nullptr);
    memset(page.data, 0x00, page.size);

    const uintptr_t target = (uintptr_t)(page.data + 0x500);

    // Place two rel32 references to the same target
    place_rel32(page.data, 0x100, target);
    place_rel32(page.data, 0x200, target);

    auto results = utility::scan_relative_references(
        (uintptr_t)page.data, page.size, target, nullptr);

    TEST_ASSERT(results.size() >= 2);

    // Check that both positions are found
    bool found100 = false, found200 = false;
    for (auto addr : results) {
        if (addr == (uintptr_t)(page.data + 0x100)) found100 = true;
        if (addr == (uintptr_t)(page.data + 0x200)) found200 = true;
    }
    TEST_ASSERT(found100);
    TEST_ASSERT(found200);
    return 0;
}

// ============================================================================
// scan_reference — absolute and relative modes
// ============================================================================

int test_scan_reference_absolute() {
    RWXPage page;
    TEST_ASSERT(page.data != nullptr);
    memset(page.data, 0x00, page.size);

    // Place a pointer-sized value at offset 0x80
    const uintptr_t needle = 0xCAFEBABE;
    memcpy(page.data + 0x80, &needle, sizeof(needle));

    // absolute mode (relative=false) → delegates to scan_ptr
    auto result = utility::scan_reference(
        (uintptr_t)page.data, page.size, needle, false);

    TEST_ASSERT(result.has_value());
    TEST_ASSERT(*result == (uintptr_t)(page.data + 0x80));
    return 0;
}

int test_scan_reference_relative() {
    RWXPage page;
    TEST_ASSERT(page.data != nullptr);
    memset(page.data, 0x00, page.size);

    const uintptr_t target = (uintptr_t)(page.data + 0x500);
    place_rel32(page.data, 0x100, target);

    // relative mode (relative=true) → delegates to scan_relative_reference
    auto result = utility::scan_reference(
        (uintptr_t)page.data, page.size, target, true);

    TEST_ASSERT(result.has_value());
    TEST_ASSERT(*result == (uintptr_t)(page.data + 0x100));
    return 0;
}

// ============================================================================
// scan_relative_reference_strict — with preceding byte pattern
// ============================================================================

int test_scan_relative_reference_strict_finds_with_preceding() {
    RWXPage page;
    TEST_ASSERT(page.data != nullptr);
    memset(page.data, 0x00, page.size);

    // Layout at offset 0x100: [preceding pattern 48 8B 05] [rel32]
    // The rel32 is at offset 0x103, pointing to target
    const uintptr_t target = (uintptr_t)(page.data + 0x500);
    // 48 8B 05 = MOV RAX, [RIP+...] prefix bytes
    page.data[0x100] = 0x48;
    page.data[0x101] = 0x8B;
    page.data[0x102] = 0x05;
    place_rel32(page.data, 0x103, target);

    auto result = utility::scan_relative_reference_strict(
        (uintptr_t)page.data, page.size, target, "48 8B 05");

    TEST_ASSERT(result.has_value());
    TEST_ASSERT(*result == (uintptr_t)(page.data + 0x103));
    return 0;
}

int test_scan_relative_reference_strict_empty_pattern() {
    RWXPage page;
    TEST_ASSERT(page.data != nullptr);

    // Empty preceded_by should return nullopt
    auto result = utility::scan_relative_reference_strict(
        (uintptr_t)page.data, page.size, (uintptr_t)(page.data + 0x500), "");

    TEST_ASSERT(!result.has_value());
    return 0;
}

// ============================================================================
// resolve_displacement — resolves RIP-relative / offset operands
// ============================================================================

int test_resolve_displacement_lea_rip() {
    RWXPage page;
    TEST_ASSERT(page.data != nullptr);
    memset(page.data, 0xCC, page.size);

    // Place: LEA RAX, [RIP+0x10] = 48 8D 05 10 00 00 00 (7 bytes)
    const size_t off = 0x100;
    page.data[off + 0] = 0x48;
    page.data[off + 1] = 0x8D;
    page.data[off + 2] = 0x05;
    page.data[off + 3] = 0x10;
    page.data[off + 4] = 0x00;
    page.data[off + 5] = 0x00;
    page.data[off + 6] = 0x00;

    auto result = utility::resolve_displacement((uintptr_t)(page.data + off), nullptr);
    TEST_ASSERT(result.has_value());
    // Expected: ip + 7 (instruction length) + 0x10 (displacement) = ip + 0x17
    TEST_ASSERT(*result == (uintptr_t)(page.data + off) + 7 + 0x10);
    return 0;
}

int test_resolve_displacement_call_rel32() {
    RWXPage page;
    TEST_ASSERT(page.data != nullptr);
    memset(page.data, 0xCC, page.size);

    // Place: CALL +0x20 = E8 20 00 00 00 (5 bytes)
    const size_t off = 0x200;
    page.data[off + 0] = 0xE8;
    page.data[off + 1] = 0x20;
    page.data[off + 2] = 0x00;
    page.data[off + 3] = 0x00;
    page.data[off + 4] = 0x00;

    auto result = utility::resolve_displacement((uintptr_t)(page.data + off), nullptr);
    TEST_ASSERT(result.has_value());
    // Expected: ip + 5 (instruction length) + 0x20 (rel offset) = ip + 0x25
    TEST_ASSERT(*result == (uintptr_t)(page.data + off) + 5 + 0x20);
    return 0;
}

int test_resolve_displacement_no_displacement() {
    RWXPage page;
    TEST_ASSERT(page.data != nullptr);
    memset(page.data, 0xCC, page.size);

    // Place: XOR EAX, EAX = 31 C0 (2 bytes) — no displacement operand
    const size_t off = 0x300;
    page.data[off + 0] = 0x31;
    page.data[off + 1] = 0xC0;

    auto result = utility::resolve_displacement((uintptr_t)(page.data + off), nullptr);
    TEST_ASSERT(!result.has_value());
    return 0;
}

// ============================================================================
// exhaustive_decode — decodes instructions following branches
// ============================================================================

int test_exhaustive_decode_simple_sequence() {
    RWXPage page;
    TEST_ASSERT(page.data != nullptr);
    memset(page.data, 0xCC, page.size);

    // Place: XOR EAX,EAX; NOP; RET  (2+1+1 = 4 bytes)
    const size_t off = 0x100;
    page.data[off + 0] = 0x31;
    page.data[off + 1] = 0xC0;
    page.data[off + 2] = 0x90;
    page.data[off + 3] = 0xC3;

    int call_count = 0;
    uintptr_t last_addr = 0;

    utility::exhaustive_decode((uint8_t*)(page.data + off), 100,
        [&](utility::ExhaustionContext& ctx) -> utility::ExhaustionResult {
            ++call_count;
            last_addr = ctx.addr;
            return utility::ExhaustionResult::CONTINUE;
        });

    // Should have been called for XOR EAX,EAX, NOP, and RET (3 instructions)
    TEST_ASSERT(call_count == 3);
    TEST_ASSERT(last_addr == (uintptr_t)(page.data + off + 3)); // RET at offset+3
    return 0;
}

// ============================================================================
// linear_decode — simple linear instruction decode
// ============================================================================

int test_linear_decode_simple() {
    RWXPage page;
    TEST_ASSERT(page.data != nullptr);
    memset(page.data, 0xCC, page.size);

    // Place: PUSH RBP; MOV RBP,RSP; POP RBP; RET
    // 55; 48 89 E5; 5D; C3
    const size_t off = 0x100;
    page.data[off + 0] = 0x55;             // PUSH RBP
    page.data[off + 1] = 0x48;             // MOV RBP, RSP (48 89 E5)
    page.data[off + 2] = 0x89;
    page.data[off + 3] = 0xE5;
    page.data[off + 4] = 0x5D;             // POP RBP
    page.data[off + 5] = 0xC3;             // RET

    int call_count = 0;

    utility::linear_decode((uint8_t*)(page.data + off), 100,
        [&](utility::ExhaustionContext& ctx) -> bool {
            ++call_count;
            // Stop at RET to avoid decoding 0xCC padding
            return ctx.instrux.Instruction != ND_INS_RETN;
        });

    // Should decode 4 instructions: PUSH RBP, MOV RBP RSP, POP RBP, RET
    TEST_ASSERT(call_count == 4);
    return 0;
}

// ============================================================================
// collect_basic_blocks_into — collects basic blocks from a simple function
// ============================================================================

int test_collect_basic_blocks_simple() {
    RWXPage page;
    TEST_ASSERT(page.data != nullptr);
    memset(page.data, 0xCC, page.size);

    // Place: XOR EAX,EAX; RET  (2+1 = 3 bytes) — one basic block
    const size_t off = 0x100;
    page.data[off + 0] = 0x31;
    page.data[off + 1] = 0xC0;
    page.data[off + 2] = 0xC3;

    std::vector<utility::BasicBlock> blocks;
    utility::BasicBlockCollectOptions opts;
    opts.max_size = 100;
    opts.copy_instructions = true;

    utility::collect_basic_blocks_into((uintptr_t)(page.data + off), opts, blocks);

    TEST_ASSERT(!blocks.empty());
    TEST_ASSERT(blocks.size() == 1);
    TEST_ASSERT(blocks[0].start == (uintptr_t)(page.data + off));
    TEST_ASSERT(blocks[0].end == (uintptr_t)(page.data + off + 3));
    TEST_ASSERT(blocks[0].instruction_count == 2);
    TEST_ASSERT(blocks[0].branches.empty());
    TEST_ASSERT(!blocks[0].is_call_block);
    return 0;
}

// ============================================================================
// scan_disasm — pattern match on disassembled instructions
// ============================================================================

int test_scan_disasm_finds_pattern() {
    RWXPage page;
    TEST_ASSERT(page.data != nullptr);
    memset(page.data, 0xCC, page.size);

    // Place: XOR EAX,EAX (31 C0); NOP (90); RET (C3)
    const size_t off = 0x100;
    page.data[off + 0] = 0x31;
    page.data[off + 1] = 0xC0;
    page.data[off + 2] = 0x90;
    page.data[off + 3] = 0xC3;

    // Search for pattern "90" — should match the NOP instruction
    auto result = utility::scan_disasm((uintptr_t)(page.data + off), 3, "90");
    TEST_ASSERT(result.has_value());
    TEST_ASSERT(*result == (uintptr_t)(page.data + off + 2));
    return 0;
}

int test_scan_disasm_no_match() {
    RWXPage page;
    TEST_ASSERT(page.data != nullptr);
    memset(page.data, 0xCC, page.size);

    const size_t off = 0x100;
    page.data[off + 0] = 0x31;
    page.data[off + 1] = 0xC0;
    page.data[off + 2] = 0xC3;

    // Search for pattern "FF FF" — not present in any instruction
    auto result = utility::scan_disasm((uintptr_t)(page.data + off), 3, "FF FF");
    TEST_ASSERT(!result.has_value());
    return 0;
}

// ============================================================================
// main
// ============================================================================

int main() try {
    std::cout << "===== kananlib-scan-coverage-test =====" << std::endl;

    // scan_data_reverse
    RUN_TEST(test_scan_data_reverse_finds_match);
    RUN_TEST(test_scan_data_reverse_not_found);
    RUN_TEST(test_scan_data_reverse_zero_length);

    // scan_ptr_noalign
    RUN_TEST(test_scan_ptr_noalign_finds_unaligned);
    RUN_TEST(test_scan_ptr_noalign_not_found);

    // scan_string (buffer overloads)
    RUN_TEST(test_scan_string_finds_ascii);
    RUN_TEST(test_scan_string_wchar_finds_wide);
    RUN_TEST(test_scan_string_empty_returns_nullopt);
    RUN_TEST(test_scan_string_zero_terminated);

    // scan_relative_reference_scalar
    RUN_TEST(test_scan_relative_reference_scalar_finds_match);
    RUN_TEST(test_scan_relative_reference_scalar_not_found);

    // scan_relative_reference_scalar_byte_by_byte
    RUN_TEST(test_scan_relative_reference_bbb_finds_match);
    RUN_TEST(test_scan_relative_reference_bbb_not_found);

    // scan_relative_reference (dispatch)
    RUN_TEST(test_scan_relative_reference_finds_match);
    RUN_TEST(test_scan_relative_reference_with_filter);
    RUN_TEST(test_scan_relative_reference_not_found);

    // scan_relative_references
    RUN_TEST(test_scan_relative_references_finds_all);

    // scan_reference
    RUN_TEST(test_scan_reference_absolute);
    RUN_TEST(test_scan_reference_relative);

    // scan_relative_reference_strict
    RUN_TEST(test_scan_relative_reference_strict_finds_with_preceding);
    RUN_TEST(test_scan_relative_reference_strict_empty_pattern);

    // resolve_displacement
    RUN_TEST(test_resolve_displacement_lea_rip);
    RUN_TEST(test_resolve_displacement_call_rel32);
    RUN_TEST(test_resolve_displacement_no_displacement);

    // exhaustive_decode
    RUN_TEST(test_exhaustive_decode_simple_sequence);

    // linear_decode
    RUN_TEST(test_linear_decode_simple);

    // collect_basic_blocks_into
    RUN_TEST(test_collect_basic_blocks_simple);

    // scan_disasm
    RUN_TEST(test_scan_disasm_finds_pattern);
    RUN_TEST(test_scan_disasm_no_match);

    return test_summary();
} catch(const std::exception& e) {
    std::cout << "Exception caught: " << e.what() << std::endl;
    return 1;
} catch(...) {
    std::cout << "Unknown exception caught" << std::endl;
    return 1;
}
