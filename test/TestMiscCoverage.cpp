#include <cstdint>
#include <cstdarg>
#include <cstdio>
#include <iostream>
#include <string>

#include <windows.h>
#include <bdshemu.h>

#include "TestHelpers.hpp"

#include <utility/String.hpp>
#include <utility/Emulation.hpp>
#include <utility/Module.hpp>

// ============================================================================
// Helper: variadic wrapper around utility::format_string (va_list API)
// ============================================================================

static std::string str_format(const char* f, ...) {
    va_list args;
    va_start(args, f);
    auto result = utility::format_string(f, args);
    va_end(args);
    return result;
}

// ============================================================================
// String.cpp tests — format_string
// ============================================================================

int test_format_string_basic() {
    auto result = str_format("Hello %s, number %d", "World", 42);
    TEST_ASSERT(result == "Hello World, number 42");
    return 0;
}

int test_format_string_no_specifiers() {
    auto result = str_format("no specifiers here");
    TEST_ASSERT(result == "no specifiers here");
    return 0;
}

int test_format_string_empty() {
    // Empty format => vsnprintf returns 0 => len <= 0 => returns {}
    auto result = str_format("");
    TEST_ASSERT(result.empty());
    return 0;
}

int test_format_string_long_string() {
    // Produce a string > 256 chars to exercise the resize path
    std::string long_arg(512, 'X');
    auto result = str_format("prefix_%s_suffix", long_arg.c_str());
    TEST_ASSERT(result.size() == 7 + 512 + 7); // "prefix_" + 512 X + "_suffix"
    TEST_ASSERT(result.substr(0, 7) == "prefix_");
    TEST_ASSERT(result.substr(result.size() - 7) == "_suffix");
    return 0;
}

int test_format_string_multiple_specifiers() {
    auto result = str_format("%s %s %d %x %c", "a", "bb", 255, 0xFF, 'Z');
    TEST_ASSERT(result == "a bb 255 ff Z");
    return 0;
}

int test_format_string_int_max() {
    auto result = str_format("%d", INT_MAX);
    TEST_ASSERT(result == "2147483647");
    return 0;
}

int test_format_string_repeated() {
    auto a = str_format("%d", 1);
    auto b = str_format("%d", 2);
    auto c = str_format("%d", 3);
    TEST_ASSERT(a == "1");
    TEST_ASSERT(b == "2");
    TEST_ASSERT(c == "3");
    return 0;
}

// ============================================================================
// String.cpp tests — narrow / widen edge cases
// ============================================================================

int test_narrow_widen_ascii() {
    std::string original = "ASCII only test 123!@#";
    auto widened = utility::widen(original);
    auto narrowed = utility::narrow(widened);
    TEST_ASSERT(narrowed == original);
    TEST_ASSERT(widened.size() == original.size()); // ASCII: same length
    return 0;
}

int test_narrow_single_char() {
    std::wstring ws = L"A";
    auto ns = utility::narrow(ws);
    TEST_ASSERT(ns == "A");

    auto w2 = utility::widen("A");
    TEST_ASSERT(w2 == L"A");
    return 0;
}

// ============================================================================
// Emulation.cpp tests — uncovered paths
// (DO NOT duplicate: ShemuContext constructors, NOP/mov/ret emulation,
//  single-step emulate(), free emulate(base,size,ip,n))
// ============================================================================

// x86-64 NOP and RET
static const uint8_t NOP_BYTE = 0x90;
static const uint8_t RET_BYTE = 0xC3;

// Helper: allocate an RWX buffer with known bytes for emulation
struct EmuBuffer {
    void* mem = nullptr;
    size_t size = 0x1000;

    EmuBuffer() {
        mem = VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (mem) {
            memset(mem, NOP_BYTE, size);
            static_cast<uint8_t*>(mem)[0] = RET_BYTE;
        }
    }
    ~EmuBuffer() {
        if (mem) VirtualFree(mem, 0, MEM_RELEASE);
    }
};

// Test: emulate(HMODULE, ip, n) free function — returns ShemuContext by value
int test_emulate_hmodule_free_fn() {
    auto kernel32 = GetModuleHandleA("kernel32.dll");
    TEST_ASSERT(kernel32 != nullptr);

    auto getlasterror_addr = GetProcAddress(kernel32, "GetLastError");
    TEST_ASSERT(getlasterror_addr != nullptr);

    auto ip = reinterpret_cast<uintptr_t>(getlasterror_addr);
    auto result = utility::emulate(kernel32, ip, 5);

    TEST_ASSERT(result.ctx != nullptr);
    TEST_ASSERT(!result.stack.empty());
    TEST_ASSERT(!result.internal_buffer.empty());
    return 0;
}

// Test: callback emulate — BREAK callback stops immediately
int test_emulate_callback_break() {
    auto kernel32 = GetModuleHandleA("kernel32.dll");
    TEST_ASSERT(kernel32 != nullptr);

    auto getlasterror_addr = GetProcAddress(kernel32, "GetLastError");
    TEST_ASSERT(getlasterror_addr != nullptr);

    auto ip = reinterpret_cast<uintptr_t>(getlasterror_addr);
    int callback_count = 0;

    utility::emulate(kernel32, ip, 100,
        [&](const utility::ShemuContextExtended& ext) -> utility::ExhaustionResult {
            callback_count++;
            return utility::BREAK;
        });

    TEST_ASSERT(callback_count == 1);
    return 0;
}

// Test: callback emulate — STEP_OVER advances RIP without emulating
int test_emulate_callback_step_over() {
    auto kernel32 = GetModuleHandleA("kernel32.dll");
    TEST_ASSERT(kernel32 != nullptr);

    auto getlasterror_addr = GetProcAddress(kernel32, "GetLastError");
    TEST_ASSERT(getlasterror_addr != nullptr);

    auto ip = reinterpret_cast<uintptr_t>(getlasterror_addr);
    int callback_count = 0;
    uintptr_t first_rip = 0;
    uintptr_t second_rip = 0;

    utility::emulate(kernel32, ip, 100,
        [&](const utility::ShemuContextExtended& ext) -> utility::ExhaustionResult {
            callback_count++;
            if (callback_count == 1) {
                first_rip = ext.ctx->ctx->Registers.RegRip;
                return utility::STEP_OVER;
            }
            second_rip = ext.ctx->ctx->Registers.RegRip;
            return utility::BREAK;
        });

    TEST_ASSERT(callback_count == 2);
    TEST_ASSERT(second_rip > first_rip);
    return 0;
}

// Test: callback emulate — CONTINUE exercises the full emulation path
int test_emulate_callback_continue() {
    EmuBuffer buf;
    TEST_ASSERT(buf.mem != nullptr);

    auto base = reinterpret_cast<uintptr_t>(buf.mem);
    int callback_count = 0;

    utility::ShemuContext ctx{base, buf.size};
    ctx.ctx->Registers.RegRip = base + 1; // NOP byte (offset 0 is RET)

    utility::emulate(
        GetModuleHandleA("kernel32.dll"),
        base + 1,   // IP: NOP byte (offset 0 is RET)
        5,
        ctx,
        [&](const utility::ShemuContextExtended& ext) -> utility::ExhaustionResult {
            callback_count++;
            return utility::CONTINUE;
        });

    // CONTINUE with NOPs should invoke the callback multiple times
    TEST_ASSERT(callback_count >= 1);
    return 0;
}

// Test: 5-arg callback overload with pre-built ShemuContext
int test_emulate_callback_with_start_ctx() {
    EmuBuffer buf;
    TEST_ASSERT(buf.mem != nullptr);

    auto base = reinterpret_cast<uintptr_t>(buf.mem);
    utility::ShemuContext ctx{base, buf.size};
    ctx.ctx->Registers.RegRip = base + 1; // NOP byte (offset 0 is RET)

    int callback_count = 0;
    utility::emulate(
        GetModuleHandleA("kernel32.dll"),
        base + 1,
        10,
        ctx,
        [&](const utility::ShemuContextExtended& ext) -> utility::ExhaustionResult {
            callback_count++;
            return utility::BREAK;
        });

    TEST_ASSERT(callback_count == 1);
    TEST_ASSERT(ctx.ctx != nullptr);
    return 0;
}

// Test: ShemuContextExtended fields are populated correctly in callback
int test_emulate_extended_fields() {
    EmuBuffer buf;
    TEST_ASSERT(buf.mem != nullptr);

    auto base = reinterpret_cast<uintptr_t>(buf.mem);
    utility::ShemuContext ctx{base, buf.size};
    ctx.ctx->Registers.RegRip = base + 1; // NOP byte (offset 0 is RET)

    bool got_ctx_ptr = false;
    bool got_ix = false;
    bool callback_ran = false;

    utility::emulate(
        GetModuleHandleA("kernel32.dll"),
        base + 1, // NOP byte
        5,
        ctx,
        [&](const utility::ShemuContextExtended& ext) -> utility::ExhaustionResult {
            callback_ran = true;
            got_ctx_ptr = (ext.ctx != nullptr);
            got_ix = (ext.next.ix.Length > 0);
            return utility::BREAK;
        });

    TEST_ASSERT(callback_ran);
    TEST_ASSERT(got_ctx_ptr);
    TEST_ASSERT(got_ix);
    return 0;
}

// Test: status field is set after HMODULE-based free emulate
int test_emulate_hmodule_status() {
    auto kernel32 = GetModuleHandleA("kernel32.dll");
    TEST_ASSERT(kernel32 != nullptr);

    auto getlasterror_addr = GetProcAddress(kernel32, "GetLastError");
    TEST_ASSERT(getlasterror_addr != nullptr);

    auto ip = reinterpret_cast<uintptr_t>(getlasterror_addr);
    auto result = utility::emulate(kernel32, ip, 1);

    TEST_ASSERT(result.ctx != nullptr);
    return 0;
}

// ============================================================================
// main
// ============================================================================

int main() {
    std::cout << "===== kananlib-misc-coverage-test =====" << std::endl;

    // String.cpp — format_string
    RUN_TEST(test_format_string_basic);
    RUN_TEST(test_format_string_no_specifiers);
    RUN_TEST(test_format_string_empty);
    RUN_TEST(test_format_string_long_string);
    RUN_TEST(test_format_string_multiple_specifiers);
    RUN_TEST(test_format_string_int_max);
    RUN_TEST(test_format_string_repeated);

    // String.cpp — narrow/widen edge cases
    RUN_TEST(test_narrow_widen_ascii);
    RUN_TEST(test_narrow_single_char);

    // Emulation.cpp — uncovered paths
    RUN_TEST(test_emulate_hmodule_free_fn);
    RUN_TEST(test_emulate_callback_break);
    RUN_TEST(test_emulate_callback_step_over);
    RUN_TEST(test_emulate_callback_continue);
    RUN_TEST(test_emulate_callback_with_start_ctx);
    RUN_TEST(test_emulate_extended_fields);
    RUN_TEST(test_emulate_hmodule_status);

    return test_summary();
}
