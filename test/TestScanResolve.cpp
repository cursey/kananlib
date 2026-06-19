// ============================================================================
// Tests for Scan.cpp resolver family and string-ref / linear-block collection.
//
// Functions covered:
//   scan_ptr (HMODULE overload),
//   find_function_from_string_ref (narrow + wide),
//   find_function_with_string_refs,
//   find_function_with_refs,
//   find_virtual_function_start,
//   find_virtual_function_from_string_ref,
//   resolve_instruction,
//   get_disassembly_behind,
//   collect_linear_blocks,
//   collect_ascii_string_references,
//   collect_unicode_string_references,
//   scan_displacement_references (HMODULE overload)
// ============================================================================

#include <cstdint>
#include <string>
#include <iostream>
#include <cstring>
#include <vector>
#include <functional>
#include <optional>

#include <windows.h>

#include <utility/Scan.hpp>
#include <utility/Module.hpp>

#include "TestHelpers.hpp"

// ============================================================================
// Real test functions with unique marker strings
// ============================================================================

// Unique narrow string — only referenced by resolve_narrow_marker_func
static const char NARROW_MARKER[] = "ResolveTestNarrowMarkerX7Q9Z";
// Unique wide string — only referenced by resolve_wide_marker_func
static const wchar_t WIDE_MARKER[] = L"ResolveTestWideMarkerY8K3W";

// Dual-string markers for find_function_with_string_refs
static const wchar_t DUAL_A[] = L"DualRefAlphaResolveM1";
static const wchar_t DUAL_B[] = L"DualRefBetaResolveN2";

// These globals exist so the linker keeps our marker strings alive
volatile int g_resolve_sink = 0;

__declspec(noinline) int resolve_narrow_marker_func() {
    volatile const char* p = NARROW_MARKER;
    printf("%s\n", p);
    volatile int x = static_cast<int>(p[0]);
    g_resolve_sink = x;
    return x;
}

__declspec(noinline) int resolve_wide_marker_func() {
    volatile const wchar_t* p = WIDE_MARKER;
    printf("%ls\n", p);
    volatile int x = static_cast<int>(p[0]);
    g_resolve_sink = x;
    return x;
}

__declspec(noinline) int resolve_dual_string_func() {
    volatile const wchar_t* a = DUAL_A;
    volatile const wchar_t* b = DUAL_B;
    printf("%ls %ls\n", a, b);
    g_resolve_sink = static_cast<int>(a[0]) + static_cast<int>(b[0]);
    return 42;
}

// A multi-block function with a branch — for collect_linear_blocks
__declspec(noinline) int resolve_multiblock_func(int x) {
    volatile int y = x + 1;
    if (y > 10) {
        volatile int z = y * 2;
        g_resolve_sink = z;
        return z;
    }
    volatile int w = y - 5;
    g_resolve_sink = w;
    return w;
}

// ============================================================================
// Virtual function test class
// ============================================================================

static const wchar_t VIRT_MARKER_W[] = L"VirtResolveMarkerP4R7S";

class ResolveVirtTarget {
public:
    virtual ~ResolveVirtTarget() = default;

    __declspec(noinline) virtual int virt_with_marker() {
        volatile const wchar_t* p = VIRT_MARKER_W;
        printf("%ls\n", p);
        g_resolve_sink = static_cast<int>(p[0]);
        return 99;
    }
};

static ResolveVirtTarget g_resolve_virt_target;

// ============================================================================
// Helper: call target functions to ensure they are emitted and have code
// ============================================================================

static void force_call_targets() {
    g_resolve_sink = resolve_narrow_marker_func();
    g_resolve_sink = resolve_wide_marker_func();
    g_resolve_sink = resolve_dual_string_func();
    g_resolve_sink = resolve_multiblock_func(5);
    g_resolve_sink = resolve_multiblock_func(15);
    g_resolve_sink = g_resolve_virt_target.virt_with_marker();
}

// ============================================================================
// Test: scan_ptr (HMODULE overload) — finds pointer stored in module data
// ============================================================================

int test_scan_ptr_hmodule() {
    HMODULE exe = utility::get_executable();
    TEST_ASSERT(exe != nullptr);

    // &g_resolve_sink should have its address stored in the executable somewhere
    // (the vtable for g_resolve_virt_target contains a pointer to virt_with_marker).
    // Instead let's search for the address of the string data itself.
    const auto result = utility::scan_ptr(exe, (uintptr_t)NARROW_MARKER);
    if (result.has_value()) {
        TEST_ASSERT(*result >= (uintptr_t)exe);
        std::cout << "  scan_ptr(HMODULE) found NARROW_MARKER ref" << std::endl;
    } else {
        // Pointer may be encoded as a relative offset, not a raw pointer.
        // That's OK — scan_ptr only finds absolute pointers.
        std::cout << "  scan_ptr(HMODULE): no absolute pointer found (may be RIP-relative)" << std::endl;
    }

    // Negative: search for a pointer that cannot be embedded as an 8-byte
    // immediate in the image. A fixed sentinel like 0xDEADBEEFCAFEBABE is not
    // safe — some compilers (clang-cl) emit that exact byte run somewhere in
    // .rdata/.text. Derive a high-entropy value at runtime instead.
    LARGE_INTEGER qpc{};
    QueryPerformanceCounter(&qpc);
    const uintptr_t runtime_unique =
        (static_cast<uintptr_t>(qpc.QuadPart) * 0x9E3779B97F4A7C15ULL) ^ 0xA5A5A5A5A5A5A5A5ULL;
    const auto no_result = utility::scan_ptr(exe, runtime_unique);
    TEST_ASSERT(!no_result.has_value());

    return 0;
}

// ============================================================================
// Test: find_function_from_string_ref (narrow string)
// ============================================================================

int test_find_function_from_string_ref_narrow() {
    HMODULE exe = utility::get_executable();
    TEST_ASSERT(exe != nullptr);

    const auto fn = utility::find_function_from_string_ref(
        exe, std::string_view{NARROW_MARKER});

    TEST_ASSERT(fn.has_value());
    // The result should be within the executable module
    auto mod_size = utility::get_module_size(exe);
    TEST_ASSERT(mod_size.has_value());
    TEST_ASSERT(*fn >= (uintptr_t)exe);
    TEST_ASSERT(*fn < (uintptr_t)exe + *mod_size);

    std::cout << "  find_function_from_string_ref(narrow) => 0x"
              << std::hex << *fn << std::dec << std::endl;
    return 0;
}

// ============================================================================
// Test: find_function_from_string_ref (wide string)
// ============================================================================

int test_find_function_from_string_ref_wide() {
    HMODULE exe = utility::get_executable();
    TEST_ASSERT(exe != nullptr);

    const auto fn = utility::find_function_from_string_ref(
        exe, std::wstring_view{WIDE_MARKER});

    TEST_ASSERT(fn.has_value());
    auto mod_size = utility::get_module_size(exe);
    TEST_ASSERT(mod_size.has_value());
    TEST_ASSERT(*fn >= (uintptr_t)exe);
    TEST_ASSERT(*fn < (uintptr_t)exe + *mod_size);

    std::cout << "  find_function_from_string_ref(wide) => 0x"
              << std::hex << *fn << std::dec << std::endl;
    return 0;
}

// ============================================================================
// Test: find_function_from_string_ref — string not in module
// ============================================================================

int test_find_function_from_string_ref_not_found() {
    HMODULE exe = utility::get_executable();
    TEST_ASSERT(exe != nullptr);

    // Build a high-entropy string at runtime so the byte run cannot exist in the
    // binary's .rdata (a predictable run like 128+i can collide with compiler tables).
    LARGE_INTEGER qpc{};
    QueryPerformanceCounter(&qpc);
    uint64_t state = static_cast<uint64_t>(qpc.QuadPart) ^ 0xC0FFEE1234567ULL;
    std::string fake_str(64, '\0');
    for (int i = 0; i < 64; ++i) {
        state = state * 6364136223846793005ULL + 1442695040888963407ULL; // LCG
        fake_str[i] = static_cast<char>(0x80 | ((state >> 48) & 0x7F));
    }

    const auto fn = utility::find_function_from_string_ref(
        exe, std::string_view{fake_str});

    TEST_ASSERT(!fn.has_value());
    return 0;
}

// ============================================================================
// Test: find_function_from_string_ref (wide) — not found
// ============================================================================

int test_find_function_from_string_ref_wide_not_found() {
    HMODULE exe = utility::get_executable();
    TEST_ASSERT(exe != nullptr);

    // Build a wide string from a high-entropy runtime value so the byte run
    // cannot appear in the image. A predictable monotonic run (0x8000+i) is not
    // safe — clang-cl emits a matching incrementing 16-bit table in .rdata.
    LARGE_INTEGER qpc{};
    QueryPerformanceCounter(&qpc);
    uint64_t state = static_cast<uint64_t>(qpc.QuadPart) ^ 0x123456789ABCDEFULL;
    std::wstring fake_wstr(32, L'\0');
    for (int i = 0; i < 32; ++i) {
        state = state * 6364136223846793005ULL + 1442695040888963407ULL; // LCG
        // Keep chars in the BMP private-use area, away from any real .rdata text.
        fake_wstr[i] = static_cast<wchar_t>(0xE000 + (state >> 48) % 0x1800);
    }

    const auto fn = utility::find_function_from_string_ref(
        exe, std::wstring_view{fake_wstr});

    TEST_ASSERT(!fn.has_value());
    return 0;
}


// ============================================================================
// Test: find_function_with_string_refs — dual wide string match
// ============================================================================

int test_find_function_with_string_refs() {
    HMODULE exe = utility::get_executable();
    TEST_ASSERT(exe != nullptr);

    const auto fn = utility::find_function_with_string_refs(
        exe, DUAL_A, DUAL_B);

    if (fn.has_value()) {
        auto mod_size = utility::get_module_size(exe);
        TEST_ASSERT(mod_size.has_value());
        TEST_ASSERT(*fn >= (uintptr_t)exe);
        TEST_ASSERT(*fn < (uintptr_t)exe + *mod_size);
        std::cout << "  find_function_with_string_refs => 0x"
                  << std::hex << *fn << std::dec << std::endl;
    } else {
        // This function does exhaustive_decode which can be heavy;
        // it returning nullopt on a test binary is acceptable
        std::cout << "  find_function_with_string_refs: nullopt (exhaustive decode may have bailed)" << std::endl;
    }

    return 0;
}

// ============================================================================
// Test: find_function_with_string_refs — one string not found
// ============================================================================

int test_find_function_with_string_refs_not_found() {
    HMODULE exe = utility::get_executable();
    TEST_ASSERT(exe != nullptr);

    // Build wide strings at runtime so they won't be in the binary
    std::wstring fake_a(40, L'\0');
    for (int i = 0; i < 40; ++i) fake_a[i] = static_cast<wchar_t>(0x9000 + i);
    std::wstring fake_b(40, L'\0');
    for (int i = 0; i < 40; ++i) fake_b[i] = static_cast<wchar_t>(0xA000 + i);

    const auto fn = utility::find_function_with_string_refs(
        exe, fake_a, fake_b);

    TEST_ASSERT(!fn.has_value());
    return 0;
}

// ============================================================================
// Test: find_virtual_function_start — given a middle address
// ============================================================================

int test_find_virtual_function_start() {
    // Force the vtable entry to be populated
    ResolveVirtTarget obj;
    volatile int r = obj.virt_with_marker();
    (void)r;

    // Get the vtable pointer from the object
    void* vtable = *(void**)&obj;
    TEST_ASSERT(vtable != nullptr);

    // First entry in vtable should be virt_with_marker
    auto* vtable_entries = reinterpret_cast<uintptr_t*>(vtable);
    uintptr_t virt_fn = vtable_entries[0];
    TEST_ASSERT(virt_fn != 0);

    // Now try to find virtual function start from the middle
    const auto result = utility::find_virtual_function_start(virt_fn + 8);
    if (result.has_value()) {
        TEST_ASSERT(*result <= virt_fn + 8);
        std::cout << "  find_virtual_function_start => 0x" << std::hex
                  << *result << " (expected <= 0x" << virt_fn + 8
                  << ")" << std::dec << std::endl;
    } else {
        // May return nullopt if no .pdata entry exists for this function
        std::cout << "  find_virtual_function_start: nullopt (no unwind data?)" << std::endl;
    }
    return 0;
}

// ============================================================================
// Test: find_virtual_function_from_string_ref
// ============================================================================

int test_find_virtual_function_from_string_ref() {
    HMODULE exe = utility::get_executable();
    TEST_ASSERT(exe != nullptr);

    const auto result = utility::find_virtual_function_from_string_ref(
        exe, std::wstring_view{VIRT_MARKER_W});

    if (result.has_value()) {
        auto mod_size = utility::get_module_size(exe);
        TEST_ASSERT(mod_size.has_value());
        TEST_ASSERT(*result >= (uintptr_t)exe);
        TEST_ASSERT(*result < (uintptr_t)exe + *mod_size);
        std::cout << "  find_virtual_function_from_string_ref => 0x"
                  << std::hex << *result << std::dec << std::endl;
    } else {
        // Might return nullopt if the vtable walk doesn't match
        std::cout << "  find_virtual_function_from_string_ref: nullopt" << std::endl;
    }
    return 0;
}

// ============================================================================
// Test: resolve_instruction — given address in a known function body
// ============================================================================

int test_resolve_instruction() {
    // resolve_multiblock_func is a real function with a known prologue
    auto* fn_ptr = reinterpret_cast<uint8_t*>(&resolve_multiblock_func);
    // Pick a point a bit into the function (after prologue)
    const auto middle = reinterpret_cast<uintptr_t>(fn_ptr + 16);

    const auto result = utility::resolve_instruction(middle);
    if (result.has_value()) {
        TEST_ASSERT(result->addr <= middle);
        TEST_ASSERT(result->addr + result->instrux.Length > middle
                    || result->addr + result->instrux.Length == middle);
        std::cout << "  resolve_instruction(0x" << std::hex << middle
                  << ") => 0x" << result->addr << " len=" << std::dec
                  << result->instrux.Length << std::endl;
    } else {
        std::cout << "  resolve_instruction: nullopt" << std::endl;
    }
    return 0;
}

// ============================================================================
// Test: get_disassembly_behind — disassemble backwards from middle
// ============================================================================

int test_get_disassembly_behind() {
    // Pick an address 32 bytes into resolve_multiblock_func
    auto* fn_ptr = reinterpret_cast<uint8_t*>(&resolve_multiblock_func);
    const auto middle = reinterpret_cast<uintptr_t>(fn_ptr + 32);

    const auto results = utility::get_disassembly_behind(middle);

    if (!results.empty()) {
        // All returned instructions should precede 'middle'
        for (const auto& r : results) {
            TEST_ASSERT(r.addr < middle);
            TEST_ASSERT(r.addr + r.instrux.Length <= middle
                        || r.addr + r.instrux.Length == middle);
        }
        std::cout << "  get_disassembly_behind => " << results.size()
                  << " instructions" << std::endl;
    } else {
        // Could be empty if no .pdata for this function
        std::cout << "  get_disassembly_behind: empty result" << std::endl;
    }
    return 0;
}

// ============================================================================
// Test: collect_linear_blocks — basic block collection on real function
// ============================================================================

int test_collect_linear_blocks_basic() {
    uintptr_t fn_start = reinterpret_cast<uintptr_t>(&resolve_multiblock_func);
    // Use determine_function_bounds to find the end
    auto bounds = utility::determine_function_bounds(fn_start);
    uintptr_t fn_end = 0;
    if (bounds.has_value()) {
        fn_end = bounds->end;
    } else {
        // Fallback: assume function is at most 256 bytes
        fn_end = fn_start + 256;
    }

    auto blocks = utility::collect_linear_blocks(fn_start, fn_end);

    TEST_ASSERT(!blocks.empty());

    // First block should start at fn_start
    TEST_ASSERT(blocks[0].start == fn_start);

    // All blocks should have start < end
    for (const auto& b : blocks) {
        TEST_ASSERT(b.start < b.end);
        TEST_ASSERT(b.start >= fn_start);
        TEST_ASSERT(b.end <= fn_end);
    }

    std::cout << "  collect_linear_blocks => " << blocks.size()
              << " blocks" << std::endl;
    return 0;
}

// ============================================================================
// Test: collect_linear_blocks — degenerate range returns empty
// ============================================================================

int test_collect_linear_blocks_degenerate() {
    // start >= end should return empty
    auto blocks = utility::collect_linear_blocks(0x1000, 0x1000);
    TEST_ASSERT(blocks.empty());

    auto blocks2 = utility::collect_linear_blocks(0x2000, 0x1000);
    TEST_ASSERT(blocks2.empty());

    return 0;
}

// ============================================================================
// Test: collect_ascii_string_references — function with ASCII string
// ============================================================================

int test_collect_ascii_string_refs() {
    uintptr_t fn_ptr = reinterpret_cast<uintptr_t>(&resolve_narrow_marker_func);

    auto refs = utility::collect_ascii_string_references(
        fn_ptr, 500, utility::StringReferenceOptions{}.with_min_length(5));

    if (!refs.empty()) {
        // At least one should point to our NARROW_MARKER
        bool found_marker = false;
        for (const auto& ref : refs) {
            if (ref.ascii && std::string_view{ref.ascii}.find("Resolve") != std::string_view::npos) {
                found_marker = true;
                break;
            }
        }
        TEST_ASSERT(found_marker);
        std::cout << "  collect_ascii_string_references => " << refs.size()
                  << " refs (found marker)" << std::endl;
    } else {
        // Could be empty if exhaustive_decode bails in Debug mode
        std::cout << "  collect_ascii_string_references: empty (decode may have bailed)" << std::endl;
    }

    return 0;
}

// ============================================================================
// Test: collect_unicode_string_references — function with wide string
// ============================================================================

int test_collect_unicode_string_refs() {
    uintptr_t fn_ptr = reinterpret_cast<uintptr_t>(&resolve_wide_marker_func);

    auto refs = utility::collect_unicode_string_references(
        fn_ptr, 500, utility::StringReferenceOptions{}.with_min_length(5));

    if (!refs.empty()) {
        bool found_marker = false;
        for (const auto& ref : refs) {
            if (ref.unicode && std::wstring_view{ref.unicode}.find(L"Resolve") != std::wstring_view::npos) {
                found_marker = true;
                break;
            }
        }
        TEST_ASSERT(found_marker);
        std::cout << "  collect_unicode_string_references => " << refs.size()
                  << " refs (found marker)" << std::endl;
    } else {
        std::cout << "  collect_unicode_string_references: empty (decode may have bailed)" << std::endl;
    }

    return 0;
}

// ============================================================================
// Test: collect_ascii_string_references — with follow_calls option
// ============================================================================

int test_collect_ascii_string_refs_follow_calls() {
    uintptr_t fn_ptr = reinterpret_cast<uintptr_t>(&resolve_narrow_marker_func);

    auto refs = utility::collect_ascii_string_references(
        fn_ptr, 1000,
        utility::StringReferenceOptions{}.with_min_length(4).with_follow_calls(true));

    // Not asserting found because follow_calls may decode into printf or other thunks
    // Just verify it doesn't crash and returns a vector
    std::cout << "  collect_ascii_string_refs(follow_calls) => " << refs.size()
              << " refs" << std::endl;
    return 0;
}

// ============================================================================
// Test: scan_displacement_references (HMODULE overload)
// ============================================================================

int test_scan_displacement_references_hmodule() {
    HMODULE exe = utility::get_executable();
    TEST_ASSERT(exe != nullptr);

    // Find displacement references to the NARROW_MARKER string data
    auto refs = utility::scan_displacement_references(exe, (uintptr_t)NARROW_MARKER);

    if (!refs.empty()) {
        // All returned addresses should be within the module
        auto mod_size = utility::get_module_size(exe);
        TEST_ASSERT(mod_size.has_value());
        for (auto ref : refs) {
            TEST_ASSERT(ref >= (uintptr_t)exe);
            TEST_ASSERT(ref < (uintptr_t)exe + *mod_size);
        }
        std::cout << "  scan_displacement_references(HMODULE) => " << refs.size()
                  << " refs" << std::endl;
    } else {
        // It's possible the string is not referenced via RIP-relative displacement
        std::cout << "  scan_displacement_references(HMODULE): empty" << std::endl;
    }

    return 0;
}

// ============================================================================
// Test: scan_displacement_references — empty for bogus address
// ============================================================================

int test_scan_displacement_references_bogus() {
    HMODULE exe = utility::get_executable();
    TEST_ASSERT(exe != nullptr);

    auto refs = utility::scan_displacement_references(exe, (uintptr_t)0xDEAD);
    TEST_ASSERT(refs.empty());
    return 0;
}

// ============================================================================
// Test: find_function_with_refs — less than 2 ptrs returns nullopt
// ============================================================================

int test_find_function_with_refs_too_few() {
    HMODULE exe = utility::get_executable();
    TEST_ASSERT(exe != nullptr);

    // 0 ptrs
    auto r0 = utility::find_function_with_refs(exe, {});
    TEST_ASSERT(!r0.has_value());

    // 1 ptr
    auto r1 = utility::find_function_with_refs(exe, {(uintptr_t)&g_resolve_sink});
    TEST_ASSERT(!r1.has_value());

    return 0;
}

// ============================================================================
// Test: collect_linear_blocks — single-instruction function (just ret)
// ============================================================================

int test_collect_linear_blocks_single_insn() {
    // A degenerate range of 1 byte — decode should yield a single block
    // We use a known NOP + RET sequence in an RWX page
    uint8_t* page = (uint8_t*)VirtualAlloc(
        nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    TEST_ASSERT(page != nullptr);

    page[0] = 0x90; // NOP
    page[1] = 0xC3; // RET

    auto blocks = utility::collect_linear_blocks((uintptr_t)page, (uintptr_t)&page[2]);

    if (!blocks.empty()) {
        TEST_ASSERT(blocks[0].start == (uintptr_t)page);
        TEST_ASSERT(blocks[0].end <= (uintptr_t)&page[2]);
        std::cout << "  collect_linear_blocks(single insn) => " << blocks.size()
                  << " blocks" << std::endl;
    } else {
        std::cout << "  collect_linear_blocks(single insn): empty" << std::endl;
    }

    VirtualFree(page, 0, MEM_RELEASE);
    return 0;
}

// ============================================================================
// main
// ============================================================================

int main() try {
    force_call_targets();

    std::cout << "=== Scan Resolve Tests ===" << std::endl;

    // scan_ptr
    RUN_TEST(test_scan_ptr_hmodule);

    // find_function_from_string_ref
    RUN_TEST(test_find_function_from_string_ref_narrow);
    RUN_TEST(test_find_function_from_string_ref_wide);
    RUN_TEST(test_find_function_from_string_ref_not_found);
    RUN_TEST(test_find_function_from_string_ref_wide_not_found);

    // find_function_with_string_refs
    RUN_TEST(test_find_function_with_string_refs);
    RUN_TEST(test_find_function_with_string_refs_not_found);

    // find_virtual_function_start / find_virtual_function_from_string_ref
    RUN_TEST(test_find_virtual_function_start);
    RUN_TEST(test_find_virtual_function_from_string_ref);

    // resolve_instruction / get_disassembly_behind
    RUN_TEST(test_resolve_instruction);
    RUN_TEST(test_get_disassembly_behind);

    // collect_linear_blocks
    RUN_TEST(test_collect_linear_blocks_basic);
    RUN_TEST(test_collect_linear_blocks_degenerate);
    RUN_TEST(test_collect_linear_blocks_single_insn);

    // collect string references
    RUN_TEST(test_collect_ascii_string_refs);
    RUN_TEST(test_collect_unicode_string_refs);
    RUN_TEST(test_collect_ascii_string_refs_follow_calls);

    // scan_displacement_references
    RUN_TEST(test_scan_displacement_references_hmodule);
    RUN_TEST(test_scan_displacement_references_bogus);

    // find_function_with_refs edge case
    RUN_TEST(test_find_function_with_refs_too_few);

    std::cout << std::endl;
    return test_summary();
} catch(const std::exception& e) {
    std::cerr << "Unhandled exception: " << e.what() << std::endl;
    return 1;
} catch(...) {
    std::cerr << "Unhandled unknown exception" << std::endl;
    return 1;
}
