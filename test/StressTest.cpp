#define NOMINMAX
#include <cstdint>
#include <string>
#include <iostream>
#include <vector>
#include <chrono>
#include <algorithm>
#include <numeric>
#include <iomanip>
#include <set>

#include <utility/Logging.hpp>
#include <utility/Scan.hpp>
#include <utility/Module.hpp>

#include <Windows.h>

#define STRESS_ASSERT(x) if (!(x)) { \
    std::cout << "FAIL: " << #x << " @ " << __FILE__ << ":" << __LINE__ << std::endl; \
    return 1; \
}

// ============================================================================
// Synthetic test functions with known CFG shapes
// All noinline + volatile to prevent optimizer from eliminating control flow
// ============================================================================

// A1: Pure linear flow, no branches
__declspec(noinline) int synth_linear(int a, int b) {
    volatile int x = a + b;
    volatile int y = x * 2;
    volatile int z = y - a;
    volatile int w = z + 1;
    return w;
}

// A2: Single conditional branch (diamond pattern)
__declspec(noinline) int synth_if_else(int a) {
    volatile int result;
    if (a > 0) {
        result = a + 10;
    } else {
        result = a - 10;
    }
    return result;
}

// A3: Loop with back-edge
__declspec(noinline) int synth_loop(int n) {
    volatile int sum = 0;
    for (volatile int i = 0; i < n; ++i) {
        sum += i;
    }
    return sum;
}

// A4: Nested conditionals (4 paths)
__declspec(noinline) int synth_nested_diamond(int a, int b) {
    volatile int result = 0;
    if (a > 0) {
        if (b > 0) {
            result = a + b;
        } else {
            result = a - b;
        }
    } else {
        if (b > 0) {
            result = b - a;
        } else {
            result = -(a + b);
        }
    }
    return result;
}

// A5: 9-case switch (may produce jump table)
__declspec(noinline) int synth_switch(int selector) {
    volatile int result = 0;
    switch (selector) {
        case 0: result = 100; break;
        case 1: result = 200; break;
        case 2: result = 300; break;
        case 3: result = 400; break;
        case 4: result = 500; break;
        case 5: result = 600; break;
        case 6: result = 700; break;
        case 7: result = 800; break;
        default: result = -1; break;
    }
    return result;
}

// Small callees for multi-call test
__declspec(noinline) int callee_add(int a, int b) { volatile int r = a + b; return r; }
__declspec(noinline) int callee_mul(int a, int b) { volatile int r = a * b; return r; }
__declspec(noinline) int callee_sub(int a, int b) { volatile int r = a - b; return r; }

// A6: Multiple calls (tests STEP_OVER and call-block merging)
__declspec(noinline) int synth_multi_call(int a, int b) {
    volatile int x = callee_add(a, b);
    volatile int y = callee_mul(x, a);
    volatile int z = callee_sub(y, b);
    if (z > 0) {
        z = callee_add(z, 1);
    }
    return z;
}

// A7: Many branches to stress the branch stack
__declspec(noinline) int synth_many_branches(int a, int b, int c, int d) {
    volatile int result = 0;
    if (a > 0) result += 1;
    if (b > 0) result += 2;
    if (c > 0) result += 4;
    if (d > 0) result += 8;
    if (a > b) result += 16;
    if (b > c) result += 32;
    if (c > d) result += 64;
    if (d > a) result += 128;
    if (a + b > c + d) result += 256;
    if (a * b > c * d) result += 512;
    if ((a ^ b) > (c ^ d)) result += 1024;
    if ((a | b) > (c | d)) result += 2048;
    for (volatile int i = 0; i < a; ++i) {
        if (i % 2 == 0) result += i;
        else result -= i;
    }
    for (volatile int j = 0; j < b; ++j) {
        if (j % 3 == 0) result += j * 2;
        else if (j % 3 == 1) result -= j;
        else result ^= j;
    }
    return result;
}

// A8: Deep nested loops -- many back-edges, stresses seen_addresses set
__declspec(noinline) int synth_deep_nested_loops(int a, int b, int c) {
    volatile int result = 0;
    for (volatile int i = 0; i < a; ++i) {
        for (volatile int j = 0; j < b; ++j) {
            for (volatile int k = 0; k < c; ++k) {
                if (i + j + k > 10) {
                    result += k;
                } else {
                    result -= k;
                }
            }
            result ^= j;
        }
        result += i;
    }
    return result;
}

// A9: Multiple early returns -- several ret instructions in one function
__declspec(noinline) int synth_early_returns(int a, int b, int c, int d) {
    volatile int x = a;
    if (x < 0) return -1;
    x += b;
    if (x > 100) return 100;
    x *= c;
    if (x == 0) return 0;
    x -= d;
    if (x < -50) return -50;
    if (x > 50) return 50;
    volatile int y = x * x;
    if (y > 1000) return 999;
    return y;
}

// A10: Long else-if chain -- sequential cmp/jcc pairs, not a jump table
__declspec(noinline) int synth_else_if_chain(int selector) {
    volatile int result = 0;
    if (selector == 1) result = 10;
    else if (selector == 2) result = 20;
    else if (selector == 3) result = 30;
    else if (selector == 4) result = 40;
    else if (selector == 5) result = 50;
    else if (selector == 6) result = 60;
    else if (selector == 7) result = 70;
    else if (selector == 8) result = 80;
    else if (selector == 9) result = 90;
    else if (selector == 10) result = 100;
    else if (selector == 11) result = 110;
    else if (selector == 12) result = 120;
    else if (selector == 13) result = 130;
    else if (selector == 14) result = 140;
    else if (selector == 15) result = 150;
    else if (selector == 16) result = 160;
    else result = -1;
    return result;
}

// A11: Dense calls interleaved with branches -- stresses STEP_OVER + merge interaction
__declspec(noinline) int synth_call_branch_interleave(int a, int b, int c) {
    volatile int r = callee_add(a, b);
    if (r > 10) r = callee_mul(r, 2);
    else r = callee_sub(r, 1);
    volatile int s = callee_add(r, c);
    if (s < 0) s = callee_mul(s, -1);
    volatile int t = callee_sub(s, a);
    if (t > 100) {
        t = callee_add(t, b);
        if (t > 200) t = callee_sub(t, c);
    }
    return t;
}

// A12: Huge straight-line -- one massive basic block, lots of instructions, no branches
__declspec(noinline) int synth_long_linear(int a, int b) {
    volatile int x = a;
    x += b; x *= 3; x -= a; x += 7; x ^= b; x += 11; x -= 5; x *= 2;
    x += a; x -= b; x *= 5; x += 13; x ^= a; x += 17; x -= 3; x *= 7;
    x += b; x -= a; x *= 11; x += 19; x ^= b; x += 23; x -= 7; x *= 3;
    x += a; x -= b; x *= 13; x += 29; x ^= a; x += 31; x -= 11; x *= 5;
    x += b; x -= a; x *= 17; x += 37; x ^= b; x += 41; x -= 13; x *= 7;
    x += a; x -= b; x *= 19; x += 43; x ^= a; x += 47; x -= 17; x *= 11;
    x += b; x -= a; x *= 23; x += 53; x ^= b; x += 59; x -= 19; x *= 13;
    x += a; x -= b; x *= 29; x += 61; x ^= a; x += 67; x -= 23; x *= 17;
    return x;
}

// ============================================================================
// Helpers
// ============================================================================

// Resolve MSVC incremental linking JMP thunks (ILT stubs).
// In Debug/RelWithDebInfo builds, &function points to a `jmp rel32` stub
// rather than the actual function body. Follow the jmp to get the real address.
uintptr_t resolve_jmp_thunk(uintptr_t addr) {
    INSTRUX instrux{};
    auto status = NdDecodeEx(&instrux, (uint8_t*)addr, 15, ND_CODE_64, ND_DATA_64);
    if (ND_SUCCESS(status) && instrux.Instruction == ND_INS_JMPNR
        && instrux.Operands[0].Type == ND_OP_OFFS) {
        return addr + instrux.Length + (int64_t)instrux.Operands[0].Info.RelativeOffset.Rel;
    }
    return addr;
}

// Convenience: resolve a function pointer
template<typename T>
uintptr_t fn_addr(T* fn) {
    return resolve_jmp_thunk((uintptr_t)fn);
}

void print_blocks(const std::vector<utility::BasicBlock>& blocks) {
    for (size_t i = 0; i < blocks.size(); ++i) {
        const auto& b = blocks[i];
        std::cout << "  block[" << i << "]: " << std::hex
                  << b.start << "-" << b.end << std::dec
                  << " insns=" << b.instruction_count
                  << " branches=" << b.branches.size();
        for (auto t : b.branches) {
            std::cout << " ->" << std::hex << t << std::dec;
        }
        std::cout << std::endl;
    }
}

// ============================================================================
// FrozenFn RAII helper: allocates executable memory from frozen byte arrays
// ============================================================================

struct FrozenFn {
    void* exec_mem = nullptr;
    size_t size = 0;

    uintptr_t addr() const { return (uintptr_t)exec_mem; }

    FrozenFn() = default;
    FrozenFn(const uint8_t* bytes, size_t sz) : size(sz) {
        exec_mem = VirtualAlloc(nullptr, sz, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (exec_mem) memcpy(exec_mem, bytes, sz);
    }
    ~FrozenFn() { if (exec_mem) VirtualFree(exec_mem, 0, MEM_RELEASE); }

    FrozenFn(const FrozenFn&) = delete;
    FrozenFn& operator=(const FrozenFn&) = delete;
    FrozenFn(FrozenFn&& o) noexcept : exec_mem(o.exec_mem), size(o.size) { o.exec_mem = nullptr; }
    FrozenFn& operator=(FrozenFn&& o) noexcept {
        if (exec_mem) VirtualFree(exec_mem, 0, MEM_RELEASE);
        exec_mem = o.exec_mem; size = o.size; o.exec_mem = nullptr; return *this;
    }
};

// ============================================================================
// Correctness tests -- all take a frozen address
// ============================================================================

int test_linear_correctness(uintptr_t addr) {
    std::cout << "=== test_linear_correctness ===" << std::endl;
    auto blocks = utility::collect_basic_blocks(addr,
        { .max_size = 500, .sort = true, .merge_call_blocks = true, .copy_instructions = true }
    );
    STRESS_ASSERT(!blocks.empty());
    STRESS_ASSERT(blocks.size() >= 1);
    STRESS_ASSERT(blocks.front().start == addr);
    STRESS_ASSERT(blocks.front().instruction_count >= 4);
    std::cout << "  blocks: " << blocks.size()
              << ", total insns: " << blocks.front().instruction_count << std::endl;
    print_blocks(blocks);
    return 0;
}

int test_if_else_correctness(uintptr_t addr) {
    std::cout << "=== test_if_else_correctness ===" << std::endl;
    auto blocks = utility::collect_basic_blocks(addr,
        { .max_size = 500, .sort = true, .merge_call_blocks = true, .copy_instructions = true }
    );
    STRESS_ASSERT(!blocks.empty());
    STRESS_ASSERT(blocks.size() >= 2);
    STRESS_ASSERT(blocks.front().start == addr);

    // At least one block should have branches
    bool found_branch = false;
    for (const auto& b : blocks) {
        if (!b.branches.empty()) { found_branch = true; break; }
    }
    STRESS_ASSERT(found_branch);

    // Branch targets should land within some block's range or past the end
    for (const auto& b : blocks) {
        for (auto target : b.branches) {
            bool target_in_block = std::any_of(blocks.begin(), blocks.end(),
                [target](const utility::BasicBlock& bb) { return target >= bb.start && target < bb.end; });
            bool target_past_end = target >= blocks.back().end;
            STRESS_ASSERT(target_in_block || target_past_end);
        }
    }

    print_blocks(blocks);
    return 0;
}

int test_loop_correctness(uintptr_t addr) {
    std::cout << "=== test_loop_correctness ===" << std::endl;
    auto blocks = utility::collect_basic_blocks(addr,
        { .max_size = 500, .sort = true, .merge_call_blocks = true, .copy_instructions = true }
    );
    STRESS_ASSERT(!blocks.empty());
    STRESS_ASSERT(blocks.size() >= 2);
    STRESS_ASSERT(blocks.front().start == addr);

    // Check for back-edge: at least one branch target points to a block at or before
    bool found_back_edge = false;
    for (const auto& b : blocks) {
        for (auto target : b.branches) {
            if (target <= b.start) {
                found_back_edge = true;
            }
        }
    }
    STRESS_ASSERT(found_back_edge);

    print_blocks(blocks);
    return 0;
}

int test_nested_diamond_correctness(uintptr_t addr) {
    std::cout << "=== test_nested_diamond_correctness ===" << std::endl;
    auto blocks = utility::collect_basic_blocks(addr,
        { .max_size = 500, .sort = true, .merge_call_blocks = true, .copy_instructions = true }
    );
    STRESS_ASSERT(!blocks.empty());
    STRESS_ASSERT(blocks.size() >= 4);
    STRESS_ASSERT(blocks.front().start == addr);

    size_t total_insns = 0;
    for (const auto& b : blocks) total_insns += b.instruction_count;
    STRESS_ASSERT(total_insns >= 10);

    print_blocks(blocks);
    return 0;
}

int test_multi_call_correctness(uintptr_t addr) {
    std::cout << "=== test_multi_call_correctness ===" << std::endl;

    // Without merging
    auto blocks_unmerged = utility::collect_basic_blocks(addr,
        { .max_size = 500, .sort = true, .merge_call_blocks = false, .copy_instructions = true }
    );

    // With merging (requires copy_instructions=true for the merge logic)
    auto blocks_merged = utility::collect_basic_blocks(addr,
        { .max_size = 500, .sort = true, .merge_call_blocks = true, .copy_instructions = true }
    );

    STRESS_ASSERT(!blocks_unmerged.empty());
    STRESS_ASSERT(!blocks_merged.empty());
    STRESS_ASSERT(blocks_merged.size() <= blocks_unmerged.size());

    STRESS_ASSERT(blocks_unmerged.front().start == addr);
    STRESS_ASSERT(blocks_merged.front().start == addr);

    // Total instruction count should be identical (merging doesn't lose instructions)
    size_t total_unmerged = 0, total_merged = 0;
    for (const auto& b : blocks_unmerged) total_unmerged += b.instruction_count;
    for (const auto& b : blocks_merged) total_merged += b.instruction_count;
    STRESS_ASSERT(total_unmerged == total_merged);

    std::cout << "  unmerged: " << blocks_unmerged.size()
              << ", merged: " << blocks_merged.size() << std::endl;
    print_blocks(blocks_merged);
    return 0;
}

int test_many_branches_correctness(uintptr_t addr) {
    std::cout << "=== test_many_branches_correctness ===" << std::endl;
    auto blocks = utility::collect_basic_blocks(addr,
        { .max_size = 2000, .sort = true, .merge_call_blocks = true, .copy_instructions = true }
    );
    STRESS_ASSERT(!blocks.empty());
    STRESS_ASSERT(blocks.size() >= 10);
    STRESS_ASSERT(blocks.front().start == addr);

    // Verify sorted order
    for (size_t i = 1; i < blocks.size(); ++i) {
        STRESS_ASSERT(blocks[i].start >= blocks[i - 1].start);
    }

    print_blocks(blocks);
    return 0;
}

int test_deep_nested_loops_correctness(uintptr_t addr) {
    std::cout << "=== test_deep_nested_loops_correctness ===" << std::endl;
    auto blocks = utility::collect_basic_blocks(addr,
        { .max_size = 2000, .sort = true, .merge_call_blocks = true, .copy_instructions = true }
    );
    STRESS_ASSERT(!blocks.empty());
    STRESS_ASSERT(blocks.size() >= 5); // 3 loop headers + conditional + body
    STRESS_ASSERT(blocks.front().start == addr);

    // Should have multiple back-edges (at least one per loop level)
    size_t back_edges = 0;
    for (const auto& b : blocks) {
        for (auto target : b.branches) {
            if (target <= b.start) ++back_edges;
        }
    }
    STRESS_ASSERT(back_edges >= 3);

    size_t total_insns = 0;
    for (const auto& b : blocks) total_insns += b.instruction_count;
    std::cout << "  blocks: " << blocks.size() << ", insns: " << total_insns
              << ", back_edges: " << back_edges << std::endl;
    print_blocks(blocks);
    return 0;
}

int test_early_returns_correctness(uintptr_t addr) {
    std::cout << "=== test_early_returns_correctness ===" << std::endl;
    auto blocks = utility::collect_basic_blocks(addr,
        { .max_size = 1000, .sort = true, .merge_call_blocks = true, .copy_instructions = true }
    );
    STRESS_ASSERT(!blocks.empty());
    STRESS_ASSERT(blocks.size() >= 6); // each early return creates a branch point
    STRESS_ASSERT(blocks.front().start == addr);

    // Count blocks that end with ret (last instruction is ND_INS_RETN)
    size_t ret_blocks = 0;
    for (const auto& b : blocks) {
        if (!b.instructions.empty() && b.instructions.back().instrux.Instruction == ND_INS_RETN) {
            ++ret_blocks;
        }
    }
    // Should have multiple ret-terminating blocks
    STRESS_ASSERT(ret_blocks >= 2);

    std::cout << "  blocks: " << blocks.size() << ", ret_blocks: " << ret_blocks << std::endl;
    print_blocks(blocks);
    return 0;
}

int test_else_if_chain_correctness(uintptr_t addr) {
    std::cout << "=== test_else_if_chain_correctness ===" << std::endl;
    auto blocks = utility::collect_basic_blocks(addr,
        { .max_size = 2000, .sort = true, .merge_call_blocks = true, .copy_instructions = true }
    );
    STRESS_ASSERT(!blocks.empty());
    STRESS_ASSERT(blocks.size() >= 10); // at least one block per else-if arm
    STRESS_ASSERT(blocks.front().start == addr);

    // Verify sorted order
    for (size_t i = 1; i < blocks.size(); ++i) {
        STRESS_ASSERT(blocks[i].start >= blocks[i - 1].start);
    }

    size_t total_insns = 0;
    for (const auto& b : blocks) total_insns += b.instruction_count;
    std::cout << "  blocks: " << blocks.size() << ", insns: " << total_insns << std::endl;
    print_blocks(blocks);
    return 0;
}

int test_call_branch_interleave_correctness(uintptr_t addr) {
    std::cout << "=== test_call_branch_interleave_correctness ===" << std::endl;

    auto blocks_unmerged = utility::collect_basic_blocks(addr,
        { .max_size = 1000, .sort = true, .merge_call_blocks = false, .copy_instructions = true }
    );
    auto blocks_merged = utility::collect_basic_blocks(addr,
        { .max_size = 1000, .sort = true, .merge_call_blocks = true, .copy_instructions = true }
    );

    STRESS_ASSERT(!blocks_unmerged.empty());
    STRESS_ASSERT(!blocks_merged.empty());
    STRESS_ASSERT(blocks_merged.size() <= blocks_unmerged.size());

    // This function has calls mixed with branches, so merging should reduce block count
    // but the merged version should still have branches from the if statements
    bool has_branches = false;
    for (const auto& b : blocks_merged) {
        if (!b.branches.empty()) { has_branches = true; break; }
    }
    STRESS_ASSERT(has_branches);

    size_t total_unmerged = 0, total_merged = 0;
    for (const auto& b : blocks_unmerged) total_unmerged += b.instruction_count;
    for (const auto& b : blocks_merged) total_merged += b.instruction_count;
    STRESS_ASSERT(total_unmerged == total_merged);

    std::cout << "  unmerged: " << blocks_unmerged.size()
              << ", merged: " << blocks_merged.size() << std::endl;
    print_blocks(blocks_merged);
    return 0;
}

int test_long_linear_correctness(uintptr_t addr) {
    std::cout << "=== test_long_linear_correctness ===" << std::endl;
    auto blocks = utility::collect_basic_blocks(addr,
        { .max_size = 2000, .sort = true, .merge_call_blocks = true, .copy_instructions = true }
    );
    STRESS_ASSERT(!blocks.empty());
    STRESS_ASSERT(blocks.front().start == addr);

    // Should be a single large block (no branches in pure arithmetic)
    // Allow for a couple blocks in case of compiler-generated prologue/epilogue splits
    STRESS_ASSERT(blocks.size() <= 3);

    size_t total_insns = 0;
    for (const auto& b : blocks) total_insns += b.instruction_count;
    // 64 volatile operations + prologue/epilogue overhead
    STRESS_ASSERT(total_insns >= 60);

    std::cout << "  blocks: " << blocks.size() << ", insns: " << total_insns << std::endl;
    print_blocks(blocks);
    return 0;
}

// ============================================================================
// Structural validation -- use frozen addresses
// ============================================================================

// Forward declare FrozenSet (defined after frozen data)
struct FrozenSet;

int test_contiguous_coverage(const FrozenSet& frozen);
int test_option_variants(uintptr_t addr);

// ============================================================================
// Consistency / idempotency -- use frozen addresses
// ============================================================================

int test_consistency(const FrozenSet& frozen);

// ============================================================================
// Performance benchmarks
// ============================================================================

struct BenchResult {
    double min_us;
    double avg_us;
    double max_us;
    double total_us;
    size_t iterations;
};

BenchResult benchmark_collect(uintptr_t target, const utility::BasicBlockCollectOptions& opts, size_t iterations) {
    std::vector<double> times;
    times.reserve(iterations);

    for (size_t i = 0; i < iterations; ++i) {
        auto start = std::chrono::high_resolution_clock::now();
        auto blocks = utility::collect_basic_blocks(target, opts);
        auto end = std::chrono::high_resolution_clock::now();

        volatile auto sz = blocks.size();
        (void)sz;

        double us = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count() / 1000.0;
        times.push_back(us);
    }

    std::sort(times.begin(), times.end());
    double sum = std::accumulate(times.begin(), times.end(), 0.0);

    return { times.front(), sum / times.size(), times.back(), sum, iterations };
}

void print_bench(const char* name, const BenchResult& r) {
    std::cout << "  " << name << ": min=" << r.min_us << "us, avg=" << r.avg_us
              << "us, max=" << r.max_us << "us, total=" << r.total_us / 1000.0
              << "ms (" << r.iterations << " iters)" << std::endl;
}

int bench_exhaustive_decode(const FrozenSet& frozen);
int bench_collect_basic_blocks(const FrozenSet& frozen);

// ============================================================================
// Snapshot: dumps frozen bytes + expected block layout for golden tests
// ============================================================================

struct SnapshotTarget {
    const char* name;
    uintptr_t addr;
};

// Dump a function's bytes and block layout as C source for embedding
void snapshot_function(const SnapshotTarget& t) {
    auto blocks = utility::collect_basic_blocks(t.addr,
        { .max_size = 4000, .sort = true, .merge_call_blocks = true, .copy_instructions = true });
    if (blocks.empty()) return;

    auto highest = utility::get_highest_contiguous_block(blocks);
    if (highest == blocks.end()) return;

    const auto fn_start = blocks.front().start;
    const auto fn_end = highest->end;
    const auto fn_size = fn_end - fn_start;

    // Dump bytes as C array
    std::cout << "static const uint8_t frozen_" << t.name << "[] = {";
    for (size_t i = 0; i < fn_size; ++i) {
        if (i % 16 == 0) std::cout << "\n    ";
        std::cout << "0x" << std::hex << std::setfill('0') << std::setw(2)
                  << (unsigned)((uint8_t*)fn_start)[i] << std::dec;
        if (i + 1 < fn_size) std::cout << ",";
    }
    std::cout << "\n}; // " << fn_size << " bytes\n\n";

    // Dump expected block layout as RVAs
    std::cout << "static const ExpectedBlock expected_" << t.name << "[] = {\n";
    for (const auto& b : blocks) {
        if (b.start > fn_end || b.end > fn_end + 16) continue; // skip blocks outside contiguous range
        std::cout << "    { " << (b.start - fn_start) << ", " << (b.end - fn_start)
                  << ", " << b.instruction_count << ", {";
        bool first = true;
        for (auto target : b.branches) {
            if (!first) std::cout << ",";
            std::cout << " " << (int64_t)(target - fn_start);
            first = false;
        }
        std::cout << " } },\n";
    }
    std::cout << "};\n\n";
}

int run_snapshot() {
    std::cout << "#include <iomanip>\n\n";
    std::cout << "struct ExpectedBlock {\n";
    std::cout << "    size_t start_rva;\n";
    std::cout << "    size_t end_rva;\n";
    std::cout << "    size_t instruction_count;\n";
    std::cout << "    std::vector<int64_t> branch_rvas;\n";
    std::cout << "};\n\n";

    SnapshotTarget targets[] = {
        {"synth_linear",                 fn_addr(&synth_linear)},
        {"synth_if_else",                fn_addr(&synth_if_else)},
        {"synth_loop",                   fn_addr(&synth_loop)},
        {"synth_nested_diamond",         fn_addr(&synth_nested_diamond)},
        {"synth_multi_call",             fn_addr(&synth_multi_call)},
        {"synth_many_branches",          fn_addr(&synth_many_branches)},
        {"synth_deep_nested_loops",      fn_addr(&synth_deep_nested_loops)},
        {"synth_early_returns",          fn_addr(&synth_early_returns)},
        {"synth_else_if_chain",          fn_addr(&synth_else_if_chain)},
        {"synth_call_branch_interleave", fn_addr(&synth_call_branch_interleave)},
        {"synth_long_linear",            fn_addr(&synth_long_linear)},
    };

    for (auto& t : targets) {
        snapshot_function(t);
    }
    return 0;
}

// ============================================================================
// Golden tests: frozen bytes + exact expected layout
// ============================================================================

struct ExpectedBlock {
    size_t start_rva;
    size_t end_rva;
    size_t instruction_count;
    std::vector<int64_t> branch_rvas; // relative to function start, can be negative (shouldn't be, but safe)
};

// --- Frozen byte arrays and expected block layouts (generated by --snapshot) ---

static const uint8_t frozen_synth_linear[] = {
    0x8d,0x04,0x11,0x89,0x44,0x24,0x08,0x8b,0x44,0x24,0x08,0x03,0xc0,0x89,0x44,0x24,
    0x08,0x8b,0x44,0x24,0x08,0x2b,0xc1,0x89,0x44,0x24,0x08,0x8b,0x44,0x24,0x08,0xff,
    0xc0,0x89,0x44,0x24,0x08,0x8b,0x44,0x24,0x08,0xc3
}; // 42 bytes

static const ExpectedBlock expected_synth_linear[] = {
    { 0, 42, 13, { } },
};

static const uint8_t frozen_synth_if_else[] = {
    0x8d,0x41,0x0a,0x85,0xc9,0x7f,0x03,0x8d,0x41,0xf6,0x89,0x44,0x24,0x08,0x8b,0x44,
    0x24,0x08,0xc3
}; // 19 bytes

static const ExpectedBlock expected_synth_if_else[] = {
    { 0, 7, 3, { 10, 7 } },
    { 7, 19, 4, { 10, 7 } },
};

static const uint8_t frozen_synth_loop[] = {
    0x33,0xc0,0x89,0x44,0x24,0x10,0x89,0x44,0x24,0x08,0x8b,0x44,0x24,0x08,0x3b,0xc1,
    0x7d,0x20,0x8b,0x54,0x24,0x08,0x8b,0x44,0x24,0x10,0x03,0xd0,0x89,0x54,0x24,0x10,
    0x8b,0x44,0x24,0x08,0xff,0xc0,0x89,0x44,0x24,0x08,0x8b,0x44,0x24,0x08,0x3b,0xc1,
    0x7c,0xe0,0x8b,0x44,0x24,0x10,0xc3
}; // 55 bytes

static const ExpectedBlock expected_synth_loop[] = {
    { 0, 18, 6, { 50, 18 } },
    { 18, 50, 10, { 50, 18, 18, 50 } },
    { 50, 55, 2, { 50, 18, 18, 50 } },
};

static const uint8_t frozen_synth_nested_diamond[] = {
    0xc7,0x44,0x24,0x08,0x00,0x00,0x00,0x00,0x85,0xc9,0x7e,0x1b,0x85,0xd2,0x7e,0x0c,
    0x8d,0x04,0x11,0x89,0x44,0x24,0x08,0x8b,0x44,0x24,0x08,0xc3,0x2b,0xca,0x89,0x4c,
    0x24,0x08,0x8b,0x44,0x24,0x08,0xc3,0x85,0xd2,0x7e,0x0b,0x2b,0xd1,0x89,0x54,0x24,
    0x08,0x8b,0x44,0x24,0x08,0xc3,0x8d,0x04,0x11,0xf7,0xd8,0x89,0x44,0x24,0x08,0x8b,
    0x44,0x24,0x08,0xc3
}; // 68 bytes

static const ExpectedBlock expected_synth_nested_diamond[] = {
    { 0, 12, 3, { 39, 12 } },
    { 12, 16, 2, { 39, 12, 28, 16 } },
    { 16, 28, 4, { 39, 12, 28, 16 } },
    { 28, 39, 4, { 39, 12, 28, 16 } },
    { 39, 43, 2, { 39, 12, 28, 16, 54, 43 } },
    { 43, 54, 4, { 39, 12, 28, 16, 54, 43 } },
    { 54, 68, 5, { 39, 12, 28, 16, 54, 43 } },
};

static const uint8_t frozen_synth_multi_call[] = {
    0x48,0x89,0x5c,0x24,0x08,0x57,0x48,0x83,0xec,0x20,0x8b,0xfa,0x8b,0xd9,0xe8,0x0d,
    0xcb,0xff,0xff,0x89,0x44,0x24,0x40,0x8b,0xd3,0x8b,0x4c,0x24,0x40,0xe8,0x0e,0xcb,
    0xff,0xff,0x89,0x44,0x24,0x40,0x8b,0xd7,0x8b,0x4c,0x24,0x40,0xe8,0x0f,0xcb,0xff,
    0xff,0x89,0x44,0x24,0x40,0x8b,0x44,0x24,0x40,0x85,0xc0,0x7e,0x12,0x8b,0x4c,0x24,
    0x40,0xba,0x01,0x00,0x00,0x00,0xe8,0xd5,0xca,0xff,0xff,0x89,0x44,0x24,0x40,0x8b,
    0x44,0x24,0x40,0x48,0x8b,0x5c,0x24,0x30,0x48,0x83,0xc4,0x20,0x5f,0xc3
}; // 94 bytes

static const ExpectedBlock expected_synth_multi_call[] = {
    { 0, 61, 18, { 79, 61 } },
    { 61, 94, 9, { 79, 61 } },
};

static const uint8_t frozen_synth_many_branches[] = {
    0x44,0x8b,0xda,0x44,0x8b,0xd1,0x33,0xd2,0x89,0x54,0x24,0x08,0x85,0xc9,0x7e,0x0a,
    0x8b,0x44,0x24,0x08,0xff,0xc0,0x89,0x44,0x24,0x08,0x45,0x85,0xdb,0x7e,0x0b,0x8b,
    0x44,0x24,0x08,0x83,0xc0,0x02,0x89,0x44,0x24,0x08,0x45,0x85,0xc0,0x7e,0x0b,0x8b,
    0x44,0x24,0x08,0x83,0xc0,0x04,0x89,0x44,0x24,0x08,0x45,0x85,0xc9,0x7e,0x0b,0x8b,
    0x44,0x24,0x08,0x83,0xc0,0x08,0x89,0x44,0x24,0x08,0x45,0x3b,0xd3,0x7e,0x0b,0x8b,
    0x44,0x24,0x08,0x83,0xc0,0x10,0x89,0x44,0x24,0x08,0x45,0x3b,0xd8,0x7e,0x0b,0x8b,
    0x44,0x24,0x08,0x83,0xc0,0x20,0x89,0x44,0x24,0x08,0x45,0x3b,0xc1,0x7e,0x0b,0x8b,
    0x44,0x24,0x08,0x83,0xc0,0x40,0x89,0x44,0x24,0x08,0x45,0x3b,0xca,0x7e,0x0b,0x8b,
    0x44,0x24,0x08,0x83,0xe8,0x80,0x89,0x44,0x24,0x08,0x41,0x03,0xcb,0x43,0x8d,0x04,
    0x08,0x3b,0xc8,0x7e,0x0d,0x8b,0x44,0x24,0x08,0x05,0x00,0x01,0x00,0x00,0x89,0x44,
    0x24,0x08,0x41,0x8b,0xca,0x41,0x8b,0xc0,0x41,0x0f,0xaf,0xcb,0x41,0x0f,0xaf,0xc1,
    0x3b,0xc8,0x7e,0x0d,0x8b,0x44,0x24,0x08,0x05,0x00,0x02,0x00,0x00,0x89,0x44,0x24,
    0x08,0x41,0x8b,0xca,0x41,0x8b,0xc0,0x41,0x33,0xcb,0x41,0x33,0xc1,0x3b,0xc8,0x7e,
    0x0d,0x8b,0x44,0x24,0x08,0x05,0x00,0x04,0x00,0x00,0x89,0x44,0x24,0x08,0x41,0x8b,
    0xc2,0x45,0x0b,0xc1,0x41,0x0b,0xc3,0x41,0x3b,0xc0,0x7e,0x0d,0x8b,0x44,0x24,0x08,
    0x05,0x00,0x08,0x00,0x00,0x89,0x44,0x24,0x08,0x89,0x54,0x24,0x10,0x8b,0x44,0x24,
    0x10,0x41,0x3b,0xc2,0x7d,0x35,0x8b,0x44,0x24,0x10,0xa8,0x01,0x75,0x0c,0x8b,0x4c,
    0x24,0x10,0x8b,0x44,0x24,0x08,0x03,0xc8,0xeb,0x0a,0x8b,0x44,0x24,0x10,0x8b,0x4c,
    0x24,0x08,0x2b,0xc8,0x89,0x4c,0x24,0x08,0x8b,0x44,0x24,0x10,0xff,0xc0,0x89,0x44,
    0x24,0x10,0x8b,0x44,0x24,0x10,0x41,0x3b,0xc2,0x7c,0xcb,0x89,0x54,0x24,0x10,0x8b,
    0x44,0x24,0x10,0x41,0x3b,0xc3,0x7d,0x78,0x0f,0x1f,0x84,0x00,0x00,0x00,0x00,0x00,
    0x8b,0x4c,0x24,0x10,0xb8,0x56,0x55,0x55,0x55,0xf7,0xe9,0x8b,0xc2,0xc1,0xe8,0x1f,
    0x03,0xd0,0x8d,0x04,0x52,0x3b,0xc8,0x8b,0x4c,0x24,0x10,0x75,0x0e,0x8b,0x44,0x24,
    0x08,0x03,0xc9,0x03,0xc1,0x89,0x44,0x24,0x08,0xeb,0x32,0xb8,0x56,0x55,0x55,0x55,
    0xf7,0xe9,0x8b,0xc2,0xc1,0xe8,0x1f,0x03,0xd0,0x8d,0x04,0x52,0x2b,0xc8,0x83,0xf9,
    0x01,0x75,0x0c,0x8b,0x44,0x24,0x10,0x8b,0x4c,0x24,0x08,0x2b,0xc8,0xeb,0x0a,0x8b,
    0x4c,0x24,0x10,0x8b,0x44,0x24,0x08,0x33,0xc8,0x89,0x4c,0x24,0x08,0x8b,0x44,0x24,
    0x10,0xff,0xc0,0x89,0x44,0x24,0x10,0x8b,0x44,0x24,0x10,0x41,0x3b,0xc3,0x7c,0x90,
    0x8b,0x44,0x24,0x08,0xc3
}; // 453 bytes

static const ExpectedBlock expected_synth_many_branches[] = {
    { 0, 16, 6, { 26, 16 } },
    { 16, 31, 5, { 26, 16, 42, 31 } },
    { 31, 47, 5, { 26, 16, 42, 31, 58, 47 } },
    { 47, 63, 5, { 26, 16, 42, 31, 58, 47, 74, 63 } },
    { 63, 79, 5, { 26, 16, 42, 31, 58, 47, 74, 63, 90, 79 } },
    { 79, 95, 5, { 26, 16, 42, 31, 58, 47, 74, 63, 90, 79, 106, 95 } },
    { 95, 111, 5, { 26, 16, 42, 31, 58, 47, 74, 63, 90, 79, 106, 95, 122, 111 } },
    { 111, 127, 5, { 26, 16, 42, 31, 58, 47, 74, 63, 90, 79, 106, 95, 122, 111, 138, 127 } },
    { 127, 149, 7, { 26, 16, 42, 31, 58, 47, 74, 63, 90, 79, 106, 95, 122, 111, 138, 127, 162, 149 } },
    { 149, 180, 9, { 26, 16, 42, 31, 58, 47, 74, 63, 90, 79, 106, 95, 122, 111, 138, 127, 162, 149, 193, 180 } },
    { 180, 209, 9, { 26, 16, 42, 31, 58, 47, 74, 63, 90, 79, 106, 95, 122, 111, 138, 127, 162, 149, 193, 180, 222, 209 } },
    { 209, 236, 8, { 26, 16, 42, 31, 58, 47, 74, 63, 90, 79, 106, 95, 122, 111, 138, 127, 162, 149, 193, 180, 222, 209, 249, 236 } },
    { 236, 262, 7, { 26, 16, 42, 31, 58, 47, 74, 63, 90, 79, 106, 95, 122, 111, 138, 127, 162, 149, 193, 180, 222, 209, 249, 236, 315, 262 } },
    { 262, 270, 3, { 26, 16, 42, 31, 58, 47, 74, 63, 90, 79, 106, 95, 122, 111, 138, 127, 162, 149, 193, 180, 222, 209, 249, 236, 315, 262, 282, 270 } },
    { 270, 282, 4, { 26, 16, 42, 31, 58, 47, 74, 63, 90, 79, 106, 95, 122, 111, 138, 127, 162, 149, 193, 180, 222, 209, 249, 236, 315, 262, 282, 270 } },
    { 282, 292, 3, { 26, 16, 42, 31, 58, 47, 74, 63, 90, 79, 106, 95, 122, 111, 138, 127, 162, 149, 193, 180, 222, 209, 249, 236, 315, 262, 282, 270, 262, 315, 448, 328, 379, 365, 336, 448, 415, 403 } },
    { 292, 315, 7, { 26, 16, 42, 31, 58, 47, 74, 63, 90, 79, 106, 95, 122, 111, 138, 127, 162, 149, 193, 180, 222, 209, 249, 236, 315, 262, 282, 270, 262, 315 } },
    { 315, 328, 4, { 26, 16, 42, 31, 58, 47, 74, 63, 90, 79, 106, 95, 122, 111, 138, 127, 162, 149, 193, 180, 222, 209, 249, 236, 315, 262, 282, 270, 262, 315, 448, 328 } },
    { 328, 365, 11, { 26, 16, 42, 31, 58, 47, 74, 63, 90, 79, 106, 95, 122, 111, 138, 127, 162, 149, 193, 180, 222, 209, 249, 236, 315, 262, 282, 270, 262, 315, 448, 328, 379, 365 } },
    { 365, 379, 5, { 26, 16, 42, 31, 58, 47, 74, 63, 90, 79, 106, 95, 122, 111, 138, 127, 162, 149, 193, 180, 222, 209, 249, 236, 315, 262, 282, 270, 262, 315, 448, 328, 379, 365 } },
    { 379, 403, 9, { 26, 16, 42, 31, 58, 47, 74, 63, 90, 79, 106, 95, 122, 111, 138, 127, 162, 149, 193, 180, 222, 209, 249, 236, 315, 262, 282, 270, 262, 315, 448, 328, 379, 365, 336, 448, 415, 403 } },
    { 403, 415, 4, { 26, 16, 42, 31, 58, 47, 74, 63, 90, 79, 106, 95, 122, 111, 138, 127, 162, 149, 193, 180, 222, 209, 249, 236, 315, 262, 282, 270, 262, 315, 448, 328, 379, 365, 336, 448, 415, 403 } },
    { 415, 425, 3, { 26, 16, 42, 31, 58, 47, 74, 63, 90, 79, 106, 95, 122, 111, 138, 127, 162, 149, 193, 180, 222, 209, 249, 236, 315, 262, 282, 270, 262, 315, 448, 328, 379, 365, 336, 448, 415, 403 } },
    { 425, 429, 1, { 26, 16, 42, 31, 58, 47, 74, 63, 90, 79, 106, 95, 122, 111, 138, 127, 162, 149, 193, 180, 222, 209, 249, 236, 315, 262, 282, 270, 262, 315, 448, 328, 379, 365, 336, 448, 415, 403 } },
    { 429, 448, 6, { 26, 16, 42, 31, 58, 47, 74, 63, 90, 79, 106, 95, 122, 111, 138, 127, 162, 149, 193, 180, 222, 209, 249, 236, 315, 262, 282, 270, 262, 315, 448, 328, 379, 365, 336, 448 } },
    { 448, 453, 2, { 26, 16, 42, 31, 58, 47, 74, 63, 90, 79, 106, 95, 122, 111, 138, 127, 162, 149, 193, 180, 222, 209, 249, 236, 315, 262, 282, 270, 262, 315, 448, 328, 379, 365, 336, 448 } },
};

static const uint8_t frozen_synth_deep_nested_loops[] = {
    0x48,0x83,0xec,0x18,0x45,0x33,0xd2,0x44,0x8b,0xc9,0x44,0x89,0x54,0x24,0x20,0x44,
    0x89,0x54,0x24,0x04,0x8b,0x44,0x24,0x04,0x3b,0xc1,0x0f,0x8d,0xa2,0x00,0x00,0x00,
    0x44,0x89,0x14,0x24,0x8b,0x04,0x24,0x3b,0xc2,0x7d,0x72,0x0f,0x1f,0x44,0x00,0x00,
    0x44,0x89,0x54,0x24,0x38,0x8b,0x44,0x24,0x38,0x41,0x3b,0xc0,0x7d,0x43,0x66,0x90,
    0x8b,0x4c,0x24,0x38,0x8b,0x04,0x24,0x03,0xc8,0x8b,0x44,0x24,0x04,0x03,0xc1,0x83,
    0xf8,0x0a,0x7e,0x0c,0x8b,0x4c,0x24,0x38,0x8b,0x44,0x24,0x20,0x03,0xc8,0xeb,0x0a,
    0x8b,0x44,0x24,0x38,0x8b,0x4c,0x24,0x20,0x2b,0xc8,0x89,0x4c,0x24,0x20,0x8b,0x44,
    0x24,0x38,0xff,0xc0,0x89,0x44,0x24,0x38,0x8b,0x44,0x24,0x38,0x41,0x3b,0xc0,0x7c,
    0xbf,0x8b,0x0c,0x24,0x8b,0x44,0x24,0x20,0x33,0xc8,0x89,0x4c,0x24,0x20,0x8b,0x04,
    0x24,0xff,0xc0,0x89,0x04,0x24,0x8b,0x04,0x24,0x3b,0xc2,0x7c,0x93,0x8b,0x4c,0x24,
    0x04,0x8b,0x44,0x24,0x20,0x03,0xc8,0x89,0x4c,0x24,0x20,0x8b,0x44,0x24,0x04,0xff,
    0xc0,0x89,0x44,0x24,0x04,0x8b,0x44,0x24,0x04,0x41,0x3b,0xc1,0x0f,0x8c,0x5e,0xff,
    0xff,0xff,0x8b,0x44,0x24,0x20,0x48,0x83,0xc4,0x18,0xc3
}; // 203 bytes

static const ExpectedBlock expected_synth_deep_nested_loops[] = {
    { 0, 32, 8, { 194, 32 } },
    { 32, 43, 4, { 194, 32, 157, 43 } },
    { 43, 62, 5, { 194, 32, 157, 43, 129, 62 } },
    { 62, 84, 8, { 194, 32, 157, 43, 129, 62, 96, 84 } },
    { 84, 96, 4, { 194, 32, 157, 43, 129, 62, 96, 84 } },
    { 96, 106, 3, { 194, 32, 157, 43, 129, 62, 96, 84, 64, 129, 48, 157, 32, 194 } },
    { 106, 129, 7, { 194, 32, 157, 43, 129, 62, 96, 84, 64, 129 } },
    { 129, 157, 10, { 194, 32, 157, 43, 129, 62, 96, 84, 64, 129, 48, 157 } },
    { 157, 194, 10, { 194, 32, 157, 43, 129, 62, 96, 84, 64, 129, 48, 157, 32, 194 } },
    { 194, 203, 3, { 194, 32, 157, 43, 129, 62, 96, 84, 64, 129, 48, 157, 32, 194 } },
};

static const uint8_t frozen_synth_early_returns[] = {
    0x89,0x4c,0x24,0x08,0x8b,0x44,0x24,0x08,0x85,0xc0,0x79,0x06,0xb8,0xff,0xff,0xff,
    0xff,0xc3,0x8b,0x44,0x24,0x08,0x03,0xc2,0x89,0x44,0x24,0x08,0x8b,0x44,0x24,0x08,
    0x83,0xf8,0x64,0x7e,0x06,0xb8,0x64,0x00,0x00,0x00,0xc3,0x8b,0x44,0x24,0x08,0x41,
    0x0f,0xaf,0xc0,0x89,0x44,0x24,0x08,0x8b,0x44,0x24,0x08,0x85,0xc0,0x75,0x01,0xc3,
    0x8b,0x44,0x24,0x08,0x41,0x2b,0xc1,0x89,0x44,0x24,0x08,0x8b,0x44,0x24,0x08,0x83,
    0xf8,0xce,0x7d,0x06,0xb8,0xce,0xff,0xff,0xff,0xc3,0x8b,0x44,0x24,0x08,0x83,0xf8,
    0x32,0x7e,0x06,0xb8,0x32,0x00,0x00,0x00,0xc3,0x8b,0x4c,0x24,0x08,0x8b,0x44,0x24,
    0x08,0x0f,0xaf,0xc8,0x89,0x4c,0x24,0x08,0x8b,0x44,0x24,0x08,0x3d,0xe8,0x03,0x00,
    0x00,0xb8,0xe7,0x03,0x00,0x00,0x7f,0x04,0x8b,0x44,0x24,0x08,0xc3
}; // 141 bytes

static const ExpectedBlock expected_synth_early_returns[] = {
    { 0, 12, 4, { 18, 12 } },
    { 12, 18, 2, { 18, 12 } },
    { 18, 37, 6, { 18, 12, 43, 37 } },
    { 37, 43, 2, { 18, 12, 43, 37 } },
    { 43, 63, 6, { 18, 12, 43, 37, 64, 63 } },
    { 63, 64, 1, { 18, 12, 43, 37, 64, 63 } },
    { 64, 84, 6, { 18, 12, 43, 37, 64, 63, 90, 84 } },
    { 84, 90, 2, { 18, 12, 43, 37, 64, 63, 90, 84 } },
    { 90, 99, 3, { 18, 12, 43, 37, 64, 63, 90, 84, 105, 99 } },
    { 99, 105, 2, { 18, 12, 43, 37, 64, 63, 90, 84, 105, 99 } },
    { 105, 136, 8, { 18, 12, 43, 37, 64, 63, 90, 84, 105, 99, 140, 136 } },
    { 136, 141, 2, { 18, 12, 43, 37, 64, 63, 90, 84, 105, 99, 140, 136 } },
};

static const uint8_t frozen_synth_else_if_chain[] = {
    0xc7,0x44,0x24,0x08,0x00,0x00,0x00,0x00,0x83,0xf9,0x01,0x75,0x0d,0xc7,0x44,0x24,
    0x08,0x0a,0x00,0x00,0x00,0x8b,0x44,0x24,0x08,0xc3,0x83,0xf9,0x02,0x75,0x0d,0xc7,
    0x44,0x24,0x08,0x14,0x00,0x00,0x00,0x8b,0x44,0x24,0x08,0xc3,0x83,0xf9,0x03,0x75,
    0x0d,0xc7,0x44,0x24,0x08,0x1e,0x00,0x00,0x00,0x8b,0x44,0x24,0x08,0xc3,0x83,0xf9,
    0x04,0x75,0x0d,0xc7,0x44,0x24,0x08,0x28,0x00,0x00,0x00,0x8b,0x44,0x24,0x08,0xc3,
    0x83,0xf9,0x05,0x75,0x0d,0xc7,0x44,0x24,0x08,0x32,0x00,0x00,0x00,0x8b,0x44,0x24,
    0x08,0xc3,0x83,0xf9,0x06,0x75,0x0d,0xc7,0x44,0x24,0x08,0x3c,0x00,0x00,0x00,0x8b,
    0x44,0x24,0x08,0xc3,0x83,0xf9,0x07,0x75,0x0d,0xc7,0x44,0x24,0x08,0x46,0x00,0x00,
    0x00,0x8b,0x44,0x24,0x08,0xc3,0x83,0xf9,0x08,0x75,0x0d,0xc7,0x44,0x24,0x08,0x50,
    0x00,0x00,0x00,0x8b,0x44,0x24,0x08,0xc3,0x83,0xf9,0x09,0x75,0x0d,0xc7,0x44,0x24,
    0x08,0x5a,0x00,0x00,0x00,0x8b,0x44,0x24,0x08,0xc3,0x83,0xf9,0x0a,0x75,0x0d,0xc7,
    0x44,0x24,0x08,0x64,0x00,0x00,0x00,0x8b,0x44,0x24,0x08,0xc3,0x83,0xf9,0x0b,0x75,
    0x0d,0xc7,0x44,0x24,0x08,0x6e,0x00,0x00,0x00,0x8b,0x44,0x24,0x08,0xc3,0x83,0xf9,
    0x0c,0x75,0x0d,0xc7,0x44,0x24,0x08,0x78,0x00,0x00,0x00,0x8b,0x44,0x24,0x08,0xc3,
    0x83,0xf9,0x0d,0x75,0x0d,0xc7,0x44,0x24,0x08,0x82,0x00,0x00,0x00,0x8b,0x44,0x24,
    0x08,0xc3,0x83,0xf9,0x0e,0x75,0x0d,0xc7,0x44,0x24,0x08,0x8c,0x00,0x00,0x00,0x8b,
    0x44,0x24,0x08,0xc3,0x83,0xf9,0x0f,0x75,0x0d,0xc7,0x44,0x24,0x08,0x96,0x00,0x00,
    0x00,0x8b,0x44,0x24,0x08,0xc3,0x83,0xf9,0x10,0xb8,0xff,0xff,0xff,0xff,0xba,0xa0,
    0x00,0x00,0x00,0x0f,0x44,0xc2,0x89,0x44,0x24,0x08,0x8b,0x44,0x24,0x08,0xc3
}; // 303 bytes

static const ExpectedBlock expected_synth_else_if_chain[] = {
    { 0, 13, 3, { 26, 13 } },
    { 13, 26, 3, { 26, 13 } },
    { 26, 31, 2, { 26, 13, 44, 31 } },
    { 31, 44, 3, { 26, 13, 44, 31 } },
    { 44, 49, 2, { 26, 13, 44, 31, 62, 49 } },
    { 49, 62, 3, { 26, 13, 44, 31, 62, 49 } },
    { 62, 67, 2, { 26, 13, 44, 31, 62, 49, 80, 67 } },
    { 67, 80, 3, { 26, 13, 44, 31, 62, 49, 80, 67 } },
    { 80, 85, 2, { 26, 13, 44, 31, 62, 49, 80, 67, 98, 85 } },
    { 85, 98, 3, { 26, 13, 44, 31, 62, 49, 80, 67, 98, 85 } },
    { 98, 103, 2, { 26, 13, 44, 31, 62, 49, 80, 67, 98, 85, 116, 103 } },
    { 103, 116, 3, { 26, 13, 44, 31, 62, 49, 80, 67, 98, 85, 116, 103 } },
    { 116, 121, 2, { 26, 13, 44, 31, 62, 49, 80, 67, 98, 85, 116, 103, 134, 121 } },
    { 121, 134, 3, { 26, 13, 44, 31, 62, 49, 80, 67, 98, 85, 116, 103, 134, 121 } },
    { 134, 139, 2, { 26, 13, 44, 31, 62, 49, 80, 67, 98, 85, 116, 103, 134, 121, 152, 139 } },
    { 139, 152, 3, { 26, 13, 44, 31, 62, 49, 80, 67, 98, 85, 116, 103, 134, 121, 152, 139 } },
    { 152, 157, 2, { 26, 13, 44, 31, 62, 49, 80, 67, 98, 85, 116, 103, 134, 121, 152, 139, 170, 157 } },
    { 157, 170, 3, { 26, 13, 44, 31, 62, 49, 80, 67, 98, 85, 116, 103, 134, 121, 152, 139, 170, 157 } },
    { 170, 175, 2, { 26, 13, 44, 31, 62, 49, 80, 67, 98, 85, 116, 103, 134, 121, 152, 139, 170, 157, 188, 175 } },
    { 175, 188, 3, { 26, 13, 44, 31, 62, 49, 80, 67, 98, 85, 116, 103, 134, 121, 152, 139, 170, 157, 188, 175 } },
    { 188, 193, 2, { 26, 13, 44, 31, 62, 49, 80, 67, 98, 85, 116, 103, 134, 121, 152, 139, 170, 157, 188, 175, 206, 193 } },
    { 193, 206, 3, { 26, 13, 44, 31, 62, 49, 80, 67, 98, 85, 116, 103, 134, 121, 152, 139, 170, 157, 188, 175, 206, 193 } },
    { 206, 211, 2, { 26, 13, 44, 31, 62, 49, 80, 67, 98, 85, 116, 103, 134, 121, 152, 139, 170, 157, 188, 175, 206, 193, 224, 211 } },
    { 211, 224, 3, { 26, 13, 44, 31, 62, 49, 80, 67, 98, 85, 116, 103, 134, 121, 152, 139, 170, 157, 188, 175, 206, 193, 224, 211 } },
    { 224, 229, 2, { 26, 13, 44, 31, 62, 49, 80, 67, 98, 85, 116, 103, 134, 121, 152, 139, 170, 157, 188, 175, 206, 193, 224, 211, 242, 229 } },
    { 229, 242, 3, { 26, 13, 44, 31, 62, 49, 80, 67, 98, 85, 116, 103, 134, 121, 152, 139, 170, 157, 188, 175, 206, 193, 224, 211, 242, 229 } },
    { 242, 247, 2, { 26, 13, 44, 31, 62, 49, 80, 67, 98, 85, 116, 103, 134, 121, 152, 139, 170, 157, 188, 175, 206, 193, 224, 211, 242, 229, 260, 247 } },
    { 247, 260, 3, { 26, 13, 44, 31, 62, 49, 80, 67, 98, 85, 116, 103, 134, 121, 152, 139, 170, 157, 188, 175, 206, 193, 224, 211, 242, 229, 260, 247 } },
    { 260, 265, 2, { 26, 13, 44, 31, 62, 49, 80, 67, 98, 85, 116, 103, 134, 121, 152, 139, 170, 157, 188, 175, 206, 193, 224, 211, 242, 229, 260, 247, 278, 265 } },
    { 265, 278, 3, { 26, 13, 44, 31, 62, 49, 80, 67, 98, 85, 116, 103, 134, 121, 152, 139, 170, 157, 188, 175, 206, 193, 224, 211, 242, 229, 260, 247, 278, 265 } },
    { 278, 303, 7, { 26, 13, 44, 31, 62, 49, 80, 67, 98, 85, 116, 103, 134, 121, 152, 139, 170, 157, 188, 175, 206, 193, 224, 211, 242, 229, 260, 247, 278, 265 } },
};

static const uint8_t frozen_synth_call_branch_interleave[] = {
    0x48,0x89,0x5c,0x24,0x08,0x48,0x89,0x74,0x24,0x10,0x57,0x48,0x83,0xec,0x20,0x41,
    0x8b,0xd8,0x8b,0xfa,0x8b,0xf1,0xe8,0x85,0xd3,0xff,0xff,0x89,0x44,0x24,0x48,0x8b,
    0x44,0x24,0x48,0x8b,0x4c,0x24,0x48,0x83,0xf8,0x0a,0x7e,0x0c,0xba,0x02,0x00,0x00,
    0x00,0xe8,0x7a,0xd3,0xff,0xff,0xeb,0x0a,0xba,0x01,0x00,0x00,0x00,0xe8,0x7e,0xd3,
    0xff,0xff,0x89,0x44,0x24,0x48,0x8b,0xd3,0x8b,0x4c,0x24,0x48,0xe8,0x4f,0xd3,0xff,
    0xff,0x89,0x44,0x24,0x48,0x8b,0x44,0x24,0x48,0x85,0xc0,0x79,0x12,0x8b,0x4c,0x24,
    0x48,0xba,0xff,0xff,0xff,0xff,0xe8,0x45,0xd3,0xff,0xff,0x89,0x44,0x24,0x48,0x8b,
    0x4c,0x24,0x48,0x8b,0xd6,0xe8,0x46,0xd3,0xff,0xff,0x89,0x44,0x24,0x48,0x8b,0x44,
    0x24,0x48,0x83,0xf8,0x64,0x7e,0x29,0x8b,0x4c,0x24,0x48,0x8b,0xd7,0xe8,0x0e,0xd3,
    0xff,0xff,0x89,0x44,0x24,0x48,0x8b,0x44,0x24,0x48,0x3d,0xc8,0x00,0x00,0x00,0x7e,
    0x0f,0x8b,0x4c,0x24,0x48,0x8b,0xd3,0xe8,0x14,0xd3,0xff,0xff,0x89,0x44,0x24,0x48,
    0x8b,0x44,0x24,0x48,0x48,0x8b,0x5c,0x24,0x30,0x48,0x8b,0x74,0x24,0x38,0x48,0x83,
    0xc4,0x20,0x5f,0xc3
}; // 196 bytes

static const ExpectedBlock expected_synth_call_branch_interleave[] = {
    { 0, 44, 13, { 56, 44 } },
    { 44, 56, 3, { 56, 44 } },
    { 56, 93, 10, { 56, 44, 111, 93 } },
    { 93, 135, 11, { 56, 44, 111, 93, 176, 135 } },
    { 135, 161, 7, { 56, 44, 111, 93, 176, 135, 176, 161 } },
    { 161, 196, 10, { 56, 44, 111, 93, 176, 135, 176, 161 } },
};

static const uint8_t frozen_synth_long_linear[] = {
    0x89,0x4c,0x24,0x08,0x44,0x8b,0xc9,0x8b,0x44,0x24,0x08,0x03,0xc2,0x89,0x44,0x24,
    0x08,0x8b,0x44,0x24,0x08,0x44,0x8d,0x04,0x40,0x44,0x89,0x44,0x24,0x08,0x8b,0x44,
    0x24,0x08,0x2b,0xc1,0x89,0x44,0x24,0x08,0x8b,0x44,0x24,0x08,0x83,0xc0,0x07,0x89,
    0x44,0x24,0x08,0x8b,0x44,0x24,0x08,0x33,0xc2,0x89,0x44,0x24,0x08,0x8b,0x44,0x24,
    0x08,0x83,0xc0,0x0b,0x89,0x44,0x24,0x08,0x8b,0x44,0x24,0x08,0x83,0xe8,0x05,0x89,
    0x44,0x24,0x08,0x8b,0x44,0x24,0x08,0x03,0xc0,0x89,0x44,0x24,0x08,0x8b,0x44,0x24,
    0x08,0x03,0xc1,0x89,0x44,0x24,0x08,0x8b,0x44,0x24,0x08,0x2b,0xc2,0x89,0x44,0x24,
    0x08,0x8b,0x44,0x24,0x08,0x8d,0x0c,0x80,0x89,0x4c,0x24,0x08,0x8b,0x44,0x24,0x08,
    0x83,0xc0,0x0d,0x89,0x44,0x24,0x08,0x8b,0x44,0x24,0x08,0x41,0x33,0xc1,0x89,0x44,
    0x24,0x08,0x8b,0x44,0x24,0x08,0x83,0xc0,0x11,0x89,0x44,0x24,0x08,0x8b,0x44,0x24,
    0x08,0x83,0xe8,0x03,0x89,0x44,0x24,0x08,0x8b,0x44,0x24,0x08,0x6b,0xc8,0x07,0x89,
    0x4c,0x24,0x08,0x8b,0x44,0x24,0x08,0x03,0xc2,0x89,0x44,0x24,0x08,0x8b,0x44,0x24,
    0x08,0x41,0x2b,0xc1,0x89,0x44,0x24,0x08,0x8b,0x44,0x24,0x08,0x6b,0xc8,0x0b,0x89,
    0x4c,0x24,0x08,0x8b,0x44,0x24,0x08,0x83,0xc0,0x13,0x89,0x44,0x24,0x08,0x8b,0x44,
    0x24,0x08,0x33,0xc2,0x89,0x44,0x24,0x08,0x8b,0x44,0x24,0x08,0x83,0xc0,0x17,0x89,
    0x44,0x24,0x08,0x8b,0x44,0x24,0x08,0x83,0xe8,0x07,0x89,0x44,0x24,0x08,0x8b,0x44,
    0x24,0x08,0x8d,0x0c,0x40,0x89,0x4c,0x24,0x08,0x8b,0x44,0x24,0x08,0x41,0x03,0xc1,
    0x89,0x44,0x24,0x08,0x8b,0x44,0x24,0x08,0x2b,0xc2,0x89,0x44,0x24,0x08,0x8b,0x44,
    0x24,0x08,0x6b,0xc8,0x0d,0x89,0x4c,0x24,0x08,0x8b,0x44,0x24,0x08,0x83,0xc0,0x1d,
    0x89,0x44,0x24,0x08,0x8b,0x44,0x24,0x08,0x41,0x33,0xc1,0x89,0x44,0x24,0x08,0x8b,
    0x44,0x24,0x08,0x83,0xc0,0x1f,0x89,0x44,0x24,0x08,0x8b,0x44,0x24,0x08,0x83,0xe8,
    0x0b,0x89,0x44,0x24,0x08,0x8b,0x44,0x24,0x08,0x8d,0x0c,0x80,0x89,0x4c,0x24,0x08,
    0x8b,0x44,0x24,0x08,0x03,0xc2,0x89,0x44,0x24,0x08,0x8b,0x44,0x24,0x08,0x41,0x2b,
    0xc1,0x89,0x44,0x24,0x08,0x8b,0x44,0x24,0x08,0x6b,0xc8,0x11,0x89,0x4c,0x24,0x08,
    0x8b,0x44,0x24,0x08,0x83,0xc0,0x25,0x89,0x44,0x24,0x08,0x8b,0x44,0x24,0x08,0x33,
    0xc2,0x89,0x44,0x24,0x08,0x8b,0x44,0x24,0x08,0x83,0xc0,0x29,0x89,0x44,0x24,0x08,
    0x8b,0x44,0x24,0x08,0x83,0xe8,0x0d,0x89,0x44,0x24,0x08,0x8b,0x44,0x24,0x08,0x6b,
    0xc8,0x07,0x89,0x4c,0x24,0x08,0x8b,0x44,0x24,0x08,0x41,0x03,0xc1,0x89,0x44,0x24,
    0x08,0x8b,0x44,0x24,0x08,0x2b,0xc2,0x89,0x44,0x24,0x08,0x8b,0x44,0x24,0x08,0x6b,
    0xc8,0x13,0x89,0x4c,0x24,0x08,0x8b,0x44,0x24,0x08,0x83,0xc0,0x2b,0x89,0x44,0x24,
    0x08,0x8b,0x44,0x24,0x08,0x41,0x33,0xc1,0x89,0x44,0x24,0x08,0x8b,0x44,0x24,0x08,
    0x83,0xc0,0x2f,0x89,0x44,0x24,0x08,0x8b,0x44,0x24,0x08,0x83,0xe8,0x11,0x89,0x44,
    0x24,0x08,0x8b,0x44,0x24,0x08,0x6b,0xc8,0x0b,0x89,0x4c,0x24,0x08,0x8b,0x44,0x24,
    0x08,0x03,0xc2,0x89,0x44,0x24,0x08,0x8b,0x44,0x24,0x08,0x41,0x2b,0xc1,0x89,0x44,
    0x24,0x08,0x8b,0x44,0x24,0x08,0x6b,0xc8,0x17,0x89,0x4c,0x24,0x08,0x8b,0x44,0x24,
    0x08,0x83,0xc0,0x35,0x89,0x44,0x24,0x08,0x8b,0x44,0x24,0x08,0x33,0xc2,0x89,0x44,
    0x24,0x08,0x8b,0x44,0x24,0x08,0x83,0xc0,0x3b,0x89,0x44,0x24,0x08,0x8b,0x44,0x24,
    0x08,0x83,0xe8,0x13,0x89,0x44,0x24,0x08,0x8b,0x44,0x24,0x08,0x6b,0xc8,0x0d,0x89,
    0x4c,0x24,0x08,0x8b,0x44,0x24,0x08,0x41,0x03,0xc1,0x89,0x44,0x24,0x08,0x8b,0x44,
    0x24,0x08,0x2b,0xc2,0x89,0x44,0x24,0x08,0x8b,0x44,0x24,0x08,0x6b,0xc8,0x1d,0x89,
    0x4c,0x24,0x08,0x8b,0x44,0x24,0x08,0x83,0xc0,0x3d,0x89,0x44,0x24,0x08,0x8b,0x44,
    0x24,0x08,0x41,0x33,0xc1,0x89,0x44,0x24,0x08,0x8b,0x44,0x24,0x08,0x83,0xc0,0x43,
    0x89,0x44,0x24,0x08,0x8b,0x44,0x24,0x08,0x83,0xe8,0x17,0x89,0x44,0x24,0x08,0x8b,
    0x44,0x24,0x08,0x6b,0xc8,0x11,0x89,0x4c,0x24,0x08,0x8b,0x44,0x24,0x08,0xc3
}; // 703 bytes

static const ExpectedBlock expected_synth_long_linear[] = {
    { 0, 703, 196, { } },
};

// Run collect_basic_blocks on frozen bytes in executable memory, compare against expected layout
int verify_frozen(const char* name, const uint8_t* frozen_bytes, size_t frozen_size,
                  const ExpectedBlock* expected, size_t expected_count) {
    // Allocate executable memory and copy frozen bytes
    void* exec_mem = VirtualAlloc(nullptr, frozen_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!exec_mem) {
        std::cout << "FAIL: VirtualAlloc failed for " << name << std::endl;
        return 1;
    }
    memcpy(exec_mem, frozen_bytes, frozen_size);

    auto blocks = utility::collect_basic_blocks(
        (uintptr_t)exec_mem,
        { .max_size = 4000, .sort = true, .merge_call_blocks = true, .copy_instructions = true }
    );

    const auto base = (uintptr_t)exec_mem;

    // Compare block count
    if (blocks.size() != expected_count) {
        std::cout << "FAIL: " << name << " block count: got " << blocks.size()
                  << ", expected " << expected_count << std::endl;
        VirtualFree(exec_mem, 0, MEM_RELEASE);
        return 1;
    }

    // Compare each block
    for (size_t i = 0; i < expected_count; ++i) {
        const auto& b = blocks[i];
        const auto& e = expected[i];

        size_t got_start = b.start - base;
        size_t got_end = b.end - base;

        if (got_start != e.start_rva || got_end != e.end_rva) {
            std::cout << "FAIL: " << name << " block[" << i << "] range: got "
                      << got_start << "-" << got_end << ", expected "
                      << e.start_rva << "-" << e.end_rva << std::endl;
            VirtualFree(exec_mem, 0, MEM_RELEASE);
            return 1;
        }

        if (b.instruction_count != e.instruction_count) {
            std::cout << "FAIL: " << name << " block[" << i << "] insn count: got "
                      << b.instruction_count << ", expected " << e.instruction_count << std::endl;
            VirtualFree(exec_mem, 0, MEM_RELEASE);
            return 1;
        }

        if (b.branches.size() != e.branch_rvas.size()) {
            std::cout << "FAIL: " << name << " block[" << i << "] branch count: got "
                      << b.branches.size() << ", expected " << e.branch_rvas.size() << std::endl;
            VirtualFree(exec_mem, 0, MEM_RELEASE);
            return 1;
        }

        for (size_t j = 0; j < e.branch_rvas.size(); ++j) {
            int64_t got_rva = (int64_t)(b.branches[j] - base);
            if (got_rva != e.branch_rvas[j]) {
                std::cout << "FAIL: " << name << " block[" << i << "] branch[" << j
                          << "]: got rva " << got_rva << ", expected " << e.branch_rvas[j] << std::endl;
                VirtualFree(exec_mem, 0, MEM_RELEASE);
                return 1;
            }
        }
    }

    std::cout << "  " << name << ": OK (" << expected_count << " blocks verified)" << std::endl;
    VirtualFree(exec_mem, 0, MEM_RELEASE);
    return 0;
}

// ============================================================================
// Hand-crafted byte blobs with embedded callees for exhaustive_decode CONTINUE tests
// All relative offsets are intra-buffer so they survive VirtualAlloc relocation.
// ============================================================================

// --- asm_simple_call: one caller, one callee ---
// RVA 0x00: caller — sub rsp,0x28 / call callee / mov [rsp+0x30],eax / mov eax,[rsp+0x30] / add rsp,0x28 / ret
// RVA 0x16: callee — lea eax,[rcx+rdx] / ret
static const uint8_t frozen_asm_simple_call[] = {
    0x48,0x83,0xEC,0x28,                    // 0x00: sub rsp, 0x28
    0xE8,0x0D,0x00,0x00,0x00,              // 0x04: call 0x16  (0x16 - 0x09 = 0x0D)
    0x89,0x44,0x24,0x30,                    // 0x09: mov [rsp+0x30], eax
    0x8B,0x44,0x24,0x30,                    // 0x0D: mov eax, [rsp+0x30]
    0x48,0x83,0xC4,0x28,                    // 0x11: add rsp, 0x28
    0xC3,                                    // 0x15: ret
    0x8D,0x04,0x11,                          // 0x16: lea eax, [rcx+rdx]
    0xC3,                                    // 0x19: ret
}; // 26 bytes

// --- asm_chained_calls: A calls B, B calls C ---
// RVA 0x00: func_a — sub rsp,0x28 / call func_b / mov [rsp+0x30],eax / mov eax,[rsp+0x30] / add rsp,0x28 / ret
// RVA 0x16: func_b — sub rsp,0x28 / call func_c / mov [rsp+0x30],eax / mov eax,[rsp+0x30] / add rsp,0x28 / ret
// RVA 0x2C: func_c — lea eax,[rcx+rdx] / imul eax,ecx / ret
static const uint8_t frozen_asm_chained_calls[] = {
    0x48,0x83,0xEC,0x28,                    // 0x00: sub rsp, 0x28
    0xE8,0x0D,0x00,0x00,0x00,              // 0x04: call 0x16  (0x16 - 0x09 = 0x0D)
    0x89,0x44,0x24,0x30,                    // 0x09: mov [rsp+0x30], eax
    0x8B,0x44,0x24,0x30,                    // 0x0D: mov eax, [rsp+0x30]
    0x48,0x83,0xC4,0x28,                    // 0x11: add rsp, 0x28
    0xC3,                                    // 0x15: ret
    0x48,0x83,0xEC,0x28,                    // 0x16: sub rsp, 0x28
    0xE8,0x0D,0x00,0x00,0x00,              // 0x1A: call 0x2C  (0x2C - 0x1F = 0x0D)
    0x89,0x44,0x24,0x30,                    // 0x1F: mov [rsp+0x30], eax
    0x8B,0x44,0x24,0x30,                    // 0x23: mov eax, [rsp+0x30]
    0x48,0x83,0xC4,0x28,                    // 0x27: add rsp, 0x28
    0xC3,                                    // 0x2B: ret
    0x8D,0x04,0x11,                          // 0x2C: lea eax, [rcx+rdx]
    0x0F,0xAF,0xC1,                          // 0x2F: imul eax, ecx
    0xC3,                                    // 0x32: ret
}; // 51 bytes

// --- asm_call_and_branch: conditional branch + call, tests both branch + call-follow ---
// RVA 0x00: test ecx,ecx / jle skip(0x12) / sub rsp,0x28 / call callee(0x15) / add rsp,0x28 / ret
// RVA 0x12: skip — xor eax,eax / ret
// RVA 0x15: callee — lea eax,[rcx+rdx] / ret
static const uint8_t frozen_asm_call_and_branch[] = {
    0x85,0xC9,                               // 0x00: test ecx, ecx
    0x7E,0x0E,                               // 0x02: jle 0x12  (0x12 - 0x04 = 0x0E)
    0x48,0x83,0xEC,0x28,                    // 0x04: sub rsp, 0x28
    0xE8,0x08,0x00,0x00,0x00,              // 0x08: call 0x15  (0x15 - 0x0D = 0x08)
    0x48,0x83,0xC4,0x28,                    // 0x0D: add rsp, 0x28
    0xC3,                                    // 0x11: ret
    0x33,0xC0,                               // 0x12: xor eax, eax
    0xC3,                                    // 0x14: ret
    0x8D,0x04,0x11,                          // 0x15: lea eax, [rcx+rdx]
    0xC3,                                    // 0x18: ret
}; // 25 bytes

// --- asm_multi_target_call: caller calls two different callees ---
// RVA 0x00: sub rsp,0x28 / call callee_a(0x1B) / mov[rsp+0x30],eax / call callee_b(0x1F) / mov[rsp+0x30],eax / add rsp,0x28 / ret
// RVA 0x1B: callee_a — lea eax,[rcx+rdx] / ret
// RVA 0x1F: callee_b — sub eax,ecx / ret
static const uint8_t frozen_asm_multi_target_call[] = {
    0x48,0x83,0xEC,0x28,                    // 0x00: sub rsp, 0x28
    0xE8,0x12,0x00,0x00,0x00,              // 0x04: call 0x1B  (0x1B - 0x09 = 0x12)
    0x89,0x44,0x24,0x30,                    // 0x09: mov [rsp+0x30], eax
    0xE8,0x0D,0x00,0x00,0x00,              // 0x0D: call 0x1F  (0x1F - 0x12 = 0x0D)
    0x89,0x44,0x24,0x30,                    // 0x12: mov [rsp+0x30], eax
    0x48,0x83,0xC4,0x28,                    // 0x16: add rsp, 0x28
    0xC3,                                    // 0x1A: ret
    0x8D,0x04,0x11,                          // 0x1B: lea eax, [rcx+rdx]
    0xC3,                                    // 0x1E: ret
    0x2B,0xC1,                               // 0x1F: sub eax, ecx
    0xC3,                                    // 0x21: ret
}; // 34 bytes

// ============================================================================
// FrozenSet: holds all frozen function allocations in executable memory
// ============================================================================

struct FrozenSet {
    FrozenFn linear;
    FrozenFn if_else;
    FrozenFn loop;
    FrozenFn nested_diamond;
    FrozenFn multi_call;
    FrozenFn many_branches;
    FrozenFn deep_nested_loops;
    FrozenFn early_returns;
    FrozenFn else_if_chain;
    FrozenFn call_branch_interleave;
    FrozenFn long_linear;
};

FrozenSet load_all_frozen() {
    return {
        { frozen_synth_linear, sizeof(frozen_synth_linear) },
        { frozen_synth_if_else, sizeof(frozen_synth_if_else) },
        { frozen_synth_loop, sizeof(frozen_synth_loop) },
        { frozen_synth_nested_diamond, sizeof(frozen_synth_nested_diamond) },
        { frozen_synth_multi_call, sizeof(frozen_synth_multi_call) },
        { frozen_synth_many_branches, sizeof(frozen_synth_many_branches) },
        { frozen_synth_deep_nested_loops, sizeof(frozen_synth_deep_nested_loops) },
        { frozen_synth_early_returns, sizeof(frozen_synth_early_returns) },
        { frozen_synth_else_if_chain, sizeof(frozen_synth_else_if_chain) },
        { frozen_synth_call_branch_interleave, sizeof(frozen_synth_call_branch_interleave) },
        { frozen_synth_long_linear, sizeof(frozen_synth_long_linear) },
    };
}

// ============================================================================
// Golden tests: verify frozen bytes produce exact expected block layouts
// ============================================================================

int test_golden() {
    std::cout << "=== test_golden (frozen bytes) ===" << std::endl;

    int result = 0;

#define VERIFY_FROZEN(name) \
    result |= verify_frozen(#name, frozen_##name, sizeof(frozen_##name), \
        expected_##name, sizeof(expected_##name) / sizeof(expected_##name[0]))

    VERIFY_FROZEN(synth_linear);
    VERIFY_FROZEN(synth_if_else);
    VERIFY_FROZEN(synth_loop);
    VERIFY_FROZEN(synth_nested_diamond);
    VERIFY_FROZEN(synth_multi_call);
    VERIFY_FROZEN(synth_many_branches);
    VERIFY_FROZEN(synth_deep_nested_loops);
    VERIFY_FROZEN(synth_early_returns);
    VERIFY_FROZEN(synth_else_if_chain);
    VERIFY_FROZEN(synth_call_branch_interleave);
    VERIFY_FROZEN(synth_long_linear);

#undef VERIFY_FROZEN

    return result;
}

// ============================================================================
// Structural validation implementations (use frozen addresses)
// ============================================================================

int test_contiguous_coverage(const FrozenSet& frozen) {
    std::cout << "=== test_contiguous_coverage ===" << std::endl;

    struct Target { const char* name; uintptr_t addr; };
    Target targets[] = {
        {"synth_linear",               frozen.linear.addr()},
        {"synth_if_else",              frozen.if_else.addr()},
        {"synth_loop",                 frozen.loop.addr()},
        {"synth_nested_diamond",       frozen.nested_diamond.addr()},
        {"synth_multi_call",           frozen.multi_call.addr()},
        {"synth_many_branches",        frozen.many_branches.addr()},
        {"synth_deep_nested_loops",    frozen.deep_nested_loops.addr()},
        {"synth_early_returns",        frozen.early_returns.addr()},
        {"synth_else_if_chain",        frozen.else_if_chain.addr()},
        {"synth_call_branch_interleave", frozen.call_branch_interleave.addr()},
        {"synth_long_linear",          frozen.long_linear.addr()},
    };

    for (auto& t : targets) {
        auto blocks = utility::collect_basic_blocks(t.addr,
            { .max_size = 2000, .sort = true, .merge_call_blocks = true, .copy_instructions = true });

        STRESS_ASSERT(!blocks.empty());

        auto highest = utility::get_highest_contiguous_block(blocks);
        STRESS_ASSERT(highest != blocks.end());
        STRESS_ASSERT(blocks.front().start == t.addr);

        std::cout << "  " << t.name << ": contiguous range "
                  << std::hex << blocks.front().start << "-" << highest->end
                  << std::dec << " (" << (highest->end - blocks.front().start) << " bytes)" << std::endl;
    }

    return 0;
}

int test_option_variants(uintptr_t addr) {
    std::cout << "=== test_option_variants ===" << std::endl;

    auto target = addr;

    auto with_copy = utility::collect_basic_blocks(target,
        { .max_size = 1000, .sort = true, .merge_call_blocks = true, .copy_instructions = true });
    auto without_copy = utility::collect_basic_blocks(target,
        { .max_size = 1000, .sort = true, .merge_call_blocks = false, .copy_instructions = false });

    // Without copy: instructions vector should be empty but instruction_count populated
    for (const auto& b : without_copy) {
        STRESS_ASSERT(b.instructions.empty());
        STRESS_ASSERT(b.instruction_count > 0);
    }

    // With copy: instructions.size() should match instruction_count
    for (const auto& b : with_copy) {
        STRESS_ASSERT(b.instructions.size() == b.instruction_count);
    }

    std::cout << "  Option variant checks passed." << std::endl;
    return 0;
}

// ============================================================================
// Consistency / idempotency implementation (use frozen addresses)
// ============================================================================

int test_consistency(const FrozenSet& frozen) {
    std::cout << "=== test_consistency ===" << std::endl;

    uintptr_t targets[] = {
        frozen.linear.addr(),
        frozen.if_else.addr(),
        frozen.loop.addr(),
        frozen.nested_diamond.addr(),
        frozen.multi_call.addr(),
        frozen.many_branches.addr(),
        frozen.deep_nested_loops.addr(),
        frozen.early_returns.addr(),
        frozen.else_if_chain.addr(),
        frozen.call_branch_interleave.addr(),
        frozen.long_linear.addr(),
    };

    const utility::BasicBlockCollectOptions opts{
        .max_size = 2000, .sort = true, .merge_call_blocks = true, .copy_instructions = true
    };

    for (auto target : targets) {
        auto run1 = utility::collect_basic_blocks(target, opts);
        auto run2 = utility::collect_basic_blocks(target, opts);

        STRESS_ASSERT(run1.size() == run2.size());

        for (size_t i = 0; i < run1.size(); ++i) {
            STRESS_ASSERT(run1[i].start == run2[i].start);
            STRESS_ASSERT(run1[i].end == run2[i].end);
            STRESS_ASSERT(run1[i].instruction_count == run2[i].instruction_count);
            STRESS_ASSERT(run1[i].branches.size() == run2[i].branches.size());
            for (size_t j = 0; j < run1[i].branches.size(); ++j) {
                STRESS_ASSERT(run1[i].branches[j] == run2[i].branches[j]);
            }
        }
    }

    std::cout << "  All consistency checks passed." << std::endl;
    return 0;
}

// ============================================================================
// exhaustive_decode call-following tests (hand-crafted blobs with embedded callees)
// ============================================================================

// Helper: run exhaustive_decode and collect all visited instruction RVAs
std::set<size_t> decode_collect_rvas(uintptr_t base, size_t max_size, bool step_over_calls) {
    std::set<size_t> rvas;
    utility::exhaustive_decode((uint8_t*)base, max_size, [&](utility::ExhaustionContext& ctx) {
        rvas.insert(ctx.addr - base);
        if (step_over_calls && ctx.instrux.Category == ND_CAT_CALL) {
            return utility::ExhaustionResult::STEP_OVER;
        }
        return utility::ExhaustionResult::CONTINUE;
    });
    return rvas;
}

int test_asm_simple_call() {
    std::cout << "=== test_asm_simple_call ===" << std::endl;
    FrozenFn fn(frozen_asm_simple_call, sizeof(frozen_asm_simple_call));

    auto rvas_follow = decode_collect_rvas(fn.addr(), sizeof(frozen_asm_simple_call), false);
    auto rvas_skip = decode_collect_rvas(fn.addr(), sizeof(frozen_asm_simple_call), true);

    // With CONTINUE: caller (6 insns) + callee (2 insns) = 8 unique addresses
    STRESS_ASSERT(rvas_follow.count(0x00));  // sub rsp
    STRESS_ASSERT(rvas_follow.count(0x04));  // call
    STRESS_ASSERT(rvas_follow.count(0x09));  // mov [rsp+0x30], eax
    STRESS_ASSERT(rvas_follow.count(0x0D));  // mov eax, [rsp+0x30]
    STRESS_ASSERT(rvas_follow.count(0x11));  // add rsp
    STRESS_ASSERT(rvas_follow.count(0x15));  // ret
    STRESS_ASSERT(rvas_follow.count(0x16));  // callee: lea
    STRESS_ASSERT(rvas_follow.count(0x19));  // callee: ret
    STRESS_ASSERT(rvas_follow.size() == 8);

    // With STEP_OVER: only caller (6 insns), callee not visited
    STRESS_ASSERT(rvas_skip.count(0x00));
    STRESS_ASSERT(!rvas_skip.count(0x16));   // callee NOT visited
    STRESS_ASSERT(rvas_skip.size() == 6);

    std::cout << "  follow_calls: " << rvas_follow.size()
              << " insns, step_over: " << rvas_skip.size() << " insns" << std::endl;
    return 0;
}

int test_asm_chained_calls() {
    std::cout << "=== test_asm_chained_calls ===" << std::endl;
    FrozenFn fn(frozen_asm_chained_calls, sizeof(frozen_asm_chained_calls));

    auto rvas_follow = decode_collect_rvas(fn.addr(), sizeof(frozen_asm_chained_calls), false);
    auto rvas_skip = decode_collect_rvas(fn.addr(), sizeof(frozen_asm_chained_calls), true);

    // With CONTINUE: func_a (6) + func_b (6) + func_c (3) = 15 unique addresses
    STRESS_ASSERT(rvas_follow.count(0x00));  // func_a start
    STRESS_ASSERT(rvas_follow.count(0x16));  // func_b start
    STRESS_ASSERT(rvas_follow.count(0x2C));  // func_c start
    STRESS_ASSERT(rvas_follow.count(0x2F));  // func_c: imul
    STRESS_ASSERT(rvas_follow.count(0x32));  // func_c: ret
    STRESS_ASSERT(rvas_follow.size() == 15);

    // With STEP_OVER: only func_a (6 insns)
    STRESS_ASSERT(rvas_skip.count(0x00));
    STRESS_ASSERT(!rvas_skip.count(0x16));   // func_b NOT visited
    STRESS_ASSERT(!rvas_skip.count(0x2C));   // func_c NOT visited
    STRESS_ASSERT(rvas_skip.size() == 6);

    std::cout << "  follow_calls: " << rvas_follow.size()
              << " insns, step_over: " << rvas_skip.size() << " insns" << std::endl;
    return 0;
}

int test_asm_call_and_branch() {
    std::cout << "=== test_asm_call_and_branch ===" << std::endl;
    FrozenFn fn(frozen_asm_call_and_branch, sizeof(frozen_asm_call_and_branch));

    auto rvas_follow = decode_collect_rvas(fn.addr(), sizeof(frozen_asm_call_and_branch), false);
    auto rvas_skip = decode_collect_rvas(fn.addr(), sizeof(frozen_asm_call_and_branch), true);

    // With CONTINUE: fall-through path (test, jle, sub, call, add, ret = 6)
    //                + branch path skip_call (xor, ret = 2)
    //                + callee (lea, ret = 2) = 10 unique
    STRESS_ASSERT(rvas_follow.count(0x00));  // test ecx
    STRESS_ASSERT(rvas_follow.count(0x02));  // jle
    STRESS_ASSERT(rvas_follow.count(0x04));  // sub rsp
    STRESS_ASSERT(rvas_follow.count(0x08));  // call
    STRESS_ASSERT(rvas_follow.count(0x0D));  // add rsp
    STRESS_ASSERT(rvas_follow.count(0x11));  // ret
    STRESS_ASSERT(rvas_follow.count(0x12));  // skip: xor eax
    STRESS_ASSERT(rvas_follow.count(0x14));  // skip: ret
    STRESS_ASSERT(rvas_follow.count(0x15));  // callee: lea
    STRESS_ASSERT(rvas_follow.count(0x18));  // callee: ret
    STRESS_ASSERT(rvas_follow.size() == 10);

    // With STEP_OVER: fall-through (6) + branch skip (2) = 8, callee not visited
    STRESS_ASSERT(rvas_skip.count(0x12));    // skip path IS visited (branch)
    STRESS_ASSERT(!rvas_skip.count(0x15));   // callee NOT visited
    STRESS_ASSERT(rvas_skip.size() == 8);

    std::cout << "  follow_calls: " << rvas_follow.size()
              << " insns, step_over: " << rvas_skip.size() << " insns" << std::endl;
    return 0;
}

int test_asm_multi_target_call() {
    std::cout << "=== test_asm_multi_target_call ===" << std::endl;
    FrozenFn fn(frozen_asm_multi_target_call, sizeof(frozen_asm_multi_target_call));

    auto rvas_follow = decode_collect_rvas(fn.addr(), sizeof(frozen_asm_multi_target_call), false);
    auto rvas_skip = decode_collect_rvas(fn.addr(), sizeof(frozen_asm_multi_target_call), true);

    // With CONTINUE: caller (7) + callee_a (2) + callee_b (2) = 11 unique
    STRESS_ASSERT(rvas_follow.count(0x00));  // sub rsp
    STRESS_ASSERT(rvas_follow.count(0x04));  // call callee_a
    STRESS_ASSERT(rvas_follow.count(0x0D));  // call callee_b
    STRESS_ASSERT(rvas_follow.count(0x1B));  // callee_a: lea
    STRESS_ASSERT(rvas_follow.count(0x1E));  // callee_a: ret
    STRESS_ASSERT(rvas_follow.count(0x1F));  // callee_b: sub
    STRESS_ASSERT(rvas_follow.count(0x21));  // callee_b: ret
    STRESS_ASSERT(rvas_follow.size() == 11);

    // With STEP_OVER: only caller (7), neither callee visited
    STRESS_ASSERT(!rvas_skip.count(0x1B));   // callee_a NOT visited
    STRESS_ASSERT(!rvas_skip.count(0x1F));   // callee_b NOT visited
    STRESS_ASSERT(rvas_skip.size() == 7);

    std::cout << "  follow_calls: " << rvas_follow.size()
              << " insns, step_over: " << rvas_skip.size() << " insns" << std::endl;
    return 0;
}

// ============================================================================
// Performance benchmark implementations (use frozen addresses)
// ============================================================================

int bench_exhaustive_decode(const FrozenSet& frozen) {
    std::cout << "=== bench_exhaustive_decode ===" << std::endl;

    constexpr size_t ITERS = 1000;

    struct Target { const char* name; uintptr_t addr; };
    Target targets[] = {
        {"synth_linear",               frozen.linear.addr()},
        {"synth_many_branches",        frozen.many_branches.addr()},
        {"synth_deep_nested_loops",    frozen.deep_nested_loops.addr()},
        {"synth_else_if_chain",        frozen.else_if_chain.addr()},
        {"synth_long_linear",          frozen.long_linear.addr()},
    };

    for (auto& t : targets) {
        std::vector<double> times;
        times.reserve(ITERS);

        for (size_t i = 0; i < ITERS; ++i) {
            volatile size_t count = 0;
            auto start = std::chrono::high_resolution_clock::now();
            utility::exhaustive_decode((uint8_t*)t.addr, 2000, [&](utility::ExhaustionContext& ctx) {
                ++count;
                if (ctx.instrux.Category == ND_CAT_CALL) {
                    return utility::ExhaustionResult::STEP_OVER;
                }
                return utility::ExhaustionResult::CONTINUE;
            });
            auto end = std::chrono::high_resolution_clock::now();

            double us = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count() / 1000.0;
            times.push_back(us);
        }

        std::sort(times.begin(), times.end());
        double sum = std::accumulate(times.begin(), times.end(), 0.0);

        std::cout << "  " << t.name << ": min=" << times.front() << "us, avg="
                  << (sum / times.size()) << "us, max=" << times.back()
                  << "us, total=" << sum / 1000.0 << "ms" << std::endl;
    }

    return 0;
}

int bench_collect_basic_blocks(const FrozenSet& frozen) {
    std::cout << "=== bench_collect_basic_blocks ===" << std::endl;

    constexpr size_t ITERS = 1000;
    const utility::BasicBlockCollectOptions opts{
        .max_size = 2000, .sort = true, .merge_call_blocks = true, .copy_instructions = true
    };
    const utility::BasicBlockCollectOptions opts_nocopy{
        .max_size = 2000, .sort = true, .merge_call_blocks = false, .copy_instructions = false
    };

    struct Target { const char* name; uintptr_t addr; };
    Target targets[] = {
        {"synth_linear",                 frozen.linear.addr()},
        {"synth_if_else",                frozen.if_else.addr()},
        {"synth_loop",                   frozen.loop.addr()},
        {"synth_nested_diamond",         frozen.nested_diamond.addr()},
        {"synth_multi_call",             frozen.multi_call.addr()},
        {"synth_many_branches",          frozen.many_branches.addr()},
        {"synth_deep_nested_loops",      frozen.deep_nested_loops.addr()},
        {"synth_early_returns",          frozen.early_returns.addr()},
        {"synth_else_if_chain",          frozen.else_if_chain.addr()},
        {"synth_call_branch_interleave", frozen.call_branch_interleave.addr()},
        {"synth_long_linear",            frozen.long_linear.addr()},
    };

    std::cout << "  [copy_instructions + merge_call_blocks]" << std::endl;
    for (auto& t : targets) {
        print_bench(t.name, benchmark_collect(t.addr, opts, ITERS));
    }

    std::cout << "  [no copy, no merge]" << std::endl;
    for (auto& t : targets) {
        print_bench(t.name, benchmark_collect(t.addr, opts_nocopy, ITERS));
    }

    return 0;
}

// ============================================================================
// Main
// ============================================================================

int main(int argc, char* argv[]) try {
    // Call each synthetic function to prevent dead-stripping (needed for --snapshot)
    volatile int warmup = 0;
    warmup += synth_linear(1, 2);
    warmup += synth_if_else(5);
    warmup += synth_loop(10);
    warmup += synth_nested_diamond(3, -2);
    warmup += synth_switch(4);
    warmup += synth_multi_call(3, 7);
    warmup += synth_many_branches(1, 2, 3, 4);
    warmup += synth_deep_nested_loops(3, 3, 3);
    warmup += synth_early_returns(10, 20, 3, 5);
    warmup += synth_else_if_chain(7);
    warmup += synth_call_branch_interleave(5, 3, 2);
    warmup += synth_long_linear(42, 17);
    (void)warmup;

    if (argc > 1 && std::string(argv[1]) == "--snapshot") {
        return run_snapshot();
    }

    std::cout << "===== kananlib stress test =====" << std::endl;

    // Load all frozen bytes into VirtualAlloc'd executable memory
    auto frozen = load_all_frozen();

    // Correctness tests (all use frozen addresses)
    STRESS_ASSERT(test_linear_correctness(frozen.linear.addr()) == 0);
    STRESS_ASSERT(test_if_else_correctness(frozen.if_else.addr()) == 0);
    STRESS_ASSERT(test_loop_correctness(frozen.loop.addr()) == 0);
    STRESS_ASSERT(test_nested_diamond_correctness(frozen.nested_diamond.addr()) == 0);
    STRESS_ASSERT(test_multi_call_correctness(frozen.multi_call.addr()) == 0);
    STRESS_ASSERT(test_many_branches_correctness(frozen.many_branches.addr()) == 0);
    STRESS_ASSERT(test_deep_nested_loops_correctness(frozen.deep_nested_loops.addr()) == 0);
    STRESS_ASSERT(test_early_returns_correctness(frozen.early_returns.addr()) == 0);
    STRESS_ASSERT(test_else_if_chain_correctness(frozen.else_if_chain.addr()) == 0);
    STRESS_ASSERT(test_call_branch_interleave_correctness(frozen.call_branch_interleave.addr()) == 0);
    STRESS_ASSERT(test_long_linear_correctness(frozen.long_linear.addr()) == 0);

    // Golden tests (frozen bytes, exact expected layout -- uses its own VirtualAlloc internally)
    STRESS_ASSERT(test_golden() == 0);

    // Structural validation (all use frozen addresses)
    STRESS_ASSERT(test_contiguous_coverage(frozen) == 0);
    STRESS_ASSERT(test_option_variants(frozen.nested_diamond.addr()) == 0);

    // Consistency / idempotency (uses frozen addresses)
    STRESS_ASSERT(test_consistency(frozen) == 0);

    // exhaustive_decode call-following tests (hand-crafted blobs)
    STRESS_ASSERT(test_asm_simple_call() == 0);
    STRESS_ASSERT(test_asm_chained_calls() == 0);
    STRESS_ASSERT(test_asm_call_and_branch() == 0);
    STRESS_ASSERT(test_asm_multi_target_call() == 0);

    // Performance benchmarks (use frozen addresses)
    bench_exhaustive_decode(frozen);
    bench_collect_basic_blocks(frozen);

    std::cout << std::endl << "===== All stress tests passed. =====" << std::endl;
    return 0;
} catch (const std::exception& e) {
    std::cout << "Exception: " << e.what() << std::endl;
    return 1;
} catch (...) {
    std::cout << "Unknown exception." << std::endl;
    return 1;
}
