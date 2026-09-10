#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <functional>
#include <unordered_set>
#include <vector>
#include <array>
#include <type_traits>

#include <bddisasm.h>
#include <windows.h>
#include <utility/Seh.hpp>

#include <utility/Logging.hpp>
#include <utility/Benchmark.hpp>
#include <utility/String.hpp>
#include <utility/Module.hpp>


#if defined(KANANLIB_TESTING)
namespace utility::testing {
    enum class RelativeReferenceScanImplementation {
        None,
        ScalarByteByByte,
        Scalar,
        Avx2,
    };

    void reset_relative_reference_scan_implementation();
    RelativeReferenceScanImplementation last_relative_reference_scan_implementation();
    bool relative_reference_avx2_available_for_dispatch();
}
#endif

namespace utility {
    // KANANLIB_ARCH_X86_32 is 1 when building for 32-bit x86 (MSVC _M_IX86 or
    // GCC/Clang __i386__), 0 otherwise (i.e. x64 on any OS). Do NOT use _WIN64
    // for this: _WIN64 is undefined on non-Windows 64-bit targets (e.g. Linux
    // x64), which would wrongly select the 32-bit path there and mis-decode.
#if defined(_M_IX86) || defined(__i386__)
#define KANANLIB_ARCH_X86_32 1
#else
#define KANANLIB_ARCH_X86_32 0
#endif

    // Decode mode used for bddisasm calls: x64 processes run in 64-bit code/
    // data mode, x86 in 32-bit mode. Mixing these (e.g. always decoding in
    // 64-bit mode on an x86 target) corrupts instruction lengths/operand
    // kinds for encodings that differ between the two modes.
#if KANANLIB_ARCH_X86_32
    constexpr auto KANANLIB_DECODE_MODE = ND_CODE_32;
    constexpr auto KANANLIB_DECODE_DATA = ND_DATA_32;
#else
    constexpr auto KANANLIB_DECODE_MODE = ND_CODE_64;
    constexpr auto KANANLIB_DECODE_DATA = ND_DATA_64;
#endif

    // Runtime decode mode/data for a given target architecture. Defaults across
    // the decode/scan API resolve to host_arch(), so existing host-only callers
    // behave exactly as before while a 64-bit host can decode a mapped 32-bit
    // target by passing TargetArch::X86.
    constexpr uint8_t decode_mode(TargetArch arch) noexcept {
        return arch == TargetArch::X86 ? ND_CODE_32 : ND_CODE_64;
    }
    constexpr uint8_t decode_data(TargetArch arch) noexcept {
        return arch == TargetArch::X86 ? ND_DATA_32 : ND_DATA_64;
    }

    std::optional<uintptr_t> scan(const std::string& module, const std::string& pattern);
    std::optional<uintptr_t> scan(const std::wstring& module, const std::string& pattern);
    std::optional<uintptr_t> scan(const std::string& module, uintptr_t start, const std::string& pattern);
    std::optional<uintptr_t> scan(const std::wstring& module, uintptr_t start, const std::string& pattern);
    std::optional<uintptr_t> scan(HMODULE module, const std::string& pattern);
    std::optional<uintptr_t> scan(uintptr_t start, size_t length, const std::string& pattern);
    std::optional<uintptr_t> scan_reverse(uintptr_t start, size_t length, const std::string& pattern);
    
    std::optional<uintptr_t> scan_data(HMODULE, const uint8_t* data, size_t size);
    std::optional<uintptr_t> scan_data(uintptr_t start, size_t length, const uint8_t* data, size_t size);
    
    template<typename T>
    std::optional<uintptr_t> scan_data_t(HMODULE module, const T& data) {
        return scan_data(module, reinterpret_cast<const uint8_t*>(&data), sizeof(T));
    }

    template<typename T>
    std::optional<uintptr_t> scan_data_t(uintptr_t start, size_t length, const T& data) {
        return scan_data(start, length, reinterpret_cast<const uint8_t*>(&data), sizeof(T));
    }

    std::optional<uintptr_t> scan_data_reverse(uintptr_t start, size_t length, const uint8_t* data, size_t size);
    std::optional<uintptr_t> scan_ptr(HMODULE module, uintptr_t ptr);
    std::optional<uintptr_t> scan_ptr(uintptr_t start, size_t length, uintptr_t ptr, TargetArch arch = host_arch());
    std::optional<uintptr_t> scan_ptr_noalign(HMODULE module, uintptr_t ptr);
    std::optional<uintptr_t> scan_ptr_noalign(uintptr_t start, size_t length, uintptr_t ptr, TargetArch arch = host_arch());
    std::optional<uintptr_t> scan_string(HMODULE module, const std::string& str, bool zero_terminated = false);
    std::optional<uintptr_t> scan_string(HMODULE module, const std::wstring& str, bool zero_terminated = false);
    std::optional<uintptr_t> scan_string(uintptr_t start, size_t length, const std::string& str, bool zero_terminated = false);
    std::optional<uintptr_t> scan_string(uintptr_t start, size_t length, const std::wstring& str, bool zero_terminated = false);
    std::vector<uintptr_t> scan_strings(HMODULE module, const std::string& str, bool zero_terminated = false);
    std::vector<uintptr_t> scan_strings(HMODULE module, const std::wstring& str, bool zero_terminated = false);
    std::vector<uintptr_t> scan_strings(uintptr_t start, size_t length, const std::string& str, bool zero_terminated = false);
    std::vector<uintptr_t> scan_strings(uintptr_t start, size_t length, const std::wstring& str, bool zero_terminated = false);

    std::optional<uintptr_t> scan_relative_reference_scalar_byte_by_byte(uintptr_t start, size_t length, uintptr_t ptr, std::function<bool(uintptr_t)> filter = nullptr);
    std::optional<uintptr_t> scan_relative_reference_scalar(uintptr_t start, size_t length, uintptr_t ptr, std::function<bool(uintptr_t)> filter = nullptr);

    std::optional<uintptr_t> scan_relative_reference(uintptr_t start, size_t length, uintptr_t ptr, std::function<bool(uintptr_t)> filter = nullptr);
    std::optional<uintptr_t> scan_relative_reference(HMODULE module, uintptr_t ptr, std::function<bool(uintptr_t)> filter = nullptr);
    std::vector<uintptr_t> scan_relative_references(uintptr_t start, size_t length, uintptr_t ptr, std::function<bool(uintptr_t)> filter = nullptr);
    std::vector<uintptr_t> scan_relative_references(HMODULE module, uintptr_t ptr, std::function<bool(uintptr_t)> filter = nullptr);


    std::optional<uintptr_t> scan_reference(HMODULE module, uintptr_t ptr, bool relative = true);
    std::optional<uintptr_t> scan_reference(uintptr_t start, size_t length, uintptr_t ptr, bool relative = true);
    std::optional<uintptr_t> scan_relative_reference_strict(HMODULE module, uintptr_t ptr, const std::string& preceded_by);
    std::optional<uintptr_t> scan_relative_reference_strict(uintptr_t start, size_t length, uintptr_t ptr, const std::string& preceded_by);
    std::optional<uintptr_t> scan_displacement_reference(HMODULE module, uintptr_t ptr, std::function<bool(uintptr_t)> filter = nullptr);
    std::optional<uintptr_t> scan_displacement_reference(uintptr_t start, size_t length, uintptr_t ptr, std::function<bool(uintptr_t)> filter = nullptr);
    std::vector<uintptr_t> scan_displacement_references(HMODULE module, uintptr_t ptr);
    std::vector<uintptr_t> scan_displacement_references(uintptr_t start, size_t length, uintptr_t ptr);

    std::optional<uintptr_t> scan_opcode(uintptr_t ip, size_t num_instructions, uint8_t opcode, TargetArch arch = host_arch());
    std::optional<uintptr_t> scan_disasm(uintptr_t ip, size_t num_instructions, const std::string& pattern, TargetArch arch = host_arch());
    std::optional<uintptr_t> scan_mnemonic(uintptr_t ip, size_t num_instructions, const std::string& mnemonic, TargetArch arch = host_arch());

    uint32_t get_insn_size(uintptr_t ip, TargetArch arch = host_arch());

    uintptr_t calculate_absolute(uintptr_t address, uint8_t custom_offset = 4);

    std::optional<INSTRUX> decode_one(uint8_t* ip, size_t max_size = 1000, TargetArch arch = host_arch());
    // exhaustive_decode decodes until it hits something like a return, int3, etc
    // except when it notices a conditional jmp, it will decode both branches separately
    enum ExhaustionResult {
        CONTINUE,
        BREAK,
        STEP_OVER
    };
    struct ExhaustionContext {
        uintptr_t addr{};
        INSTRUX instrux{};

        uintptr_t branch_start{};
        uintptr_t resolved_target{}; // Pre-resolved branch/displacement target (0 if none)
    };

    // Forward declaration needed by the template below
    std::optional<uintptr_t> resolve_displacement(uintptr_t ip, const INSTRUX* instrux_in, TargetArch arch);

    namespace detail {
        // Grow-on-demand open-addressing address set for exhaustive_decode.
        // Thread-local and reused across calls; grow-only (never shrinks) so its
        // footprint tracks the largest function a thread actually decodes, not the
        // worst-case max_size. Internal implementation detail exposed only for unit
        // testing; not a supported API. nullptr is the empty-slot sentinel and is
        // never a valid key.
        struct SeenSet {
            uint8_t** slots = nullptr;   // power-of-two sized
            size_t* dirty = nullptr;     // occupied-slot indices for O(occupied) cleanup
            size_t cap = 0;              // slot count (power of two; 0 = unallocated)
            size_t bits = 0;             // log2(cap)
            size_t count = 0;            // live entries
            size_t dirty_count = 0;
            bool oomed = false;          // latched when a grow() allocation fails

            SeenSet() = default;
            SeenSet(const SeenSet&) = delete;
            SeenSet& operator=(const SeenSet&) = delete;
            ~SeenSet() { free(slots); free(dirty); }

            static constexpr uint64_t kFib = 11400714819323198485ULL;
            size_t hash(uint8_t* p) const { return (size_t)(((uint64_t)(uintptr_t)p * kFib) >> (64 - bits)); }

            // Ensure at least `initial` slots (grow-only) and clear membership for a
            // fresh decode. Returns false only if no table could be allocated.
            bool begin(size_t initial) {
                oomed = false;                              // clear latch for a fresh decode
                size_t want_bits = 4;                       // minimum 16 slots
                while ((size_t{1} << want_bits) < initial) ++want_bits;
                const size_t want = size_t{1} << want_bits;
                if (want > cap) {
                    uint8_t** ns = (uint8_t**)calloc(want, sizeof(uint8_t*));
                    size_t* nd = (size_t*)malloc((want / 2) * sizeof(size_t));
                    if (!ns || !nd) { free(ns); free(nd); if (cap != 0) { clear(); return true; } return false; }
                    free(slots); free(dirty);
                    slots = ns; dirty = nd; cap = want; bits = want_bits;
                }
                clear();
                return true;
            }

            bool contains(uint8_t* p) const {
                if (cap == 0 || p == nullptr) return false;
                const size_t mask = cap - 1;
                for (size_t si = hash(p);; si = (si + 1) & mask) {
                    if (slots[si] == p) return true;
                    if (slots[si] == nullptr) return false;
                }
            }

            enum class Insert { Inserted, Present, Full, Oom };

            // Insert p unless present. `budget` caps live entries; `max_cap` caps
            // growth. nullptr is treated as present (never stored).
            Insert insert_if_absent(uint8_t* p, size_t budget, size_t max_cap) {
                if (p == nullptr) return Insert::Present;
                size_t mask = cap - 1;
                size_t si = hash(p);
                for (;; si = (si + 1) & mask) {
                    if (slots[si] == p) return Insert::Present;
                    if (slots[si] == nullptr) break;
                }
                if (count >= budget) return Insert::Full;
                if (count >= (cap >> 1)) {              // load factor 0.5 -> grow
                    if (cap >= max_cap) return Insert::Full;
                    if (oomed || !grow()) { oomed = true; return Insert::Oom; } // latch: never retry a failed calloc
                    mask = cap - 1;
                    for (si = hash(p); slots[si] != nullptr; si = (si + 1) & mask) {}
                }
                slots[si] = p;
                dirty[dirty_count++] = si;
                ++count;
                return Insert::Inserted;
            }

            // Clear membership; retains capacity for reuse.
            void clear() {
                if (cap == 0) return;
                if (dirty_count > cap / 8) {
                    memset(slots, 0, cap * sizeof(uint8_t*));
                } else {
                    for (size_t i = 0; i < dirty_count; ++i) slots[dirty[i]] = nullptr;
                }
                count = 0; dirty_count = 0;
            }

        private:
            // Double capacity and rehash live entries via the dirty list.
            bool grow() {
                const size_t nc = cap << 1;
                const size_t nb = bits + 1;
                uint8_t** ns = (uint8_t**)calloc(nc, sizeof(uint8_t*));
                size_t* nd = (size_t*)malloc((nc / 2) * sizeof(size_t));
                if (!ns || !nd) { free(ns); free(nd); return false; }
                const size_t nmask = nc - 1;
                size_t ndc = 0;
                for (size_t d = 0; d < dirty_count; ++d) {
                    uint8_t* q = slots[dirty[d]];
                    size_t si = (size_t)(((uint64_t)(uintptr_t)q * kFib) >> (64 - nb));
                    for (; ns[si] != nullptr; si = (si + 1) & nmask) {}
                    ns[si] = q; nd[ndc++] = si;
                }
                free(slots); free(dirty);
                slots = ns; dirty = nd; cap = nc; bits = nb; dirty_count = ndc;
                return true;
            }
        };
    }

    template<typename F>
    void exhaustive_decode(uint8_t* start, size_t max_size, F&& callback, TargetArch arch = host_arch()) {
        KANANLIB_BENCH();
        SPDLOG_DEBUG("Running exhaustive_decode on {:x}", (uintptr_t)start);

        // Per-call growth target from max_size (saturating next-power-of-two so a
        // huge/malformed max_size can't wrap the multiply nor drive the shift to the
        // size_t width -- both UB).
        constexpr size_t kMaxBits = sizeof(size_t) * 8 - 1;
        size_t budget_bits = 4;
        {
            const size_t budget_cap = (max_size > (SIZE_MAX / 64)) ? SIZE_MAX
                                       : std::max<size_t>(65536, max_size * 64);
            const size_t target = (budget_cap > (SIZE_MAX / 2)) ? SIZE_MAX : budget_cap * 2;
            while (budget_bits < kMaxBits && (size_t{1} << budget_bits) < target) ++budget_bits;
        }
        const size_t call_ceiling = size_t{1} << budget_bits;

        // Preserve the old work ceiling for all representable inputs. Previously
        // max_seen derived from the thread's grow-only table (tls.capacity / 2), so a
        // thread that once ran a large max_size kept that larger ceiling for later
        // calls. Reproduce that coupling with a thread-local high-water -- but keep it
        // independent of the (now small, grow-on-demand) table, so table memory
        // tracks actual usage while the work bound is unchanged for any max_size the
        // old code didn't overflow on (the new saturating math only differs for
        // pathological/overflowing max_size, which the old code left as UB).
        thread_local size_t g_seen_ceiling = 0;
        if (call_ceiling > g_seen_ceiling) g_seen_ceiling = call_ceiling;
        const size_t max_cap = g_seen_ceiling;          // table growth ceiling (== old tls.capacity high-water)
        const size_t seen_budget = max_cap / 2;         // == old max_seen
        // (Note: no separate branch-work ceiling is needed. Every enqueue below is
        // preceded by decoding a branch instruction -- hence a seen insert -- so
        // branches.size() <= 1 + seen.count, and the outer loop stops once
        // seen.count reaches seen_budget. The work is bounded by seen_budget alone.)

        // Grow-on-demand seen set: start small so the footprint tracks the largest
        // function a thread actually decodes, growing up to max_cap only if needed.
        constexpr size_t kInitialSlots = 4096;
        thread_local detail::SeenSet seen{};
        if (!seen.begin(kInitialSlots < max_cap ? kInitialSlots : max_cap)) {
            return; // could not allocate even the initial table
        }

        thread_local std::vector<uint8_t*> branches{};
        branches.clear();
        branches.push_back(start);

        // total_branches_seen is CFG bookkeeping that drives ctx.branch_start for
        // direct-jump redirects; kept paired with an actual enqueue below, as before.
        uint32_t total_branches_seen = 0;

        // Enqueue a branch target. Centralized so total_branches_seen stays paired
        // with an actual enqueue (unchanged from the original inline sites).
        auto try_enqueue = [&](uint8_t* target) {
            branches.push_back(target);
            ++total_branches_seen;
        };

        auto decode_branch = [&](uint8_t* ip) {
            const auto branch_start = (uintptr_t)ip;

            ExhaustionContext ctx{};
            ctx.branch_start = branch_start;

            for (size_t i = 0; i < max_size; ++i) {
                // Single-probe check-and-insert. Stops this path when the address
                // was already decoded (Present), the work budget is hit (Full), or
                // the table could not grow (Oom). Grows the table on demand.
                if (seen.insert_if_absent(ip, seen_budget, max_cap) != detail::SeenSet::Insert::Inserted) {
                    break;
                }

                // This instead of IsBadReadPtr so we don't branch into kernel32 every time
                // we want to test the readability of the memory
#ifdef NDEBUG
                KANANLIB_SEH_TRY {
                    volatile auto test1 = *(uintptr_t*)(ip);
                    volatile auto test8 = *(uintptr_t*)(ip + 56); // check if we can read ahead without page crossing
                    (void)test1; (void)test8;
                } KANANLIB_SEH_EXCEPT (EXCEPTION_EXECUTE_HANDLER) {
                    break;
                }
#else
                if (IsBadReadPtr(ip, 64)) {
                    break;
                }
#endif
                const auto status = NdDecodeEx(&ctx.instrux, ip, 64, decode_mode(arch), decode_data(arch));

                if (!ND_SUCCESS(status)) {
                    break;
                }

                ctx.addr = (uintptr_t)ip;

                auto& ix = ctx.instrux;

                // Pre-resolve branch target so the callback can use it without re-resolving
                ctx.resolved_target = 0;
                if (ix.IsRipRelative && !ix.BranchInfo.IsIndirect && ix.BranchInfo.IsBranch) {
                    if (auto dest = utility::resolve_displacement((uintptr_t)ip, &ix, arch); dest) {
                        ctx.resolved_target = *dest;
                    }
                }

                ExhaustionResult result{};

                if constexpr (std::is_invocable_v<F, ExhaustionContext&>) {
                    result = callback(ctx);
                } else {
                    result = callback(ctx.instrux, ctx.addr);
                }

                if (result == ExhaustionResult::BREAK) {
                    return;
                }

                // Allows the callback to at least process that we hit a ret or int3, but we will stop here.
                if (ix.Instruction == ND_INS_RETN || ix.Instruction == ND_INS_INT3) {
                    break;
                }

                const auto prev_branches_count = total_branches_seen;

                // We dont want to follow indirect branches, we aren't emulating
                if (ix.IsRipRelative && !ix.BranchInfo.IsIndirect) {
                    if (ix.BranchInfo.IsBranch && ix.BranchInfo.IsConditional) {
                        SPDLOG_DEBUG("Conditional Branch detected: {:x}", (uintptr_t)ip);

                        if (ctx.resolved_target != 0) {
                            if (result != ExhaustionResult::STEP_OVER) {
                                try_enqueue((uint8_t*)ctx.resolved_target);
                            }
                        } else {
                            SPDLOG_ERROR("Failed to resolve displacement for {:x}", (uintptr_t)ip);
                            SPDLOG_ERROR(" TODO: Fix this");
                        }
                    } else if (ix.BranchInfo.IsBranch && !ix.BranchInfo.IsConditional) {
                        SPDLOG_DEBUG("Unconditional Branch detected: {:x}", (uintptr_t)ip);

                        const auto is_jmp = ix.Instruction >= ND_INS_JMPE && ix.Instruction <= ND_INS_JMPNR;

                        if (is_jmp) {
                            if (ctx.resolved_target != 0) {
                                ip = (uint8_t*)ctx.resolved_target;
                                ctx.branch_start = ctx.resolved_target;
                                ++total_branches_seen;
                                continue;
                            } else {
                                SPDLOG_ERROR("Failed to resolve displacement for {:x}", (uintptr_t)ip);
                                SPDLOG_ERROR(" TODO: Fix this");
                            }
                        } else if (result != ExhaustionResult::STEP_OVER) {
                            if (ctx.resolved_target != 0) {
                                try_enqueue((uint8_t*)ctx.resolved_target);
                            } else {
                                SPDLOG_ERROR("Failed to resolve displacement for {:x}", (uintptr_t)ip);
                                SPDLOG_ERROR(" TODO: Fix this");
                            }
                        }
                    }
                } else if (ix.IsRipRelative && ip[0] == 0xFF && ip[1] == 0x25) { // jmp qword ptr [rip+0xdeadbeef]
                    SPDLOG_DEBUG("Indirect jmp detected: {:x}", (uintptr_t)ip);
                    const auto dest = utility::calculate_absolute((uintptr_t)ip + 2);

                    if (dest != 0 && dest != (uintptr_t)ip && !IsBadReadPtr((void*)dest, sizeof(void*))) {
                        const auto real_dest = *(uintptr_t*)dest;

                        // Cannot step over jmps
                        if (real_dest != 0 && real_dest != (uintptr_t)ip && !IsBadReadPtr((void*)real_dest, sizeof(void*))) {
                            SPDLOG_DEBUG("Indirect jmp destination: {:x}", (uintptr_t)real_dest);
                            ip = (uint8_t*)real_dest;
                            ctx.branch_start = (uintptr_t)real_dest;
                            ++total_branches_seen;
                            continue;
                        }
                    }

                    SPDLOG_DEBUG("Failed to resolve indirect jmp destination: {:x}", (uintptr_t)ip);
                    break;
                } else if (ix.IsRipRelative && ip[0] == 0xFF && ip[1] == 0x15) { // call qword ptr [rip+0xdeadbeef]
                    SPDLOG_DEBUG("Indirect call detected: {:x}", (uintptr_t)ip);

                    const auto dest = utility::calculate_absolute((uintptr_t)ip + 2);

                    if (dest != 0 && dest != (uintptr_t)ip && !IsBadReadPtr((void*)dest, sizeof(void*))) {
                        const auto real_dest = *(uintptr_t*)dest;

                        if (real_dest != 0 && real_dest != (uintptr_t)ip && !IsBadReadPtr((void*)real_dest, sizeof(void*)) && result != ExhaustionResult::STEP_OVER) {
                            try_enqueue((uint8_t*)real_dest);
                            SPDLOG_DEBUG("Indirect call destination: {:x}", (uintptr_t)real_dest);
                        }
                    }
                } else if (ix.BranchInfo.IsBranch && !ix.BranchInfo.IsConditional) {
                    if (ix.Category != ND_CAT_CALL) {
                        break;
                    }
                }

                ip += ix.Length;

                if (total_branches_seen != prev_branches_count) {
                    ctx.branch_start = (uintptr_t)ip;
                }
            }
        };

        for (size_t branch_idx = 0; branch_idx < branches.size() && seen.count < seen_budget && !seen.oomed; ++branch_idx) {
            decode_branch(branches[branch_idx]);
        }

        // Dirty list is faster for sparse usage; memset is faster when heavily filled
        seen.clear();
    }

    void linear_decode(uint8_t* ip, size_t max_size, std::function<bool(ExhaustionContext&)> callback, TargetArch arch = host_arch());

    struct BasicBlock {
        struct Instruction {
            uintptr_t addr{};
            INSTRUX instrux{};
        };

        uintptr_t start{};
        uintptr_t end{};
        std::vector<Instruction> instructions{};
        std::vector<uintptr_t> branches{}; // the addresses they branch to, not the addresses of the instructions themselves
        size_t instruction_count{};
        bool is_call_block{}; // whether this block ends with a call instruction
    };
    struct BasicBlockCollectOptions {
        size_t max_size{1000};
        bool sort{false};
        bool merge_call_blocks{true}; // if a block ends with a call, and the next block starts with the instruction after the call, merge them into one block
        bool copy_instructions{true}; // if false, the instructions vector will be empty, and only the start/end/branches will be populated
    };
    void collect_basic_blocks_into(uintptr_t start, const BasicBlockCollectOptions& options, std::vector<BasicBlock>& blocks, TargetArch arch = host_arch());
    std::vector<BasicBlock> collect_basic_blocks(uintptr_t start, const BasicBlockCollectOptions& options = {}, TargetArch arch = host_arch());
    std::vector<BasicBlock>::const_iterator get_highest_contiguous_block(const std::vector<BasicBlock>& blocks, TargetArch arch = host_arch());

    struct LinearBlock {
        uintptr_t start{};
        uintptr_t end{};
        std::vector<uintptr_t> branches{};
    };

    std::vector<LinearBlock> collect_linear_blocks(uintptr_t fn_start, uintptr_t fn_end);

    // We are storing a list of ranges inside buckets, so we can quickly find the correct bucket
    // Doing this with multithreading was much slower and inefficient
    struct Bucket {
        struct IMAGE_RUNTIME_FUNCTION_ENTRY_KANANLIB {
            DWORD BeginAddress{};
            DWORD EndAddress{};
            union {
                DWORD UnwindInfoAddress{};
                DWORD UnwindData;
            } DUMMYUNIONNAME;

            PIMAGE_RUNTIME_FUNCTION_ENTRY original{nullptr};

            IMAGE_RUNTIME_FUNCTION_ENTRY_KANANLIB(PIMAGE_RUNTIME_FUNCTION_ENTRY entry)
                : BeginAddress(entry->BeginAddress),
                  EndAddress(entry->EndAddress),
                  original(entry)
            {
                this->UnwindData = entry->UnwindData;
            }

            IMAGE_RUNTIME_FUNCTION_ENTRY_KANANLIB() = default;
        };

        uint32_t start_range{};
        uint32_t end_range{};
        std::vector<IMAGE_RUNTIME_FUNCTION_ENTRY_KANANLIB> entries{};
    };

    void populate_function_buckets_heuristic(uintptr_t module);
    std::optional<Bucket::IMAGE_RUNTIME_FUNCTION_ENTRY_KANANLIB> find_function_entry(uintptr_t middle);

    namespace detail {
        // Removes function-start candidate RVAs whose bytes at (module + rva) do
        // not decode to a valid instruction. Undecodable candidates would otherwise
        // become zero-width bucket entries in populate_function_buckets_heuristic.
        // Internal implementation detail exposed for deterministic unit testing;
        // not a supported API.
        void remove_undecodable_starts(std::vector<uint32_t>& starts, uintptr_t module, TargetArch arch = host_arch());
    }

    struct FunctionBounds {
        uintptr_t start{};
        uintptr_t end{};
        size_t instruction_count{};
    };
    std::vector<FunctionBounds> find_all_function_bounds(HMODULE module);
    std::optional<FunctionBounds> determine_function_bounds(uintptr_t start);

    std::optional<uintptr_t> find_function_start(uintptr_t middle);
    // same as prev, but unwinds until the main procedure is found
    // separate function because a lot of code depends on find_function_start
    // finding the basic block the middle is in, and not the actual function start
    std::optional<uintptr_t> find_function_start_unwind(uintptr_t middle);
    // same as prev, but keeps going backwards until the "function" it lands on
    // is actually called somewhere within the module
    std::optional<uintptr_t> find_function_start_with_call(uintptr_t middle);

    // Given a function that is an SEH exception filter, finds the owning function
    // by scanning .pdata scope tables for a reference to the filter's RVA.
    std::optional<uintptr_t> resolve_scope_table_owner(HMODULE module, uintptr_t filter_func);

    std::optional<uintptr_t> find_function_from_string_ref(HMODULE module, std::string_view str, bool zero_terminated = false);
    std::optional<uintptr_t> find_function_from_string_ref(HMODULE module, std::wstring_view str, bool zero_terminated = false);

    // finds the function(s) containing the A string, and then
    // disassembles each one looking for a reference to data that contains the B string
    std::optional<uintptr_t> find_function_with_string_refs(HMODULE module, std::wstring_view a, std::wstring_view b, bool follow_calls = false, bool zero_terminated = false);
    std::optional<uintptr_t> find_function_with_refs(HMODULE module, std::vector<uintptr_t> ptrs);

    // Same as the previous, but it keeps going upwards until utility::scan_ptr returns something
    std::optional<uintptr_t> find_virtual_function_start(uintptr_t middle);
    std::optional<uintptr_t> find_virtual_function_from_string_ref(HMODULE module, std::wstring_view str, bool zero_terminated = false);

    // Given any address/instruction within a function, walk a virtual table and disassemble to see if
    // any of the given functions contain the address/instruction
    std::optional<uintptr_t> find_encapsulating_virtual_function(uintptr_t vtable, size_t walk_amount, uintptr_t middle);
    std::optional<uintptr_t> find_encapsulating_virtual_function_disp(uintptr_t vtable, size_t walk_amount, uintptr_t disp, bool follow_calls = true);

    // Given any address/instruction within a function, disassemble forwards until we hit a call
    // then disassemble the called function's instructions to see if any of them contain the address/instruction
    // Is a bit naive, it could be improved by checking the function calls within the function too,
    // but it only finds the top level function that contains the address/instruction
    // It DOES check the function calls within the function, but it doesn't treat those as the encapsulating function, only the top level one
    std::optional<uintptr_t> find_encapsulating_function(uintptr_t start_instruction, uintptr_t middle);
    std::optional<uintptr_t> find_encapsulating_function_disp(uintptr_t start_instruction, uintptr_t disp, bool follow_calls = true);

    // Can supply an instrux if we've already decoded this (reduces redundant decoding when we just want to resolve the displacement)
    std::optional<uintptr_t> resolve_displacement(uintptr_t ip, const INSTRUX* instrux_in = nullptr, TargetArch arch = host_arch());

    struct Resolved {
        uintptr_t addr{};
        INSTRUX instrux{};
    };

    struct ResolvedDisplacement : Resolved {
        uintptr_t displacement{};
    };

    std::optional<ResolvedDisplacement> find_next_displacement(uintptr_t ip, bool follow_calls = false); // stops if ret, int3
    std::optional<Resolved> resolve_instruction(uintptr_t middle); // finds the start of the instruction given an address in the middle of the instruction 

    std::optional<ResolvedDisplacement> find_string_reference_in_path(uintptr_t start_instruction, std::string_view str, bool follow_calls = true);
    std::optional<ResolvedDisplacement> find_string_reference_in_path(uintptr_t start_instruction, std::wstring_view str, bool follow_calls = true);
    std::optional<ResolvedDisplacement> find_pointer_in_path(uintptr_t start_instruction, const void* pointer, bool follow_calls = true);
    std::optional<ResolvedDisplacement> find_displacement_in_path(uintptr_t start_instruction, uintptr_t disp, bool follow_calls = true);
    std::optional<Resolved> find_mnemonic_in_path(uintptr_t start_instruction, uint32_t num_instructions, std::string_view mnemonic, bool follow_calls = true);
    std::optional<Resolved> find_register_usage_in_path(uintptr_t start_instruction, uint32_t num_instructions, uint32_t reg, bool follow_calls = true);

    // This is scan_disasm but it will stop whenever execution fully exhausts all branches and hits a return, int3, etc
    std::optional<Resolved> find_pattern_in_path(uint8_t* ip, size_t max_size, bool follow_calls, const std::string& pattern);
    std::optional<Resolved> find_landmark_sequence(HMODULE module, const std::string& initial_pattern, const std::vector<std::string>& patterns, bool follow_calls = true);
    std::optional<Resolved> find_landmark_sequence(uintptr_t start, size_t size, const std::string& initial_pattern, const std::vector<std::string>& patterns, bool follow_calls = true);

    // Finds the function start given the middle, and then disassembles and stores all instructions until it hits the middle
    // We can use this to "disassemble" backwards from the middle of an instruction
    std::vector<Resolved> get_disassembly_behind(uintptr_t middle);

    struct StringReference {
        Resolved resolved{};
        union {
            const char* ascii{nullptr};
            const utf16_char* unicode;
        };

        StringReference(const Resolved& resolved, const char* ascii) : resolved(resolved), ascii(ascii) {}
        StringReference(const Resolved& resolved, const utf16_char* unicode) : resolved(resolved), unicode(unicode) {}
    };

    struct StringReferenceOptions {
        bool follow_calls{false};
        size_t min_length{1};
        size_t max_length{256};

        StringReferenceOptions& with_follow_calls(bool follow_calls) {
            this->follow_calls = follow_calls;
            return *this;
        }

        StringReferenceOptions& with_min_length(size_t min_length) {
            this->min_length = min_length;
            return *this;
        }

        StringReferenceOptions& with_max_length(size_t max_length) {
            this->max_length = max_length;
            return *this;
        }
    };

    std::vector<StringReference> collect_ascii_string_references(uintptr_t start, size_t max_size, const StringReferenceOptions& options = {});
    std::vector<StringReference> collect_unicode_string_references(uintptr_t start, size_t max_size, const StringReferenceOptions& options = {});
}
