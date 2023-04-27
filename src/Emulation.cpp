#include <cstdint>
#include <bdshemu.h>
#include <disasmtypes.h>

#include <spdlog/spdlog.h>

#include <utility/Module.hpp>
#include <utility/Emulation.hpp>
#include <utility/Scan.hpp>

namespace utility {
ShemuContext::ShemuContext(uintptr_t base, size_t buffer_size, size_t stack_size) 
    : ctx{std::make_unique<SHEMU_CONTEXT>()}
{
    memset(ctx.get(), 0, sizeof(SHEMU_CONTEXT));
    this->stack.resize(stack_size);
    this->internal_buffer.resize(buffer_size + stack_size);

    // Setup data is from https://github.com/bitdefender/bddisasm/blob/master/disasmtool/disasmtool.c#L1483
    ctx->Stack = this->stack.data();
    ctx->Intbuf = this->internal_buffer.data();

    ctx->Shellcode = (uint8_t*)base;
    ctx->ShellcodeBase = base;
    ctx->ShellcodeSize = buffer_size;

    ctx->StackBase = 0x100000;
    ctx->StackSize = stack_size;
    ctx->Registers.RegRsp = 0x101000;
    ctx->IntbufSize = (uint32_t)buffer_size + stack_size;

    ctx->Registers.RegFlags = NDR_RFLAG_IF | 2;
    //tx->Registers.RegRip = ctx->ShellcodeBase + offset;

    ctx->Segments.Cs.Selector = 0x10;
    ctx->Segments.Ds.Selector = 0x28;
    ctx->Segments.Es.Selector = 0x28;
    ctx->Segments.Ss.Selector = 0x28;
    ctx->Segments.Fs.Selector = 0x30;
    ctx->Segments.Fs.Base = 0x7FFF0000;
    ctx->Segments.Gs.Selector = 0x30;
    ctx->Segments.Gs.Base = 0x7FFF0000;

    // Dummy values, to resemble regular CR0/CR4 values.
    ctx->Registers.RegCr0 = 0x0000000080050031;
    ctx->Registers.RegCr4 = 0x0000000000170678;

    ctx->Mode = ND_CODE_64;
    ctx->Ring = 3;
    ctx->TibBase = ctx->Mode == ND_CODE_32 ? ctx->Segments.Fs.Base : ctx->Segments.Gs.Base;
    ctx->MaxInstructionsCount = 4096;
    ctx->Flags = 0;
    ctx->Options = 0;
    ctx->Log = nullptr;
    ctx->AccessMemory = (ShemuMemAccess)+[](PSHEMU_CONTEXT ctx, uint64_t gla, size_t size, uint8_t* buffer, bool store) {
        if (!store) {
            // On loads, always return 0.
            //memset(buffer, 0, size);

            if (!IsBadReadPtr((void*)gla, size)) {
                memcpy(buffer, (void*)gla, size);
            }
        }
        else {
            // On stores, do nothing.
        }

        return true;
    };

    // Configurable thresholds.
    ctx->NopThreshold = SHEMU_DEFAULT_NOP_THRESHOLD;
    ctx->StrThreshold = SHEMU_DEFAULT_STR_THRESHOLD;
    ctx->MemThreshold = SHEMU_DEFAULT_MEM_THRESHOLD;
}

ShemuContext::ShemuContext(HMODULE module, size_t stack_size)
    : ShemuContext((uintptr_t)module, utility::get_module_size(module).value_or(0), stack_size)
{
}

uint32_t ShemuContext::emulate(uintptr_t ip, size_t num_instructions) {
    this->ctx->Registers.RegRip = ip;
    this->ctx->MaxInstructionsCount = num_instructions;
    this->status = ShemuEmulate(this->ctx.get());

    return this->status;
}

uint32_t ShemuContext::emulate() {
    this->ctx->MaxInstructionsCount = this->ctx->InstructionsCount + 1;
    this->status = ShemuEmulate(this->ctx.get());

    return this->status;
}

ShemuContext emulate(uintptr_t base, size_t size, uintptr_t ip, size_t num_instructions) {
    ShemuContext out{base, size};
    out.emulate(ip, num_instructions);
    return out;
}

ShemuContext emulate(HMODULE module, uintptr_t ip, size_t num_instructions) {
    ShemuContext out{module};
    out.emulate(ip, num_instructions);
    return out;
}

void emulate(HMODULE module, uintptr_t ip, size_t num_instructions, std::function<ExhaustionResult(const ShemuContextExtended& ctx)> callback) {
    utility::ShemuContext emu{module};

    emu.ctx->MemThreshold = 100;
    emu.ctx->Registers.RegRip = ip;

    emulate(module, ip, num_instructions, emu, callback);
}

void emulate(HMODULE module, uintptr_t ip, size_t num_instructions, ShemuContext& emu, std::function<ExhaustionResult(const ShemuContextExtended& ctx)> callback) {
    utility::ShemuContextExtended ctx{&emu, false};

    while (true) try {
        if (emu.ctx->InstructionsCount > num_instructions) {
            break;
        }

        const auto ix = utility::decode_one((uint8_t*)emu.ctx->Registers.RegRip);

        if (!ix) {
            spdlog::error("Failed to decode instruction at {:x}", emu.ctx->Registers.RegRip);
            break;
        }

        ctx.next.ix = *ix;
        ctx.next.writes_to_memory = (ix->MemoryAccess & ND_ACCESS_ANY_WRITE) != 0 && !ix->BranchInfo.IsBranch;

        const auto result = callback(ctx);

        if (result == ExhaustionResult::BREAK) {
            break;
        }

        if (result == ExhaustionResult::STEP_OVER) {
            emu.ctx->Registers.RegRip += ctx.next.ix.Length;
            emu.ctx->Instruction = *ix;
            ++emu.ctx->InstructionsCount;
            continue;
        }

        // Continue
        const auto emu_failed = emu.emulate() != SHEMU_SUCCESS;

        if (emu_failed) {
            spdlog::error("Emulation failed at {:x}", emu.ctx->Registers.RegRip);

            const auto ix_cur = utility::decode_one((uint8_t*)emu.ctx->Registers.RegRip);

            if (!ix_cur) {
                spdlog::error("Failed to decode instruction at {:x}", emu.ctx->Registers.RegRip);
                break;
            }

            emu.ctx->Registers.RegRip += ix_cur->Length;
            emu.ctx->Instruction = *ix_cur;
            ++emu.ctx->InstructionsCount;
        }
    } catch (...) {
        spdlog::error("Exception in emulation loop");
        break;
    }
}
}