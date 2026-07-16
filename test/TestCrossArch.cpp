#include <algorithm>
#include <array>
#include <cstdint>
#include <iostream>
#include <string>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <vector>

#include <windows.h>

#include <utility/Module.hpp>
#include <utility/Scan.hpp>
#include <utility/RTTI.hpp>

#include "TestHelpers.hpp"

#define KANANLIB_STR2(x) #x
#define KANANLIB_STR(x) KANANLIB_STR2(x)
#ifndef KANANLIB_SAMPLE_DIR
#define KANANLIB_SAMPLE_DIR .
#endif

namespace {
std::string pe32_sample_path() {
    return std::string{KANANLIB_STR(KANANLIB_SAMPLE_DIR)} + "/kananlib_sample32.dll";
}

std::vector<uint8_t> make_relocatable_pe32() {
    constexpr size_t kFileSize = 0x800;
    constexpr uint32_t kImageBase = 0x400000;
    std::vector<uint8_t> bytes(kFileSize);

    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(bytes.data());
    dos->e_magic = IMAGE_DOS_SIGNATURE;
    dos->e_lfanew = 0x80;

    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS32*>(bytes.data() + dos->e_lfanew);
    nt->Signature = IMAGE_NT_SIGNATURE;
    nt->FileHeader.Machine = IMAGE_FILE_MACHINE_I386;
    nt->FileHeader.NumberOfSections = 3;
    nt->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER32);
    nt->FileHeader.Characteristics =
        IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_32BIT_MACHINE | IMAGE_FILE_DLL;

    auto& optional = nt->OptionalHeader;
    optional.Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
    optional.AddressOfEntryPoint = 0x1000;
    optional.BaseOfCode = 0x1000;
    optional.BaseOfData = 0x2000;
    optional.ImageBase = kImageBase;
    optional.SectionAlignment = 0x1000;
    optional.FileAlignment = 0x200;
    optional.MajorOperatingSystemVersion = 6;
    optional.MajorSubsystemVersion = 6;
    optional.SizeOfCode = 0x200;
    optional.SizeOfInitializedData = 0x400;
    optional.SizeOfImage = 0x4000;
    optional.SizeOfHeaders = 0x200;
    optional.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI;
    optional.DllCharacteristics =
        IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE | IMAGE_DLLCHARACTERISTICS_NX_COMPAT;
    optional.SizeOfStackReserve = 0x100000;
    optional.SizeOfStackCommit = 0x1000;
    optional.SizeOfHeapReserve = 0x100000;
    optional.SizeOfHeapCommit = 0x1000;
    optional.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
    optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC] = {0x3000, 28};

    auto* sections = IMAGE_FIRST_SECTION(nt);
    std::memcpy(sections[0].Name, ".text", 5);
    sections[0].Misc.VirtualSize = 0x100;
    sections[0].VirtualAddress = 0x1000;
    sections[0].SizeOfRawData = 0x200;
    sections[0].PointerToRawData = 0x200;
    sections[0].Characteristics =
        IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;

    std::memcpy(sections[1].Name, ".rdata", 6);
    sections[1].Misc.VirtualSize = 0x200;
    sections[1].VirtualAddress = 0x2000;
    sections[1].SizeOfRawData = 0x200;
    sections[1].PointerToRawData = 0x400;
    sections[1].Characteristics =
        IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;

    std::memcpy(sections[2].Name, ".reloc", 6);
    sections[2].Misc.VirtualSize = 28;
    sections[2].VirtualAddress = 0x3000;
    sections[2].SizeOfRawData = 0x200;
    sections[2].PointerToRawData = 0x600;
    sections[2].Characteristics =
        IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_DISCARDABLE;

    const uint8_t code[] = {0xA1, 0x00, 0x20, 0x40, 0x00, 0xC3};
    std::memcpy(bytes.data() + 0x200, code, sizeof(code));
    *reinterpret_cast<uint32_t*>(bytes.data() + 0x400) = kImageBase + 0x1000;

    // Minimal x86 MSVC RTTI graph:
    // COL @ 0x402100, TypeDescriptor @ 0x402140,
    // COL slot @ 0x40217c, vtable @ 0x402180.
    auto* locator = reinterpret_cast<uint32_t*>(bytes.data() + 0x500);
    locator[0] = 0;
    locator[1] = 0;
    locator[2] = 0;
    locator[3] = kImageBase + 0x2140;
    locator[4] = 0;
    auto* type_descriptor = bytes.data() + 0x540;
    *reinterpret_cast<uint32_t*>(type_descriptor) = 0;
    *reinterpret_cast<uint32_t*>(type_descriptor + 4) = 0;
    constexpr char kRttiName[] = ".?AVCrossArchRtti@@";
    std::memcpy(type_descriptor + 8, kRttiName, sizeof(kRttiName));
    *reinterpret_cast<uint32_t*>(bytes.data() + 0x57C) =
        kImageBase + 0x2100;
    *reinterpret_cast<uint32_t*>(bytes.data() + 0x580) =
        kImageBase + 0x1000;

    auto* code_reloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>(bytes.data() + 0x600);
    code_reloc->VirtualAddress = 0x1000;
    code_reloc->SizeOfBlock = 12;
    auto* code_entries = reinterpret_cast<uint16_t*>(code_reloc + 1);
    code_entries[0] = (IMAGE_REL_BASED_HIGHLOW << 12) | 1;
    code_entries[1] = IMAGE_REL_BASED_ABSOLUTE << 12;

    auto* pointer_reloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>(bytes.data() + 0x60C);
    pointer_reloc->VirtualAddress = 0x2000;
    pointer_reloc->SizeOfBlock = 16;
    auto* pointer_entries = reinterpret_cast<uint16_t*>(pointer_reloc + 1);
    pointer_entries[0] = IMAGE_REL_BASED_HIGHLOW << 12;
    pointer_entries[1] = (IMAGE_REL_BASED_HIGHLOW << 12) | 0x10C;
    pointer_entries[2] = (IMAGE_REL_BASED_HIGHLOW << 12) | 0x17C;
    pointer_entries[3] = (IMAGE_REL_BASED_HIGHLOW << 12) | 0x180;
    return bytes;
}

std::filesystem::path write_relocatable_pe32() {
    const auto path = std::filesystem::temp_directory_path() / "kananlib_cross_arch_reloc32.dll";
    const auto bytes = make_relocatable_pe32();
    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    file.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    return path;
}
}

int test_host_arch_matches_process() {
#if defined(_M_IX86) || defined(__i386__)
    TEST_ASSERT(utility::host_arch() == utility::TargetArch::X86);
#else
    TEST_ASSERT(utility::host_arch() == utility::TargetArch::X64);
#endif
    TEST_ASSERT(utility::AnalysisContext::raw(utility::TargetArch::X86).pointer_width() == 4);
    TEST_ASSERT(utility::AnalysisContext::raw(utility::TargetArch::X64).pointer_width() == 8);
    return 0;
}

int test_pe32_context_is_magic_aware() {
    auto mapped = utility::map_view_of_pe(pe32_sample_path());
    TEST_ASSERT(mapped.has_value());
    TEST_ASSERT(mapped->module != nullptr);

    const auto context = utility::get_analysis_context(mapped->module);
    TEST_ASSERT(context.has_value());
    TEST_ASSERT(context->arch == utility::TargetArch::X86);
    TEST_ASSERT(context->pointer_width() == 4);
    TEST_ASSERT(context->host_base == reinterpret_cast<uintptr_t>(mapped->module));
    TEST_ASSERT(context->preferred_image_base == 0x400000);
    TEST_ASSERT(context->image_size == 0x2000);
    TEST_ASSERT(context->mapped_image);
#if defined(_WIN32)
    TEST_ASSERT(!context->relocations_applied);
#endif

    const auto image_base = utility::get_dll_imagebase(mapped->module);
    TEST_ASSERT(image_base.has_value());
    TEST_ASSERT(*image_base == 0x400000);
    return 0;
}

int test_pe32_address_translation() {
    auto mapped = utility::map_view_of_pe(pe32_sample_path());
    TEST_ASSERT(mapped.has_value());
    const auto context = utility::get_analysis_context(mapped->module);
    TEST_ASSERT(context.has_value());

    const auto host_base = reinterpret_cast<uintptr_t>(mapped->module);
    const auto host_rdata = context->target_va_to_host(0x401000);
    TEST_ASSERT(host_rdata.has_value());
    TEST_ASSERT(*host_rdata == host_base + 0x1000);
    TEST_ASSERT(context->contains_host(*host_rdata, 21));

    const auto target_rdata = context->host_to_target_va(*host_rdata);
    TEST_ASSERT(target_rdata.has_value());
    TEST_ASSERT(*target_rdata == 0x401000);

    const auto stored_rdata = context->stored_address_to_host(0x401000);
    TEST_ASSERT(stored_rdata.has_value());
    TEST_ASSERT(*stored_rdata == *host_rdata);

    TEST_ASSERT(!context->target_va_to_host(0x3FFFFF).has_value());
    TEST_ASSERT(!context->target_va_to_host(0x402000).has_value());
    TEST_ASSERT(!context->host_to_target_va(host_base - 1).has_value());
    TEST_ASSERT(!context->stored_address_to_host(
        context->stored_image_base + context->image_size).has_value());
    return 0;
}

int test_pe32_relocation_state_matches_mapped_bytes() {
    const auto path = write_relocatable_pe32();
    auto mapped = utility::map_view_of_pe(path.string());
    TEST_ASSERT(mapped.has_value());

    const auto context = utility::get_analysis_context(mapped->module);
    TEST_ASSERT(context.has_value());
    TEST_ASSERT(context->arch == utility::TargetArch::X86);
    TEST_ASSERT(context->preferred_image_base == 0x400000);
    TEST_ASSERT(context->image_size == 0x4000);

    const auto host_base = reinterpret_cast<uintptr_t>(mapped->module);
    const auto stored_pointer = *reinterpret_cast<const uint32_t*>(host_base + 0x2000);
    const auto stored_operand = *reinterpret_cast<const uint32_t*>(host_base + 0x1001);
    TEST_ASSERT(context->stored_image_base <= UINT32_MAX);
    TEST_ASSERT(context->relocations_applied ==
                (context->stored_image_base !=
                 context->preferred_image_base));
    TEST_ASSERT(stored_pointer ==
                static_cast<uint32_t>(context->stored_image_base + 0x1000));
    TEST_ASSERT(stored_operand ==
                static_cast<uint32_t>(context->stored_image_base + 0x2000));

    const auto translated = context->stored_address_to_host(stored_pointer);
    TEST_ASSERT(translated.has_value());
    TEST_ASSERT(*translated == host_base + 0x1000);
    const auto translated_operand = context->stored_address_to_host(stored_operand);
    TEST_ASSERT(translated_operand.has_value());
    TEST_ASSERT(*translated_operand == host_base + 0x2000);

    mapped.reset();
    std::error_code error;
    std::filesystem::remove(path, error);
    TEST_ASSERT(!error);
    return 0;
}

int test_pe32_decode_uses_target_context() {
    const auto path = write_relocatable_pe32();
    auto mapped = utility::map_view_of_pe(path.string());
    TEST_ASSERT(mapped.has_value());
    const auto context = utility::get_analysis_context(mapped->module);
    TEST_ASSERT(context.has_value());

    const auto host_base = reinterpret_cast<uintptr_t>(mapped->module);
    auto* code = reinterpret_cast<uint8_t*>(host_base + 0x1000);
    const auto decoded = utility::decode_one(code, 16, *context);
    TEST_ASSERT(decoded.has_value());
    TEST_ASSERT(decoded->Length == 5);
    TEST_ASSERT(std::string_view{decoded->Mnemonic} == "MOV");
    TEST_ASSERT(utility::get_insn_size((uintptr_t)code, *context) == 5);

    const auto displacement =
        utility::resolve_displacement((uintptr_t)code, &*decoded, *context);
    TEST_ASSERT(displacement.has_value());
    TEST_ASSERT(*displacement == host_base + 0x2000);

#if !defined(_M_IX86) && !defined(__i386__)
    const auto host_decoded = utility::decode_one(code, 16);
    TEST_ASSERT(host_decoded.has_value());
    TEST_ASSERT(host_decoded->Length != decoded->Length);
#endif

    size_t linear_count = 0;
    utility::linear_decode(code, 16, [&](utility::ExhaustionContext& current) {
        ++linear_count;
        return current.instrux.Instruction != ND_INS_RETN;
    }, *context);
    TEST_ASSERT(linear_count == 2);

    size_t exhaustive_count = 0;
    utility::exhaustive_decode(code, 16, [&](utility::ExhaustionContext&) {
        ++exhaustive_count;
        return utility::ExhaustionResult::CONTINUE;
    }, *context);
    TEST_ASSERT(exhaustive_count == 2);

    const auto blocks = utility::collect_basic_blocks(
        (uintptr_t)code,
        utility::BasicBlockCollectOptions{
            .max_size = 16,
            .sort = true,
            .merge_call_blocks = true,
            .copy_instructions = true,
        },
        *context);
    TEST_ASSERT(blocks.size() == 1);
    TEST_ASSERT(blocks.front().instruction_count == 2);
    TEST_ASSERT(blocks.front().instructions.size() == 2);

    mapped.reset();
    std::error_code error;
    std::filesystem::remove(path, error);
    TEST_ASSERT(!error);
    return 0;
}

int test_pe32_function_bounds_use_target_pointer_width() {
    const auto path = write_relocatable_pe32();
    auto mapped = utility::map_view_of_pe(path.string());
    TEST_ASSERT(mapped.has_value());

    const auto host_base = reinterpret_cast<uintptr_t>(mapped->module);
    const auto aligned_pointer =
        utility::scan_ptr(mapped->module, host_base + 0x1000);
    TEST_ASSERT(aligned_pointer.has_value());
    TEST_ASSERT(*aligned_pointer == host_base + 0x2000);
    const auto unaligned_pointer =
        utility::scan_ptr_noalign(mapped->module, host_base + 0x1000);
    TEST_ASSERT(unaligned_pointer.has_value());
    TEST_ASSERT(*unaligned_pointer == host_base + 0x2000);

    const auto functions = utility::find_all_function_bounds(mapped->module);
    const auto found = std::find_if(
        functions.begin(), functions.end(), [host_base](const utility::FunctionBounds& function) {
            return function.start == host_base + 0x1000 &&
                   function.end > function.start;
        });
    TEST_ASSERT(found != functions.end());

    mapped.reset();
    std::error_code error;
    std::filesystem::remove(path, error);
    TEST_ASSERT(!error);
    return 0;
}

int test_pe32_rtti_uses_target_pointer_width() {
    const auto path = write_relocatable_pe32();
    auto mapped = utility::map_view_of_pe(path.string());
    TEST_ASSERT(mapped.has_value());
    const auto base = reinterpret_cast<uintptr_t>(mapped->module);
    constexpr std::string_view raw_name = ".?AVCrossArchRtti@@";

    const auto raw_vtable =
        utility::rtti::find_vtable(mapped->module, raw_name);
    TEST_ASSERT(raw_vtable.has_value());
    TEST_ASSERT(*raw_vtable == base + 0x2180);

#if !defined(_M_IX86) && !defined(__i386__)
    const auto friendly_vtable =
        utility::rtti::find_vtable(mapped->module, "class CrossArchRtti");
    TEST_ASSERT(friendly_vtable == raw_vtable);
    const auto partial =
        utility::rtti::find_vtable_partial(mapped->module, "CrossArchRtti");
    TEST_ASSERT(partial == raw_vtable);
    const auto regex = utility::rtti::find_vtable_regex(
        mapped->module, "class CrossArchRtti");
    TEST_ASSERT(regex == raw_vtable);
    TEST_ASSERT(utility::rtti::get_type_info(
        mapped->module, "class CrossArchRtti") ==
        reinterpret_cast<std::type_info*>(base + 0x2140));
#endif

    const auto matching =
        utility::rtti::find_vtables(mapped->module, raw_name);
    TEST_ASSERT(matching.size() == 1);
    TEST_ASSERT(matching.front() == base + 0x2180);
    const auto all = utility::rtti::find_all_vtables(mapped->module);
    TEST_ASSERT(std::find(all.begin(), all.end(), base + 0x2180) != all.end());

    mapped.reset();
    std::error_code error;
    std::filesystem::remove(path, error);
    TEST_ASSERT(!error);
    return 0;
}

int test_pe32_full_analysis_is_deterministic() {
    const auto path = write_relocatable_pe32();
    std::array<uintptr_t, 7> baseline{};

    for (size_t iteration = 0; iteration < 3; ++iteration) {
        auto mapped = utility::map_view_of_pe(path.string());
        TEST_ASSERT(mapped.has_value());
        const auto context = utility::get_analysis_context(mapped->module);
        TEST_ASSERT(context.has_value());
        TEST_ASSERT(context->arch == utility::TargetArch::X86);

        const auto base = reinterpret_cast<uintptr_t>(mapped->module);
        const auto code = base + 0x1000;
        const auto decoded =
            utility::decode_one((uint8_t*)code, 16, *context);
        TEST_ASSERT(decoded.has_value());
        const auto target =
            utility::resolve_displacement(code, &*decoded, *context);
        TEST_ASSERT(target.has_value());
        const auto pointer =
            utility::scan_ptr(mapped->module, code);
        TEST_ASSERT(pointer.has_value());
        const auto mnemonic =
            utility::scan_mnemonic(code, 2, "RETN", *context);
        TEST_ASSERT(mnemonic.has_value());
        const auto opcode =
            utility::scan_opcode(code, 2, 0xC3, *context);
        TEST_ASSERT(opcode == mnemonic);
        const auto disasm =
            utility::scan_disasm(code, 2, "C3", *context);
        TEST_ASSERT(disasm == mnemonic);
        const auto vtable = utility::rtti::find_vtable(
            mapped->module, ".?AVCrossArchRtti@@");
        TEST_ASSERT(vtable.has_value());

        const auto functions =
            utility::find_all_function_bounds(mapped->module);
        const auto function = std::find_if(
            functions.begin(), functions.end(),
            [code](const utility::FunctionBounds& candidate) {
                return candidate.start == code;
            });
        TEST_ASSERT(function != functions.end());

        const std::array<uintptr_t, 7> snapshot{
            decoded->Length,
            *target - base,
            *pointer - base,
            *mnemonic - base,
            *vtable - base,
            function->start - base,
            function->end - function->start,
        };
        if (iteration == 0) {
            baseline = snapshot;
        } else {
            TEST_ASSERT(snapshot == baseline);
        }
    }

    std::error_code error;
    std::filesystem::remove(path, error);
    TEST_ASSERT(!error);
    return 0;
}

int test_pe32_sections_use_target_header_layout() {
    auto mapped = utility::map_view_of_pe(pe32_sample_path());
    TEST_ASSERT(mapped.has_value());

    const auto sections = utility::get_module_sections(mapped->module);
    TEST_ASSERT(sections.has_value());
    TEST_ASSERT(sections->size() == 1);
    TEST_ASSERT(sections->front().name == ".rdata");
    TEST_ASSERT(sections->front().virtual_address ==
                reinterpret_cast<uintptr_t>(mapped->module) + 0x1000);
    TEST_ASSERT(sections->front().virtual_size == 21);
    return 0;
}

int main() try {
    std::cout << "===== kananlib-cross-arch-test =====" << std::endl;
    RUN_TEST(test_host_arch_matches_process);
    RUN_TEST(test_pe32_context_is_magic_aware);
    RUN_TEST(test_pe32_address_translation);
    RUN_TEST(test_pe32_relocation_state_matches_mapped_bytes);
    RUN_TEST(test_pe32_decode_uses_target_context);
    RUN_TEST(test_pe32_function_bounds_use_target_pointer_width);
    RUN_TEST(test_pe32_rtti_uses_target_pointer_width);
    RUN_TEST(test_pe32_full_analysis_is_deterministic);
    RUN_TEST(test_pe32_sections_use_target_header_layout);
    return test_summary();
} catch (const std::exception& e) {
    std::cout << "Exception: " << e.what() << std::endl;
    return 1;
} catch (...) {
    std::cout << "Unknown exception." << std::endl;
    return 1;
}
