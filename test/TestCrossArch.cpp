// Cross-architecture analysis: a 64-bit process mapping and analyzing a 32-bit
// PE (and, on an x86 build, the same code paths at host arch). Everything is
// driven off a synthetic, relocatable PE32 built in-memory so the test is
// deterministic and self-contained.
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

#include <windows.h>

#include <utility/Module.hpp>
#include <utility/Scan.hpp>
#include <utility/RTTI.hpp>

#include "TestHelpers.hpp"

namespace {
// Builds a minimal relocatable 32-bit PE:
//   .text  (0x1000): `mov eax, [0x402000]` ; `ret`   -- absolute disp32 ref
//   .rdata (0x2000): a function pointer (-> .text) and a tiny MSVC RTTI graph
//                    (CompleteObjectLocator -> TypeDescriptor -> vtable)
//   .reloc (0x3000): HIGHLOW relocations for every absolute field above
// so that SEC_IMAGE mapping relocates all absolute pointers to the mapped base.
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
    optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC] = {0x3000, 36};  // 12 + 24

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
    sections[2].Misc.VirtualSize = 36;
    sections[2].VirtualAddress = 0x3000;
    sections[2].SizeOfRawData = 0x200;
    sections[2].PointerToRawData = 0x600;
    sections[2].Characteristics =
        IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_DISCARDABLE;

    // .text: mov eax, [0x402000] ; ret
    const uint8_t code[] = {0xA1, 0x00, 0x20, 0x40, 0x00, 0xC3};
    std::memcpy(bytes.data() + 0x200, code, sizeof(code));

    // .rdata @ 0x2000: pointer into .text (0x401000).
    *reinterpret_cast<uint32_t*>(bytes.data() + 0x400) = kImageBase + 0x1000;

    // Minimal x86 MSVC RTTI graph:
    //   CompleteObjectLocator @ 0x402100, TypeDescriptor @ 0x402140,
    //   COL slot @ 0x40217c, vtable @ 0x402180.
    auto* locator = reinterpret_cast<uint32_t*>(bytes.data() + 0x500);
    locator[0] = 0;                    // signature (0 = x86, absolute refs)
    locator[1] = 0;                    // offset
    locator[2] = 0;                    // cdOffset
    locator[3] = kImageBase + 0x2140;  // pTypeDescriptor (absolute)
    locator[4] = 0;                    // pClassDescriptor
    auto* type_descriptor = bytes.data() + 0x540;
    *reinterpret_cast<uint32_t*>(type_descriptor) = 0;      // vfptr
    *reinterpret_cast<uint32_t*>(type_descriptor + 4) = 0;  // spare
    constexpr char kRttiName[] = ".?AVCrossArchRtti@@";
    std::memcpy(type_descriptor + 8, kRttiName, sizeof(kRttiName));
    *reinterpret_cast<uint32_t*>(bytes.data() + 0x57C) = kImageBase + 0x2100;  // COL slot
    *reinterpret_cast<uint32_t*>(bytes.data() + 0x580) = kImageBase + 0x1000;  // vtable[0]

    // A second vtable of the same type at a different subobject offset, sharing
    // the TypeDescriptor. find_vtables() must return both, ordered by the COL's
    // offset -- exercising the target-pointer-width COL read in its sort.
    auto* locator2 = reinterpret_cast<uint32_t*>(bytes.data() + 0x520);
    locator2[0] = 0;                    // signature
    locator2[1] = 8;                    // offset (subobject; sorts after 0)
    locator2[2] = 0;                    // cdOffset
    locator2[3] = kImageBase + 0x2140;  // pTypeDescriptor (same type)
    locator2[4] = 0;                    // pClassDescriptor
    *reinterpret_cast<uint32_t*>(bytes.data() + 0x59C) = kImageBase + 0x2120;  // COL2 slot
    *reinterpret_cast<uint32_t*>(bytes.data() + 0x5A0) = kImageBase + 0x1000;  // vtable2[0]

    // .reloc: HIGHLOW entries for the absolute fields.
    auto* code_reloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>(bytes.data() + 0x600);
    code_reloc->VirtualAddress = 0x1000;
    code_reloc->SizeOfBlock = 12;
    auto* code_entries = reinterpret_cast<uint16_t*>(code_reloc + 1);
    code_entries[0] = (IMAGE_REL_BASED_HIGHLOW << 12) | 1;  // mov disp32 @ 0x1001
    code_entries[1] = IMAGE_REL_BASED_ABSOLUTE << 12;

    auto* pointer_reloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>(bytes.data() + 0x60C);
    pointer_reloc->VirtualAddress = 0x2000;
    // 8-byte header + 7 entries = 22; pad with a trailing ABSOLUTE (no-op) entry
    // so SizeOfBlock stays DWORD-aligned as the PE spec requires.
    pointer_reloc->SizeOfBlock = 24;
    auto* pointer_entries = reinterpret_cast<uint16_t*>(pointer_reloc + 1);
    pointer_entries[0] = IMAGE_REL_BASED_HIGHLOW << 12;             // ptr @ 0x2000
    pointer_entries[1] = (IMAGE_REL_BASED_HIGHLOW << 12) | 0x10C;   // COL.pTypeDescriptor
    pointer_entries[2] = (IMAGE_REL_BASED_HIGHLOW << 12) | 0x17C;   // COL slot
    pointer_entries[3] = (IMAGE_REL_BASED_HIGHLOW << 12) | 0x180;   // vtable[0]
    pointer_entries[4] = (IMAGE_REL_BASED_HIGHLOW << 12) | 0x12C;   // COL2.pTypeDescriptor
    pointer_entries[5] = (IMAGE_REL_BASED_HIGHLOW << 12) | 0x19C;   // COL2 slot
    pointer_entries[6] = (IMAGE_REL_BASED_HIGHLOW << 12) | 0x1A0;   // vtable2[0]
    pointer_entries[7] = IMAGE_REL_BASED_ABSOLUTE << 12;            // padding
    return bytes;
}

std::filesystem::path write_relocatable_pe32() {
    const auto path = std::filesystem::temp_directory_path() / "kananlib_cross_arch_reloc32.dll";
    const auto bytes = make_relocatable_pe32();
    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    file.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    return path;
}
}  // namespace

int test_host_arch_and_pointer_width() {
#if defined(_M_IX86) || defined(__i386__)
    TEST_ASSERT(utility::host_arch() == utility::TargetArch::X86);
#else
    TEST_ASSERT(utility::host_arch() == utility::TargetArch::X64);
#endif
    TEST_ASSERT(utility::pointer_width(utility::TargetArch::X86) == 4);
    TEST_ASSERT(utility::pointer_width(utility::TargetArch::X64) == 8);
    return 0;
}

int test_map_pe32_detects_target() {
    const auto path = write_relocatable_pe32();
    auto mapped = utility::map_view_of_pe(path.string());
    TEST_ASSERT(mapped.has_value());
    auto module = mapped->module;

    // Architecture and header fields are read PE32-correctly even on an x64 host.
    // A wrong (x64-layout) read would return garbage, not the real image base.
    const auto base = reinterpret_cast<uintptr_t>(module);
    TEST_ASSERT(utility::get_module_arch(module) == utility::TargetArch::X86);
    const auto imagebase = utility::get_dll_imagebase(Address{module});
    TEST_ASSERT(imagebase.has_value());
    // SEC_IMAGE patches the in-memory ImageBase to the actual mapped base.
    TEST_ASSERT(*imagebase == base);
    const auto size = utility::get_module_size(module);
    TEST_ASSERT(size.has_value());
    TEST_ASSERT(*size == 0x4000);

    const auto sections = utility::get_module_sections(module);
    TEST_ASSERT(sections.has_value());
    const auto rdata = std::find_if(sections->begin(), sections->end(),
        [](const utility::ModuleSection& s) { return s.name == ".rdata"; });
    TEST_ASSERT(rdata != sections->end());
    TEST_ASSERT(rdata->virtual_address == base + 0x2000);

    mapped.reset();
    std::error_code error;
    std::filesystem::remove(path, error);
    TEST_ASSERT(!error);
    return 0;
}

int test_decode_uses_target_arch() {
    const auto path = write_relocatable_pe32();
    auto mapped = utility::map_view_of_pe(path.string());
    TEST_ASSERT(mapped.has_value());
    const auto base = reinterpret_cast<uintptr_t>(mapped->module);
    auto* code = reinterpret_cast<uint8_t*>(base + 0x1000);

    // `mov eax, [disp32]` is 5 bytes in 32-bit mode; the same bytes decode
    // differently in 64-bit mode, so the target arch must be honored.
    const auto decoded = utility::decode_one(code, 16, utility::TargetArch::X86);
    TEST_ASSERT(decoded.has_value());
    TEST_ASSERT(decoded->Length == 5);
    TEST_ASSERT(std::string_view{decoded->Mnemonic} == "MOV");
    TEST_ASSERT(utility::get_insn_size((uintptr_t)code, utility::TargetArch::X86) == 5);
#if !defined(_M_IX86) && !defined(__i386__)
    const auto host_decoded = utility::decode_one(code, 16);
    TEST_ASSERT(host_decoded.has_value());
    TEST_ASSERT(host_decoded->Length != decoded->Length);
#endif

    // The absolute [disp32] operand resolves to the mapped host address.
    const auto ref = utility::resolve_displacement(
        (uintptr_t)code, &*decoded, utility::TargetArch::X86);
    TEST_ASSERT(ref.has_value());
    TEST_ASSERT(*ref == base + 0x2000);

    // linear/exhaustive decode + basic-block collection walk `mov; ret` = 2 insns.
    size_t linear = 0;
    utility::linear_decode(code, 16, [&](utility::ExhaustionContext& ctx) {
        ++linear;
        return ctx.instrux.Instruction != ND_INS_RETN;
    }, utility::TargetArch::X86);
    TEST_ASSERT(linear == 2);

    size_t exhaustive = 0;
    utility::exhaustive_decode(code, 16, [&](utility::ExhaustionContext&) {
        ++exhaustive;
        return utility::ExhaustionResult::CONTINUE;
    }, utility::TargetArch::X86);
    TEST_ASSERT(exhaustive == 2);

    const auto blocks = utility::collect_basic_blocks(
        (uintptr_t)code,
        utility::BasicBlockCollectOptions{.max_size = 16, .copy_instructions = true},
        utility::TargetArch::X86);
    TEST_ASSERT(blocks.size() == 1);
    TEST_ASSERT(blocks.front().instruction_count == 2);

    mapped.reset();
    std::error_code error;
    std::filesystem::remove(path, error);
    TEST_ASSERT(!error);
    return 0;
}

int test_scan_and_bounds_use_target_width() {
    const auto path = write_relocatable_pe32();
    auto mapped = utility::map_view_of_pe(path.string());
    TEST_ASSERT(mapped.has_value());
    auto module = mapped->module;
    const auto base = reinterpret_cast<uintptr_t>(module);

    // The .rdata pointer (0x2000) is a 4-byte slot holding the address of the
    // function at 0x1000; scanning must use the target's 4-byte width.
    const auto aligned = utility::scan_ptr(module, base + 0x1000);
    TEST_ASSERT(aligned.has_value());
    TEST_ASSERT(*aligned == base + 0x2000);
    const auto unaligned = utility::scan_ptr_noalign(module, base + 0x1000);
    TEST_ASSERT(unaligned.has_value());
    TEST_ASSERT(*unaligned == base + 0x2000);

    // Heuristic function discovery (x86 has no .pdata) finds the function via
    // the 4-byte pointer table entry.
    const auto functions = utility::find_all_function_bounds(module);
    const auto found = std::find_if(functions.begin(), functions.end(),
        [base](const utility::FunctionBounds& f) {
            return f.start == base + 0x1000 && f.end > f.start;
        });
    TEST_ASSERT(found != functions.end());

    mapped.reset();
    std::error_code error;
    std::filesystem::remove(path, error);
    TEST_ASSERT(!error);
    return 0;
}

int test_rtti_uses_target_width() {
    const auto path = write_relocatable_pe32();
    auto mapped = utility::map_view_of_pe(path.string());
    TEST_ASSERT(mapped.has_value());
    auto module = mapped->module;
    const auto base = reinterpret_cast<uintptr_t>(module);
    constexpr std::string_view raw_name = ".?AVCrossArchRtti@@";

    // Vtable discovery reads 4-byte COL/TypeDescriptor pointers and matches the
    // decorated RTTI name (the host CRT undecorator can't run on a foreign type).
    const auto vtable = utility::rtti::find_vtable(module, raw_name);
    TEST_ASSERT(vtable.has_value());
    TEST_ASSERT(*vtable == base + 0x2180);

    // Two vtables share this type at subobject offsets 0 and 8; find_vtables
    // must return both, ordered by the COL offset it reads at 4-byte width.
    const auto matching = utility::rtti::find_vtables(module, raw_name);
    TEST_ASSERT(matching.size() == 2);
    TEST_ASSERT(matching[0] == base + 0x2180);
    TEST_ASSERT(matching[1] == base + 0x21a0);

    const auto all = utility::rtti::find_all_vtables(module);
    TEST_ASSERT(std::find(all.begin(), all.end(), base + 0x2180) != all.end());
    TEST_ASSERT(std::find(all.begin(), all.end(), base + 0x21a0) != all.end());

    const auto ti = utility::rtti::get_type_info(module, raw_name);
    TEST_ASSERT(ti == reinterpret_cast<std::type_info*>(base + 0x2140));

    mapped.reset();
    std::error_code error;
    std::filesystem::remove(path, error);
    TEST_ASSERT(!error);
    return 0;
}

// A PE whose optional-header magic is neither PE32 nor PE32+ must not be
// silently classified as a 64-bit target -- on an x86 host that would flip
// decode/pointer width away from the host's. Fall back to the host arch.
int test_module_arch_falls_back_on_unknown_magic() {
    std::vector<uint8_t> bytes(0x400);
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(bytes.data());
    dos->e_magic = IMAGE_DOS_SIGNATURE;
    dos->e_lfanew = 0x80;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(bytes.data() + dos->e_lfanew);
    nt->Signature = IMAGE_NT_SIGNATURE;

    // Real PE32 / PE32+ magics classify normally.
    nt->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
    TEST_ASSERT(utility::get_module_arch((HMODULE)bytes.data()) == utility::TargetArch::X86);
    nt->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    TEST_ASSERT(utility::get_module_arch((HMODULE)bytes.data()) == utility::TargetArch::X64);

    // A ROM image and an outright garbage magic are neither; both must degrade
    // to the host architecture rather than being assumed 64-bit.
    nt->OptionalHeader.Magic = 0x107;  // IMAGE_ROM_OPTIONAL_HDR_MAGIC
    TEST_ASSERT(utility::get_module_arch((HMODULE)bytes.data()) == utility::host_arch());
    nt->OptionalHeader.Magic = 0xDEAD;
    TEST_ASSERT(utility::get_module_arch((HMODULE)bytes.data()) == utility::host_arch());
    return 0;
}

// get_dll_imagebase must read ImageBase by the optional-header magic: it lives
// at a different offset and width in PE32 (28, 4 bytes) vs PE32+ (24, 8 bytes).
// An unrecognized magic identifies neither layout, so there is nothing valid to
// read -- report failure rather than reading whichever layout we guessed.
int test_dll_imagebase_reads_by_magic() {
    std::vector<uint8_t> bytes(0x400);
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(bytes.data());
    dos->e_magic = IMAGE_DOS_SIGNATURE;
    dos->e_lfanew = 0x80;
    auto* nt32 = reinterpret_cast<IMAGE_NT_HEADERS32*>(bytes.data() + dos->e_lfanew);
    auto* nt64 = reinterpret_cast<IMAGE_NT_HEADERS64*>(bytes.data() + dos->e_lfanew);
    const auto reset = [&] {
        std::memset(bytes.data() + dos->e_lfanew, 0, 0x100);
        nt32->Signature = IMAGE_NT_SIGNATURE;
    };

    // PE32: the 4-byte field at optional-header offset 28.
    reset();
    nt32->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
    nt32->OptionalHeader.ImageBase = 0x11223344;
    auto ib = utility::get_dll_imagebase(Address{bytes.data()});
    TEST_ASSERT(ib.has_value());
    TEST_ASSERT(*ib == 0x11223344);

    // PE32+: the 8-byte field at optional-header offset 24. Reading the PE32
    // offset instead would land on the zeroed upper half.
    reset();
    nt64->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    nt64->OptionalHeader.ImageBase = 0x55667788;
    ib = utility::get_dll_imagebase(Address{bytes.data()});
    TEST_ASSERT(ib.has_value());
    TEST_ASSERT(*ib == 0x55667788);

    // Neither layout: no valid ImageBase to report.
    reset();
    nt32->OptionalHeader.Magic = 0x107;  // IMAGE_ROM_OPTIONAL_HDR_MAGIC
    TEST_ASSERT(!utility::get_dll_imagebase(Address{bytes.data()}).has_value());
    reset();
    nt32->OptionalHeader.Magic = 0xDEAD;
    TEST_ASSERT(!utility::get_dll_imagebase(Address{bytes.data()}).has_value());
    return 0;
}

// scan_ptr_noalign must search a pattern of the *target's* pointer width, not
// the host's. The buffer below holds a 4-byte-matching decoy first and the real
// 8-byte value second, so a host-width search on a 32-bit host picks the decoy.
int test_scan_ptr_noalign_uses_target_width() {
    const uint8_t bytes[] = {
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22,  // 4-byte match only
        0xAA, 0xBB, 0xCC, 0xDD, 0x00, 0x00, 0x00, 0x00,  // full 8-byte match
    };
    const auto start = reinterpret_cast<uintptr_t>(bytes);
    constexpr uintptr_t needle = 0xDDCCBBAAull;

    const auto as_x64 = utility::scan_ptr_noalign(
        start, sizeof(bytes), needle, utility::TargetArch::X64);
    TEST_ASSERT(as_x64.has_value());
    TEST_ASSERT(*as_x64 == start + 8);

    const auto as_x86 = utility::scan_ptr_noalign(
        start, sizeof(bytes), needle, utility::TargetArch::X86);
    TEST_ASSERT(as_x86.has_value());
    TEST_ASSERT(*as_x86 == start);
    return 0;
}

int main() try {
    std::cout << "===== kananlib-cross-arch-test =====" << std::endl;
    RUN_TEST(test_host_arch_and_pointer_width);
    RUN_TEST(test_map_pe32_detects_target);
    RUN_TEST(test_decode_uses_target_arch);
    RUN_TEST(test_scan_and_bounds_use_target_width);
    RUN_TEST(test_rtti_uses_target_width);
    RUN_TEST(test_module_arch_falls_back_on_unknown_magic);
    RUN_TEST(test_dll_imagebase_reads_by_magic);
    RUN_TEST(test_scan_ptr_noalign_uses_target_width);
    return test_summary();
} catch (const std::exception& e) {
    std::cout << "Exception: " << e.what() << std::endl;
    return 1;
} catch (...) {
    std::cout << "Unknown exception." << std::endl;
    return 1;
}
