// Regression tests for bugs found in the Linux compat layer audit.
//
// Tests Bug 1 (VirtualProtect size=0), Bug 4 (VirtualQuery MEM_FREE Protect),
// Bug 5 (VirtualQuery MEM_FREE BaseAddress alignment), and Bug 3
// (_BitScanReverse LP64).

#include <cstdint>
#include <cstring>
#include <iostream>

#include <windows.h>
#include <intrin.h>

#include "TestHelpers.hpp"
#include <utility/Module.hpp>

// ---------------------------------------------------------------------------
// Bug 1: VirtualProtect(addr, 0, ...) should be a no-op returning TRUE.
// On the buggy shim it mprotects one full page.
// ---------------------------------------------------------------------------
int test_virtual_protect_size_zero() {
    // Allocate a page with PAGE_READWRITE.
    void* p = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    TEST_ASSERT(p != nullptr);

    // Write a known pattern so we can verify the memory is still accessible
    // after the size-0 VirtualProtect.
    std::memset(p, 0xAB, 4096);

    DWORD old_prot = 0xDEADBEEF;
    // Windows docs: "If the size is 0, the function returns non-zero and does
    // not modify page protection."
    BOOL ok = VirtualProtect(p, 0, PAGE_NOACCESS, &old_prot);
    TEST_ASSERT(ok == TRUE);  // Must succeed

    // The memory must still be accessible (no page was changed).
    // If the shim mprotected the page to PAGE_NOACCESS, this will SIGSEGV.
    volatile uint8_t first = *(volatile uint8_t*)p;
    TEST_ASSERT(first == 0xAB);

    // old_prot should reflect the current (unchanged) protection.
    TEST_ASSERT(old_prot == PAGE_READWRITE);

    VirtualFree(p, 0, MEM_RELEASE);
    return 0;
}

// Bug 1b: VirtualProtect(addr, 0, ...) on a non-page-aligned address.
int test_virtual_protect_size_zero_unaligned() {
    void* p = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    TEST_ASSERT(p != nullptr);

    // Use an interior address (non-page-aligned).
    uint8_t* interior = (uint8_t*)p + 128;
    *interior = 0xCD;

    DWORD old_prot = 0;
    BOOL ok = VirtualProtect(interior, 0, PAGE_READONLY, &old_prot);
    TEST_ASSERT(ok == TRUE);

    // Memory must still be writable (protection unchanged).
    *interior = 0xEF;
    TEST_ASSERT(*interior == 0xEF);

    VirtualFree(p, 0, MEM_RELEASE);
    return 0;
}

// ---------------------------------------------------------------------------
// Bug 4: VirtualQuery on MEM_FREE region should report Protect=0, not
// PAGE_NOACCESS (0x01).
// ---------------------------------------------------------------------------
int test_virtual_query_free_protect() {
    // Query a high unmapped address that is almost certainly in a free region.
    // Use 0x7FFFFF000000 — well above any normal mapping on Linux.
    void* probe = (void*)0x7FFFFF000000ULL;

    MEMORY_BASIC_INFORMATION mbi{};
    SIZE_T result = VirtualQuery(probe, &mbi, sizeof(mbi));
    TEST_ASSERT(result == sizeof(mbi));

    // The region should be MEM_FREE.
    TEST_ASSERT(mbi.State == MEM_FREE);

    // Windows docs: Protect is 0 for MEM_FREE regions.
    TEST_ASSERT(mbi.Protect == 0);

    return 0;
}

// ---------------------------------------------------------------------------
// Bug 5: VirtualQuery MEM_FREE BaseAddress should be page-aligned.
// ---------------------------------------------------------------------------
int test_virtual_query_free_base_aligned() {
    void* probe = (void*)0x7FFFFF001234ULL; // intentionally not page-aligned

    MEMORY_BASIC_INFORMATION mbi{};
    SIZE_T result = VirtualQuery(probe, &mbi, sizeof(mbi));
    TEST_ASSERT(result == sizeof(mbi));
    TEST_ASSERT(mbi.State == MEM_FREE);

    // BaseAddress must be page-aligned.
    uintptr_t ps = 4096;
    TEST_ASSERT(((uintptr_t)mbi.BaseAddress & (ps - 1)) == 0);

    return 0;
}

// Bug 5b: VirtualQuery on a mapped region — BaseAddress should also be
// page-aligned (this is already correct, but guard against regressions).
int test_virtual_query_mapped_base_aligned() {
    void* p = VirtualAlloc(nullptr, 4096 * 4, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    TEST_ASSERT(p != nullptr);

    // Query an interior address.
    uint8_t* interior = (uint8_t*)p + 512;
    MEMORY_BASIC_INFORMATION mbi{};
    SIZE_T result = VirtualQuery(interior, &mbi, sizeof(mbi));
    TEST_ASSERT(result == sizeof(mbi));
    TEST_ASSERT(mbi.State == MEM_COMMIT);

    // BaseAddress should be the page containing `interior`.
    // For our VirtualAlloc, the whole allocation starts at p, and p is
    // page-aligned. Interior lands on the same page, so BaseAddress == p.
    TEST_ASSERT(mbi.BaseAddress == p);

    VirtualFree(p, 0, MEM_RELEASE);
    return 0;
}

// ---------------------------------------------------------------------------
// Bug 3: _BitScanReverse on LP64 — the compat shim hardcodes "31 - clz(mask)"
// which is wrong when unsigned long is 64-bit. Not called by kananlib today,
// but validates the fix for downstream consumers.
// ---------------------------------------------------------------------------
int test_bitscan_reverse_low_bit() {
    // mask = 0x01 (bit 0 set). _BitScanReverse should return index 0.
    unsigned long index = 0xDEADBEEF;
    unsigned char found = _BitScanReverse(&index, 0x01UL);
    TEST_ASSERT(found == 1);
    TEST_ASSERT(index == 0);
    return 0;
}

int test_bitscan_reverse_high_bit32() {
    // mask = 0x80000000 (bit 31). Index should be 31.
    unsigned long index = 0;
    unsigned char found = _BitScanReverse(&index, 0x80000000UL);
    TEST_ASSERT(found == 1);
    TEST_ASSERT(index == 31);
    return 0;
}

int test_bitscan_reverse_mid() {
    // mask = 0x0F (bits 0-3). Highest set bit is 3.
    unsigned long index = 0;
    unsigned char found = _BitScanReverse(&index, 0x0FUL);
    TEST_ASSERT(found == 1);
    TEST_ASSERT(index == 3);
    return 0;
}

int test_bitscan_reverse_zero() {
    unsigned long index = 0xCAFEBABE;
    unsigned char found = _BitScanReverse(&index, 0);
    TEST_ASSERT(found == 0);
    return 0;
}

int test_bitscan_forward_low_bit() {
    unsigned long index = 0;
    unsigned char found = _BitScanForward(&index, 0x80000000UL);
    TEST_ASSERT(found == 1);
    TEST_ASSERT(index == 31);
    return 0;
}

int test_bitscan_forward_zero() {
    unsigned long index = 0xCAFEBABE;
    unsigned char found = _BitScanForward(&index, 0);
    TEST_ASSERT(found == 0);
    return 0;
}

// ---------------------------------------------------------------------------
// Bug 6: /proc/self/maps line buffer — long paths cause regions to be dropped.
// We can't easily craft a /proc/self/maps, but we can verify that IsBadReadPtr
// correctly identifies mapped memory (which exercises the /proc/self/maps path).
// ---------------------------------------------------------------------------
int test_isbadreadptr_mapped() {
    void* p = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    TEST_ASSERT(p != nullptr);

    // A committed page should NOT be a bad read.
    TEST_ASSERT(IsBadReadPtr(p, 1) == FALSE);

    VirtualFree(p, 0, MEM_RELEASE);
    return 0;
}

int test_isbadreadptr_unmapped() {
    // An address at the top of the address space is almost certainly unmapped.
    void* probe = (void*)0x7FFFFF000000ULL;
    TEST_ASSERT(IsBadReadPtr(probe, 1) == TRUE);
    return 0;
}

int test_isbadwriteptr_mapped() {
    void* p = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    TEST_ASSERT(p != nullptr);

    TEST_ASSERT(IsBadWritePtr(p, 1) == FALSE);

    VirtualFree(p, 0, MEM_RELEASE);
    return 0;
}

// ---------------------------------------------------------------------------
// VirtualProtect round-trip: change protection, query it back.
// ---------------------------------------------------------------------------
int test_virtual_protect_roundtrip() {
    void* p = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    TEST_ASSERT(p != nullptr);

    DWORD old_prot = 0;
    BOOL ok = VirtualProtect(p, 4096, PAGE_READONLY, &old_prot);
    TEST_ASSERT(ok == TRUE);
    TEST_ASSERT(old_prot == PAGE_READWRITE);

    // Query back — should now be PAGE_READONLY.
    MEMORY_BASIC_INFORMATION mbi{};
    SIZE_T result = VirtualQuery(p, &mbi, sizeof(mbi));
    TEST_ASSERT(result == sizeof(mbi));
    TEST_ASSERT(mbi.Protect == PAGE_READONLY);

    // Restore.
    ok = VirtualProtect(p, 4096, PAGE_READWRITE, &old_prot);
    TEST_ASSERT(ok == TRUE);
    TEST_ASSERT(old_prot == PAGE_READONLY);

    VirtualFree(p, 0, MEM_RELEASE);
    return 0;
}

// ---------------------------------------------------------------------------
// VirtualAlloc / VirtualFree lifecycle.
// ---------------------------------------------------------------------------
int test_alloc_free_lifecycle() {
    void* p = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    TEST_ASSERT(p != nullptr);

    // Write and read.
    std::memset(p, 0x42, 4096);
    TEST_ASSERT(((uint8_t*)p)[0] == 0x42);
    TEST_ASSERT(((uint8_t*)p)[4095] == 0x42);

    BOOL freed = VirtualFree(p, 0, MEM_RELEASE);
    TEST_ASSERT(freed == TRUE);

    return 0;
}

// ---------------------------------------------------------------------------
// VirtualQuery RegionSize sanity: a mapped region should report size >= 4096.
// ---------------------------------------------------------------------------
int test_virtual_query_region_size() {
    void* p = VirtualAlloc(nullptr, 4096 * 4, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    TEST_ASSERT(p != nullptr);

    MEMORY_BASIC_INFORMATION mbi{};
    SIZE_T result = VirtualQuery(p, &mbi, sizeof(mbi));
    TEST_ASSERT(result == sizeof(mbi));
    TEST_ASSERT(mbi.State == MEM_COMMIT);
    TEST_ASSERT(mbi.RegionSize >= 4096 * 4);

    VirtualFree(p, 0, MEM_RELEASE);
    return 0;
}

// ---------------------------------------------------------------------------
// Bug 2: map_view_of_pe section table bounds check.
// A PE with NumberOfSections=0x7FFF causes IMAGE_FIRST_SECTION +
// NumberOfSections*sizeof(IMAGE_SECTION_HEADER) to extend past the file data.
// Without the bounds check, the mapper reads heap memory past file_data.
// With the fix, map_view_of_file returns std::nullopt.
// ---------------------------------------------------------------------------
#include <filesystem>
#include <fstream>

int test_malformed_pe_section_table_bounds() {
    // Build a minimal PE in memory with a huge NumberOfSections.
    // The file is just big enough for the DOS header + NT headers + optional
    // header, but NOT for 0x7FFF section headers (which would need ~1MB).
    constexpr size_t FILE_SIZE = 1024; // way too small for the section table
    std::vector<uint8_t> pe_data(FILE_SIZE, 0);

    // DOS header
    auto* dos = (IMAGE_DOS_HEADER*)pe_data.data();
    dos->e_magic = IMAGE_DOS_SIGNATURE;  // MZ
    dos->e_lfanew = 64;                  // NT headers at offset 64

    // NT headers
    auto* nt = (IMAGE_NT_HEADERS*)(pe_data.data() + 64);
    nt->Signature = IMAGE_NT_SIGNATURE;  // PE\0\0
    nt->FileHeader.Machine = 0x8664;     // AMD64
    nt->FileHeader.NumberOfSections = 0x7FFF; // huge — table overflows file
    nt->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
    nt->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    nt->OptionalHeader.SizeOfImage = 0x10000;
    nt->OptionalHeader.SizeOfHeaders = 1024;
    nt->OptionalHeader.SectionAlignment = 0x1000;

    nt->OptionalHeader.FileAlignment = 0x200;

    // Write to a temp file.
    auto tmpdir = std::filesystem::temp_directory_path();
    auto tmppath = tmpdir / "kananlib_test_malformed_pe.exe";
    {
        std::ofstream ofs(tmppath, std::ios::binary);
        ofs.write((const char*)pe_data.data(), pe_data.size());
    }

    // map_view_of_file should return nullopt (not crash, not return garbage).
    auto result = utility::map_view_of_file(tmppath.string());

    // Clean up temp file.
    std::filesystem::remove(tmppath);

    // Without the bounds check fix, this either:
    //   a) reads past the heap allocation (UB / ASAN error), or
    //   b) returns a FakeModule with garbage section data.
    // With the fix, it must return nullopt.
    TEST_ASSERT(!result.has_value());

    return 0;
}

// Bug 2b: PE with valid section count but section table past file end.
// The optional header's SizeOfOptionalHeader is set larger than the file,
// pushing IMAGE_FIRST_SECTION past the file buffer.
int test_malformed_pe_large_optional_header() {
    // File is 512 bytes. NT headers at offset 64. SizeOfOptionalHeader = 400,
    // so sections start at 64 + 20 + 400 = 484. With even 1 section, the
    // section header (40 bytes) overflows: 484 + 40 = 524 > 512.
    constexpr size_t FILE_SIZE = 512;
    std::vector<uint8_t> pe_data(FILE_SIZE, 0);

    auto* dos = (IMAGE_DOS_HEADER*)pe_data.data();
    dos->e_magic = IMAGE_DOS_SIGNATURE;
    dos->e_lfanew = 64;

    auto* nt = (IMAGE_NT_HEADERS*)(pe_data.data() + 64);
    nt->Signature = IMAGE_NT_SIGNATURE;
    nt->FileHeader.Machine = 0x8664;
    nt->FileHeader.NumberOfSections = 1;
    nt->FileHeader.SizeOfOptionalHeader = 400; // way larger than sizeof(IMAGE_OPTIONAL_HEADER64)
    // OptionalHeader starts at offset 84 (64 + 20). With SizeOfOptionalHeader=400,
    // sections start at 64 + 20 + 400 = 484. One section header = 40 bytes = 524 > 512.
    nt->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    nt->OptionalHeader.SizeOfImage = 0x10000;
    nt->OptionalHeader.SizeOfHeaders = FILE_SIZE;

    auto tmpdir = std::filesystem::temp_directory_path();
    auto tmppath = tmpdir / "kananlib_test_malformed_pe_opt.exe";
    {
        std::ofstream ofs(tmppath, std::ios::binary);
        ofs.write((const char*)pe_data.data(), pe_data.size());
    }

    auto result = utility::map_view_of_file(tmppath.string());
    std::filesystem::remove(tmppath);

    TEST_ASSERT(!result.has_value());
    return 0;
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main() try {
    std::printf("=== Linux Audit Regression Tests ===\n");

    // Bug 1: VirtualProtect size=0
    RUN_TEST(test_virtual_protect_size_zero);
    RUN_TEST(test_virtual_protect_size_zero_unaligned);

    // Bug 4: VirtualQuery MEM_FREE Protect
    RUN_TEST(test_virtual_query_free_protect);

    // Bug 5: VirtualQuery BaseAddress alignment
    RUN_TEST(test_virtual_query_free_base_aligned);
    RUN_TEST(test_virtual_query_mapped_base_aligned);

    // Bug 3: _BitScanReverse / _BitScanForward
    RUN_TEST(test_bitscan_reverse_low_bit);
    RUN_TEST(test_bitscan_reverse_high_bit32);
    RUN_TEST(test_bitscan_reverse_mid);
    RUN_TEST(test_bitscan_reverse_zero);
    RUN_TEST(test_bitscan_forward_low_bit);
    RUN_TEST(test_bitscan_forward_zero);

    // Bug 6: IsBadReadPtr correctness (exercises /proc/self/maps)
    RUN_TEST(test_isbadreadptr_mapped);
    RUN_TEST(test_isbadreadptr_unmapped);
    RUN_TEST(test_isbadwriteptr_mapped);

    // General VirtualProtect/Query correctness
    RUN_TEST(test_virtual_protect_roundtrip);
    RUN_TEST(test_alloc_free_lifecycle);
    RUN_TEST(test_virtual_query_region_size);
    // Bug 2: PE section table bounds
    RUN_TEST(test_malformed_pe_section_table_bounds);
    RUN_TEST(test_malformed_pe_large_optional_header);


    return test_summary();
} catch (const std::exception& e) {
    std::printf("Exception: %s\n", e.what());
    return 1;
} catch (...) {
    std::printf("Unknown exception\n");
    return 1;
}
