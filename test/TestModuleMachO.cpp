#include <utility/Module.hpp>
#include <utility/Address.hpp>

#include "TestHelpers.hpp"

#include <Windows.h>

#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace {
    constexpr uint32_t MACHO_MH_MAGIC_64 = 0xFEEDFACF;
    constexpr uint32_t MACHO_FAT_MAGIC_BE = 0xBEBAFECA;
    constexpr uint32_t MACHO_CPU_TYPE_X86_64 = 0x01000007;
    constexpr uint32_t MACHO_CPU_TYPE_ARM64 = 0x0100000C;
    constexpr uint32_t MACHO_LC_SEGMENT_64 = 0x19;
    constexpr uint32_t MACHO_VM_PROT_READ = 0x01;
    constexpr uint32_t MACHO_VM_PROT_WRITE = 0x02;
    constexpr uint32_t MACHO_VM_PROT_EXECUTE = 0x04;

#pragma pack(push, 1)
    struct macho_header_64 {
        uint32_t magic;
        uint32_t cputype;
        uint32_t cpusubtype;
        uint32_t filetype;
        uint32_t ncmds;
        uint32_t sizeofcmds;
        uint32_t flags;
        uint32_t reserved;
    };

    struct macho_segment_command_64 {
        uint32_t cmd;
        uint32_t cmdsize;
        char segname[16];
        uint64_t vmaddr;
        uint64_t vmsize;
        uint64_t fileoff;
        uint64_t filesize;
        uint32_t maxprot;
        uint32_t initprot;
        uint32_t nsects;
        uint32_t flags;
    };

    struct macho_fat_header {
        uint32_t magic;
        uint32_t nfat_arch;
    };

    struct macho_fat_arch {
        uint32_t cputype;
        uint32_t cpusubtype;
        uint32_t offset;
        uint32_t size;
        uint32_t align;
    };
#pragma pack(pop)

    static_assert(sizeof(macho_header_64) == 32);
    static_assert(sizeof(macho_segment_command_64) == 72);
    static_assert(sizeof(macho_fat_header) == 8);
    static_assert(sizeof(macho_fat_arch) == 20);

    uint32_t be32(uint32_t v) {
        return _byteswap_ulong(v);
    }

    std::filesystem::path temp_path(const char* name) {
        auto dir = std::filesystem::temp_directory_path() / "kananlib_macho_tests";
        std::filesystem::create_directories(dir);
        return dir / name;
    }

    void write_file(const std::filesystem::path& path, const std::vector<uint8_t>& bytes) {
        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    }

    template <typename T>
    void write_struct(std::vector<uint8_t>& bytes, size_t offset, const T& value) {
        if (bytes.size() < offset + sizeof(T)) {
            bytes.resize(offset + sizeof(T));
        }
        std::memcpy(bytes.data() + offset, &value, sizeof(T));
    }

    std::vector<uint8_t> make_thin_macho(uint32_t cputype = MACHO_CPU_TYPE_X86_64,
                                         bool include_segments = true,
                                         bool invalid_extent = false,
                                         bool malformed_command = false) {
        const uint64_t text_vm = 0x1000;
        const uint64_t data_vm = invalid_extent ? 0x100000010ULL : 0x2000;
        const uint64_t text_fileoff = 0x1000;
        const uint64_t text_size = 16;
        const uint64_t data_fileoff = 0x1010;
        const uint64_t data_size = 8;

        const uint32_t ncmds = include_segments ? 2u : (malformed_command ? 1u : 0u);
        const uint32_t sizeofcmds = include_segments ? sizeof(macho_segment_command_64) * 2u
                                                     : (malformed_command ? sizeof(macho_segment_command_64) : 0u);
        const size_t file_size = include_segments ? static_cast<size_t>(data_fileoff + data_size)
                                                  : static_cast<size_t>(sizeof(macho_header_64) + sizeofcmds);
        std::vector<uint8_t> bytes(std::max<size_t>(file_size, sizeof(macho_header_64) + sizeofcmds), 0);

        macho_header_64 header{};
        header.magic = MACHO_MH_MAGIC_64;
        header.cputype = cputype;
        header.cpusubtype = 3;
        header.filetype = 2;
        header.ncmds = ncmds;
        header.sizeofcmds = sizeofcmds;
        write_struct(bytes, 0, header);

        if (malformed_command) {
            struct { uint32_t cmd; uint32_t cmdsize; } bad{ MACHO_LC_SEGMENT_64, 0 };
            write_struct(bytes, sizeof(macho_header_64), bad);
            return bytes;
        }

        if (!include_segments) {
            return bytes;
        }

        macho_segment_command_64 text{};
        text.cmd = MACHO_LC_SEGMENT_64;
        text.cmdsize = sizeof(macho_segment_command_64);
        std::memcpy(text.segname, "__TEXT", 6);
        text.vmaddr = text_vm;
        text.vmsize = 0x1000;
        text.fileoff = text_fileoff;
        text.filesize = text_size;
        text.maxprot = MACHO_VM_PROT_READ | MACHO_VM_PROT_EXECUTE;
        text.initprot = MACHO_VM_PROT_READ | MACHO_VM_PROT_EXECUTE;
        write_struct(bytes, sizeof(macho_header_64), text);

        macho_segment_command_64 data{};
        data.cmd = MACHO_LC_SEGMENT_64;
        data.cmdsize = sizeof(macho_segment_command_64);
        std::memcpy(data.segname, "__DATA", 6);
        data.vmaddr = data_vm;
        data.vmsize = 0x1000;
        data.fileoff = data_fileoff;
        data.filesize = data_size;
        data.maxprot = MACHO_VM_PROT_READ | MACHO_VM_PROT_WRITE;
        data.initprot = MACHO_VM_PROT_READ | MACHO_VM_PROT_WRITE;
        write_struct(bytes, sizeof(macho_header_64) + sizeof(macho_segment_command_64), data);

        const uint8_t text_payload[16] = { 0xC3, 0x90, 0x90, 0x90, 'T', 'E', 'X', 'T', 1, 2, 3, 4, 5, 6, 7, 8 };
        const uint8_t data_payload[8] = { 'D', 'A', 'T', 'A', 9, 10, 11, 12 };
        std::memcpy(bytes.data() + text_fileoff, text_payload, sizeof(text_payload));
        std::memcpy(bytes.data() + data_fileoff, data_payload, sizeof(data_payload));
        return bytes;
    }

    std::vector<uint8_t> make_fat_macho_with_x64() {
        auto thin = make_thin_macho();
        constexpr size_t offset = 0x100;
        std::vector<uint8_t> bytes(offset + thin.size(), 0);
        macho_fat_header fat{};
        fat.magic = MACHO_FAT_MAGIC_BE;
        fat.nfat_arch = be32(1);
        write_struct(bytes, 0, fat);

        macho_fat_arch arch{};
        arch.cputype = be32(MACHO_CPU_TYPE_X86_64);
        arch.cpusubtype = be32(3);
        arch.offset = be32(static_cast<uint32_t>(offset));
        arch.size = be32(static_cast<uint32_t>(thin.size()));
        arch.align = be32(12);
        write_struct(bytes, sizeof(fat), arch);
        std::memcpy(bytes.data() + offset, thin.data(), thin.size());
        return bytes;
    }

    std::vector<uint8_t> make_fat_macho_without_x64() {
        // Must be >= sizeof(macho_header_64), otherwise map_view_of_macho exits
        // through the generic "file too small" guard before reaching the fat parser.
        std::vector<uint8_t> bytes(64, 0);
        macho_fat_header fat{};
        fat.magic = MACHO_FAT_MAGIC_BE;
        fat.nfat_arch = be32(1);
        write_struct(bytes, 0, fat);
        macho_fat_arch arch{};
        arch.cputype = be32(MACHO_CPU_TYPE_ARM64);
        arch.offset = be32(0x30);
        arch.size = be32(0x10);
        write_struct(bytes, sizeof(fat), arch);
        return bytes;
    }

    std::vector<uint8_t> make_truncated_fat_header() {
        std::vector<uint8_t> bytes(64, 0);
        macho_fat_header fat{};
        fat.magic = MACHO_FAT_MAGIC_BE;
        fat.nfat_arch = be32(4); // claims 4 arch entries, but file only stores one
        write_struct(bytes, 0, fat);
        return bytes;
    }
}

int test_map_view_of_macho_thin_maps_segments() {
    const auto path = temp_path("thin_valid.macho");
    write_file(path, make_thin_macho());

    auto mapped = utility::map_view_of_macho(path.string());
    TEST_ASSERT(mapped.has_value());
    TEST_ASSERT(mapped->module != nullptr);
    TEST_ASSERT(mapped->is_virtual_alloc);

    auto size = utility::get_module_size(mapped->module);
    TEST_ASSERT(size.has_value());
    TEST_ASSERT(*size == 0x2000);

    auto within_text = utility::get_module_within(reinterpret_cast<uintptr_t>(mapped->module) + 4);
    TEST_ASSERT(within_text.has_value());
    TEST_ASSERT(*within_text == mapped->module);

    const auto* bytes = reinterpret_cast<const uint8_t*>(mapped->module);
    TEST_ASSERT(bytes[0] == 0xC3);
    TEST_ASSERT(bytes[4] == 'T');
    TEST_ASSERT(bytes[0x1000] == 'D');
    return 0;
}


int test_map_view_of_file_auto_detects_macho() {
    const auto path = temp_path("thin_auto.macho");
    write_file(path, make_thin_macho());

    auto mapped = utility::map_view_of_file(path.string());
    TEST_ASSERT(mapped.has_value());
    TEST_ASSERT(mapped->module != nullptr);
    TEST_ASSERT(mapped->is_virtual_alloc);
    TEST_ASSERT(utility::get_module_size(mapped->module).value_or(0) == 0x2000);
    return 0;
}

int test_map_view_of_macho_fat_extracts_x64_slice() {
    const auto path = temp_path("fat_valid.macho");
    write_file(path, make_fat_macho_with_x64());

    auto mapped = utility::map_view_of_macho(path.string());
    TEST_ASSERT(mapped.has_value());
    TEST_ASSERT(mapped->module != nullptr);
    const auto* bytes = reinterpret_cast<const uint8_t*>(mapped->module);
    TEST_ASSERT(bytes[0] == 0xC3);
    TEST_ASSERT(bytes[0x1000] == 'D');
    return 0;
}

int test_map_view_of_macho_nonexistent_returns_nullopt() {
    const auto path = temp_path("does_not_exist.macho");
    std::error_code ec{};
    std::filesystem::remove(path, ec);
    auto mapped = utility::map_view_of_macho(path.string());
    TEST_ASSERT(!mapped.has_value());
    return 0;
}

int test_map_view_of_macho_too_small_returns_nullopt() {
    const auto path = temp_path("too_small.macho");
    write_file(path, { 1, 2, 3 });
    TEST_ASSERT(!utility::map_view_of_macho(path.string()).has_value());
    return 0;
}

int test_map_view_of_macho_invalid_magic_returns_nullopt() {
    const auto path = temp_path("bad_magic.macho");
    auto bytes = make_thin_macho();
    *reinterpret_cast<uint32_t*>(bytes.data()) = 0x12345678;
    write_file(path, bytes);
    TEST_ASSERT(!utility::map_view_of_macho(path.string()).has_value());
    return 0;
}

int test_map_view_of_macho_wrong_cpu_returns_nullopt() {
    const auto path = temp_path("wrong_cpu.macho");
    write_file(path, make_thin_macho(MACHO_CPU_TYPE_ARM64));
    TEST_ASSERT(!utility::map_view_of_macho(path.string()).has_value());
    return 0;
}

int test_map_view_of_macho_no_segments_returns_nullopt() {
    const auto path = temp_path("no_segments.macho");
    write_file(path, make_thin_macho(MACHO_CPU_TYPE_X86_64, false));
    TEST_ASSERT(!utility::map_view_of_macho(path.string()).has_value());
    return 0;
}

int test_map_view_of_macho_malformed_command_returns_nullopt() {
    const auto path = temp_path("bad_command.macho");
    write_file(path, make_thin_macho(MACHO_CPU_TYPE_X86_64, false, false, true));
    TEST_ASSERT(!utility::map_view_of_macho(path.string()).has_value());
    return 0;
}

int test_map_view_of_macho_invalid_extent_returns_nullopt() {
    const auto path = temp_path("bad_extent.macho");
    write_file(path, make_thin_macho(MACHO_CPU_TYPE_X86_64, true, true));
    TEST_ASSERT(!utility::map_view_of_macho(path.string()).has_value());
    return 0;
}

int test_map_view_of_macho_fat_without_x64_returns_nullopt() {
    const auto path = temp_path("fat_no_x64.macho");
    write_file(path, make_fat_macho_without_x64());
    TEST_ASSERT(!utility::map_view_of_macho(path.string()).has_value());
    return 0;
}

int test_map_view_of_macho_fat_header_extends_past_file_returns_nullopt() {
    const auto path = temp_path("fat_header_oob.macho");
    write_file(path, make_truncated_fat_header());
    TEST_ASSERT(!utility::map_view_of_macho(path.string()).has_value());
    return 0;
}

int test_map_view_of_macho_fat_slice_past_eof_returns_nullopt() {
    const auto path = temp_path("fat_slice_oob.macho");
    auto bytes = make_fat_macho_without_x64();
    auto* arch = reinterpret_cast<macho_fat_arch*>(bytes.data() + sizeof(macho_fat_header));
    arch->cputype = be32(MACHO_CPU_TYPE_X86_64);
    arch->offset = be32(0x1000);
    arch->size = be32(0x1000);
    write_file(path, bytes);
    TEST_ASSERT(!utility::map_view_of_macho(path.string()).has_value());
    return 0;
}

int test_unlink_null_edges_are_safe() {
    TEST_ASSERT(utility::unlink(nullptr) == nullptr);
    TEST_ASSERT(utility::safe_unlink(nullptr) == nullptr);
    return 0;
}

int test_load_module_from_current_directory_missing_returns_nullptr() {
    const auto mod = utility::load_module_from_current_directory(L"kananlib_missing_module_zzzz.dll");
    TEST_ASSERT(mod == nullptr);
    return 0;
}

int main() try {
    RUN_TEST(test_map_view_of_macho_thin_maps_segments);
    RUN_TEST(test_map_view_of_file_auto_detects_macho);
    RUN_TEST(test_map_view_of_macho_fat_extracts_x64_slice);
    RUN_TEST(test_map_view_of_macho_nonexistent_returns_nullopt);
    RUN_TEST(test_map_view_of_macho_too_small_returns_nullopt);
    RUN_TEST(test_map_view_of_macho_invalid_magic_returns_nullopt);
    RUN_TEST(test_map_view_of_macho_wrong_cpu_returns_nullopt);
    RUN_TEST(test_map_view_of_macho_no_segments_returns_nullopt);
    RUN_TEST(test_map_view_of_macho_malformed_command_returns_nullopt);
    RUN_TEST(test_map_view_of_macho_invalid_extent_returns_nullopt);
    RUN_TEST(test_map_view_of_macho_fat_without_x64_returns_nullopt);
    RUN_TEST(test_map_view_of_macho_fat_header_extends_past_file_returns_nullopt);
    RUN_TEST(test_map_view_of_macho_fat_slice_past_eof_returns_nullopt);
    RUN_TEST(test_unlink_null_edges_are_safe);
    RUN_TEST(test_load_module_from_current_directory_missing_returns_nullptr);
    return test_summary();
} catch (const std::exception& e) {
    std::printf("\n[FATAL] std::exception: %s\n", e.what());
    return 1;
} catch (...) {
    std::printf("\n[FATAL] Unknown exception\n");
    return 1;
}
