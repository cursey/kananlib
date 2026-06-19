#include <utility/PDB.hpp>

#include "TestHelpers.hpp"

#include <windows.h>

#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <vector>

namespace {
    std::vector<std::unique_ptr<std::vector<uint8_t>>> g_modules;

    std::filesystem::path temp_dir() {
        auto dir = std::filesystem::temp_directory_path() / "kananlib_pdb_edge_tests";
        std::filesystem::create_directories(dir);
        return dir;
    }

    void write_file(const std::filesystem::path& path, const std::string& contents = "") {
        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        out.write(contents.data(), static_cast<std::streamsize>(contents.size()));
    }

    template <typename T>
    void write_struct(std::vector<uint8_t>& bytes, size_t offset, const T& value) {
        if (bytes.size() < offset + sizeof(T)) {
            bytes.resize(offset + sizeof(T));
        }
        std::memcpy(bytes.data() + offset, &value, sizeof(T));
    }

    const uint8_t* keep_module(std::vector<uint8_t> bytes) {
        g_modules.emplace_back(std::make_unique<std::vector<uint8_t>>(std::move(bytes)));
        return g_modules.back()->data();
    }

    std::vector<uint8_t> make_pe_with_debug(const std::string& pdb_name,
                                            bool has_debug = true,
                                            bool codeview = true,
                                            uint32_t signature = 0x53445352) {
        constexpr size_t nt_offset = 0x80;
        constexpr uint32_t section_rva = 0x1000;
        constexpr uint32_t section_raw = 0x200;
        constexpr uint32_t debug_rva = 0x1000;
        constexpr uint32_t debug_raw = section_raw;
        constexpr uint32_t codeview_rva = 0x1040;
        constexpr uint32_t codeview_raw = section_raw + 0x40;

        const size_t codeview_size = 24 + pdb_name.size() + 1;
        std::vector<uint8_t> bytes(codeview_raw + codeview_size + 0x40, 0);

        IMAGE_DOS_HEADER dos{};
        dos.e_magic = IMAGE_DOS_SIGNATURE;
        dos.e_lfanew = nt_offset;
        write_struct(bytes, 0, dos);

        IMAGE_NT_HEADERS64 nt{};
        nt.Signature = IMAGE_NT_SIGNATURE;
        nt.FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
        nt.FileHeader.NumberOfSections = 1;
        nt.FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
        nt.OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
        nt.OptionalHeader.SizeOfImage = 0x2000;
        if (has_debug) {
            nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress = debug_rva;
            nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size = sizeof(IMAGE_DEBUG_DIRECTORY);
        }
        write_struct(bytes, nt_offset, nt);

        IMAGE_SECTION_HEADER sec{};
        std::memcpy(sec.Name, ".rdata", 6);
        sec.Misc.VirtualSize = 0x1000;
        sec.VirtualAddress = section_rva;
        sec.SizeOfRawData = 0x400;
        sec.PointerToRawData = section_raw;
        write_struct(bytes, nt_offset + offsetof(IMAGE_NT_HEADERS64, OptionalHeader) + sizeof(IMAGE_OPTIONAL_HEADER64), sec);

        if (has_debug) {
            IMAGE_DEBUG_DIRECTORY debug{};
            debug.Type = codeview ? IMAGE_DEBUG_TYPE_CODEVIEW : IMAGE_DEBUG_TYPE_MISC;
            debug.SizeOfData = static_cast<DWORD>(codeview_size);
            debug.AddressOfRawData = codeview_rva; // get_pdb_path runs this through ptr_from_rva
            debug.PointerToRawData = codeview_raw;
            write_struct(bytes, debug_raw, debug);

            std::memcpy(bytes.data() + codeview_raw, &signature, sizeof(signature));
            GUID guid{0x11223344, 0x5566, 0x7788, {0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97}};
            write_struct(bytes, codeview_raw + 4, guid);
            uint32_t age = 1;
            write_struct(bytes, codeview_raw + 20, age);
            std::memcpy(bytes.data() + codeview_raw + 24, pdb_name.c_str(), pdb_name.size() + 1);
        }

        return bytes;
    }
}

int test_get_pdb_path_null_and_bad_headers() {
    TEST_ASSERT(!utility::pdb::get_pdb_path(nullptr).has_value());

    auto bad_dos = make_pe_with_debug("bad.pdb");
    reinterpret_cast<IMAGE_DOS_HEADER*>(bad_dos.data())->e_magic = 0;
    TEST_ASSERT(!utility::pdb::get_pdb_path(keep_module(std::move(bad_dos))).has_value());

    auto bad_nt = make_pe_with_debug("badnt.pdb");
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(bad_nt.data());
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(bad_nt.data() + dos->e_lfanew);
    nt->Signature = 0;
    TEST_ASSERT(!utility::pdb::get_pdb_path(keep_module(std::move(bad_nt))).has_value());
    return 0;
}

int test_get_pdb_path_no_debug_and_non_codeview() {
    TEST_ASSERT(!utility::pdb::get_pdb_path(keep_module(make_pe_with_debug("nodebug.pdb", false))).has_value());
    TEST_ASSERT(!utility::pdb::get_pdb_path(keep_module(make_pe_with_debug("misc.pdb", true, false))).has_value());
    return 0;
}

int test_get_pdb_path_invalid_codeview_signature() {
    const auto* module = keep_module(make_pe_with_debug("invalidsig.pdb", true, true, 0x12345678));
    TEST_ASSERT(!utility::pdb::get_pdb_path(module).has_value());
    return 0;
}

int test_get_pdb_path_absolute_existing_pdb_and_cache() {
    const auto pdb = temp_dir() / "absolute_existing.pdb";
    write_file(pdb, "pdb");
    const auto* module = keep_module(make_pe_with_debug(pdb.string()));

    auto first = utility::pdb::get_pdb_path(module);
    TEST_ASSERT(first.has_value());
    TEST_ASSERT(std::filesystem::equivalent(*first, pdb));

    auto second = utility::pdb::get_pdb_path(module);
    TEST_ASSERT(second.has_value());
    TEST_ASSERT(*second == *first);
    return 0;
}

int test_get_pdb_path_local_base_next_to_module() {
    const auto dir = temp_dir() / "local_base";
    std::filesystem::create_directories(dir);
    const auto module_path = dir / "fake_module.dll";
    const auto pdb_path = dir / "local_base_name.pdb";
    write_file(module_path, "not a real dll");
    write_file(pdb_path, "pdb");

    const auto* module = keep_module(make_pe_with_debug("local_base_name.pdb"));
    auto resolved = utility::pdb::get_pdb_path(module, module_path.string());
    TEST_ASSERT(resolved.has_value());
    TEST_ASSERT(std::filesystem::equivalent(*resolved, pdb_path));
    return 0;
}

int test_generate_c_struct_formats_all_member_kinds() {
    utility::pdb::StructInfo info{};
    info.name = "EDGE_STRUCT";
    info.size = 0x30;
    info.members.push_back({"plain", "uint32_t", 0x00, 4});

    utility::pdb::StructMember ptr{};
    ptr.name = "ptr";
    ptr.type = "void";
    ptr.offset = 0x08;
    ptr.size = 8;
    ptr.is_pointer = true;
    info.members.push_back(ptr);

    utility::pdb::StructMember arr{};
    arr.name = "arr";
    arr.type = "char";
    arr.offset = 0x10;
    arr.size = 4;
    arr.is_array = true;
    arr.array_count = 4;
    info.members.push_back(arr);

    utility::pdb::StructMember unknown{};
    unknown.name = "unknown";
    unknown.offset = 0x18;
    unknown.size = 4;
    info.members.push_back(unknown);

    utility::pdb::StructMember bit{};
    bit.name = "flags";
    bit.offset = 0x20;
    bit.size = 4;
    bit.is_bitfield = true;
    bit.bit_position = 3;
    bit.bit_length = 5;
    info.members.push_back(bit);

    auto c = utility::pdb::generate_c_struct(info);
    TEST_ASSERT(c.find("typedef struct") != std::string::npos);
    TEST_ASSERT(c.find("uint32_t plain") != std::string::npos);
    TEST_ASSERT(c.find("void* ptr") != std::string::npos);
    TEST_ASSERT(c.find("char arr[4]") != std::string::npos);
    TEST_ASSERT(c.find("void unknown") != std::string::npos);
    TEST_ASSERT(c.find("unsigned __int32 flags : 5") != std::string::npos);
    TEST_ASSERT(c.find("_padding_0x4") != std::string::npos);
    TEST_ASSERT(c.find("_padding_final") != std::string::npos);
    TEST_ASSERT(c.find("EDGE_STRUCT") != std::string::npos);
    return 0;
}

int test_generate_c_struct_sorts_members_by_offset() {
    utility::pdb::StructInfo info{};
    info.name = "SORTED_STRUCT";
    info.size = 8;
    info.members.push_back({"second", "int", 4, 4});
    info.members.push_back({"first", "int", 0, 4});
    const auto c = utility::pdb::generate_c_struct(info);
    TEST_ASSERT(c.find("first") < c.find("second"));
    return 0;
}

int main() try {
    RUN_TEST(test_get_pdb_path_null_and_bad_headers);
    RUN_TEST(test_get_pdb_path_no_debug_and_non_codeview);
    RUN_TEST(test_get_pdb_path_invalid_codeview_signature);
    RUN_TEST(test_get_pdb_path_absolute_existing_pdb_and_cache);
    RUN_TEST(test_get_pdb_path_local_base_next_to_module);
    RUN_TEST(test_generate_c_struct_formats_all_member_kinds);
    RUN_TEST(test_generate_c_struct_sorts_members_by_offset);
    return test_summary();
} catch (const std::exception& e) {
    std::printf("\n[FATAL] std::exception: %s\n", e.what());
    return 1;
} catch (...) {
    std::printf("\n[FATAL] Unknown exception\n");
    return 1;
}
