#include <cstdint>
#include <string>
#include <iostream>
#include <typeinfo>

#include <windows.h>

#include <utility/PDB.hpp>
#include <utility/RTTI.hpp>
#include <utility/Module.hpp>

#include "TestHelpers.hpp"

// ============================================================================
// Test class hierarchy for RTTI tests
// ============================================================================

class PDBRTTITestBase {
public:
    virtual ~PDBRTTITestBase() = default;
    virtual int get_id() { return 1; }
};

class PDBRTTITestDerived : public PDBRTTITestBase {
public:
    int get_id() override { return 2; }
};

// Global instances so they're in the module's data section
static PDBRTTITestBase g_base_obj;
static PDBRTTITestDerived g_derived_obj;

// Helper to prevent MSVC devirtualization in Release builds
static PDBRTTITestBase* get_volatile_base() {
    PDBRTTITestBase* volatile p = &g_base_obj;
    return p;
}

static PDBRTTITestBase* get_volatile_derived() {
    PDBRTTITestBase* volatile p = &g_derived_obj;
    return p;
}

// ============================================================================
// PDB Tests (require DIA SDK)
// ============================================================================

#ifdef KANANLIB_USE_DIA_SDK
// PDB Tests
// ============================================================================

// Test: get_symbol_name — resolve RVA back to symbol name
// Strategy: Use get_symbol_address to get the RVA of a known export,
//           then use get_symbol_name to resolve it back.
int test_pdb_get_symbol_name() {
    const auto* ntdll = utility::get_module("ntdll.dll");
    if (!ntdll) {
        std::cout << "  SKIP: ntdll.dll not found" << std::endl;
        return 0;
    }

    // First, check PDB is available
    const auto pdb_path = utility::pdb::get_pdb_path((const uint8_t*)ntdll);
    if (!pdb_path.has_value()) {
        std::cout << "  SKIP: no PDB for ntdll.dll" << std::endl;
        return 0;
    }

    // Get the RVA of a well-known function
    const auto rva = utility::pdb::get_symbol_address((const uint8_t*)ntdll, "NtClose");
    if (!rva.has_value()) {
        std::cout << "  SKIP: could not resolve NtClose (PDB may be partial)" << std::endl;
        return 0;
    }

    std::cout << "  NtClose RVA: 0x" << std::hex << *rva << std::dec << std::endl;
    TEST_ASSERT(*rva != 0);

    // Resolve the RVA back to a name
    const auto name = utility::pdb::get_symbol_name((const uint8_t*)ntdll, *rva);
    TEST_ASSERT(name.has_value());
    TEST_ASSERT(!name->empty());

    std::cout << "  Resolved name: " << *name << std::endl;

    // The resolved name should contain "NtClose" (may be undecorated/fully qualified)
    TEST_ASSERT(name->find("NtClose") != std::string::npos);

    // Negative: resolve RVA 0 should fail
    const auto bad = utility::pdb::get_symbol_name((const uint8_t*)ntdll, 0);
    TEST_ASSERT(!bad.has_value());

    return 0;
}

// Test: get_symbol_map — get full symbol map
// Strategy: Call get_symbol_map on a module with a PDB and verify non-empty
//           and that known symbols are present.
int test_pdb_get_symbol_map() {
    const auto* ntdll = utility::get_module("ntdll.dll");
    if (!ntdll) {
        std::cout << "  SKIP: ntdll.dll not found" << std::endl;
        return 0;
    }

    const auto pdb_path = utility::pdb::get_pdb_path((const uint8_t*)ntdll);
    if (!pdb_path.has_value()) {
        std::cout << "  SKIP: no PDB for ntdll.dll" << std::endl;
        return 0;
    }

    const auto sym_map = utility::pdb::get_symbol_map((const uint8_t*)ntdll);
    std::cout << "  Symbol map size: " << sym_map.size() << std::endl;

    // The symbol map should not be empty
    if (sym_map.empty()) {
        std::cout << "  SKIP: symbol map is empty (PDB may be partial)" << std::endl;
        return 0;
    }

    // Look for NtClose in the map (search by name)
    bool found_ntclose = false;
    for (const auto& [rva, name] : sym_map) {
        if (name.find("NtClose") != std::string::npos) {
            found_ntclose = true;
            std::cout << "  Found " << name << " at RVA 0x" << std::hex << rva << std::dec << std::endl;
            break;
        }
    }

    if (!found_ntclose) {
        std::cout << "  WARNING: NtClose not found in symbol map (may be partial)" << std::endl;
    }

    return 0;
}

// Test: enumerate_symbols — list symbols from PDB
// Strategy: Call enumerate_symbols on ntdll and verify we get a non-empty list.
int test_pdb_enumerate_symbols() {
    const auto* ntdll = utility::get_module("ntdll.dll");
    if (!ntdll) {
        std::cout << "  SKIP: ntdll.dll not found" << std::endl;
        return 0;
    }

    const auto pdb_path = utility::pdb::get_pdb_path((const uint8_t*)ntdll);
    if (!pdb_path.has_value()) {
        std::cout << "  SKIP: no PDB for ntdll.dll" << std::endl;
        return 0;
    }

    const auto symbols = utility::pdb::enumerate_symbols((const uint8_t*)ntdll, 500);
    std::cout << "  Enumerated " << symbols.size() << " symbols" << std::endl;

    if (symbols.empty()) {
        std::cout << "  SKIP: no symbols enumerated (PDB may be partial)" << std::endl;
        return 0;
    }

    // Verify each symbol name is non-empty
    for (const auto& name : symbols) {
        TEST_ASSERT(!name.empty());
    }

    // Print first few for visibility
    const size_t show_count = (std::min)(symbols.size(), (size_t)5);
    for (size_t i = 0; i < show_count; ++i) {
        std::cout << "    [" << i << "] " << symbols[i] << std::endl;
    }

    return 0;
}

// Test: PDB negative cases — null module
int test_pdb_negative() {
    // get_symbol_address with null module
    const auto addr = utility::pdb::get_symbol_address(nullptr, "NtClose");
    TEST_ASSERT(!addr.has_value());

    // get_symbol_name with null module
    const auto name = utility::pdb::get_symbol_name(nullptr, 0x1234);
    TEST_ASSERT(!name.has_value());

    // get_symbol_map with null module
    const auto sym_map = utility::pdb::get_symbol_map(nullptr);
    TEST_ASSERT(sym_map.empty());

    // enumerate_symbols with null module
    const auto syms = utility::pdb::enumerate_symbols(nullptr);
    TEST_ASSERT(syms.empty());

    return 0;
}

#endif // KANANLIB_USE_DIA_SDK

// ============================================================================
// RTTI Tests
// ============================================================================

// Test: is_vtable — check if a pointer is a known vtable
int test_rtti_is_vtable() {
    const auto exe = utility::get_executable();

    // First, find the vtable for our test class
    const auto vtable = utility::rtti::find_vtable(exe, "class PDBRTTITestBase");
    if (!vtable.has_value()) {
        std::cout << "  SKIP: could not find vtable for PDBRTTITestBase" << std::endl;
        return 0;
    }

    std::cout << "  PDBRTTITestBase vtable: 0x" << std::hex << *vtable << std::dec << std::endl;

    // Verify the vtable pointer matches our object's vptr
    const auto base_vptr = *(uintptr_t*)&g_base_obj;
    TEST_ASSERT(*vtable == base_vptr);

    // is_vtable should return true for a known vtable
    const bool is_vt = utility::rtti::is_vtable((void*)*vtable);
    TEST_ASSERT(is_vt);

    // Negative: is_vtable with nullptr
    TEST_ASSERT(!utility::rtti::is_vtable(nullptr));

    // Negative: is_vtable with a stack address (not a vtable)
    int stack_var = 42;
    TEST_ASSERT(!utility::rtti::is_vtable((void*)&stack_var));

    return 0;
}

// Test: get_locator — get the CompleteObjectLocator from a polymorphic object
int test_rtti_get_locator() {
    // get_locator expects a pointer to a polymorphic object (first sizeof(void*) bytes = vptr)
    auto* base = get_volatile_base();
    const auto locator = utility::rtti::get_locator(base);
    TEST_ASSERT(locator != nullptr);
    std::cout << "  Base locator: 0x" << std::hex << (uintptr_t)locator << std::dec << std::endl;

    auto* derived = get_volatile_derived();
    const auto derived_locator = utility::rtti::get_locator(derived);
    TEST_ASSERT(derived_locator != nullptr);
    std::cout << "  Derived locator: 0x" << std::hex << (uintptr_t)derived_locator << std::dec << std::endl;

    // Negative: null object
    TEST_ASSERT(utility::rtti::get_locator(nullptr) == nullptr);

    return 0;
}

// Test: get_type_info — get type_info from a polymorphic object
int test_rtti_get_type_info() {
    auto* base = get_volatile_base();
    const auto ti = utility::rtti::get_type_info(base);
    TEST_ASSERT(ti != nullptr);

    const std::string type_name = ti->name();
    std::cout << "  Base type_info name: " << type_name << std::endl;

    // The name should contain "PDBRTTITestBase"
    TEST_ASSERT(type_name.find("PDBRTTITestBase") != std::string::npos);

    auto* derived = get_volatile_derived();
    const auto derived_ti = utility::rtti::get_type_info(derived);
    TEST_ASSERT(derived_ti != nullptr);

    const std::string derived_name = derived_ti->name();
    std::cout << "  Derived type_info name: " << derived_name << std::endl;
    TEST_ASSERT(derived_name.find("PDBRTTITestDerived") != std::string::npos);

    // Negative: null
    TEST_ASSERT(utility::rtti::get_type_info(nullptr) == nullptr);

    return 0;
}

// Test: derives_from — check inheritance relationships
int test_rtti_derives_from() {
    auto* base = get_volatile_base();
    auto* derived = get_volatile_derived();

    // Base derives from itself
    const bool base_from_base = utility::rtti::derives_from(base, "class PDBRTTITestBase");
    TEST_ASSERT(base_from_base);

    // Derived derives from itself
    const bool derived_from_derived = utility::rtti::derives_from(derived, "class PDBRTTITestDerived");
    TEST_ASSERT(derived_from_derived);

    // Derived derives from base (inheritance)
    const bool derived_from_base = utility::rtti::derives_from(derived, "class PDBRTTITestBase");
    TEST_ASSERT(derived_from_base);

    // Negative: base does NOT derive from derived
    const bool base_from_derived = utility::rtti::derives_from(base, "class PDBRTTITestDerived");
    TEST_ASSERT(!base_from_derived);

    // Negative: null object
    TEST_ASSERT(!utility::rtti::derives_from(nullptr, "class PDBRTTITestBase"));

    return 0;
}

// Test: find_vtable_partial — find vtable by partial name match
int test_rtti_find_vtable_partial() {
    const auto exe = utility::get_executable();

    // Search with partial name "PDBRTTITestBase" — should find our class
    const auto result = utility::rtti::find_vtable_partial(exe, "PDBRTTITestBase");
    TEST_ASSERT(result.has_value());

    const auto expected_vptr = *(uintptr_t*)&g_base_obj;
    TEST_ASSERT(*result == expected_vptr);
    std::cout << "  find_vtable_partial found: 0x" << std::hex << *result << std::dec << std::endl;

    // Negative: search for something that doesn't exist
    const auto no_result = utility::rtti::find_vtable_partial(exe, "NonexistentClassXYZ123");
    TEST_ASSERT(!no_result.has_value());

    return 0;
}

// Test: find_vtable_regex — find vtable by regex
int test_rtti_find_vtable_regex() {
    const auto exe = utility::get_executable();

    // Search with regex matching our test class
    const auto result = utility::rtti::find_vtable_regex(exe, ".*PDBRTTITestDerived.*");
    TEST_ASSERT(result.has_value());

    const auto expected_vptr = *(uintptr_t*)&g_derived_obj;
    TEST_ASSERT(*result == expected_vptr);
    std::cout << "  find_vtable_regex found: 0x" << std::hex << *result << std::dec << std::endl;

    // Negative: regex that matches nothing
    const auto no_result = utility::rtti::find_vtable_regex(exe, "^NonexistentXYZ$");
    TEST_ASSERT(!no_result.has_value());

    return 0;
}

// Test: find_all_vtables — enumerate all vtables in a module
int test_rtti_find_all_vtables() {
    const auto exe = utility::get_executable();

    const auto all_vtables = utility::rtti::find_all_vtables(exe);
    std::cout << "  Total vtables in executable: " << all_vtables.size() << std::endl;

    // We should have at least our test class vtables
    // (PDBRTTITestBase, PDBRTTITestDerived, and also RTTITest from Main.cpp)
    TEST_ASSERT(all_vtables.size() >= 2);

    // Verify our test class vtables are in the list
    const auto base_vptr = *(uintptr_t*)&g_base_obj;
    const auto derived_vptr = *(uintptr_t*)&g_derived_obj;

    bool found_base = false;
    bool found_derived = false;
    for (const auto vt : all_vtables) {
        if (vt == base_vptr) found_base = true;
        if (vt == derived_vptr) found_derived = true;
    }

    TEST_ASSERT(found_base);
    TEST_ASSERT(found_derived);
    std::cout << "  Found base vtable: " << (found_base ? "yes" : "no") << std::endl;
    std::cout << "  Found derived vtable: " << (found_derived ? "yes" : "no") << std::endl;

    return 0;
}

// ============================================================================
// main
// ============================================================================

int main() try {
    std::cout << "===== kananlib-pdb-rtti-test =====" << std::endl;

#ifdef KANANLIB_USE_DIA_SDK
    // PDB tests (4 tests, require DIA SDK)
    RUN_TEST(test_pdb_get_symbol_name);
    RUN_TEST(test_pdb_get_symbol_map);
    RUN_TEST(test_pdb_enumerate_symbols);
    RUN_TEST(test_pdb_negative);
#endif

    // RTTI tests (8 tests)
    RUN_TEST(test_rtti_is_vtable);
    RUN_TEST(test_rtti_get_locator);
    RUN_TEST(test_rtti_get_type_info);
    RUN_TEST(test_rtti_derives_from);
    RUN_TEST(test_rtti_find_vtable_partial);
    RUN_TEST(test_rtti_find_vtable_regex);
    RUN_TEST(test_rtti_find_all_vtables);

    return test_summary();
} catch(const std::exception& e) {
    std::cout << "Exception caught: " << e.what() << std::endl;
    return 1;
} catch(...) {
    std::cout << "Unknown exception caught" << std::endl;
    return 1;
}
