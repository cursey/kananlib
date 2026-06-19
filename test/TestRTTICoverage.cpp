// ============================================================================
// RTTI.cpp coverage tests — exercises public API NOT covered by existing
// TestPDBRTTI.cpp, TestBehavior.cpp, or Main.cpp (test_rtti).
//
// Focus: find_vtable (exact), find_vtables (plural), find_vtables_derived_from,
//        get_type_info(HMODULE, name), derives_from(obj, type_info*),
//        find_object_inline, find_objects_ptr,
//        multi-level hierarchy (Base -> Mid -> Derived),
//        and negative / edge-case paths.
// ============================================================================

#include <cstdint>
#include <string>
#include <iostream>
#include <typeinfo>
#include <algorithm>

#include <windows.h>

#include <utility/RTTI.hpp>
#include <utility/Module.hpp>

#include "TestHelpers.hpp"

// ============================================================================
// Three-level polymorphic hierarchy — MSVC emits real RTTI for these.
// ============================================================================

class RTTICoverBase {
public:
    __declspec(noinline) virtual int whoami() volatile { return 1; }
    virtual ~RTTICoverBase() = default;
};

class RTTICoverMid : public RTTICoverBase {
public:
    __declspec(noinline) int whoami() volatile override { return 2; }
    virtual ~RTTICoverMid() = default;
};

class RTTICoverDerived : public RTTICoverMid {
public:
    __declspec(noinline) int whoami() volatile override { return 3; }
};

// Global instances — live in the module's data section with real vtables.
static RTTICoverBase     g_base;
static RTTICoverMid      g_mid;
static RTTICoverDerived  g_derived;

// Level-1 pointer variables for find_objects_ptr (scans for Obj**).
static RTTICoverBase*    g_base_ptr    = &g_base;
static RTTICoverDerived* g_derived_ptr = &g_derived;

// Prevent devirtualization in Release.
static RTTICoverBase* volatile_base()     { RTTICoverBase* volatile p = &g_base;    return p; }
static RTTICoverBase* volatile_mid()      { RTTICoverBase* volatile p = &g_mid;     return p; }
static RTTICoverBase* volatile_derived()  { RTTICoverBase* volatile p = &g_derived; return p; }

// Completely unrelated class — used for negative derives_from checks.
class RTTICoverUnrelated {
public:
    virtual ~RTTICoverUnrelated() = default;
};
static RTTICoverUnrelated g_unrelated;
static RTTICoverUnrelated* volatile_unrelated() { RTTICoverUnrelated* volatile p = &g_unrelated; return p; }

// ============================================================================
// Helpers
// ============================================================================

static HMODULE get_exe() {
    return utility::get_executable();
}

// ============================================================================
// 1. Multi-level derives_from (string overload)
//    Exercises the full base-class-array walk in derives_from(obj, string_view).
// ============================================================================
int test_derives_from_string_multilevel() {
    auto* b = volatile_base();
    auto* m = volatile_mid();
    auto* d = volatile_derived();

    // Base derives from itself
    TEST_ASSERT(utility::rtti::derives_from(b, "class RTTICoverBase"));
    // Mid derives from Base
    TEST_ASSERT(utility::rtti::derives_from(m, "class RTTICoverBase"));
    // Mid derives from itself
    TEST_ASSERT(utility::rtti::derives_from(m, "class RTTICoverMid"));
    // Derived derives from Base (transitive, exercises the full hierarchy walk)
    TEST_ASSERT(utility::rtti::derives_from(d, "class RTTICoverBase"));
    // Derived derives from Mid
    TEST_ASSERT(utility::rtti::derives_from(d, "class RTTICoverMid"));
    // Derived derives from itself
    TEST_ASSERT(utility::rtti::derives_from(d, "class RTTICoverDerived"));

    // Negative: Base does NOT derive from Mid or Derived
    TEST_ASSERT(!utility::rtti::derives_from(b, "class RTTICoverMid"));
    TEST_ASSERT(!utility::rtti::derives_from(b, "class RTTICoverDerived"));

    // Negative: Mid does NOT derive from Derived
    TEST_ASSERT(!utility::rtti::derives_from(m, "class RTTICoverDerived"));

    return 0;
}

// ============================================================================
// 2. derives_from with completely unrelated type name
// ============================================================================
int test_derives_from_string_negative_nonexistent() {
    auto* d = volatile_derived();
    TEST_ASSERT(!utility::rtti::derives_from(d, "class DoesNotExistXYZ999"));
    return 0;
}

// ============================================================================
// 3. derives_from(obj, type_info*) overload
//    Uses the same multi-level hierarchy.
// ============================================================================
int test_derives_from_typeinfo() {
    auto* b = volatile_base();
    auto* m = volatile_mid();
    auto* d = volatile_derived();

    // Resolve type_info* for each class via the object itself
    const auto* ti_base = utility::rtti::get_type_info(b);
    const auto* ti_mid  = utility::rtti::get_type_info(m);
    const auto* ti_der  = utility::rtti::get_type_info(d);

    TEST_ASSERT(ti_base != nullptr);
    TEST_ASSERT(ti_mid  != nullptr);
    TEST_ASSERT(ti_der  != nullptr);

    // They should be distinct type_info objects
    TEST_ASSERT(ti_base != ti_mid);
    TEST_ASSERT(ti_mid  != ti_der);

    // derives_from with type_info*
    // Base -> Base
    TEST_ASSERT(utility::rtti::derives_from(b, const_cast<std::type_info*>(ti_base)));
    // Mid -> Mid, Mid -> Base
    TEST_ASSERT(utility::rtti::derives_from(m, const_cast<std::type_info*>(ti_mid)));
    TEST_ASSERT(utility::rtti::derives_from(m, const_cast<std::type_info*>(ti_base)));
    // Derived -> all three
    TEST_ASSERT(utility::rtti::derives_from(d, const_cast<std::type_info*>(ti_der)));
    TEST_ASSERT(utility::rtti::derives_from(d, const_cast<std::type_info*>(ti_mid)));
    TEST_ASSERT(utility::rtti::derives_from(d, const_cast<std::type_info*>(ti_base)));

    // Negative: Base does NOT derive from Mid or Derived type_info
    TEST_ASSERT(!utility::rtti::derives_from(b, const_cast<std::type_info*>(ti_mid)));
    TEST_ASSERT(!utility::rtti::derives_from(b, const_cast<std::type_info*>(ti_der)));

    // Negative: null obj
    TEST_ASSERT(!utility::rtti::derives_from(nullptr, const_cast<std::type_info*>(ti_base)));

    return 0;
}

// ============================================================================
// 4. get_type_info(HMODULE, string_view) overload
//    Resolves type_info from a module handle + class name.
// ============================================================================
int test_get_type_info_module() {
    const auto exe = get_exe();

    auto* ti = utility::rtti::get_type_info(exe, "class RTTICoverBase");
    TEST_ASSERT(ti != nullptr);

    const std::string name = ti->name();
    TEST_ASSERT(name.find("RTTICoverBase") != std::string::npos);

    // Negative: nonexistent type
    auto* ti_none = utility::rtti::get_type_info(exe, "class NonexistentXYZ999");
    TEST_ASSERT(ti_none == nullptr);

    return 0;
}

// ============================================================================
// 5. get_locator on each level of the hierarchy
// ============================================================================
int test_get_locator_multilevel() {
    auto* b = volatile_base();
    auto* m = volatile_mid();
    auto* d = volatile_derived();

    auto* loc_b = utility::rtti::get_locator(b);
    auto* loc_m = utility::rtti::get_locator(m);
    auto* loc_d = utility::rtti::get_locator(d);

    TEST_ASSERT(loc_b != nullptr);
    TEST_ASSERT(loc_m != nullptr);
    TEST_ASSERT(loc_d != nullptr);

    // Each locator is a distinct object (different vtable addresses)
    TEST_ASSERT(loc_b != loc_m);
    TEST_ASSERT(loc_m != loc_d);

    return 0;
}

// ============================================================================
// 6. get_type_info(obj) — verify name for each hierarchy level
// ============================================================================
int test_get_type_info_multilevel() {
    auto* b = volatile_base();
    auto* m = volatile_mid();
    auto* d = volatile_derived();

    const auto* ti_b = utility::rtti::get_type_info(b);
    const auto* ti_m = utility::rtti::get_type_info(m);
    const auto* ti_d = utility::rtti::get_type_info(d);

    TEST_ASSERT(ti_b != nullptr);
    TEST_ASSERT(ti_m != nullptr);
    TEST_ASSERT(ti_d != nullptr);

    const std::string name_b = ti_b->name();
    const std::string name_m = ti_m->name();
    const std::string name_d = ti_d->name();

    TEST_ASSERT(name_b.find("RTTICoverBase")    != std::string::npos);
    TEST_ASSERT(name_m.find("RTTICoverMid")     != std::string::npos);
    TEST_ASSERT(name_d.find("RTTICoverDerived") != std::string::npos);

    return 0;
}

// ============================================================================
// 7. get_type_info(obj) — negative: null object
// ============================================================================
int test_get_type_info_negative() {
    TEST_ASSERT(utility::rtti::get_type_info(nullptr) == nullptr);
    return 0;
}

// ============================================================================
// 8. find_vtable — exact match by full friendly name
// ============================================================================
int test_find_vtable_exact() {
    const auto exe = get_exe();

    const auto vt = utility::rtti::find_vtable(exe, "class RTTICoverBase");
    TEST_ASSERT(vt.has_value());

    // The vtable address should match the vptr of our global object
    const auto expected_vptr = *(uintptr_t*)&g_base;
    TEST_ASSERT(*vt == expected_vptr);

    // Negative: nonexistent class
    const auto vt_none = utility::rtti::find_vtable(exe, "class NonexistentXYZ999");
    TEST_ASSERT(!vt_none.has_value());

    return 0;
}

// ============================================================================
// 9. find_vtables — may return duplicates; at least one entry per class
// ============================================================================
int test_find_vtables() {
    const auto exe = get_exe();

    const auto vts = utility::rtti::find_vtables(exe, "class RTTICoverDerived");
    TEST_ASSERT(!vts.empty());

    // At least one entry should match our global's vptr
    const auto expected_vptr = *(uintptr_t*)&g_derived;
    bool found = false;
    for (auto vt : vts) {
        if (vt == expected_vptr) { found = true; break; }
    }
    TEST_ASSERT(found);

    // Negative: nonexistent class -> empty vector
    const auto vts_none = utility::rtti::find_vtables(exe, "class NonexistentXYZ999");
    TEST_ASSERT(vts_none.empty());

    return 0;
}

// ============================================================================
// 10. find_vtables_derived_from — finds vtables of all classes deriving from a base
// ============================================================================
int test_find_vtables_derived_from() {
    const auto exe = get_exe();

    // All classes deriving from RTTICoverBase should include Mid and Derived too
    const auto derived_vts = utility::rtti::find_vtables_derived_from(exe, "class RTTICoverBase");
    TEST_ASSERT(!derived_vts.empty());

    const auto vptr_base = *(uintptr_t*)&g_base;
    const auto vptr_mid  = *(uintptr_t*)&g_mid;
    const auto vptr_der  = *(uintptr_t*)&g_derived;

    bool found_base = false, found_mid = false, found_der = false;
    for (auto* vp : derived_vts) {
        auto addr = (uintptr_t)vp;
        if (addr == vptr_base) found_base = true;
        if (addr == vptr_mid)  found_mid  = true;
        if (addr == vptr_der)  found_der  = true;
    }

    // Base itself counts as "derived from" itself
    TEST_ASSERT(found_base);
    // Mid and Derived also derive from Base
    TEST_ASSERT(found_mid);
    TEST_ASSERT(found_der);

    return 0;
}

// ============================================================================
// 11. find_vtables_derived_from — negative: base not found
// ============================================================================
int test_find_vtables_derived_from_nonexistent() {
    const auto exe = get_exe();

    const auto result = utility::rtti::find_vtables_derived_from(exe, "class DoesNotExistXYZ999");
    TEST_ASSERT(result.empty());

    return 0;
}

// ============================================================================
// 12. find_object_inline — level-0 object search by vtable scan
// ============================================================================
int test_find_object_inline() {
    const auto exe = get_exe();

    const auto obj = utility::rtti::find_object_inline(exe, "class RTTICoverBase");
    TEST_ASSERT(obj.has_value());

    // The found address should be our global (or at least point to the same vtable)
    const auto expected_vptr = *(uintptr_t*)&g_base;
    const auto found_vptr = *(uintptr_t*)*obj;
    TEST_ASSERT(found_vptr == expected_vptr);

    // Negative: nonexistent type
    const auto obj_none = utility::rtti::find_object_inline(exe, "class NonexistentXYZ999");
    TEST_ASSERT(!obj_none.has_value());

    return 0;
}

// ============================================================================
// 13. find_objects_ptr — find all pointers to objects of a given type
// ============================================================================
int test_find_objects_ptr() {
    const auto exe = get_exe();

    // find_objects_ptr scans for level-1 pointers (Obj**) in the module.
    // We have g_base_ptr and g_derived_ptr as global pointers to our objects.
    const auto objs = utility::rtti::find_objects_ptr(exe, "class RTTICoverBase");

    // At least g_base_ptr should be found (it's a RTTICoverBase* in .data)
    bool found_base_ptr = false;
    for (auto* p : objs) {
        if (p == (uintptr_t*)&g_base_ptr) {
            found_base_ptr = true;
        }
    }
    TEST_ASSERT(found_base_ptr);

    // Negative: nonexistent class -> empty
    const auto objs_none = utility::rtti::find_objects_ptr(exe, "class NonexistentXYZ999");
    TEST_ASSERT(objs_none.empty());

    return 0;
}

// ============================================================================
// 14. is_vtable on our hierarchy vtables
// ============================================================================
int test_is_vtable_our_classes() {
    const auto exe = get_exe();

    const auto vt_base = utility::rtti::find_vtable(exe, "class RTTICoverBase");
    const auto vt_mid  = utility::rtti::find_vtable(exe, "class RTTICoverMid");
    const auto vt_der  = utility::rtti::find_vtable(exe, "class RTTICoverDerived");

    if (vt_base) TEST_ASSERT(utility::rtti::is_vtable((void*)*vt_base));
    if (vt_mid)  TEST_ASSERT(utility::rtti::is_vtable((void*)*vt_mid));
    if (vt_der)  TEST_ASSERT(utility::rtti::is_vtable((void*)*vt_der));

    // Negative: null
    TEST_ASSERT(!utility::rtti::is_vtable(nullptr));

    // Negative: stack address (not a vtable)
    int dummy = 42;
    TEST_ASSERT(!utility::rtti::is_vtable((void*)&dummy));

    return 0;
}

// ============================================================================
// 15. derives_from on unrelated class — should return false for any of ours
// ============================================================================
int test_derives_from_unrelated_class() {
    auto* u = volatile_unrelated();

    // Unrelated does not derive from any of our hierarchy
    TEST_ASSERT(!utility::rtti::derives_from(u, "class RTTICoverBase"));
    TEST_ASSERT(!utility::rtti::derives_from(u, "class RTTICoverMid"));
    TEST_ASSERT(!utility::rtti::derives_from(u, "class RTTICoverDerived"));

    return 0;
}

// ============================================================================
// 16. get_locator negative — null object
// ============================================================================
int test_get_locator_negative() {
    TEST_ASSERT(utility::rtti::get_locator(nullptr) == nullptr);
    return 0;
}

// ============================================================================
// 17. find_vtable_partial on our hierarchy — verifies substring matching
// ============================================================================
int test_find_vtable_partial_hierarchy() {
    const auto exe = get_exe();

    // Substring "RTTICover" should match all three (just take the first)
    const auto result = utility::rtti::find_vtable_partial(exe, "RTTICoverDerived");
    TEST_ASSERT(result.has_value());

    const auto expected_vptr = *(uintptr_t*)&g_derived;
    TEST_ASSERT(*result == expected_vptr);

    return 0;
}

// ============================================================================
// 18. find_vtable_regex on our hierarchy
// ============================================================================
int test_find_vtable_regex_hierarchy() {
    const auto exe = get_exe();

    const auto result = utility::rtti::find_vtable_regex(exe, ".*RTTICoverMid.*");
    TEST_ASSERT(result.has_value());

    const auto expected_vptr = *(uintptr_t*)&g_mid;
    TEST_ASSERT(*result == expected_vptr);

    return 0;
}

// ============================================================================
// main
// ============================================================================

int main() try {
    std::cout << "===== kananlib-rtti-coverage-test =====" << std::endl;

    // Drive the virtual functions so the compiler keeps the RTTI + vtables
    volatile_base()->whoami();
    volatile_mid()->whoami();
    volatile_derived()->whoami();

    // derives_from tests
    RUN_TEST(test_derives_from_string_multilevel);
    RUN_TEST(test_derives_from_string_negative_nonexistent);
    RUN_TEST(test_derives_from_typeinfo);
    RUN_TEST(test_derives_from_unrelated_class);

    // get_type_info tests
    RUN_TEST(test_get_type_info_module);
    RUN_TEST(test_get_type_info_multilevel);
    RUN_TEST(test_get_type_info_negative);

    // get_locator tests
    RUN_TEST(test_get_locator_multilevel);
    RUN_TEST(test_get_locator_negative);

    // find_vtable / find_vtables / find_vtables_derived_from
    RUN_TEST(test_find_vtable_exact);
    RUN_TEST(test_find_vtables);
    RUN_TEST(test_find_vtables_derived_from);
    RUN_TEST(test_find_vtables_derived_from_nonexistent);
    RUN_TEST(test_find_vtable_partial_hierarchy);
    RUN_TEST(test_find_vtable_regex_hierarchy);

    // Object search
    RUN_TEST(test_find_object_inline);
    RUN_TEST(test_find_objects_ptr);

    // is_vtable
    RUN_TEST(test_is_vtable_our_classes);

    return test_summary();
} catch (const std::exception& e) {
    std::cout << "Exception caught: " << e.what() << std::endl;
    return 1;
} catch (...) {
    std::cout << "Unknown exception caught" << std::endl;
    return 1;
}
