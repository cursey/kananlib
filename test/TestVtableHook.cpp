#include <cstdint>
#include <iostream>

#include <windows.h>

#include <utility/Address.hpp>
#include <utility/VtableHook.hpp>

#include "TestHelpers.hpp"

// ============================================================================
// Test virtual class for VtableHook testing
// ============================================================================

class TestBase {
public:
    virtual int get_value() { return 42; }
    virtual int get_other() { return 99; }
    virtual ~TestBase() = default;
};

// Replacement functions that match the ABI of virtual member functions.
// On x64 MSVC, the calling convention is the same for free functions and
// member functions - this pointer is passed in rcx.
static int replacement_get_value(TestBase*) { return 100; }
static int replacement_get_other(TestBase*) { return 200; }

// Prevent devirtualization: MSVC in Release mode resolves virtual calls on
// known-type stack objects at compile time.  Passing through a volatile
// pointer forces the compiler to emit a real vtable lookup.
static TestBase* get_volatile_ptr(TestBase* p) {
    TestBase* volatile vp = p;
    return vp;
}

// ============================================================================
// VtableHook tests
// ============================================================================

int test_vtable_hook_create_and_remove() {
    TestBase obj;
    auto* p = get_volatile_ptr(&obj);
    TEST_ASSERT(p->get_value() == 42);

    {
        VtableHook hook{Address{&obj}};
        TEST_ASSERT((uintptr_t)hook.get_instance() != 0);

        // Virtual calls should still work because we copied the vtable.
        TEST_ASSERT(p->get_value() == 42);
        TEST_ASSERT(p->get_other() == 99);
    }

    // After hook is destroyed, virtual calls should still work.
    TEST_ASSERT(p->get_value() == 42);
    TEST_ASSERT(p->get_other() == 99);

    return 0;
}

int test_vtable_hook_hook_method() {
    TestBase obj;
    auto* p = get_volatile_ptr(&obj);
    TEST_ASSERT(p->get_value() == 42);

    VtableHook hook{Address{&obj}};

    // Hook method 0 (get_value) with our replacement.
    TEST_ASSERT(hook.hook_method(0, Address{(void*)replacement_get_value}));

    // Now calling get_value() should go through our replacement.
    TEST_ASSERT(p->get_value() == 100);

    // get_other() should still work (not hooked).
    TEST_ASSERT(p->get_other() == 99);

    // get_method(0) should return the ORIGINAL get_value, not the replacement.
    auto orig = hook.get_method(0);
    TEST_ASSERT((uintptr_t)orig != 0);
    TEST_ASSERT((uintptr_t)orig != (uintptr_t)replacement_get_value);

    return 0;
}

int test_vtable_hook_get_method_typed() {
    TestBase obj;
    VtableHook hook{Address{&obj}};

    // Hook method 0.
    TEST_ASSERT(hook.hook_method(0, Address{(void*)replacement_get_value}));

    // get_method<T>(0) should return the original function pointer.
    using FnType = int(*)(TestBase*);
    auto orig_fn = hook.get_method<FnType>(0);
    TEST_ASSERT(orig_fn != nullptr);
    TEST_ASSERT(orig_fn != replacement_get_value);

    // Verify the original function returns the expected value.
    TEST_ASSERT(orig_fn(&obj) == 42);

    return 0;
}

int test_vtable_hook_multiple_methods() {
    TestBase obj;
    auto* p = get_volatile_ptr(&obj);

    VtableHook hook{Address{&obj}};

    // Hook both methods.
    TEST_ASSERT(hook.hook_method(0, Address{(void*)replacement_get_value}));
    TEST_ASSERT(hook.hook_method(1, Address{(void*)replacement_get_other}));

    TEST_ASSERT(p->get_value() == 100);
    TEST_ASSERT(p->get_other() == 200);

    return 0;
}

int test_vtable_hook_remove_restore() {
    TestBase obj;
    auto* p = get_volatile_ptr(&obj);

    VtableHook hook{Address{&obj}};

    TEST_ASSERT(hook.hook_method(0, Address{(void*)replacement_get_value}));
    TEST_ASSERT(p->get_value() == 100);

    // Remove restores the original vtable.
    TEST_ASSERT(hook.remove());
    TEST_ASSERT(p->get_value() == 42);

    return 0;
}

int test_vtable_hook_recreate() {
    TestBase obj;
    auto* p = get_volatile_ptr(&obj);

    VtableHook hook{Address{&obj}};

    TEST_ASSERT(hook.hook_method(0, Address{(void*)replacement_get_value}));
    TEST_ASSERT(p->get_value() == 100);

    // Remove restores original.
    TEST_ASSERT(hook.remove());
    TEST_ASSERT(p->get_value() == 42);

    // Recreate re-applies the hook (the method hook in m_new_vtable persists).
    TEST_ASSERT(hook.recreate());
    TEST_ASSERT(p->get_value() == 100);

    // Remove again to clean up.
    TEST_ASSERT(hook.remove());
    TEST_ASSERT(p->get_value() == 42);

    return 0;
}

int test_vtable_hook_out_of_bounds() {
    TestBase obj;
    VtableHook hook{Address{&obj}};

    // Hooking an out-of-bounds index should fail.
    TEST_ASSERT(!hook.hook_method(999, Address{(void*)replacement_get_value}));

    // get_method for out-of-bounds should return a null Address.
    auto result = hook.get_method(999);
    TEST_ASSERT((uintptr_t)result == 0);

    return 0;
}

int test_vtable_hook_default_constructor() {
    // Default-constructed VtableHook should be empty.
    VtableHook hook;
    TEST_ASSERT((uintptr_t)hook.get_instance() == 0);
    TEST_ASSERT((uintptr_t)hook.get_method(0) == 0);

    return 0;
}

// ============================================================================
// main
// ============================================================================

int main() try {
    std::cout << "===== kananlib VtableHook test =====" << std::endl;

    // VtableHook.
    RUN_TEST(test_vtable_hook_create_and_remove);
    RUN_TEST(test_vtable_hook_hook_method);
    RUN_TEST(test_vtable_hook_get_method_typed);
    RUN_TEST(test_vtable_hook_multiple_methods);
    RUN_TEST(test_vtable_hook_remove_restore);
    RUN_TEST(test_vtable_hook_recreate);
    RUN_TEST(test_vtable_hook_out_of_bounds);
    RUN_TEST(test_vtable_hook_default_constructor);

    return test_summary();
} catch (const std::exception& e) {
    std::cout << "Exception: " << e.what() << std::endl;
    return 1;
} catch (...) {
    std::cout << "Unknown exception." << std::endl;
    return 1;
}
