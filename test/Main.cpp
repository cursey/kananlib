#include <cstdint>
#include <string>
#include <iostream>

#include <spdlog/spdlog.h>

#include <utility/Scan.hpp>
#include <utility/Module.hpp>
#include <utility/RTTI.hpp>

#define KANANLIB_ASSERT(x) if (!(x)) { std::cout << "Assertion failed: " << #x << std::endl; return 1; }

const char* HELLO_WORLD{"Hello World!"};

class RTTITest {
public:
    static inline const size_t FOO_IDENTIFIER = 0xF00BA7;
    static consteval const char* FOO_STRING() {
        return "size_t RTTITest::foo()";
    }

    RTTITest() {
        std::cout << "RTTITest::RTTITest()" << std::endl;
    }
    virtual ~RTTITest() = default;

    __declspec(noinline) virtual size_t foo() try {
        printf("%s\n", FOO_STRING());
        return FOO_IDENTIFIER;
    } catch(const std::exception& e) {
        std::cout << "RTTITest::foo() threw exception: " << e.what() << std::endl;
        return 0;
    } catch(...) {
        std::cout << "RTTITest::foo() threw unknown exception" << std::endl;
        return 0;
    }

private:    
};

RTTITest* g_rtti_test{new RTTITest()};

int main() {
    std::cout << HELLO_WORLD << std::endl;
    const auto hello_world_scan = utility::scan_string(utility::get_executable(), HELLO_WORLD);

    KANANLIB_ASSERT(hello_world_scan.has_value());
    KANANLIB_ASSERT(*hello_world_scan == (uintptr_t)&HELLO_WORLD[0]);

    const auto rtti_test_scan = utility::rtti::find_vtable(utility::get_executable(), "class RTTITest");

    KANANLIB_ASSERT(rtti_test_scan.has_value());
    KANANLIB_ASSERT(*rtti_test_scan == *(uintptr_t*)g_rtti_test);

    const auto rtti_object = utility::rtti::find_object_ptr(utility::get_executable(), "class RTTITest");

    KANANLIB_ASSERT(rtti_object.has_value());
    KANANLIB_ASSERT((uintptr_t)*rtti_object == (uintptr_t)&g_rtti_test);
    KANANLIB_ASSERT(**rtti_object == (uintptr_t)g_rtti_test);

    const auto foo_function = utility::find_function_from_string_ref(utility::get_executable(), RTTITest::FOO_STRING());

    KANANLIB_ASSERT(foo_function.has_value());

    using foo_t = size_t(__thiscall*)(RTTITest*);
    foo_t foo = (foo_t)*foo_function;
    KANANLIB_ASSERT(foo(g_rtti_test) == g_rtti_test->foo());

    SPDLOG_INFO("All tests passed.");

    return 0;
}