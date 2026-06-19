#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

#include <windows.h>

#include <utility/Pattern.hpp>
#include <utility/String.hpp>
#include <utility/Address.hpp>
#include <utility/Config.hpp>

#include "TestHelpers.hpp"

// ============================================================================
// Pattern tests
// ============================================================================

int test_build_pattern() {
    // Basic hex bytes.
    auto p1 = utility::buildPattern("90 90 CC");
    TEST_ASSERT(p1.size() == 3);
    TEST_ASSERT(p1[0] == 0x90);
    TEST_ASSERT(p1[1] == 0x90);
    TEST_ASSERT(p1[2] == 0xCC);

    // Wildcards.
    auto p2 = utility::buildPattern("AA ? BB ? CC");
    TEST_ASSERT(p2.size() == 5);
    TEST_ASSERT(p2[0] == 0xAA);
    TEST_ASSERT(p2[1] == -1);
    TEST_ASSERT(p2[2] == 0xBB);
    TEST_ASSERT(p2[3] == -1);
    TEST_ASSERT(p2[4] == 0xCC);

    // All wildcards.
    auto p3 = utility::buildPattern("? ? ?");
    TEST_ASSERT(p3.size() == 3);
    TEST_ASSERT(p3[0] == -1);
    TEST_ASSERT(p3[1] == -1);
    TEST_ASSERT(p3[2] == -1);

    // Case insensitive hex.
    auto p4 = utility::buildPattern("aA bB cC");
    TEST_ASSERT(p4.size() == 3);
    TEST_ASSERT(p4[0] == 0xAA);
    TEST_ASSERT(p4[1] == 0xBB);
    TEST_ASSERT(p4[2] == 0xCC);

    // Spaces should be ignored.
    auto p5 = utility::buildPattern("  90   CC  ");
    TEST_ASSERT(p5.size() == 2);
    TEST_ASSERT(p5[0] == 0x90);
    TEST_ASSERT(p5[1] == 0xCC);

    return 0;
}

int test_pattern_find_exact() {
    uint8_t data[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99};

    utility::Pattern pat("33 44 55");
    auto result = pat.find((uintptr_t)data, sizeof(data));
    TEST_ASSERT(result.has_value());
    TEST_ASSERT(*result == (uintptr_t)&data[3]);

    return 0;
}

int test_pattern_find_wildcard() {
    uint8_t data[] = {0xAA, 0x00, 0xBB, 0x00, 0xCC, 0xDD};

    // Match with wildcards in between.
    utility::Pattern pat("AA ? BB ? CC");
    auto result = pat.find((uintptr_t)data, sizeof(data));
    TEST_ASSERT(result.has_value());
    TEST_ASSERT(*result == (uintptr_t)&data[0]);

    return 0;
}

int test_pattern_find_multi_segment() {
    // Multi-segment pattern with * separator (default gap 256).
    uint8_t data[512] = {};
    data[0] = 0xAA;
    data[1] = 0xBB;
    data[100] = 0xCC;
    data[101] = 0xDD;

    utility::Pattern pat("AA BB * CC DD");
    auto result = pat.find((uintptr_t)data, sizeof(data));
    TEST_ASSERT(result.has_value());
    TEST_ASSERT(*result == (uintptr_t)&data[0]);

    return 0;
}

int test_pattern_find_no_match() {
    uint8_t data[] = {0x00, 0x11, 0x22, 0x33};

    utility::Pattern pat("FF FF FF");
    auto result = pat.find((uintptr_t)data, sizeof(data));
    TEST_ASSERT(!result.has_value());

    return 0;
}

int test_pattern_empty() {
    uint8_t data[] = {0x90};

    // Empty pattern should match at start.
    utility::Pattern pat("");
    auto result = pat.find((uintptr_t)data, sizeof(data));
    TEST_ASSERT(result.has_value());
    TEST_ASSERT(*result == (uintptr_t)data);

    return 0;
}

int test_pattern_all_wildcards() {
    uint8_t data[] = {0x11, 0x22, 0x33};

    utility::Pattern pat("? ? ?");
    auto result = pat.find((uintptr_t)data, sizeof(data));
    TEST_ASSERT(result.has_value());
    TEST_ASSERT(*result == (uintptr_t)data);

    return 0;
}

int test_pattern_too_short() {
    uint8_t data[] = {0xAA, 0xBB};

    utility::Pattern pat("AA BB CC DD");
    auto result = pat.find((uintptr_t)data, sizeof(data));
    TEST_ASSERT(!result.has_value());

    return 0;
}

int test_pattern_multi_segment_custom_gap() {
    uint8_t data[512] = {};
    data[0] = 0xAA;
    data[1] = 0xBB;
    data[200] = 0xCC;
    data[201] = 0xDD;

    // Default gap (256) should find it.
    utility::Pattern pat_ok("AA BB * CC DD");
    auto result_ok = pat_ok.find((uintptr_t)data, sizeof(data));
    TEST_ASSERT(result_ok.has_value());

    // Tight gap (10) should NOT find it (separated by 198 bytes).
    utility::Pattern pat_tight("AA BB *[10] CC DD");
    auto result_tight = pat_tight.find((uintptr_t)data, sizeof(data));
    TEST_ASSERT(!result_tight.has_value());

    return 0;
}

// ============================================================================
// String tests
// ============================================================================

int test_narrow_widen_roundtrip() {
    std::string original = "Hello, World!";
    auto widened = utility::widen(original);
    auto narrowed = utility::narrow(widened);
    TEST_ASSERT(narrowed == original);

    return 0;
}

int test_narrow_widen_unicode() {
    // Japanese "Hello" = こんにちは
    std::wstring wide = L"\u3053\u3093\u306B\u3061\u306F";
    auto narrowed = utility::narrow(wide);
    auto rewiden = utility::widen(narrowed);
    TEST_ASSERT(rewiden == wide);
    TEST_ASSERT(!narrowed.empty());

    return 0;
}

int test_narrow_widen_empty() {
    std::string empty_s;
    auto w = utility::widen(empty_s);
    TEST_ASSERT(w.empty());

    std::wstring empty_ws;
    auto n = utility::narrow(empty_ws);
    TEST_ASSERT(n.empty());

    return 0;
}

int test_widen_handles_malformed_utf8() {
#if defined(_WIN32)
    const std::string_view cases[] = {
        std::string_view{"\xE2\x82", 2},
        std::string_view{"\xE2\x28\xA1", 3},
        std::string_view{"\xC0\xAF", 2},
        std::string_view{"\xED\xA0\x80", 3},
        std::string_view{"\xF4\x90\x80\x80", 4},
        std::string_view{"\xE0\x80\xAF", 3},     // overlong 3-byte ('/')
        std::string_view{"\xE0\x9F\xBF", 3},     // overlong 3-byte (U+07FF)
        std::string_view{"\xF0\x80\x80\x80", 4}, // overlong 4-byte (NUL)
        std::string_view{"\xF0\x8F\xBF\xBF", 4}, // overlong 4-byte (U+FFFF)
    };

    for (const auto malformed : cases) {
        const auto length = MultiByteToWideChar(CP_UTF8, 0, malformed.data(), (int)malformed.length(), nullptr, 0);
        std::wstring expected{};
        expected.resize(length);
        MultiByteToWideChar(CP_UTF8, 0, malformed.data(), (int)malformed.length(), expected.data(), length);
        TEST_ASSERT(utility::widen(malformed) == expected);
    }
#else
    TEST_ASSERT(utility::widen(std::string_view{"\xE2\x82", 2}) == L"\uFFFD");
    TEST_ASSERT(utility::widen(std::string_view{"\xE2\x28\xA1", 3}) == L"\uFFFD(\uFFFD");
    TEST_ASSERT(utility::widen(std::string_view{"\xC0\xAF", 2}) == L"\uFFFD\uFFFD");
    TEST_ASSERT(utility::widen(std::string_view{"\xED\xA0\x80", 3}) == L"\uFFFD");
    TEST_ASSERT(utility::widen(std::string_view{"\xF4\x90\x80\x80", 4}) == L"\uFFFD");
    // Overlong encodings are malformed and must not decode to the (shorter) scalar.
    TEST_ASSERT(utility::widen(std::string_view{"\xE0\x80\xAF", 3}) == L"\uFFFD");
    TEST_ASSERT(utility::widen(std::string_view{"\xE0\x9F\xBF", 3}) == L"\uFFFD");
    TEST_ASSERT(utility::widen(std::string_view{"\xF0\x80\x80\x80", 4}) == L"\uFFFD");
    TEST_ASSERT(utility::widen(std::string_view{"\xF0\x8F\xBF\xBF", 4}) == L"\uFFFD");
#endif
    return 0;
}

int test_hash_determinism() {
    constexpr auto h1 = utility::hash("test_string");
    constexpr auto h2 = utility::hash("test_string");
    static_assert(h1 == h2, "hash must be deterministic");
    TEST_ASSERT(h1 == h2);

    return 0;
}

int test_hash_uniqueness() {
    auto h_a = utility::hash("hello");
    auto h_b = utility::hash("world");
    TEST_ASSERT(h_a != h_b);

    auto h_c = utility::hash("test");
    auto h_d = utility::hash("tset");
    TEST_ASSERT(h_c != h_d);

    return 0;
}

int test_hash_wide() {
    auto h1 = utility::hash(L"hello");
    auto h2 = utility::hash(L"hello");
    TEST_ASSERT(h1 == h2);

    auto h3 = utility::hash(L"hello");
    auto h4 = utility::hash(L"world");
    TEST_ASSERT(h3 != h4);

    return 0;
}

int test_hash_bytes() {
    uint8_t data1[] = {0x01, 0x02, 0x03};
    uint8_t data2[] = {0x01, 0x02, 0x03};
    uint8_t data3[] = {0x01, 0x02, 0x04};

    auto h1 = utility::hash(data1, 3);
    auto h2 = utility::hash(data2, 3);
    auto h3 = utility::hash(data3, 3);

    TEST_ASSERT(h1 == h2);
    TEST_ASSERT(h1 != h3);

    return 0;
}

int test_fnv_literal() {
    auto h_literal = "hello"_fnv;
    auto h_func = utility::hash("hello");
    TEST_ASSERT(h_literal == h_func);

    return 0;
}

// ============================================================================
// Address tests
// ============================================================================

int test_address_constructors() {
    // Default constructor -- null.
    Address a_default;
    TEST_ASSERT(a_default.ptr() == nullptr);
    TEST_ASSERT((uintptr_t)a_default == 0);

    // From void*.
    int x = 42;
    Address a_ptr(&x);
    TEST_ASSERT(a_ptr.ptr() == &x);

    // From uintptr_t.
    Address a_int(0x12345678ULL);
    TEST_ASSERT((uintptr_t)a_int == 0x12345678ULL);

    return 0;
}

int test_address_arithmetic() {
    Address base(0x1000);

    // get / add are the same.
    auto got = base.get(0x10);
    TEST_ASSERT((uintptr_t)got == 0x1010);

    auto added = base.add(0x20);
    TEST_ASSERT((uintptr_t)added == 0x1020);

    auto subbed = added.sub(0x10);
    TEST_ASSERT((uintptr_t)subbed == 0x1010);

    return 0;
}

int test_address_as_to() {
    uint8_t data[] = {0x78, 0x56, 0x34, 0x12};
    Address a(data);

    // as<> reinterprets the pointer value itself.
    auto as_u64 = a.as<uint64_t>();
    TEST_ASSERT(as_u64 == (uint64_t)data);

    // to<> dereferences and reads.
    auto val = a.to<uint32_t>();
    TEST_ASSERT(val == 0x12345678);

    return 0;
}

int test_address_deref() {
    int x = 0xABCD;
    int* px = &x;
    Address a(&px);

    // deref reads the pointer stored at a, giving us &x.
    auto deref_result = a.deref();
    TEST_ASSERT(deref_result.ptr() == &x);

    // Double deref: read the int value.
    auto val = deref_result.to<int>();
    TEST_ASSERT(val == 0xABCD);

    return 0;
}

int test_address_operators() {
    Address a(0x1000);
    Address b(0x1000);
    Address c(0x2000);

    TEST_ASSERT((uintptr_t)a == (uintptr_t)b);
    TEST_ASSERT((uintptr_t)a != (uintptr_t)c);
    TEST_ASSERT(a == (uintptr_t)0x1000);
    TEST_ASSERT(a != (uintptr_t)0x2000);

    // Implicit conversion to uintptr_t.
    uintptr_t val = a;
    TEST_ASSERT(val == 0x1000);

    // Implicit conversion to void*.
    Address d((void*)0x3000);
    void* ptr = d;
    TEST_ASSERT(ptr == (void*)0x3000);

    return 0;
}

int test_address_set() {
    Address a;
    TEST_ASSERT(a.ptr() == nullptr);

    int x = 42;
    a.set(&x);
    TEST_ASSERT(a.ptr() == &x);

    return 0;
}

// ============================================================================
// Config tests
// ============================================================================

int test_config_get_set_string() {
    utility::Config cfg;
    cfg.set("name", "kananlib");
    cfg.set("version", "1.0");

    auto name = cfg.get("name");
    TEST_ASSERT(name.has_value());
    TEST_ASSERT(*name == "kananlib");

    auto ver = cfg.get("version");
    TEST_ASSERT(ver.has_value());
    TEST_ASSERT(*ver == "1.0");

    // Missing key.
    auto missing = cfg.get("nonexistent");
    TEST_ASSERT(!missing.has_value());

    return 0;
}

int test_config_get_set_bool() {
    utility::Config cfg;
    cfg.set<bool>("enabled", true);
    cfg.set<bool>("disabled", false);

    auto e = cfg.get<bool>("enabled");
    TEST_ASSERT(e.has_value());
    TEST_ASSERT(*e == true);

    auto d = cfg.get<bool>("disabled");
    TEST_ASSERT(d.has_value());
    TEST_ASSERT(*d == false);

    return 0;
}

int test_config_get_set_int() {
    utility::Config cfg;
    cfg.set<int>("port", 8080);
    cfg.set<int>("negative", -42);

    auto port = cfg.get<int>("port");
    TEST_ASSERT(port.has_value());
    TEST_ASSERT(*port == 8080);

    auto neg = cfg.get<int>("negative");
    TEST_ASSERT(neg.has_value());
    TEST_ASSERT(*neg == -42);

    return 0;
}

int test_config_get_set_float() {
    utility::Config cfg;
    cfg.set<double>("scale", 2.5);

    auto scale = cfg.get<double>("scale");
    TEST_ASSERT(scale.has_value());
    TEST_ASSERT(*scale > 2.4 && *scale < 2.6);

    return 0;
}

int test_config_save_load() {
    // Use a temp path.
    char temp_dir[MAX_PATH] = {};
    GetTempPathA(MAX_PATH, temp_dir);
    std::string path = std::string(temp_dir) + "kananlib_test_cfg.ini";

    // Write.
    utility::Config cfg_out;
    cfg_out.set("key1", "value1");
    cfg_out.set<int>("key2", 42);
    cfg_out.set<bool>("key3", true);
    TEST_ASSERT(cfg_out.save(path));

    // Read.
    utility::Config cfg_in(path);
    auto v1 = cfg_in.get("key1");
    TEST_ASSERT(v1.has_value());
    TEST_ASSERT(*v1 == "value1");

    auto v2 = cfg_in.get<int>("key2");
    TEST_ASSERT(v2.has_value());
    TEST_ASSERT(*v2 == 42);

    auto v3 = cfg_in.get<bool>("key3");
    TEST_ASSERT(v3.has_value());
    TEST_ASSERT(*v3 == true);

    // Cleanup.
    DeleteFileA(path.c_str());

    return 0;
}

int test_config_empty_key_ignored() {
    utility::Config cfg;
    cfg.set("", "should_be_ignored");
    cfg.set("valid", "");

    auto empty_key = cfg.get("");
    TEST_ASSERT(!empty_key.has_value());

    auto empty_val = cfg.get("valid");
    TEST_ASSERT(!empty_val.has_value());

    return 0;
}

int test_config_overwrite() {
    utility::Config cfg;
    cfg.set("key", "first");
    TEST_ASSERT(*cfg.get("key") == "first");

    cfg.set("key", "second");
    TEST_ASSERT(*cfg.get("key") == "second");

    return 0;
}

int test_config_load_nonexistent() {
    utility::Config cfg;
    auto result = cfg.load("C:\\nonexistent_path_12345.ini");
    TEST_ASSERT(!result);
    return 0;
}

// ============================================================================
// main
// ============================================================================

int main() try {
    std::cout << "===== kananlib utils test =====" << std::endl;

    // Pattern tests.
    RUN_TEST(test_build_pattern);
    RUN_TEST(test_pattern_find_exact);
    RUN_TEST(test_pattern_find_wildcard);
    RUN_TEST(test_pattern_find_multi_segment);
    RUN_TEST(test_pattern_find_no_match);
    RUN_TEST(test_pattern_empty);
    RUN_TEST(test_pattern_all_wildcards);
    RUN_TEST(test_pattern_too_short);
    RUN_TEST(test_pattern_multi_segment_custom_gap);

    // String tests.
    RUN_TEST(test_narrow_widen_roundtrip);
    RUN_TEST(test_narrow_widen_unicode);
    RUN_TEST(test_narrow_widen_empty);
    RUN_TEST(test_widen_handles_malformed_utf8);
    RUN_TEST(test_hash_determinism);
    RUN_TEST(test_hash_uniqueness);
    RUN_TEST(test_hash_wide);
    RUN_TEST(test_hash_bytes);
    RUN_TEST(test_fnv_literal);

    // Address tests.
    RUN_TEST(test_address_constructors);
    RUN_TEST(test_address_arithmetic);
    RUN_TEST(test_address_as_to);
    RUN_TEST(test_address_deref);
    RUN_TEST(test_address_operators);
    RUN_TEST(test_address_set);

    // Config tests.
    RUN_TEST(test_config_get_set_string);
    RUN_TEST(test_config_get_set_bool);
    RUN_TEST(test_config_get_set_int);
    RUN_TEST(test_config_get_set_float);
    RUN_TEST(test_config_save_load);
    RUN_TEST(test_config_empty_key_ignored);
    RUN_TEST(test_config_overwrite);
    RUN_TEST(test_config_load_nonexistent);

    return test_summary();
} catch (const std::exception& e) {
    std::cout << "Exception: " << e.what() << std::endl;
    return 1;
} catch (...) {
    std::cout << "Unknown exception." << std::endl;
    return 1;
}
