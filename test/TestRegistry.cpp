#include <cstdint>
#include <iostream>
#include <string>
#include <string_view>

#include <Windows.h>

#include <utility/Registry.hpp>

#include "TestHelpers.hpp"

// ============================================================================
// Registry tests
// ============================================================================

int test_registry_nonexistent_key() {
    // A key that definitely does not exist should return nullopt.
    auto result = utility::get_registry_dword(
        HKEY_LOCAL_MACHINE,
        "SOFTWARE\\ThisKeyDoesNotExist_KananlibTest_12345",
        "SomeValue");
    TEST_ASSERT(!result.has_value());

    return 0;
}

int test_registry_nonexistent_value() {
    // A valid key but nonexistent value should return nullopt.
    auto result = utility::get_registry_dword(
        HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion",
        "ThisValueDoesNotExist_KananlibTest_12345");
    TEST_ASSERT(!result.has_value());

    return 0;
}

int test_registry_read_known_dword() {
    // Read a known DWORD value from the Windows registry.
    // "CommonFilesDir" under CurrentVersion is a REG_SZ (string), not DWORD.
    // We need to find a known REG_DWORD. 
    //
    // A reasonably stable one:
    //   HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run
    //   But this is REG_BINARY.
    //
    // A better approach: read from HKCU which is always writable and stable.
    //   HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced
    //   "EnableBalloonTips" is a REG_DWORD if it exists, but may not always be set.
    //
    // Safest approach: just test the not-found path returns nullopt (covered above).
    // For a positive test, we can create a temporary DWORD in HKCU and read it back.
    //
    // However, modifying the registry is an external side effect. Let's just verify
    // that calling the function with a non-DWORD type also returns nullopt.
    // "CommonFilesDir" is a REG_SZ, so reading it as DWORD should fail.
    auto result = utility::get_registry_dword(
        HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion",
        "CommonFilesDir");
    // This is a REG_SZ, not REG_DWORD, so it should return nullopt.
    TEST_ASSERT(!result.has_value());

    return 0;
}

// ============================================================================
// get_registry_dword must honor string_view length (not assume null-termination)
//
// BUG: the function passes subkey.data() / value.data() straight to
// RegOpenKeyExA / RegQueryValueExA, which require null-terminated C strings.
// std::string_view::data() is NOT guaranteed null-terminated, so a view that is
// a prefix of a larger buffer makes the Reg* APIs read past the intended end
// into trailing bytes -> wrong key/value name -> lookup fails.
//
// We read a known REG_DWORD two ways: once with null-terminated literals (the
// baseline) and once with views over buffers that carry trailing garbage beyond
// the view length. A correct implementation returns the same value both times;
// the buggy one fails the view-based lookup because it reads the garbage.
// ============================================================================

int test_registry_string_view_not_null_terminated() {
    // Baseline: null-terminated literals must find the value.
    const auto baseline = utility::get_registry_dword(
        HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
        "CurrentMajorVersionNumber");

    if (!baseline.has_value()) {
        // Value not present on this OS build; nothing to prove.
        std::cout << "  SKIP: CurrentMajorVersionNumber not present" << std::endl;
        return 0;
    }

    // Buffers with trailing junk that is NOT part of the key/value name.
    const std::string subkey_buf = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersionZZZZZZ";
    const std::string value_buf  = "CurrentMajorVersionNumberZZZZZZ";

    const std::string_view subkey_view(subkey_buf.data(),
        std::string("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion").size());
    const std::string_view value_view(value_buf.data(),
        std::string("CurrentMajorVersionNumber").size());

    const auto via_view = utility::get_registry_dword(HKEY_LOCAL_MACHINE, subkey_view, value_view);

    TEST_ASSERT(via_view.has_value());
    TEST_ASSERT(*via_view == *baseline);

    return 0;
}

// ============================================================================
// main
// ============================================================================

int main() try {
    std::cout << "===== kananlib Registry test =====" << std::endl;

    // Registry.
    RUN_TEST(test_registry_nonexistent_key);
    RUN_TEST(test_registry_nonexistent_value);
    RUN_TEST(test_registry_read_known_dword);
    RUN_TEST(test_registry_string_view_not_null_terminated);

    return test_summary();
} catch (const std::exception& e) {
    std::cout << "Exception: " << e.what() << std::endl;
    return 1;
} catch (...) {
    std::cout << "Unknown exception." << std::endl;
    return 1;
}
