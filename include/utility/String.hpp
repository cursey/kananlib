#pragma once

#include <cstdint>
#include <string>
#include <string_view>

namespace utility {
    //
    // String utilities.
    //

    // The wide-character unit for Windows-format (UTF-16) strings. On Windows
    // wchar_t already is UTF-16; on other platforms wchar_t is UTF-32, so the
    // 16-bit char16_t is used to represent in-binary UTF-16 data correctly.
#if defined(_WIN32)
    using utf16_char = wchar_t;
#else
    using utf16_char = char16_t;
#endif

    // Conversion functions for UTF8<->UTF16.
    std::string narrow(std::wstring_view std);
    std::string narrow(std::u16string_view std);
    std::wstring widen(std::string_view std);

    std::string format_string(const char* format, va_list args);
    
    // FNV-1a
    static constexpr auto hash(std::string_view data) {
        size_t result = 0xcbf29ce484222325;

        for (char c : data) {
            result ^= c;
            result *= (size_t)1099511628211;
        }

        return result;
    }

    static constexpr auto hash(std::wstring_view data) {
        size_t result = 0xcbf29ce484222325;

        for (wchar_t c : data) {
            result ^= c;
            result *= (size_t)1099511628211;
        }

        return result;
    }

    static constexpr auto hash(const uint8_t* data, size_t size) {
        size_t result = 0xcbf29ce484222325;

        for (size_t i = 0; i < size; ++i) {
            result ^= data[i];
            result *= (size_t)1099511628211;
        }

        return result;
    }
}

consteval auto operator "" _fnv(const char* s, size_t) {
    return utility::hash(s);
}

consteval auto operator "" _fnv(const wchar_t* s, size_t) {
    return utility::hash(s);
}