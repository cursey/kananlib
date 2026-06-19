#include <cstdarg>
#include <cstdint>

#include <windows.h>

#include <utility/String.hpp>

using namespace std;

namespace utility {
#if defined(_WIN32)
    string narrow(wstring_view str) {
        auto length = WideCharToMultiByte(CP_UTF8, 0, str.data(), (int)str.length(), nullptr, 0, nullptr, nullptr);
        string narrowStr{};

        narrowStr.resize(length);
        WideCharToMultiByte(CP_UTF8, 0, str.data(), (int)str.length(), (LPSTR)narrowStr.c_str(), length, nullptr, nullptr);

        return narrowStr;
    }

    wstring widen(string_view str) {
        auto length = MultiByteToWideChar(CP_UTF8, 0, str.data(), (int)str.length(), nullptr, 0);
        wstring wideStr{};

        wideStr.resize(length);
        MultiByteToWideChar(CP_UTF8, 0, str.data(), (int)str.length(), (LPWSTR)wideStr.c_str(), length);

        return wideStr;
    }
#else
    // Non-Windows wchar_t is 32-bit (UTF-32), so convert directly to/from UTF-8
    // rather than going through the (absent) Win32 codepage APIs.
    string narrow(wstring_view str) {
        string out{};
        out.reserve(str.size());
        for (wchar_t wc : str) {
            uint32_t cp = (uint32_t)wc;
            if (cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) {
                cp = 0xFFFD; // invalid scalar value -> U+FFFD (avoids malformed UTF-8)
            }
            if (cp < 0x80) {
                out.push_back((char)cp);
            } else if (cp < 0x800) {
                out.push_back((char)(0xC0 | (cp >> 6)));
                out.push_back((char)(0x80 | (cp & 0x3F)));
            } else if (cp < 0x10000) {
                out.push_back((char)(0xE0 | (cp >> 12)));
                out.push_back((char)(0x80 | ((cp >> 6) & 0x3F)));
                out.push_back((char)(0x80 | (cp & 0x3F)));
            } else {
                out.push_back((char)(0xF0 | (cp >> 18)));
                out.push_back((char)(0x80 | ((cp >> 12) & 0x3F)));
                out.push_back((char)(0x80 | ((cp >> 6) & 0x3F)));
                out.push_back((char)(0x80 | (cp & 0x3F)));
            }
        }
        return out;
    }

    wstring widen(string_view str) {
        wstring out{};
        out.reserve(str.size());
        size_t i = 0;
        const size_t n = str.size();
        while (i < n) {
            const unsigned char c = (unsigned char)str[i];
            uint32_t cp = 0;
            size_t extra = 0;
            if (c < 0x80) { cp = c; extra = 0; }
            else if ((c >> 5) == 0x6) { cp = c & 0x1F; extra = 1; }
            else if ((c >> 4) == 0xE) { cp = c & 0x0F; extra = 2; }
            else if ((c >> 3) == 0x1E) { cp = c & 0x07; extra = 3; }
            else { cp = 0xFFFD; extra = 0; }
            ++i;
            for (size_t k = 0; k < extra && i < n; ++k, ++i) {
                cp = (cp << 6) | ((unsigned char)str[i] & 0x3F);
            }
            out.push_back((wchar_t)cp);
        }
        return out;
    }
#endif

    string format_string(const char* format, va_list args) {
        va_list argsCopy{};

        va_copy(argsCopy, args);

        auto len = vsnprintf(nullptr, 0, format, argsCopy);

        va_end(argsCopy);

        if (len <= 0) {
            return {};
        }

        string buffer{};

        buffer.resize(len + 1, 0);
        vsnprintf(buffer.data(), buffer.size(), format, args);
        buffer.resize(buffer.size() - 1); // Removes the extra 0 vsnprintf adds.

        return buffer;
    }
}
