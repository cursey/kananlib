#include <cstdarg>
#include <cstdint>

#include <windows.h>

#include <utility/String.hpp>

using namespace std;

namespace utility {
    namespace {
        void append_wide_scalar(wstring& out, uint32_t cp) {
#if defined(_WIN32)
            if (cp <= 0xFFFF) {
                out.push_back((wchar_t)cp);
                return;
            }

            cp -= 0x10000;
            out.push_back((wchar_t)(0xD800 + (cp >> 10)));
            out.push_back((wchar_t)(0xDC00 + (cp & 0x3FF)));
#else
            out.push_back((wchar_t)cp);
#endif
        }

        wstring widen_utf8_lossy(string_view str) {
            wstring out{};
            out.reserve(str.size());
            size_t i = 0;
            const size_t n = str.size();
            while (i < n) {
                const unsigned char c = (unsigned char)str[i++];
                uint32_t cp = 0;
                size_t extra = 0;

                if (c < 0x80) {
                    out.push_back((wchar_t)c);
                    continue;
                } else if (c >= 0xC2 && c <= 0xDF) {
                    cp = c & 0x1F;
                    extra = 1;
                } else if (c >= 0xE0 && c <= 0xEF) {
                    cp = c & 0x0F;
                    extra = 2;
                } else if (c >= 0xF0 && c <= 0xF4) {
                    cp = c & 0x07;
                    extra = 3;
                } else {
                    out.push_back((wchar_t)0xFFFD);
                    continue;
                }

                if (n - i < extra) {
                    out.push_back((wchar_t)0xFFFD);
                    break;
                }

                bool valid = true;
                for (size_t k = 0; k < extra; ++k) {
                    const unsigned char cc = (unsigned char)str[i + k];
                    if ((cc & 0xC0) != 0x80) {
                        valid = false;
                        break;
                    }
                    cp = (cp << 6) | (cc & 0x3F);
                }

                if (!valid) {
                    out.push_back((wchar_t)0xFFFD);
                    continue;
                }

                i += extra;
                if ((cp >= 0xD800 && cp <= 0xDFFF) || cp > 0x10FFFF) {
                    out.push_back((wchar_t)0xFFFD);
                } else {
                    append_wide_scalar(out, cp);
                }
            }
            return out;
        }
    }

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
        return widen_utf8_lossy(str);
    }
#endif

    // UTF-16 -> UTF-8. Shared by both platforms: in-binary Windows strings are
    // always UTF-16 code units, independent of the host's wchar_t width.
    string narrow(u16string_view str) {
        string out{};
        out.reserve(str.size());
        for (size_t i = 0; i < str.size(); ++i) {
            uint32_t cp = (uint16_t)str[i];

            if (cp >= 0xD800 && cp <= 0xDBFF) {
                // High surrogate: combine with the following low surrogate.
                if (i + 1 < str.size()) {
                    const uint32_t low = (uint16_t)str[i + 1];
                    if (low >= 0xDC00 && low <= 0xDFFF) {
                        cp = 0x10000 + ((cp - 0xD800) << 10) + (low - 0xDC00);
                        ++i;
                    } else {
                        cp = 0xFFFD;
                    }
                } else {
                    cp = 0xFFFD;
                }
            } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
                cp = 0xFFFD; // lone low surrogate
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
