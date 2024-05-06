#include <algorithm>

#include <Windows.h>

#include <utility/Memory.hpp>
#include <utility/Pattern.hpp>

using namespace std;

namespace utility {
    static uint8_t toByte(char digit) {
        if (digit >= '0' && digit <= '9') {
            return (digit - '0');
        }

        if (digit >= 'a' && digit <= 'f') {
            return (digit - 'a' + 10);
        }

        if (digit >= 'A' && digit <= 'F') {
            return (digit - 'A' + 10);
        }

        return 0;
    }

    Pattern::Pattern(const string& pattern)
        : m_pattern{}
    {
        m_pattern = move(buildPattern(pattern));
    }

    optional<uintptr_t> Pattern::find(uintptr_t start, size_t length) {
        auto patternLength = m_pattern.size();
        auto actual_end = start + length;
        auto end_scan_from = actual_end - patternLength;

        int32_t first_non_wildcard_index{-1};

        for (size_t p = 0; p < m_pattern.size(); ++p) {
            const auto k = m_pattern[p];
            if (k != -1) {
                first_non_wildcard_index = p;
                break;
            }
        }

        if (first_non_wildcard_index == -1) {
            return start; // Pattern is all wildcards, return the start address.
        }

        auto it_wildcard = (uint8_t*)start;

        do try {
            // std::find can throw an exception if the memory is not readable.
            // std::find also appears to be highly optimized compared to a manual loop which is why we use it.
            it_wildcard = std::find((uint8_t*)it_wildcard, (uint8_t*)actual_end, (uint8_t)m_pattern[first_non_wildcard_index]);

            auto it = it_wildcard - first_non_wildcard_index;

            // Reached the end.
            if (it > (uint8_t*)end_scan_from) {
                return {};
            }

            // Do the normal pattern matching.
            auto j = it;
            auto failedToMatch = false;

            // Make sure the address is readable.
            // Actually, don't do this. It's overhead (indirectly calls through a ptr)
            // Our exception handler should be fine.
            /*if (IsBadReadPtr((const void*)it, patternLength) != FALSE) {
                it_wildcard += patternLength - 1;
                continue;
            }*/

            for (auto& k : m_pattern) {
                if (k != -1 && k != *(uint8_t*)j) {
                    failedToMatch = true;
                    break;
                }

                ++j;
            }

            if (!failedToMatch) {
                return (uintptr_t)it;
            }

            ++it_wildcard;
        } catch(...) { // MAKE SURE YOU HAVE EXCEPTION HANDLING FOR ACCESS VIOLATIONS!!!!!!!!
            ++it_wildcard;
            continue;
        } while ((it_wildcard - first_non_wildcard_index) < (uint8_t*)end_scan_from);

        return {};
    }

    vector<int16_t> buildPattern(string patternStr) {
        // Remove spaces from the pattern string.
        patternStr.erase(remove_if(begin(patternStr), end(patternStr), isspace), end(patternStr));

        auto length = patternStr.length();
        vector<int16_t> pattern{};

        for (size_t i = 0; i < length;) {
            auto p1 = patternStr[i];

            if (p1 != '?') {
                // Bytes require 2 hex characters to encode, make sure we don't read
                // past the end of the pattern string attempting to read the next char.
                if (i + 1 >= length) {
                    break;
                }

                auto p2 = patternStr[i + 1];
                auto value = toByte(p1) << 4 | toByte(p2);

                pattern.emplace_back(value);

                i += 2;
            }
            else {
                // Wildcard's (?'s) get encoded as a -1.
                pattern.emplace_back(-1);
                i += 1;
            }
        }

        return pattern;
    }
}
