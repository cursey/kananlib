#include <algorithm>
#include <charconv>

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
        : m_segments{}
    {
        // Split pattern string at '*' tokens to produce segments.
        // Syntax: "AA BB * CC DD" or "AA BB *128 CC DD" (max gap in bytes).
        // Spaces around '*' are handled by splitting on whitespace tokens.

        // Tokenize by spaces first so we can detect '*' and '*N' tokens.
        std::vector<std::string> tokens;
        {
            size_t i = 0;
            while (i < pattern.size()) {
                while (i < pattern.size() && pattern[i] == ' ') ++i;
                if (i >= pattern.size()) break;
                size_t start = i;
                while (i < pattern.size() && pattern[i] != ' ') ++i;
                tokens.emplace_back(pattern.substr(start, i - start));
            }
        }

        // Group tokens into segments separated by '*' / '*N' tokens.
        std::vector<std::string> segment_strs;
        std::vector<size_t> gap_sizes; // gap_sizes[i] = max gap before segment i

        std::string current;
        for (auto& tok : tokens) {
            if (!tok.empty() && tok[0] == '*') {
                // Flush current segment
                segment_strs.push_back(std::move(current));
                current.clear();

                // Parse optional gap size: *[N]
                size_t gap = DEFAULT_GLOB_MAX_GAP;
                if (tok.size() > 2 && tok[1] == '[') {
                    auto close = tok.find(']', 2);
                    if (close != std::string::npos) {
                        std::from_chars(tok.data() + 2, tok.data() + close, gap);
                    }
                }
                gap_sizes.push_back(gap);
            } else {
                if (!current.empty()) current += ' ';
                current += tok;
            }
        }
        // Flush last segment
        if (!current.empty()) {
            segment_strs.push_back(std::move(current));
        }

        // Build each segment
        for (size_t i = 0; i < segment_strs.size(); ++i) {
            PatternSegment seg;
            seg.pattern = buildPattern(segment_strs[i]);
            seg.max_gap = (i < gap_sizes.size() + 1 && i > 0) ? gap_sizes[i - 1] : 0;
            m_segments.push_back(std::move(seg));
        }

        // Fallback: if pattern was empty or something went wrong, push an empty segment
        if (m_segments.empty()) {
            m_segments.push_back(PatternSegment{{}, 0});
        }
    }

    optional<uintptr_t> Pattern::find_single(uintptr_t start, size_t length, const vector<int16_t>& pat) {
        auto patternLength = pat.size();

        if (patternLength == 0) {
            return start; // Empty pattern matches immediately
        }

        if (length < patternLength) {
            return {};
        }

        auto actual_end = start + length;
        auto end_scan_from = actual_end - patternLength;

        int32_t first_non_wildcard_index{-1};

        for (size_t p = 0; p < pat.size(); ++p) {
            const auto k = pat[p];
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
            it_wildcard = std::find((uint8_t*)it_wildcard, (uint8_t*)actual_end, (uint8_t)pat[first_non_wildcard_index]);

            auto it = it_wildcard - first_non_wildcard_index;

            // Reached the end.
            if (it > (uint8_t*)end_scan_from) {
                return {};
            }

            // Do the normal pattern matching.
            auto j = it;
            auto failedToMatch = false;

            for (auto& k : pat) {
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
            it_wildcard = (uint8_t*)(((uintptr_t)it_wildcard & ~0xFFF) + 0x1000);
            continue;
        } while ((it_wildcard - first_non_wildcard_index) < (uint8_t*)end_scan_from);

        return {};
    }

    optional<uintptr_t> Pattern::find(uintptr_t start, size_t length) {
        if (m_segments.empty()) {
            return {};
        }

        const auto actual_end = start + length;

        // Fast path: single segment (no glob wildcards).
        if (m_segments.size() == 1) {
            return find_single(start, length, m_segments[0].pattern);
        }

        // Multi-segment: find first segment, then each subsequent segment
        // within its max_gap window. On failure, retry with the next occurrence
        // of the first segment.
        auto search_start = start;

        while (search_start < actual_end) {
            const auto remaining = actual_end - search_start;
            auto seg0_result = find_single(search_start, remaining, m_segments[0].pattern);

            if (!seg0_result) {
                return {};
            }

            const auto match_start = *seg0_result;
            auto cursor = match_start + m_segments[0].pattern.size();
            bool all_found = true;

            for (size_t i = 1; i < m_segments.size(); ++i) {
                const auto& seg = m_segments[i];
                const auto seg_len = seg.pattern.size();
                const auto window_end = (std::min)(cursor + seg.max_gap + seg_len, actual_end);

                if (cursor >= window_end || window_end - cursor < seg_len) {
                    all_found = false;
                    break;
                }

                auto seg_result = find_single(cursor, window_end - cursor, seg.pattern);

                if (!seg_result) {
                    all_found = false;
                    break;
                }

                cursor = *seg_result + seg_len;
            }

            if (all_found) {
                return match_start;
            }

            // Retry from after the failed first-segment match
            search_start = match_start + 1;
        }

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
