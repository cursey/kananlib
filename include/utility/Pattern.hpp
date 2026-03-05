#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace utility {
    inline constexpr size_t DEFAULT_GLOB_MAX_GAP = 256;

    struct PatternSegment {
        std::vector<int16_t> pattern;
        size_t max_gap; // max gap BEFORE this segment (0 for first segment)
    };

    class Pattern {
    public:
        Pattern() = delete;
        Pattern(const Pattern& other) = default;
        Pattern(Pattern&& other) = default;
        Pattern(const std::string& pattern);
        ~Pattern() = default;

        std::optional<uintptr_t> find(uintptr_t start, size_t length);

        Pattern& operator=(const Pattern& other) = default;
        Pattern& operator=(Pattern&& other) = default;

        // Returns the length of the first segment (backward compat).
        auto pattern_len() const noexcept { return m_segments[0].pattern.size(); }

        bool is_multi_segment() const noexcept { return m_segments.size() > 1; }

    private:
        std::optional<uintptr_t> find_single(uintptr_t start, size_t length, const std::vector<int16_t>& pat);

        std::vector<PatternSegment> m_segments;
    };

    // Converts a string pattern (eg. "90 90 ? EB ? ? ?" to a vector of int's where
    // wildcards are -1.
    std::vector<int16_t> buildPattern(std::string patternStr);
}
