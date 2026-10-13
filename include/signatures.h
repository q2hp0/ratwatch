#pragma once

#include <string>
#include <vector>
#include "finding.h"

namespace ratwatch {

// pulls printable ascii/utf16 strings out of a file and checks them against
// a short list of markers tied to known commodity rat families. this is
// not a replacement for real yara rules, it's a quick first pass - a lot
// of these families reuse the same class names, mutex prefixes, or author
// tags across samples because the builders barely change between leaks.
struct StringMatch {
    std::string matched_text;
    std::string family_hint;
};

// extracts strings of at least min_len printable characters, both plain
// ascii and ascii-interleaved-with-nulls (how .net stores utf16 strings,
// which is most of what you'll find in these binaries)
std::vector<std::string> extract_strings(const std::string& file_path, size_t min_len = 6);

std::vector<StringMatch> match_known_indicators(const std::vector<std::string>& strings);

FindingList scan_file_strings(const std::string& file_path);

} // namespace ratwatch
