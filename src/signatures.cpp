#include "signatures.h"

#include <fstream>
#include <algorithm>
#include <cctype>
#include <cstdint>

namespace ratwatch {

namespace {

bool is_print(unsigned char c) {
    return c >= 0x20 && c < 0x7f;
}

// small, obviously not exhaustive. these are generic markers that show up
// across public write-ups for these families - class/namespace names and
// the kind of debug strings builders leave behind. real detection needs a
// proper yara ruleset, this is just a quick triage pass.
struct Indicator {
    const char* needle;
    const char* family;
};

const Indicator kIndicators[] = {
    { "XWorm",              "xworm" },
    { "Xwormmm",             "xworm" },
    { "njRAT",               "njrat" },
    { "njw0rm",               "njrat family" },
    { "im523",               "njrat family (im523 builder)" },
    { "Mason",               "mason rat (weak signal, common word too)" },
    { "RunPE",               "generic process-hollowing helper, common in .net rats" },
    { "AsyncRAT",             "asyncrat" },
    { "DcRatByqwqdanchun",    "dcrat" },
    { "Client.exe",           "generic rat client naming (weak signal on its own)" },
};

} // namespace

std::vector<std::string> extract_strings(const std::string& file_path, size_t min_len) {
    std::vector<std::string> result;

    std::ifstream in(file_path, std::ios::binary);
    if (!in.is_open()) return result;

    std::vector<uint8_t> buf((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());

    std::string current;
    for (size_t i = 0; i < buf.size(); i++) {
        if (is_print(buf[i])) {
            current += (char)buf[i];
        } else {
            if (current.size() >= min_len) result.push_back(current);
            current.clear();
        }
    }
    if (current.size() >= min_len) result.push_back(current);

    // .net binaries store strings as utf16le, so ascii text shows up as
    // "X.W.o.r.m." with a null between every char. the loop above already
    // picks each letter as its own 1-char run and drops it since it's
    // below min_len, so do a second pass stripping nulls first
    std::string stripped;
    stripped.reserve(buf.size() / 2);
    for (size_t i = 0; i + 1 < buf.size(); i += 2) {
        if (buf[i + 1] == 0 && is_print(buf[i])) {
            stripped += (char)buf[i];
        } else {
            if (stripped.size() >= min_len) result.push_back(stripped);
            stripped.clear();
        }
    }
    if (stripped.size() >= min_len) result.push_back(stripped);

    return result;
}

std::vector<StringMatch> match_known_indicators(const std::vector<std::string>& strings) {
    std::vector<StringMatch> matches;

    for (const auto& s : strings) {
        for (const auto& ind : kIndicators) {
            if (s.find(ind.needle) != std::string::npos) {
                matches.push_back({ s, ind.family });
            }
        }
    }

    return matches;
}

FindingList scan_file_strings(const std::string& file_path) {
    FindingList out;

    auto strings = extract_strings(file_path);
    auto matches = match_known_indicators(strings);

    for (const auto& m : matches) {
        Finding f;
        f.severity = Severity::bad;
        f.category = "static";
        f.title = "string match for " + m.family_hint;
        f.detail = file_path + " contains \"" + m.matched_text + "\"";
        out.push_back(f);
    }

    return out;
}

} // namespace ratwatch
