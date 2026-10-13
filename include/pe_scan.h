#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include "finding.h"

// parses the pe header by hand (no windows.h needed, just reads bytes),
// which means this one can actually be unit tested on linux. the goal
// isn't a full pe parser, just enough to pull out stuff that's useful for
// telling "this is probably a normal exe" from "this looks packed/weird"
namespace ratwatch {

struct SectionInfo {
    std::string name;
    uint32_t raw_size = 0;
    double entropy = 0.0; // 0 = totally uniform, ~8 = basically random (packed/encrypted)
};

struct PeInfo {
    bool valid_pe = false;
    bool is_64bit = false;
    bool is_dotnet = false;     // has a cor20 / clr header data directory
    uint32_t num_sections = 0;
    uint32_t overlay_size = 0;  // bytes tacked on after the last section, common in droppers
    std::vector<SectionInfo> sections;
};

// reads and parses the pe header of the given file. returns valid_pe=false
// if it's not a pe file at all (wrong magic, truncated, whatever)
PeInfo parse_pe_file(const std::string& path);

// turns a parsed PeInfo into findings - high entropy sections, big overlay,
// weird section counts, that sort of thing. separate from parsing so the
// parsing logic itself stays trivially testable without needing Finding
FindingList evaluate_pe(const std::string& path, const PeInfo& info);

// shannon entropy of a byte buffer, exposed separately since it's useful
// on its own and easy to unit test in isolation
double shannon_entropy(const std::vector<uint8_t>& data);

} // namespace ratwatch
