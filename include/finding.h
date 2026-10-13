#pragma once

#include <string>
#include <vector>

// a single thing we noticed that looks sketchy. keeping this dead simple on
// purpose, severity is just my gut feeling 1-3, not some fancy cvss thing
namespace ratwatch {

enum class Severity {
    info = 1,
    warn = 2,
    bad = 3
};

struct Finding {
    Severity severity;
    std::string category;   // "persistence", "process", "network"
    std::string title;      // short one liner
    std::string detail;     // the actual path/key/pid/whatever
};

inline const char* severity_label(Severity s) {
    switch (s) {
        case Severity::info: return "info";
        case Severity::warn: return "warn";
        case Severity::bad:  return "BAD ";
    }
    return "?";
}

using FindingList = std::vector<Finding>;

} // namespace ratwatch
