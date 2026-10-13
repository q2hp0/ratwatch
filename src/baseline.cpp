#include "baseline.h"

#include <fstream>
#include <sstream>

namespace ratwatch {

std::string Baseline::make_key(const std::string& kind, const std::string& value) {
    // just smash them together with a separator that's never going to show
    // up in a registry path or pid number
    return kind + "|" + value;
}

bool Baseline::load(const std::string& path) {
    std::ifstream in(path);
    if (!in.is_open()) {
        // no baseline yet is fine, just means everything looks "new" for now
        return false;
    }

    std::string line;
    while (std::getline(in, line)) {
        if (line.empty()) continue;
        entries_.insert(line);
    }
    return true;
}

bool Baseline::save(const std::string& path) const {
    std::ofstream out(path, std::ios::trunc);
    if (!out.is_open()) return false;

    for (const auto& e : entries_) {
        out << e << "\n";
    }
    return true;
}

void Baseline::add(const std::string& kind, const std::string& value) {
    entries_.insert(make_key(kind, value));
}

bool Baseline::contains(const std::string& kind, const std::string& value) const {
    return entries_.count(make_key(kind, value)) > 0;
}

} // namespace ratwatch
