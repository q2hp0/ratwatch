#include "config.h"

#include <fstream>
#include <algorithm>

namespace ratwatch {

namespace {

std::string trim(const std::string& s) {
    size_t start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    size_t end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

} // namespace

bool Config::load(const std::string& path) {
    std::ifstream in(path);
    if (!in.is_open()) return false;

    std::string line;
    while (std::getline(in, line)) {
        std::string trimmed = trim(line);
        if (trimmed.empty() || trimmed[0] == '#') continue;

        size_t eq = trimmed.find('=');
        if (eq == std::string::npos) continue;

        std::string key = trim(trimmed.substr(0, eq));
        std::string value = trim(trimmed.substr(eq + 1));
        if (key.empty() || value.empty()) continue;

        raw_entries_.emplace_back(key, value);

        if (key == "ignore_path") {
            // store lowercased so comparisons later don't need to redo it
            std::string lower = value;
            std::transform(lower.begin(), lower.end(), lower.begin(),
                            [](unsigned char c) { return (char)std::tolower(c); });
            ignore_paths.push_back(lower);
        } else if (key == "extra_shell_parent") {
            std::string lower = value;
            std::transform(lower.begin(), lower.end(), lower.begin(),
                            [](unsigned char c) { return (char)std::tolower(c); });
            extra_shell_parents.push_back(lower);
        } else if (key == "ignore_run_entry") {
            ignore_run_entries.push_back(value);
        }
    }

    return true;
}

bool Config::path_is_ignored(const std::string& lower_path) const {
    for (const auto& p : ignore_paths) {
        if (lower_path.find(p) != std::string::npos) return true;
    }
    return false;
}

} // namespace ratwatch
