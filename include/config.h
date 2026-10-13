#pragma once

#include <string>
#include <vector>

// dead simple config file, one rule per line, format is "key=value".
// blank lines and lines starting with # are skipped. keys can repeat
// (e.g. multiple ignore_path lines), values are just kept as a list.
//
// kept platform independent on purpose so it's unit testable on linux.
namespace ratwatch {

class Config {
public:
    // ok to call on a missing file, you just get an empty config back
    // (meaning "no extra allowlisting, default behavior")
    bool load(const std::string& path);

    // substrings of process paths that should never be flagged, even if
    // they live in appdata/temp/etc. useful for stuff like steam, discord,
    // your ide, whatever legit app happens to run from appdata on your box
    std::vector<std::string> ignore_paths;

    // process names (like "obs64.exe") that are allowed to spawn a shell
    // without getting flagged, on top of the built-in allowlist
    std::vector<std::string> extra_shell_parents;

    // registry value names under the run keys that are known-good and
    // shouldn't show up as findings even without a full baseline
    std::vector<std::string> ignore_run_entries;

    bool path_is_ignored(const std::string& lower_path) const;

private:
    std::vector<std::pair<std::string, std::string>> raw_entries_;
};

} // namespace ratwatch
