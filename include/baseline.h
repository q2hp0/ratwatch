#pragma once

#include <set>
#include <string>

// baseline is just a flat text file of "stuff we already knew about" so repeat
// scans don't keep yelling about the same run key you added on purpose.
// one entry per line, format is "<kind>|<value>", e.g. "runkey|HKCU\...\Foo"
//
// kept this logic platform independent (no win32 calls) so it can be unit
// tested on linux without a windows box.
namespace ratwatch {

class Baseline {
public:
    // loads an existing baseline file, ok if it doesn't exist yet (just empty)
    bool load(const std::string& path);

    // overwrites the baseline file with whatever entries are in here right now
    bool save(const std::string& path) const;

    void add(const std::string& kind, const std::string& value);
    bool contains(const std::string& kind, const std::string& value) const;
    size_t count() const { return entries_.size(); }

private:
    static std::string make_key(const std::string& kind, const std::string& value);
    std::set<std::string> entries_;
};

} // namespace ratwatch
