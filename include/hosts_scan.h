#pragma once

#include <string>
#include "finding.h"

namespace ratwatch {

// the hosts file is a weirdly common target, redirecting a domain to
// somewhere else or blocking av update domains. this just hashes it and
// compares against what we saw last time, nothing fancy. kept portable
// (just plain file reading) so it's testable without a windows box.
FindingList check_hosts_file(const std::string& hosts_path, const std::string& hash_store_path);

// fnv-1a, not cryptographically anything, just need something stable and
// fast to notice "this file changed since last time"
std::string simple_hash(const std::string& content);

} // namespace ratwatch
