#pragma once

#include "finding.h"

namespace ratwatch {

// reads the active tcp table and maps connections back to owning pids.
// flags:
//  - a process we already flagged in scan_processes() that also has an
//    active outbound connection
//  - very crude beacon detection: call this repeatedly from watch mode and
//    it keeps its own little history of (pid, remote ip) pairs in memory,
//    if the same pair shows up on a suspiciously regular interval a few
//    times in a row it gets flagged
FindingList scan_network();

} // namespace ratwatch
