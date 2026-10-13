#pragma once

#include <string>
#include "finding.h"

// tiny logging helper, nothing fancy. prints to stdout with color if we're on
// a real terminal, and can also append to a log file for watch mode.
namespace ratwatch {

void print_finding(const Finding& f);
void print_findings(const FindingList& findings);

// appends a plain text line to a log file, timestamped. used by watch mode
// so you have a record after the fact instead of just scrollback.
void log_to_file(const std::string& path, const std::string& line);

} // namespace ratwatch
