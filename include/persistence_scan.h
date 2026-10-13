#pragma once

#include "finding.h"
#include "baseline.h"

// checks the usual autorun spots. windows only, obviously - the registry and
// startup folder stuff needs the real win32 api.
namespace ratwatch {

// looks at HKCU/HKLM run + runonce keys and the startup folder, compares
// against baseline (if given), returns anything new as a finding
FindingList scan_persistence(const Baseline* baseline);

// does schtasks /query under the hood since the native task scheduler com
// api is way more code than it's worth for a quick check like this
FindingList scan_scheduled_tasks(const Baseline* baseline);

} // namespace ratwatch
