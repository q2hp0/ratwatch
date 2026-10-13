#pragma once

#include "finding.h"
#include "baseline.h"

namespace ratwatch {

// goes through windows services and flags ones whose binary path points
// somewhere weird (appdata, temp, a random folder instead of program files
// or system32). services are a common persistence spot because they
// survive reboots and can run as system.
FindingList scan_services(const Baseline* baseline);

} // namespace ratwatch
