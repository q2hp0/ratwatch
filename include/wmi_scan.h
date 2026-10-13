#pragma once

#include "finding.h"
#include "baseline.h"

namespace ratwatch {

// wmi event subscriptions are a persistence trick that doesn't touch the
// registry or disk in the usual spots, so a lot of people miss it. shells
// out to powershell since the native com api for this is a lot of ceremony
// for a tool this size.
FindingList scan_wmi_subscriptions(const Baseline* baseline);

} // namespace ratwatch
