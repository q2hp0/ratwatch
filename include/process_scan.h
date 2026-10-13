#pragma once

#include "finding.h"

namespace ratwatch {

// walks the running process list looking for:
//  - exe living in appdata/temp/public (common drop spots for rats)
//  - parent/child combos that are classic initial-access patterns
//    (word/excel/outlook/acrobat spawning cmd, powershell or wscript)
FindingList scan_processes();

} // namespace ratwatch
