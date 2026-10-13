#pragma once

#include "finding.h"

namespace ratwatch {

// walks each running process's memory regions looking for private (not
// backed by a mapped file/image) memory that's both writable and
// executable. normal programs basically never need this - it's one of
// the more reliable signs of shellcode or an unpacked/injected payload
// sitting in memory. uses VirtualQueryEx, which is the documented, normal
// way any process explorer-type tool reads memory region info.
FindingList scan_memory();

} // namespace ratwatch
