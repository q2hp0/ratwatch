#pragma once

#include <string>
#include <cstdint>

// the "do something about it" half, kept separate and deliberately small.
// everything here is a reversible, documented-api action - no process
// injection, no driver, no deleting anything. point is to buy time (stop
// a process from doing more damage, get a file out of the way) not to be
// a full incident response suite.
namespace ratwatch {

// suspends every thread in the target process via SuspendThread. doesn't
// kill it, doesn't touch its memory, just freezes it so you can go look
// at it with a real debugger/analysis tool without it doing anything else
// in the meantime. returns the number of threads actually suspended.
int suspend_process(uint32_t pid);

// un-does suspend_process
int resume_process(uint32_t pid);

// moves a file into ./quarantine/ next to the exe, renames it so it can't
// be double clicked by accident (.exe becomes .quarantined) and marks it
// hidden+readonly. doesn't delete anything, doesn't touch permissions in
// a way that can't be undone by just renaming it back.
bool quarantine_file(const std::string& path, std::string& out_new_path);

} // namespace ratwatch
