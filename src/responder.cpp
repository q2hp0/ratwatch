#include "responder.h"

#ifdef _WIN32
#include <windows.h>
#include <tlhelp32.h>
#include <filesystem>
#include <iostream>

namespace fs = std::filesystem;

namespace ratwatch {

int suspend_process(uint32_t pid) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    THREADENTRY32 te{};
    te.dwSize = sizeof(te);
    int suspended = 0;

    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid) continue;

            HANDLE th = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
            if (!th) continue;

            if (SuspendThread(th) != (DWORD)-1) {
                suspended++;
            }
            CloseHandle(th);
        } while (Thread32Next(snap, &te));
    }

    CloseHandle(snap);
    return suspended;
}

int resume_process(uint32_t pid) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    THREADENTRY32 te{};
    te.dwSize = sizeof(te);
    int resumed = 0;

    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid) continue;

            HANDLE th = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
            if (!th) continue;

            if (ResumeThread(th) != (DWORD)-1) {
                resumed++;
            }
            CloseHandle(th);
        } while (Thread32Next(snap, &te));
    }

    CloseHandle(snap);
    return resumed;
}

bool quarantine_file(const std::string& path, std::string& out_new_path) {
    std::error_code ec;

    fs::path src(path);
    if (!fs::exists(src, ec)) return false;

    fs::path quarantine_dir = "quarantine";
    fs::create_directories(quarantine_dir, ec);

    // throw a timestamp on the name so running this twice on the same
    // filename doesn't clobber the earlier one
    auto now = std::chrono::system_clock::now().time_since_epoch().count();
    std::string new_name = src.filename().string() + "." + std::to_string(now) + ".quarantined";
    fs::path dest = quarantine_dir / new_name;

    fs::rename(src, dest, ec);
    if (ec) {
        // rename can fail across drives, fall back to copy+delete
        fs::copy_file(src, dest, fs::copy_options::overwrite_existing, ec);
        if (ec) return false;
        fs::remove(src, ec);
    }

    // mark it hidden + readonly so it doesn't get double clicked by accident.
    // nothing destructive, just attribute flags, easy to undo
    SetFileAttributesA(dest.string().c_str(), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_READONLY);

    out_new_path = dest.string();
    return true;
}

} // namespace ratwatch

#else // not windows

namespace ratwatch {
int suspend_process(uint32_t) { return 0; }
int resume_process(uint32_t) { return 0; }
bool quarantine_file(const std::string&, std::string&) { return false; }
} // namespace ratwatch

#endif
