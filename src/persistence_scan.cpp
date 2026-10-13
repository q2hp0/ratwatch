#include "persistence_scan.h"

#ifdef _WIN32
#include <windows.h>
#include <shlobj.h>
#include <array>
#include <cstdio>
#include <memory>
#include <string>

namespace ratwatch {

namespace {

// the handful of run keys worth checking. there's more exotic ones (image
// file execution options, winlogon shell, etc) but these cover the vast
// majority of what commodity rats actually use because they're the easy ones
struct RunKeySpec {
    HKEY root;
    const char* path;
    const char* label;
};

const RunKeySpec kRunKeys[] = {
    { HKEY_CURRENT_USER,  "Software\\Microsoft\\Windows\\CurrentVersion\\Run",        "HKCU\\...\\Run" },
    { HKEY_CURRENT_USER,  "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",    "HKCU\\...\\RunOnce" },
    { HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\Run",        "HKLM\\...\\Run" },
    { HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",    "HKLM\\...\\RunOnce" },
};

void scan_one_run_key(const RunKeySpec& spec, const Baseline* baseline, FindingList& out) {
    HKEY hkey;
    if (RegOpenKeyExA(spec.root, spec.path, 0, KEY_READ, &hkey) != ERROR_SUCCESS) {
        return; // key might just not exist, that's normal
    }

    char value_name[16384];
    BYTE value_data[16384];
    DWORD index = 0;

    for (;;) {
        DWORD name_len = sizeof(value_name);
        DWORD data_len = sizeof(value_data);
        DWORD type;

        LONG rc = RegEnumValueA(hkey, index, value_name, &name_len, nullptr,
                                 &type, value_data, &data_len);
        if (rc == ERROR_NO_MORE_ITEMS) break;
        if (rc != ERROR_SUCCESS) { index++; continue; }

        if (type == REG_SZ || type == REG_EXPAND_SZ) {
            std::string full_key = std::string(spec.label) + "\\" + value_name;
            std::string cmd(reinterpret_cast<char*>(value_data));

            bool known = baseline && baseline->contains("runkey", full_key);
            if (!known) {
                Finding f;
                f.severity = Severity::warn;
                f.category = "persistence";
                f.title = "new autorun entry: " + std::string(value_name);
                f.detail = full_key + " = " + cmd;
                out.push_back(f);
            }
        }
        index++;
    }

    RegCloseKey(hkey);
}

void scan_startup_folder(const Baseline* baseline, FindingList& out) {
    char path[MAX_PATH];
    if (FAILED(SHGetFolderPathA(nullptr, CSIDL_STARTUP, nullptr, 0, path))) {
        return;
    }

    std::string pattern = std::string(path) + "\\*";
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(pattern.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return;

    do {
        std::string name = fd.cFileName;
        if (name == "." || name == "..") continue;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;

        std::string full = std::string(path) + "\\" + name;
        bool known = baseline && baseline->contains("startupfile", full);
        if (!known) {
            Finding f;
            f.severity = Severity::warn;
            f.category = "persistence";
            f.title = "new file in startup folder: " + name;
            f.detail = full;
            out.push_back(f);
        }
    } while (FindNextFileA(h, &fd));

    FindClose(h);
}

} // namespace

FindingList scan_persistence(const Baseline* baseline) {
    FindingList out;
    for (const auto& spec : kRunKeys) {
        scan_one_run_key(spec, baseline, out);
    }
    scan_startup_folder(baseline, out);
    return out;
}

FindingList scan_scheduled_tasks(const Baseline* baseline) {
    FindingList out;

    // shelling out to schtasks is lazy but it saves dealing with the com
    // task scheduler api which is a few hundred lines on its own for
    // something this simple. csv output is easy enough to split on commas.
    std::unique_ptr<FILE, decltype(&_pclose)> pipe(
        _popen("schtasks /query /fo CSV /nh", "r"), _pclose);
    if (!pipe) return out;

    std::array<char, 2048> buf{};
    while (fgets(buf.data(), (int)buf.size(), pipe.get()) != nullptr) {
        std::string line(buf.data());
        if (line.empty()) continue;

        // first csv field is the task name, quoted
        size_t first_quote = line.find('"');
        size_t second_quote = line.find('"', first_quote + 1);
        if (first_quote == std::string::npos || second_quote == std::string::npos) continue;

        std::string task_name = line.substr(first_quote + 1, second_quote - first_quote - 1);
        if (task_name.empty() || task_name == "TaskName") continue;

        bool known = baseline && baseline->contains("task", task_name);
        if (!known) {
            Finding f;
            f.severity = Severity::info;
            f.category = "persistence";
            f.title = "scheduled task: " + task_name;
            f.detail = "run 'schtasks /query /tn \"" + task_name + "\" /v /fo list' for details";
            out.push_back(f);
        }
    }

    return out;
}

} // namespace ratwatch

#else // not windows

namespace ratwatch {
FindingList scan_persistence(const Baseline*) { return {}; }
FindingList scan_scheduled_tasks(const Baseline*) { return {}; }
} // namespace ratwatch

#endif
