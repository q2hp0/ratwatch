#include "process_scan.h"

#ifdef _WIN32
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <algorithm>
#include <cctype>
#include <map>
#include <string>

namespace ratwatch {

namespace {

std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                    [](unsigned char c) { return (char)std::tolower(c); });
    return s;
}

// process names that are expected to spawn a shell/script host sometimes
// (installers, build tools etc) - not flagging these to keep noise down
const char* kShellSpawnAllowlist[] = {
    "cmd.exe", "powershell.exe", "wt.exe", "explorer.exe", "vscode.exe",
    "code.exe", "windowsterminal.exe", "conhost.exe", "taskmgr.exe"
};

bool is_allowlisted_parent(const std::string& parent_lower) {
    for (const char* a : kShellSpawnAllowlist) {
        if (parent_lower == a) return true;
    }
    return false;
}

// apps that, if they suddenly spawn a shell or script interpreter, are a
// pretty strong initial-access signal. this is the classic "phishing doc
// opens and spawns powershell" pattern
const char* kOfficeLikeApps[] = {
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
    "acrord32.exe", "acrobat.exe", "mspub.exe"
};

bool is_office_like(const std::string& name_lower) {
    for (const char* a : kOfficeLikeApps) {
        if (name_lower == a) return true;
    }
    return false;
}

const char* kShellLikeChildren[] = {
    "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "regsvr32.exe", "rundll32.exe"
};

bool is_shell_like(const std::string& name_lower) {
    for (const char* a : kShellLikeChildren) {
        if (name_lower == a) return true;
    }
    return false;
}

std::string get_exe_path(DWORD pid) {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return {};

    char path[MAX_PATH] = {0};
    DWORD size = MAX_PATH;
    std::string result;
    if (QueryFullProcessImageNameA(h, 0, path, &size)) {
        result = path;
    }
    CloseHandle(h);
    return result;
}

struct ProcInfo {
    DWORD pid;
    DWORD parent_pid;
    std::string name;
};

} // namespace

FindingList scan_processes() {
    FindingList out;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return out;

    PROCESSENTRY32 pe{};
    pe.dwSize = sizeof(pe);

    std::map<DWORD, ProcInfo> procs;

    if (Process32First(snap, &pe)) {
        do {
            ProcInfo info;
            info.pid = pe.th32ProcessID;
            info.parent_pid = pe.th32ParentProcessID;
            info.name = pe.szExeFile;
            procs[info.pid] = info;
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);

    // drop locations we consider suspicious for an exe to be running from.
    // using getenv since these are per-user anyway and we don't need the
    // shfolder api for this one
    std::string appdata = getenv("APPDATA") ? getenv("APPDATA") : "";
    std::string localappdata = getenv("LOCALAPPDATA") ? getenv("LOCALAPPDATA") : "";
    std::string temp = getenv("TEMP") ? getenv("TEMP") : "";

    for (const auto& [pid, info] : procs) {
        if (pid == 0 || pid == 4) continue; // system idle / system process

        std::string full_path = get_exe_path(pid);
        std::string path_lower = to_lower(full_path);

        bool in_suspicious_dir =
            (!appdata.empty() && path_lower.find(to_lower(appdata)) != std::string::npos) ||
            (!localappdata.empty() && path_lower.find(to_lower(localappdata)) != std::string::npos) ||
            (!temp.empty() && path_lower.find(to_lower(temp)) != std::string::npos) ||
            path_lower.find("\\programdata\\") != std::string::npos ||
            path_lower.find("\\public\\") != std::string::npos;

        if (in_suspicious_dir && !full_path.empty()) {
            Finding f;
            f.severity = Severity::warn;
            f.category = "process";
            f.title = "process running from a drop-style folder: " + info.name;
            f.detail = "pid " + std::to_string(pid) + " -> " + full_path;
            out.push_back(f);
        }

        // check the parent/child pattern
        auto parent_it = procs.find(info.parent_pid);
        if (parent_it != procs.end()) {
            std::string parent_lower = to_lower(parent_it->second.name);
            std::string child_lower = to_lower(info.name);

            if (is_office_like(parent_lower) && is_shell_like(child_lower)) {
                Finding f;
                f.severity = Severity::bad;
                f.category = "process";
                f.title = parent_it->second.name + " spawned " + info.name;
                f.detail = "pid " + std::to_string(pid) + " (parent pid "
                           + std::to_string(info.parent_pid) + "), classic initial-access pattern";
                out.push_back(f);
            } else if (is_shell_like(child_lower) && !is_allowlisted_parent(parent_lower)
                       && parent_lower != "svchost.exe" && parent_lower != "services.exe") {
                // softer signal, something non-obvious spawned a shell. keep it at info
                // level since this has a decent amount of legit reasons to happen too
                Finding f;
                f.severity = Severity::info;
                f.category = "process";
                f.title = info.name + " spawned by " + parent_it->second.name;
                f.detail = "pid " + std::to_string(pid) + ", parent pid "
                           + std::to_string(info.parent_pid);
                out.push_back(f);
            }
        }
    }

    return out;
}

} // namespace ratwatch

#else // not windows

namespace ratwatch {
FindingList scan_processes() { return {}; }
} // namespace ratwatch

#endif
