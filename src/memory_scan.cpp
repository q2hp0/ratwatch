#include "memory_scan.h"

#ifdef _WIN32
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <vector>
#include <string>
#include <cstdint>

namespace ratwatch {

namespace {

std::string get_proc_name(DWORD pid) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return "pid " + std::to_string(pid);

    PROCESSENTRY32 pe{};
    pe.dwSize = sizeof(pe);
    std::string name = "pid " + std::to_string(pid);

    if (Process32First(snap, &pe)) {
        do {
            if (pe.th32ProcessID == pid) {
                name = pe.szExeFile;
                break;
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return name;
}

} // namespace

FindingList scan_memory() {
    FindingList out;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return out;

    PROCESSENTRY32 pe{};
    pe.dwSize = sizeof(pe);

    std::vector<DWORD> pids;
    if (Process32First(snap, &pe)) {
        do {
            if (pe.th32ProcessID != 0 && pe.th32ProcessID != 4) {
                pids.push_back(pe.th32ProcessID);
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);

    for (DWORD pid : pids) {
        // need PROCESS_QUERY_INFORMATION + PROCESS_VM_READ for this, a lot
        // of system processes will just deny us and that's fine, skip them
        HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (!h) continue;

        MEMORY_BASIC_INFORMATION mbi{};
        uint8_t* addr = nullptr;
        size_t rwx_region_count = 0;
        size_t rwx_total_bytes = 0;

        // walk the address space one region at a time
        while (VirtualQueryEx(h, addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
            bool is_exec_write = (mbi.AllocationProtect == PAGE_EXECUTE_READWRITE) ||
                                   (mbi.Protect == PAGE_EXECUTE_READWRITE);
            bool is_private = (mbi.Type == MEM_PRIVATE); // not backed by a mapped file/image
            bool is_committed = (mbi.State == MEM_COMMIT);

            if (is_exec_write && is_private && is_committed) {
                rwx_region_count++;
                rwx_total_bytes += mbi.RegionSize;
            }

            uint8_t* next = addr + mbi.RegionSize;
            if (next <= addr) break; // overflow guard, shouldn't normally happen
            addr = next;
        }

        CloseHandle(h);

        // a region or two of rwx private memory isn't unheard of (some jits
        // do this legitimately), but a decent chunk of it is worth a look
        if (rwx_total_bytes > 64 * 1024) {
            Finding f;
            f.severity = Severity::warn;
            f.category = "memory";
            f.title = "process has private rwx memory (" + get_proc_name(pid) + ")";
            f.detail = "pid " + std::to_string(pid) + ", " + std::to_string(rwx_region_count)
                       + " region(s), " + std::to_string(rwx_total_bytes / 1024) + " kb total - "
                       "could be a jit doing its thing, could be shellcode, worth a closer look";
            out.push_back(f);
        }
    }

    return out;
}

} // namespace ratwatch

#else // not windows

namespace ratwatch {
FindingList scan_memory() { return {}; }
} // namespace ratwatch

#endif
