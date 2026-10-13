#include "network_scan.h"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <chrono>
#include <cmath>
#include <map>
#include <string>
#include <vector>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

namespace ratwatch {

namespace {

std::string ip_to_string(DWORD addr) {
    in_addr a;
    a.S_un.S_addr = addr;
    char buf[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, &a, buf, sizeof(buf))) {
        return buf;
    }
    return "?";
}

// remembers the last few times we saw a given (pid, remote ip) pair connected,
// so repeated calls (from watch mode) can notice a tight regular interval.
// this is global/static on purpose, it's a cheap in-memory thing that only
// needs to live for the life of the process, not worth threading through
// every call site
struct BeaconTracker {
    struct Seen {
        std::chrono::steady_clock::time_point last_seen;
        std::vector<double> recent_gaps_sec;
    };
    std::map<std::string, Seen> history;

    bool note_and_check(const std::string& key) {
        using namespace std::chrono;
        auto now = steady_clock::now();
        auto it = history.find(key);
        if (it == history.end()) {
            history[key] = { now, {} };
            return false;
        }

        double gap = duration_cast<duration<double>>(now - it->second.last_seen).count();
        it->second.last_seen = now;

        // ignore noise, only care about gaps in a "plausible beacon" range
        if (gap < 1.0 || gap > 600.0) {
            it->second.recent_gaps_sec.clear();
            return false;
        }

        it->second.recent_gaps_sec.push_back(gap);
        if (it->second.recent_gaps_sec.size() > 5) {
            it->second.recent_gaps_sec.erase(it->second.recent_gaps_sec.begin());
        }

        if (it->second.recent_gaps_sec.size() < 3) return false;

        // check if the last few gaps are all close to each other (within 20%)
        // real beacon malware usually has jitter built in, but it's rarely
        // more than 20-30% of the base interval
        double avg = 0;
        for (double g : it->second.recent_gaps_sec) avg += g;
        avg /= it->second.recent_gaps_sec.size();

        bool all_close = true;
        for (double g : it->second.recent_gaps_sec) {
            if (avg == 0 || std::abs(g - avg) / avg > 0.25) {
                all_close = false;
                break;
            }
        }
        return all_close;
    }
};

BeaconTracker g_beacon_tracker;

} // namespace

FindingList scan_network() {
    FindingList out;

    DWORD size = 0;
    GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (size == 0) return out;

    std::vector<BYTE> buf(size);
    if (GetExtendedTcpTable(buf.data(), &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR) {
        return out;
    }

    auto* table = reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(buf.data());

    for (DWORD i = 0; i < table->dwNumEntries; i++) {
        const auto& row = table->table[i];
        if (row.dwState != MIB_TCP_STATE_ESTAB) continue; // only care about live connections

        std::string remote_ip = ip_to_string(row.dwRemoteAddr);
        DWORD remote_port = ntohs((u_short)row.dwRemotePort);
        DWORD pid = row.dwOwningPid;

        // skip loopback and obviously local stuff, not interesting
        if (remote_ip.rfind("127.", 0) == 0 || remote_ip.rfind("10.", 0) == 0) continue;

        std::string key = std::to_string(pid) + "->" + remote_ip;
        if (g_beacon_tracker.note_and_check(key)) {
            Finding f;
            f.severity = Severity::bad;
            f.category = "network";
            f.title = "regular interval connection pattern (possible beacon)";
            f.detail = "pid " + std::to_string(pid) + " -> " + remote_ip + ":" + std::to_string(remote_port);
            out.push_back(f);
        }
    }

    return out;
}

} // namespace ratwatch

#else // not windows

namespace ratwatch {
FindingList scan_network() { return {}; }
} // namespace ratwatch

#endif
