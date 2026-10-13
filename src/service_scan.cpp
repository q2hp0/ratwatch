#include "service_scan.h"

#ifdef _WIN32
#include <windows.h>
#include <string>
#include <vector>
#include <algorithm>

namespace ratwatch {

namespace {

std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return (char)std::tolower(c); });
    return s;
}

bool looks_like_weird_path(const std::string& path_lower) {
    // services legitimately live in system32, program files, programdata
    // most of the time. appdata and temp are not normal spots for a service
    // binary, that's basically always a red flag
    if (path_lower.find("\\appdata\\") != std::string::npos) return true;
    if (path_lower.find("\\temp\\") != std::string::npos) return true;
    if (path_lower.find("\\users\\public\\") != std::string::npos) return true;
    return false;
}

} // namespace

FindingList scan_services(const Baseline* baseline) {
    FindingList out;

    SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) return out;

    DWORD bytes_needed = 0, services_returned = 0, resume_handle = 0;

    // first call just to find out how big the buffer needs to be
    EnumServicesStatusExA(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
                           nullptr, 0, &bytes_needed, &services_returned, &resume_handle, nullptr);

    if (bytes_needed == 0) {
        CloseServiceHandle(scm);
        return out;
    }

    std::vector<BYTE> buf(bytes_needed);
    BOOL ok = EnumServicesStatusExA(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
                                     buf.data(), bytes_needed, &bytes_needed, &services_returned,
                                     &resume_handle, nullptr);

    if (ok) {
        auto* entries = reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSA*>(buf.data());

        for (DWORD i = 0; i < services_returned; i++) {
            SC_HANDLE svc = OpenServiceA(scm, entries[i].lpServiceName, SERVICE_QUERY_CONFIG);
            if (!svc) continue;

            DWORD cfg_bytes = 0;
            QueryServiceConfigA(svc, nullptr, 0, &cfg_bytes);

            if (cfg_bytes > 0) {
                std::vector<BYTE> cfg_buf(cfg_bytes);
                auto* cfg = reinterpret_cast<QUERY_SERVICE_CONFIGA*>(cfg_buf.data());

                if (QueryServiceConfigA(svc, cfg, cfg_bytes, &cfg_bytes) && cfg->lpBinaryPathName) {
                    std::string bin_path = cfg->lpBinaryPathName;
                    std::string lower_path = lower(bin_path);

                    bool known = baseline && baseline->contains("service", entries[i].lpServiceName);

                    if (!known && looks_like_weird_path(lower_path)) {
                        Finding f;
                        f.severity = Severity::bad;
                        f.category = "persistence";
                        f.title = "service with a sketchy binary path: " + std::string(entries[i].lpServiceName);
                        f.detail = bin_path;
                        out.push_back(f);
                    } else if (!known) {
                        // not flagged as weird-path but still new since last baseline,
                        // keep it low severity, services get created legitimately all the time
                        Finding f;
                        f.severity = Severity::info;
                        f.category = "persistence";
                        f.title = "new service: " + std::string(entries[i].lpServiceName);
                        f.detail = bin_path;
                        out.push_back(f);
                    }
                }
            }

            CloseServiceHandle(svc);
        }
    }

    CloseServiceHandle(scm);
    return out;
}

} // namespace ratwatch

#else

namespace ratwatch {
FindingList scan_services(const Baseline*) { return {}; }
} // namespace ratwatch

#endif
