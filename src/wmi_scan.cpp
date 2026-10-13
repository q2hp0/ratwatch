#include "wmi_scan.h"

#ifdef _WIN32
#include <windows.h>
#include <array>
#include <cstdio>
#include <memory>
#include <string>
#include <sstream>

namespace ratwatch {

namespace {

std::string run_command(const std::string& cmd) {
    std::unique_ptr<FILE, decltype(&_pclose)> pipe(_popen(cmd.c_str(), "r"), _pclose);
    if (!pipe) return {};

    std::string result;
    std::array<char, 512> buf{};
    while (fgets(buf.data(), (int)buf.size(), pipe.get()) != nullptr) {
        result += buf.data();
    }
    return result;
}

} // namespace

FindingList scan_wmi_subscriptions(const Baseline* baseline) {
    FindingList out;

    // CommandLineEventConsumer is the one actually used to run something,
    // __EventFilter/__FilterToConsumerBinding just wire up the trigger.
    // querying the consumer name is usually enough to notice something's there
    std::string cmd =
        "powershell -NoProfile -Command "
        "\"Get-WmiObject -Namespace root\\subscription -Class CommandLineEventConsumer "
        "| Select-Object -ExpandProperty Name\"";

    std::string output = run_command(cmd);
    if (output.empty()) return out;

    std::istringstream iss(output);
    std::string line;
    while (std::getline(iss, line)) {
        // trim trailing \r that windows loves to leave in there
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n' || line.back() == ' ')) {
            line.pop_back();
        }
        if (line.empty()) continue;

        bool known = baseline && baseline->contains("wmi_consumer", line);
        if (!known) {
            Finding f;
            f.severity = Severity::bad;
            f.category = "persistence";
            f.title = "wmi event consumer found: " + line;
            f.detail = "run 'Get-WmiObject -Namespace root\\subscription -Class "
                       "CommandLineEventConsumer' in an elevated powershell to see what it runs";
            out.push_back(f);
        }
    }

    return out;
}

} // namespace ratwatch

#else

namespace ratwatch {
FindingList scan_wmi_subscriptions(const Baseline*) { return {}; }
} // namespace ratwatch

#endif
