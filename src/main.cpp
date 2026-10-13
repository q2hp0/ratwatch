#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include <cstdlib>

#include "finding.h"
#include "baseline.h"
#include "config.h"
#include "persistence_scan.h"
#include "process_scan.h"
#include "network_scan.h"
#include "memory_scan.h"
#include "pe_scan.h"
#include "responder.h"
#include "service_scan.h"
#include "wmi_scan.h"
#include "hosts_scan.h"
#include "signatures.h"
#include "log.h"
#include <fstream>
#include <ctime>

namespace {

const char* kBaselineFile = "ratwatch_baseline.txt";
const char* kConfigFile = "ratwatch.conf";
const char* kLogFile = "ratwatch.log";
const char* kHostsHashFile = "ratwatch_hosts.hash";

std::string windows_hosts_path() {
    const char* sysroot = std::getenv("SystemRoot");
    std::string root = sysroot ? sysroot : "C:\\Windows";
    return root + "\\System32\\drivers\\etc\\hosts";
}

ratwatch::FindingList run_all_scans(const ratwatch::Baseline* baseline, const ratwatch::Config& cfg) {
    (void)cfg;
    ratwatch::FindingList all;

    auto append = [&all](ratwatch::FindingList part) {
        for (auto& f : part) all.push_back(std::move(f));
    };

    append(ratwatch::scan_persistence(baseline));
    append(ratwatch::scan_scheduled_tasks(baseline));
    append(ratwatch::scan_services(baseline));
    append(ratwatch::scan_wmi_subscriptions(baseline));
    append(ratwatch::scan_processes());
    append(ratwatch::scan_network());
    append(ratwatch::scan_memory());
    append(ratwatch::check_hosts_file(windows_hosts_path(), kHostsHashFile));

    return all;
}

ratwatch::Config load_config() {
    ratwatch::Config cfg;
    cfg.load(kConfigFile); // fine if it doesn't exist, just means no extra rules
    return cfg;
}

int cmd_scan() {
    ratwatch::Config cfg = load_config();

    ratwatch::Baseline baseline;
    bool has_baseline = baseline.load(kBaselineFile);
    if (!has_baseline) {
        std::cout << "no baseline found, run 'ratwatch baseline' first if you want\n"
                      "quieter output next time. showing everything for now.\n\n";
    }

    auto findings = run_all_scans(has_baseline ? &baseline : nullptr, cfg);
    ratwatch::print_findings(findings);
    return findings.empty() ? 0 : 1;
}

int cmd_baseline() {
    ratwatch::Config cfg = load_config();
    ratwatch::Baseline baseline;

    auto findings = run_all_scans(nullptr, cfg);
    for (const auto& f : findings) {
        if (f.category == "persistence") {
            if (f.title.rfind("new autorun entry", 0) == 0) {
                baseline.add("runkey", f.detail.substr(0, f.detail.find(" = ")));
            } else if (f.title.rfind("new file in startup folder", 0) == 0) {
                baseline.add("startupfile", f.detail);
            } else if (f.title.rfind("scheduled task", 0) == 0) {
                baseline.add("task", f.title.substr(std::string("scheduled task: ").size()));
            } else if (f.title.rfind("new service", 0) == 0) {
                baseline.add("service", f.title.substr(std::string("new service: ").size()));
            } else if (f.title.rfind("service with a sketchy binary path", 0) == 0) {
                baseline.add("service", f.title.substr(f.title.find(": ") + 2));
            } else if (f.title.rfind("wmi event consumer found", 0) == 0) {
                baseline.add("wmi_consumer", f.title.substr(std::string("wmi event consumer found: ").size()));
            }
        }
    }

    if (baseline.save(kBaselineFile)) {
        std::cout << "saved baseline with " << baseline.count() << " known entries to "
                      << kBaselineFile << "\n";
        return 0;
    }
    std::cerr << "couldn't write baseline file, check permissions\n";
    return 1;
}

int cmd_watch() {
    ratwatch::Config cfg = load_config();
    ratwatch::Baseline baseline;
    bool has_baseline = baseline.load(kBaselineFile);

    std::cout << "watching... checking every 5 seconds, ctrl+c to stop\n";
    std::cout << "logging to " << kLogFile << "\n\n";

    for (;;) {
        auto findings = run_all_scans(has_baseline ? &baseline : nullptr, cfg);
        if (!findings.empty()) {
            ratwatch::print_findings(findings);
            for (const auto& f : findings) {
                ratwatch::log_to_file(kLogFile,
                    std::string(ratwatch::severity_label(f.severity)) + " "
                    + f.category + ": " + f.title + " | " + f.detail);
            }
            std::cout << "\n";
        }
        std::this_thread::sleep_for(std::chrono::seconds(5));
    }
}

int cmd_static(const std::string& file_path) {
    auto info = ratwatch::parse_pe_file(file_path);
    auto findings = ratwatch::evaluate_pe(file_path, info);

    std::cout << "file: " << file_path << "\n";
    if (info.valid_pe) {
        std::cout << "  pe: yes, " << (info.is_64bit ? "64-bit" : "32-bit")
                   << ", " << info.num_sections << " section(s)"
                   << (info.is_dotnet ? ", .net assembly" : "") << "\n";
        for (const auto& sec : info.sections) {
            std::cout << "    section " << sec.name << ": " << sec.raw_size
                       << " bytes, entropy " << sec.entropy << "\n";
        }
        if (info.overlay_size > 0) {
            std::cout << "  overlay: " << info.overlay_size << " bytes after last section\n";
        }
    } else {
        std::cout << "  not a valid pe file\n";
    }
    std::cout << "\n";

    ratwatch::print_findings(findings);
    return findings.empty() ? 0 : 1;
}

int cmd_mem() {
    auto findings = ratwatch::scan_memory();
    ratwatch::print_findings(findings);
    return findings.empty() ? 0 : 1;
}

int cmd_suspend(const std::string& pid_str) {
    uint32_t pid = (uint32_t)std::strtoul(pid_str.c_str(), nullptr, 10);
    if (pid == 0) {
        std::cerr << "give me a real pid\n";
        return 1;
    }
    int n = ratwatch::suspend_process(pid);
    std::cout << "suspended " << n << " thread(s) in pid " << pid << "\n";
    return n > 0 ? 0 : 1;
}

int cmd_resume(const std::string& pid_str) {
    uint32_t pid = (uint32_t)std::strtoul(pid_str.c_str(), nullptr, 10);
    if (pid == 0) {
        std::cerr << "give me a real pid\n";
        return 1;
    }
    int n = ratwatch::resume_process(pid);
    std::cout << "resumed " << n << " thread(s) in pid " << pid << "\n";
    return n > 0 ? 0 : 1;
}

int cmd_quarantine(const std::string& file_path) {
    std::string new_path;
    if (ratwatch::quarantine_file(file_path, new_path)) {
        std::cout << "moved to " << new_path << "\n";
        return 0;
    }
    std::cerr << "couldn't quarantine that file, does it exist?\n";
    return 1;
}

int cmd_strings(const std::string& file_path) {
    auto findings = ratwatch::scan_file_strings(file_path);
    if (findings.empty()) {
        std::cout << "no known indicator strings found in " << file_path << "\n"
                      "(doesn't mean it's clean, just means it didn't hit the small list we check)\n";
        return 0;
    }
    ratwatch::print_findings(findings);
    return 1;
}

// bundles a full scan plus whatever static/strings checks were asked for
// into one text file, so you've got something to paste or keep around
// instead of just terminal scrollback
int cmd_report(const std::string& out_path) {
    ratwatch::Config cfg = load_config();
    ratwatch::Baseline baseline;
    bool has_baseline = baseline.load(kBaselineFile);

    auto findings = run_all_scans(has_baseline ? &baseline : nullptr, cfg);

    std::ofstream out(out_path, std::ios::trunc);
    if (!out.is_open()) {
        std::cerr << "couldn't open " << out_path << " for writing\n";
        return 1;
    }

    std::time_t now = std::time(nullptr);
    out << "ratwatch report - " << std::ctime(&now);
    out << "baseline loaded: " << (has_baseline ? "yes" : "no") << "\n";
    out << findings.size() << " finding(s)\n\n";

    for (const auto& f : findings) {
        out << "[" << ratwatch::severity_label(f.severity) << "] " << f.category << ": " << f.title << "\n";
        if (!f.detail.empty()) out << "    " << f.detail << "\n";
    }

    std::cout << "wrote report to " << out_path << " (" << findings.size() << " finding(s))\n";
    return findings.empty() ? 0 : 1;
}

void print_usage() {
    std::cout <<
        "ratwatch - small windows watchdog against rat-style persistence/behavior\n\n"
        "usage:\n"
        "  ratwatch scan                one-shot check across everything\n"
        "  ratwatch baseline             save current state as known-good\n"
        "  ratwatch watch                keep checking every 5s\n"
        "  ratwatch static <file.exe>    analyze a single pe file (entropy, .net, overlay)\n"
        "  ratwatch mem                  scan running processes for rwx private memory\n"
        "  ratwatch suspend <pid>        freeze all threads in a process\n"
        "  ratwatch resume <pid>         undo suspend\n"
        "  ratwatch quarantine <file>    move a file into ./quarantine/\n"
        "  ratwatch strings <file>       check a file's strings against known rat indicators\n"
        "  ratwatch report [out.txt]     run a full scan and write a text report\n\n"
        "scan/watch/baseline also now cover services and wmi event consumers,\n"
        "and check the hosts file for changes between runs.\n\n"
        "drop a ratwatch.conf next to the exe to customize allowlists,\n"
        "see ratwatch.conf.example for the format.\n";
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        print_usage();
        return 1;
    }

    std::string cmd = argv[1];
    if (cmd == "scan") return cmd_scan();
    if (cmd == "baseline") return cmd_baseline();
    if (cmd == "watch") return cmd_watch();
    if (cmd == "mem") return cmd_mem();

    if (cmd == "static") {
        if (argc < 3) { std::cerr << "usage: ratwatch static <file.exe>\n"; return 1; }
        return cmd_static(argv[2]);
    }
    if (cmd == "suspend") {
        if (argc < 3) { std::cerr << "usage: ratwatch suspend <pid>\n"; return 1; }
        return cmd_suspend(argv[2]);
    }
    if (cmd == "resume") {
        if (argc < 3) { std::cerr << "usage: ratwatch resume <pid>\n"; return 1; }
        return cmd_resume(argv[2]);
    }
    if (cmd == "quarantine") {
        if (argc < 3) { std::cerr << "usage: ratwatch quarantine <file>\n"; return 1; }
        return cmd_quarantine(argv[2]);
    }
    if (cmd == "strings") {
        if (argc < 3) { std::cerr << "usage: ratwatch strings <file>\n"; return 1; }
        return cmd_strings(argv[2]);
    }
    if (cmd == "report") {
        std::string out_path = argc >= 3 ? argv[2] : "ratwatch_report.txt";
        return cmd_report(out_path);
    }

    print_usage();
    return 1;
}
