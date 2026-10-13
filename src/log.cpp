#include "log.h"

#include <iostream>
#include <fstream>
#include <ctime>
#include <iomanip>
#include <sstream>

namespace ratwatch {

namespace {

std::string now_str() {
    std::time_t t = std::time(nullptr);
    std::tm tm_buf{};
#if defined(_WIN32)
    localtime_s(&tm_buf, &t);
#else
    localtime_r(&t, &tm_buf);
#endif
    std::ostringstream oss;
    oss << std::put_time(&tm_buf, "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

} // namespace

void print_finding(const Finding& f) {
    // not bothering with actual ansi color detection, just always emit it -
    // windows terminal and most modern consoles handle this fine these days
    const char* color = "";
    const char* reset = "\033[0m";
    switch (f.severity) {
        case Severity::info: color = "\033[36m"; break; // cyan
        case Severity::warn: color = "\033[33m"; break; // yellow
        case Severity::bad:  color = "\033[31m"; break; // red
    }

    std::cout << color << "[" << severity_label(f.severity) << "] "
               << f.category << ": " << f.title << reset << "\n";
    if (!f.detail.empty()) {
        std::cout << "       -> " << f.detail << "\n";
    }
}

void print_findings(const FindingList& findings) {
    if (findings.empty()) {
        std::cout << "nothing jumped out, looks clean for now\n";
        return;
    }
    for (const auto& f : findings) {
        print_finding(f);
    }
    std::cout << findings.size() << " finding(s)\n";
}

void log_to_file(const std::string& path, const std::string& line) {
    std::ofstream out(path, std::ios::app);
    if (!out.is_open()) return;
    out << "[" << now_str() << "] " << line << "\n";
}

} // namespace ratwatch
