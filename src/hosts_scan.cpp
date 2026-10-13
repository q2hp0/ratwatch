#include "hosts_scan.h"

#include <fstream>
#include <sstream>
#include <cstdint>

namespace ratwatch {

std::string simple_hash(const std::string& content) {
    uint64_t h = 14695981039346656037ULL; // fnv offset basis
    for (unsigned char c : content) {
        h ^= c;
        h *= 1099511628211ULL; // fnv prime
    }
    std::ostringstream oss;
    oss << std::hex << h;
    return oss.str();
}

FindingList check_hosts_file(const std::string& hosts_path, const std::string& hash_store_path) {
    FindingList out;

    std::ifstream hosts_in(hosts_path, std::ios::binary);
    if (!hosts_in.is_open()) return out; // nothing we can do if we can't read it

    std::string content((std::istreambuf_iterator<char>(hosts_in)), std::istreambuf_iterator<char>());
    std::string current_hash = simple_hash(content);

    std::string previous_hash;
    std::ifstream store_in(hash_store_path);
    if (store_in.is_open()) {
        std::getline(store_in, previous_hash);
    }

    if (previous_hash.empty()) {
        // first run, nothing to compare against yet, just save it
        std::ofstream store_out(hash_store_path, std::ios::trunc);
        if (store_out.is_open()) store_out << current_hash;
        return out;
    }

    if (current_hash != previous_hash) {
        Finding f;
        f.severity = Severity::warn;
        f.category = "persistence";
        f.title = "hosts file changed since last check";
        f.detail = hosts_path + " - worth opening it and checking for entries you didn't add, "
                   "redirecting a domain or blocking av updates is a known trick";
        out.push_back(f);

        std::ofstream store_out(hash_store_path, std::ios::trunc);
        if (store_out.is_open()) store_out << current_hash;
    }

    return out;
}

} // namespace ratwatch
