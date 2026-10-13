// super lightweight test harness, didn't want to pull in gtest/catch2 for
// a project this size. just a few asserts with a counter at the end.

#include <iostream>
#include <fstream>
#include <cstdio>
#include <vector>
#include <cmath>
#include "baseline.h"
#include "config.h"
#include "pe_scan.h"
#include "hosts_scan.h"
#include "signatures.h"

namespace {

int g_failures = 0;
int g_checks = 0;

void check(bool cond, const char* what) {
    g_checks++;
    if (!cond) {
        g_failures++;
        std::cout << "FAIL: " << what << "\n";
    }
}

// ---------- baseline ----------

void test_baseline_empty_by_default() {
    ratwatch::Baseline b;
    check(b.count() == 0, "fresh baseline should have 0 entries");
    check(!b.contains("runkey", "nothing"), "fresh baseline shouldn't contain random stuff");
}

void test_baseline_add_and_contains() {
    ratwatch::Baseline b;
    b.add("runkey", "HKCU\\...\\Run\\Foo");
    check(b.contains("runkey", "HKCU\\...\\Run\\Foo"), "should contain what we just added");
    check(!b.contains("runkey", "HKCU\\...\\Run\\Bar"), "shouldn't contain something we didn't add");
    check(!b.contains("task", "HKCU\\...\\Run\\Foo"), "same value but different kind shouldn't match");
}

void test_baseline_save_and_load_roundtrip() {
    const char* tmp_path = "test_baseline_tmp.txt";

    ratwatch::Baseline b1;
    b1.add("runkey", "HKCU\\...\\Run\\Thing");
    b1.add("startupfile", "C:\\Users\\bob\\Startup\\thing.lnk");
    b1.add("task", "my weird task");

    check(b1.save(tmp_path), "save should succeed");

    ratwatch::Baseline b2;
    check(b2.load(tmp_path), "load should succeed for a file we just wrote");
    check(b2.count() == 3, "loaded baseline should have same number of entries");
    check(b2.contains("runkey", "HKCU\\...\\Run\\Thing"), "roundtrip should preserve runkey entry");
    check(b2.contains("startupfile", "C:\\Users\\bob\\Startup\\thing.lnk"), "roundtrip should preserve startupfile entry");
    check(b2.contains("task", "my weird task"), "roundtrip should preserve task entry");

    std::remove(tmp_path);
}

void test_baseline_load_missing_file_is_not_fatal() {
    ratwatch::Baseline b;
    bool ok = b.load("this_file_definitely_does_not_exist_12345.txt");
    check(!ok, "loading a missing file should return false");
    check(b.count() == 0, "but baseline should still be usable and empty");
}

// ---------- config ----------

void test_config_missing_file_is_not_fatal() {
    ratwatch::Config cfg;
    bool ok = cfg.load("this_config_also_does_not_exist_98765.conf");
    check(!ok, "loading a missing config should return false");
    check(cfg.ignore_paths.empty(), "but should still just be an empty, usable config");
}

void test_config_parses_ignore_paths() {
    const char* tmp_path = "test_config_tmp.conf";
    {
        std::ofstream out(tmp_path);
        out << "# a comment, should be skipped\n";
        out << "\n"; // blank line, should also be skipped
        out << "ignore_path=\\AppData\\Roaming\\Discord\\\n";
        out << "ignore_path=\\Steam\\\n";
        out << "extra_shell_parent=obs64.exe\n";
        out << "ignore_run_entry=OneDrive\n";
    }

    ratwatch::Config cfg;
    check(cfg.load(tmp_path), "loading an existing config should succeed");
    check(cfg.ignore_paths.size() == 2, "should pick up both ignore_path lines");
    check(cfg.extra_shell_parents.size() == 1, "should pick up the extra_shell_parent line");
    check(cfg.ignore_run_entries.size() == 1, "should pick up the ignore_run_entry line");

    // paths get lowercased on load, so check with a lowercase needle
    check(cfg.path_is_ignored("c:\\users\\bob\\appdata\\roaming\\discord\\discord.exe"),
          "a path containing an ignored substring should be flagged as ignored");
    check(!cfg.path_is_ignored("c:\\users\\bob\\appdata\\roaming\\sketchy\\thing.exe"),
          "a path not matching any ignore rule should not be ignored");

    std::remove(tmp_path);
}

// ---------- pe_scan ----------

void test_entropy_of_uniform_data_is_zero() {
    std::vector<uint8_t> data(1000, 0x41); // all the same byte
    double e = ratwatch::shannon_entropy(data);
    check(e < 0.001, "entropy of a buffer that's all one byte value should be ~0");
}

void test_entropy_of_empty_data_is_zero() {
    std::vector<uint8_t> data;
    double e = ratwatch::shannon_entropy(data);
    check(e == 0.0, "entropy of empty data should be 0, not nan or crash");
}

void test_entropy_of_random_ish_data_is_high() {
    // not true random, but a deterministic pattern that touches most byte
    // values roughly evenly, good enough to sanity check the formula without
    // needing a real rng dependency in the test
    std::vector<uint8_t> data;
    data.reserve(4096);
    uint32_t x = 12345;
    for (int i = 0; i < 4096; i++) {
        x = x * 1103515245u + 12345u; // classic lcg, deterministic across runs
        data.push_back((uint8_t)(x >> 16));
    }
    double e = ratwatch::shannon_entropy(data);
    check(e > 7.0, "entropy of pseudo-random-looking data should be high (close to 8)");
}

void test_parse_pe_rejects_non_pe_file() {
    const char* tmp_path = "test_not_a_pe.bin";
    {
        std::ofstream out(tmp_path, std::ios::binary);
        out << "this is just a text file, not an exe at all";
    }

    auto info = ratwatch::parse_pe_file(tmp_path);
    check(!info.valid_pe, "a plain text file should not parse as a valid pe");

    std::remove(tmp_path);
}

void test_parse_pe_rejects_missing_file() {
    auto info = ratwatch::parse_pe_file("this_exe_does_not_exist_55555.exe");
    check(!info.valid_pe, "a missing file should not parse as a valid pe");
}

void test_evaluate_pe_on_invalid_file_gives_info_finding() {
    auto info = ratwatch::parse_pe_file("this_exe_also_does_not_exist_55555.exe");
    auto findings = ratwatch::evaluate_pe("this_exe_also_does_not_exist_55555.exe", info);
    check(findings.size() == 1, "an invalid pe should produce exactly one explanatory finding");
    check(findings[0].severity == ratwatch::Severity::info,
          "the 'not a valid pe' finding should just be informational, not scary");
}

// ---------- hosts_scan ----------

void test_hosts_hash_is_stable() {
    std::string a = ratwatch::simple_hash("127.0.0.1 localhost");
    std::string b = ratwatch::simple_hash("127.0.0.1 localhost");
    std::string c = ratwatch::simple_hash("127.0.0.1 localhost\nevil.example.com 6.6.6.6");
    check(a == b, "hashing the same content twice should give the same result");
    check(a != c, "different content should hash differently");
}

void test_hosts_first_run_no_finding() {
    const char* hosts = "test_fake_hosts.txt";
    const char* store = "test_fake_hosts_hash.txt";
    std::remove(store); // in case a previous failed run left it behind

    { std::ofstream out(hosts); out << "127.0.0.1 localhost\n"; }

    auto findings = ratwatch::check_hosts_file(hosts, store);
    check(findings.empty(), "first time checking a hosts file, nothing to compare against yet");

    std::remove(hosts);
    std::remove(store);
}

void test_hosts_change_is_flagged() {
    const char* hosts = "test_fake_hosts2.txt";
    const char* store = "test_fake_hosts2_hash.txt";
    std::remove(store);

    { std::ofstream out(hosts); out << "127.0.0.1 localhost\n"; }
    ratwatch::check_hosts_file(hosts, store); // establishes the baseline hash

    { std::ofstream out(hosts); out << "127.0.0.1 localhost\nevil.example.com 1.2.3.4\n"; }
    auto findings = ratwatch::check_hosts_file(hosts, store);
    check(findings.size() == 1, "a changed hosts file should produce exactly one finding");

    std::remove(hosts);
    std::remove(store);
}

// ---------- signatures ----------

void test_extract_strings_finds_ascii_text() {
    const char* tmp_path = "test_strings_ascii.bin";
    {
        std::ofstream out(tmp_path, std::ios::binary);
        out << "\x01\x02hello there friend\x00\x00\x03junk";
    }

    auto strings = ratwatch::extract_strings(tmp_path, 6);
    bool found = false;
    for (auto& s : strings) if (s == "hello there friend") found = true;
    check(found, "should pull a plain ascii string out of a binary blob");

    std::remove(tmp_path);
}

void test_extract_strings_finds_utf16_text() {
    const char* tmp_path = "test_strings_utf16.bin";
    {
        std::ofstream out(tmp_path, std::ios::binary);
        // "XwormClient" as utf16le, which is how .net stores its strings
        const char* word = "XwormClient";
        for (const char* p = word; *p; p++) {
            out.put(*p);
            out.put('\0');
        }
    }

    auto strings = ratwatch::extract_strings(tmp_path, 6);
    bool found = false;
    for (auto& s : strings) if (s.find("XwormClient") != std::string::npos) found = true;
    check(found, "should pull a utf16le string out of a binary blob too");

    std::remove(tmp_path);
}

void test_match_known_indicators() {
    std::vector<std::string> strings = { "some boring string", "XWorm-Client-v1.2", "another one" };
    auto matches = ratwatch::match_known_indicators(strings);
    check(!matches.empty(), "a string containing a known indicator should match");
    check(matches[0].matched_text == "XWorm-Client-v1.2", "the match should report back the actual string");
}

void test_match_known_indicators_no_false_positive_on_clean_strings() {
    std::vector<std::string> strings = { "System.Windows.Forms", "just a normal dll import" };
    auto matches = ratwatch::match_known_indicators(strings);
    check(matches.empty(), "ordinary looking strings shouldn't match anything");
}

} // namespace

int main() {
    test_baseline_empty_by_default();
    test_baseline_add_and_contains();
    test_baseline_save_and_load_roundtrip();
    test_baseline_load_missing_file_is_not_fatal();

    test_config_missing_file_is_not_fatal();
    test_config_parses_ignore_paths();

    test_entropy_of_uniform_data_is_zero();
    test_entropy_of_empty_data_is_zero();
    test_entropy_of_random_ish_data_is_high();
    test_parse_pe_rejects_non_pe_file();
    test_parse_pe_rejects_missing_file();
    test_evaluate_pe_on_invalid_file_gives_info_finding();

    test_hosts_hash_is_stable();
    test_hosts_first_run_no_finding();
    test_hosts_change_is_flagged();
    test_extract_strings_finds_ascii_text();
    test_extract_strings_finds_utf16_text();
    test_match_known_indicators();
    test_match_known_indicators_no_false_positive_on_clean_strings();

    std::cout << (g_checks - g_failures) << "/" << g_checks << " checks passed\n";
    return g_failures == 0 ? 0 : 1;
}
