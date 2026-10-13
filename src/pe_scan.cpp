#include "pe_scan.h"

#include <fstream>
#include <cmath>
#include <cstring>
#include <array>

namespace ratwatch {

namespace {

// just the handful of fields we actually care about, laid out manually so
// we don't need <windows.h> to read a pe file. field offsets here are the
// standard documented pe/coff layout, nothing exotic.

uint16_t read_u16(const std::vector<uint8_t>& buf, size_t off) {
    if (off + 2 > buf.size()) return 0;
    return (uint16_t)(buf[off] | (buf[off + 1] << 8));
}

uint32_t read_u32(const std::vector<uint8_t>& buf, size_t off) {
    if (off + 4 > buf.size()) return 0;
    return (uint32_t)(buf[off] | (buf[off + 1] << 8) | (buf[off + 2] << 16) | (buf[off + 3] << 24));
}

} // namespace

double shannon_entropy(const std::vector<uint8_t>& data) {
    if (data.empty()) return 0.0;

    std::array<size_t, 256> counts{};
    for (uint8_t b : data) counts[b]++;

    double entropy = 0.0;
    double total = (double)data.size();
    for (size_t c : counts) {
        if (c == 0) continue;
        double p = (double)c / total;
        entropy -= p * std::log2(p);
    }
    return entropy;
}

PeInfo parse_pe_file(const std::string& path) {
    PeInfo info;

    std::ifstream in(path, std::ios::binary);
    if (!in.is_open()) return info;

    std::vector<uint8_t> buf((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    if (buf.size() < 0x40) return info; // too small to even have a dos header

    // dos header: "MZ" magic, e_lfanew at offset 0x3c points to the pe header
    if (buf[0] != 'M' || buf[1] != 'Z') return info;

    uint32_t pe_offset = read_u32(buf, 0x3c);
    if (pe_offset == 0 || pe_offset + 24 > buf.size()) return info;

    // pe signature "PE\0\0"
    if (buf[pe_offset] != 'P' || buf[pe_offset + 1] != 'E' ||
        buf[pe_offset + 2] != 0 || buf[pe_offset + 3] != 0) {
        return info;
    }

    info.valid_pe = true;

    size_t coff_header = pe_offset + 4;
    uint16_t num_sections = read_u16(buf, coff_header + 2);
    uint16_t opt_header_size = read_u16(buf, coff_header + 16);
    info.num_sections = num_sections;

    size_t opt_header = coff_header + 20;
    if (opt_header + 2 > buf.size()) return info;

    uint16_t magic = read_u16(buf, opt_header);
    info.is_64bit = (magic == 0x20b); // PE32+ magic

    // data directories live at a different offset depending on 32 vs 64 bit,
    // the clr/cor20 header is data directory index 14
    size_t data_dir_offset = opt_header + (info.is_64bit ? 112 : 96);
    size_t clr_dir_entry = data_dir_offset + (14 * 8);
    if (clr_dir_entry + 4 <= buf.size()) {
        uint32_t clr_rva = read_u32(buf, clr_dir_entry);
        info.is_dotnet = (clr_rva != 0);
    }

    // walk the section table to grab names/sizes and compute entropy per
    // section. section table starts right after the optional header.
    size_t section_table = opt_header + opt_header_size;
    uint32_t highest_end_of_raw_data = 0;

    for (uint16_t i = 0; i < num_sections; i++) {
        size_t entry = section_table + (i * 40); // each section header is 40 bytes
        if (entry + 40 > buf.size()) break;

        char name_buf[9] = {0};
        std::memcpy(name_buf, &buf[entry], 8);

        uint32_t raw_size = read_u32(buf, entry + 16);
        uint32_t raw_ptr = read_u32(buf, entry + 20);

        SectionInfo sec;
        sec.name = name_buf;
        sec.raw_size = raw_size;

        if (raw_ptr > 0 && raw_size > 0 && raw_ptr + raw_size <= buf.size()) {
            std::vector<uint8_t> section_data(buf.begin() + raw_ptr, buf.begin() + raw_ptr + raw_size);
            sec.entropy = shannon_entropy(section_data);
            highest_end_of_raw_data = std::max(highest_end_of_raw_data, raw_ptr + raw_size);
        }

        info.sections.push_back(sec);
    }

    if (highest_end_of_raw_data > 0 && highest_end_of_raw_data < buf.size()) {
        info.overlay_size = (uint32_t)(buf.size() - highest_end_of_raw_data);
    }

    return info;
}

FindingList evaluate_pe(const std::string& path, const PeInfo& info) {
    FindingList out;

    if (!info.valid_pe) {
        Finding f;
        f.severity = Severity::info;
        f.category = "static";
        f.title = "not a valid pe file (or couldn't read it)";
        f.detail = path;
        out.push_back(f);
        return out;
    }

    if (info.num_sections == 0) {
        Finding f;
        f.severity = Severity::warn;
        f.category = "static";
        f.title = "pe file has zero sections, that's not normal";
        f.detail = path;
        out.push_back(f);
    }

    for (const auto& sec : info.sections) {
        // 7.2 is a pretty common threshold in writeups for "probably packed
        // or encrypted", real code (even compiled release binaries) tends
        // to sit lower than that
        if (sec.entropy > 7.2 && sec.raw_size > 4096) {
            Finding f;
            f.severity = Severity::warn;
            f.category = "static";
            f.title = "high entropy section (" + sec.name + "), might be packed or encrypted";
            f.detail = path + " section=" + sec.name + " entropy=" + std::to_string(sec.entropy)
                       + " size=" + std::to_string(sec.raw_size);
            out.push_back(f);
        }
    }

    // a big overlay (data appended after the last section) is a pattern
    // seen a lot in droppers that embed a second stage or config blob
    if (info.overlay_size > 1024 * 50) {
        Finding f;
        f.severity = Severity::warn;
        f.category = "static";
        f.title = "large overlay data appended after the pe sections";
        f.detail = path + " overlay=" + std::to_string(info.overlay_size) + " bytes, "
                   "worth checking what's actually in there";
        out.push_back(f);
    }

    if (info.is_dotnet) {
        Finding f;
        f.severity = Severity::info;
        f.category = "static";
        f.title = ".net assembly";
        f.detail = path + " - a lot of commodity rats (xworm, njrat, etc) are .net, "
                   "doesn't mean it's bad on its own, just worth knowing";
        out.push_back(f);
    }

    return out;
}

} // namespace ratwatch
