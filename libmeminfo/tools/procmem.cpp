/*
 * Copyright (C) 2018 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include <meminfo/procmeminfo.h>

using ProcMemInfo = ::android::meminfo::ProcMemInfo;
using MemUsage = ::android::meminfo::MemUsage;

static void usage(const char* cmd) {
    fprintf(stderr,
            "Usage: %s [-i] [ -w | -W ] [ -p | -m ] [ -h ] pid\n"
            "    -i  Uses idle page tracking for working set statistics.\n"
            "    -w  Displays statistics for the working set only.\n"
            "    -W  Resets the working set of the process.\n"
            "    -p  Sort by PSS.\n"
            "    -u  Sort by USS.\n"
            "    -m  Sort by mapping order (as read from /proc).\n"
            "    -h  Hide maps with no RSS.\n",
            cmd);
}

static void show_footer(uint32_t nelem, const std::string& padding) {
    std::string elem(7, '-');

    for (uint32_t i = 0; i < nelem; ++i) {
        std::cout << std::setw(7) << elem << padding;
    }
    std::cout << std::endl;
}

static void show_header(const std::vector<std::string>& header, const std::string& padding) {
    if (header.empty()) return;

    for (size_t i = 0; i < header.size() - 1; ++i) {
        std::cout << std::setw(7) << header[i] << padding;
    }
    std::cout << header.back() << std::endl;
    show_footer(header.size() - 1, padding);
}

static void scan_usage(std::stringstream& ss, const MemUsage& usage, const std::string& padding,
                       bool show_wss) {
    // clear string stream first.
    ss.str("");
    // TODO: use ::android::base::StringPrintf instead of <iomanip> here.
    if (!show_wss)
        ss << std::setw(6) << usage.vss/1024 << padding;
    ss << std::setw(6) << usage.rss/1024 << padding << std::setw(6)
       << usage.pss/1024 << padding << std::setw(6) << usage.uss/1024 << padding
       << std::setw(6) << usage.shared_clean/1024 << padding << std::setw(6)
       << usage.shared_dirty/1024 << padding << std::setw(6)
       << usage.private_clean/1024 << padding << std::setw(6)
       << usage.private_dirty/1024 << padding;
}

static int show(ProcMemInfo& proc, bool hide_zeroes, bool show_wss) {
    const std::vector<std::string> main_header = {"Vss",  "Rss",  "Pss",  "Uss", "ShCl",
                                                  "ShDi", "PrCl", "PrDi", "Name"};
    const std::vector<std::string> wss_header = {"WRss",  "WPss",  "WUss",  "WShCl",
                                                 "WShDi", "WPrCl", "WPrDi", "Name"};
    const std::vector<std::string>& header = show_wss ? wss_header : main_header;

    // Read process memory stats
    const MemUsage& stats = show_wss ? proc.Wss() : proc.Usage();
    const std::vector<::android::meminfo::Vma>& maps = proc.Maps();

    // following retains 'procmem' output so as to not break any scripts
    // that rely on it.
    std::string spaces = "  ";
    show_header(header, spaces);
    const std::string padding = "K  ";
    std::stringstream ss;
    for (auto& vma : maps) {
        const MemUsage& vma_stats = show_wss ? vma.wss : vma.usage;
        if (hide_zeroes && vma_stats.rss == 0) {
            continue;
        }
        scan_usage(ss, vma_stats, padding, show_wss);
        ss << vma.name << std::endl;
        std::cout << ss.str();
    }
    show_footer(header.size() - 1, spaces);
    scan_usage(ss, stats, padding, show_wss);
    ss << "TOTAL" << std::endl;
    std::cout << ss.str();

    return 0;
}

int main(int argc, char* argv[]) {
    bool use_pageidle = false;
    bool hide_zeroes = false;
    bool wss_reset = false;
    bool show_wss = false;
    int opt;

    while ((opt = getopt(argc, argv, "himpuWw")) != -1) {
        switch (opt) {
            case 'h':
                hide_zeroes = true;
                break;
            case 'i':
                use_pageidle = true;
                break;
            case 'm':
                break;
            case 'p':
                break;
            case 'u':
                break;
            case 'W':
                wss_reset = true;
                break;
            case 'w':
                show_wss = true;
                break;
            case '?':
                usage(argv[0]);
                return 0;
            default:
                abort();
        }
    }

    if (optind != (argc - 1)) {
        fprintf(stderr, "Need exactly one pid at the end\n");
        usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    pid_t pid = atoi(argv[optind]);
    if (pid == 0) {
        std::cerr << "Invalid process id" << std::endl;
        exit(EXIT_FAILURE);
    }

    bool need_wss = wss_reset || show_wss;
    ProcMemInfo proc(pid, need_wss);
    if (wss_reset) {
        if (!proc.WssReset()) {
            std::cerr << "Failed to reset working set of pid : " << pid << std::endl;
            exit(EXIT_FAILURE);
        }
        return 0;
    }

    return show(proc, hide_zeroes, show_wss);
}
