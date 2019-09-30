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
#include <inttypes.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include <android-base/stringprintf.h>
#include <meminfo/procmeminfo.h>

using Vma = ::android::meminfo::Vma;
using ProcMemInfo = ::android::meminfo::ProcMemInfo;
using MemUsage = ::android::meminfo::MemUsage;

// Global flags to control procmem output

// Set to use page idle bits for working set detection
bool use_pageidle = false;
// hides map entries with zero rss
bool hide_zeroes = false;
// Reset working set and exit
bool reset_wss = false;
// Show working set, mutually exclusive with reset_wss;
bool show_wss = false;

[[noreturn]] static void usage(int exit_status) {
    fprintf(stderr,
            "Usage: %s [-i] [ -w | -W ] [ -p | -m ] [ -h ] pid\n"
            "    -i  Uses idle page tracking for working set statistics.\n"
            "    -w  Displays statistics for the working set only.\n"
            "    -W  Resets the working set of the process.\n"
            "    -p  Sort by PSS.\n"
            "    -u  Sort by USS.\n"
            "    -m  Sort by mapping order (as read from /proc).\n"
            "    -h  Hide maps with no RSS.\n",
            getprogname());

    exit(exit_status);
}

static void print_separator(std::stringstream& ss) {
    if (show_wss) {
        ss << ::android::base::StringPrintf("%7s  %7s  %7s  %7s  %7s  %7s  %7s  %7s  %s\n",
                                            "-------", "-------", "-------", "-------", "-------",
                                            "-------", "-------", "-------", "");
        return;
    }
    ss << ::android::base::StringPrintf("%7s  %7s  %7s  %7s  %7s  %7s  %7s  %7s  %7s  %s\n",
                                        "-------", "-------", "-------", "-------", "-------",
                                        "-------", "-------", "-------", "-------", "");
}

static void print_header(std::stringstream& ss) {
    if (show_wss) {
        ss << ::android::base::StringPrintf("%7s  %7s  %7s  %7s  %7s  %7s  %7s  %7s  %s\n", "WRss",
                                            "WPss", "WUss", "WShCl", "WShDi", "WPrCl", "WPrDi",
                                            "Flags", "Name");
    } else {
        ss << ::android::base::StringPrintf("%7s  %7s  %7s  %7s  %7s  %7s  %7s  %7s  %7s  %s\n",
                                            "Vss", "Rss", "Pss", "Uss", "ShCl", "ShDi", "PrCl",
                                            "PrDi", "Flags", "Name");
    }
    print_separator(ss);
}

static void print_stats(std::stringstream& ss, const MemUsage& stats) {
    if (!show_wss) {
        ss << ::android::base::StringPrintf("%6" PRIu64 "K  ", stats.vss / 1024);
    }

    ss << ::android::base::StringPrintf("%6" PRIu64 "K  %6" PRIu64 "K  %6" PRIu64 "K  %6" PRIu64
                                        "K  %6" PRIu64 "K  %6" PRIu64 "K  %6" PRIu64 "K  ",
                                        stats.rss / 1024, stats.pss / 1024, stats.uss / 1024,
                                        stats.shared_clean / 1024, stats.shared_dirty / 1024,
                                        stats.private_clean / 1024, stats.private_dirty / 1024);
}

static int show(const MemUsage& proc_stats, const std::vector<Vma>& maps) {
    std::stringstream ss;
    print_header(ss);
    for (auto& vma : maps) {
        const MemUsage& vma_stats = vma.usage;
        if (hide_zeroes && vma_stats.rss == 0) {
            continue;
        }
        print_stats(ss, vma_stats);

        // TODO: b/141711064 fix libprocinfo to record (p)rivate or (s)hared flag
        // for now always report as private
        std::string flags_str("---p");
        if (vma.flags & PROT_READ) flags_str[0] = 'r';
        if (vma.flags & PROT_WRITE) flags_str[1] = 'w';
        if (vma.flags & PROT_EXEC) flags_str[2] = 'x';

        ss << ::android::base::StringPrintf("%7s  ", flags_str.c_str()) << vma.name << std::endl;
    }
    print_separator(ss);
    print_stats(ss, proc_stats);
    ss << "TOTAL" << std::endl;
    std::cout << ss.str();

    return 0;
}

int main(int argc, char* argv[]) {
    int opt;
    auto pss_sort = [](const Vma& a, const Vma& b) {
        uint64_t pss_a = a.usage.pss;
        uint64_t pss_b = b.usage.pss;
        return pss_a > pss_b;
    };

    auto uss_sort = [](const Vma& a, const Vma& b) {
        uint64_t uss_a = a.usage.uss;
        uint64_t uss_b = b.usage.uss;
        return uss_a > uss_b;
    };

    std::function<bool(const Vma& a, const Vma& b)> sort_func = nullptr;
    while ((opt = getopt(argc, argv, "himpuWw")) != -1) {
        switch (opt) {
            case 'h':
                hide_zeroes = true;
                break;
            case 'i':
                // TODO: libmeminfo doesn't support the flag to chose
                // between idle page tracking vs clear_refs. So for now,
                // this flag is unused and the library defaults to using
                // /proc/<pid>/clear_refs for finding the working set.
                use_pageidle = true;
                break;
            case 'm':
                // this is the default
                break;
            case 'p':
                sort_func = pss_sort;
                break;
            case 'u':
                sort_func = uss_sort;
                break;
            case 'W':
                reset_wss = true;
                break;
            case 'w':
                show_wss = true;
                break;
            case '?':
                usage(EXIT_SUCCESS);
            default:
                usage(EXIT_FAILURE);
        }
    }

    if (optind != (argc - 1)) {
        fprintf(stderr, "Need exactly one pid at the end\n");
        usage(EXIT_FAILURE);
    }

    pid_t pid = atoi(argv[optind]);
    if (pid == 0) {
        std::cerr << "Invalid process id" << std::endl;
        exit(EXIT_FAILURE);
    }

    if (reset_wss) {
        if (!ProcMemInfo::ResetWorkingSet(pid)) {
            std::cerr << "Failed to reset working set of pid : " << pid << std::endl;
            exit(EXIT_FAILURE);
        }
        return 0;
    }

    ProcMemInfo proc(pid, show_wss);
    const MemUsage& proc_stats = proc.Usage();
    std::vector<Vma> maps(proc.Maps());
    if (sort_func != nullptr) {
        std::sort(maps.begin(), maps.end(), sort_func);
    }

    return show(proc_stats, maps);
}
