/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include <getopt.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <memory>
#include <string>
#include <vector>

#include <meminfo/pageacct.h>
#include <meminfo/procmeminfo.h>

using ::android::meminfo::ProcMemInfo;
using ::android::meminfo::Vma;

// Global options
static int32_t g_delay = 0;
static int32_t g_total = 2;
static pid_t g_pid = -1;

[[noreturn]] static void usage(int exit_status) {
    fprintf(stderr,
            "%s [-d DELAY_BETWEEN_EACH_SAMPLE] [-n REFRESH_TOTAL] PID\n"
            "-d\tdelay between each working set sample (default 0)\n"
            "-n\ttotal number of refreshes before we exit (default 2)\n",
            getprogname());

    exit(exit_status);
}

static void print_header() {
    const char* addr1 = "           start              end ";
    const char* addr2 = "            addr             addr ";

    printf("%s  virtual                        shared    shared   private   private\n", addr1);
    printf("%s     size       RSS       PSS     clean     dirty     clean     dirty      swap   "
           "swapPSS",
           addr2);
    printf(" object\n");
}

static void print_divider() {
    printf("---------------- ---------------- ");
    printf("--------- --------- --------- --------- --------- --------- --------- --------- "
           "--------- ");
    printf("------------------------------\n");
}

static void print_vma(const Vma& v) {
    printf("%16" PRIx64 " %16" PRIx64 " ", v.start, v.end);
    printf("%8" PRIu64 "K %8" PRIu64 "K %8" PRIu64 "K %8" PRIu64 "K %8" PRIu64 "K %8" PRIu64
           "K %8" PRIu64 "K %8" PRIu64 "K %8" PRIu64 "K ",
           v.usage.vss / 1024, v.usage.rss / 1024, v.usage.pss / 1024, v.usage.shared_clean / 1024,
           v.usage.shared_dirty / 1024, v.usage.private_clean / 1024, v.usage.private_dirty / 1024,
           v.usage.swap / 1024, v.usage.swap_pss / 1024);
    printf("%s\n", v.name.c_str());
}

static bool same_vma(const Vma& cur, const Vma& last) {
    return (cur.start == last.start && cur.end == last.end && cur.name == last.name &&
            cur.flags == last.flags && cur.offset == last.offset);
}

static Vma diff_vma_params(const Vma& cur, const Vma& last) {
    Vma res;
    res.usage.shared_clean = cur.usage.shared_clean > last.usage.shared_clean
                                     ? cur.usage.shared_clean - last.usage.shared_clean
                                     : 0;
    res.usage.shared_dirty = cur.usage.shared_dirty > last.usage.shared_dirty
                                     ? cur.usage.shared_dirty - last.usage.shared_dirty
                                     : 0;
    res.usage.private_clean = cur.usage.private_clean > last.usage.private_clean
                                      ? cur.usage.private_clean - last.usage.private_clean
                                      : 0;
    res.usage.private_dirty = cur.usage.private_dirty > last.usage.private_dirty
                                      ? cur.usage.private_dirty - last.usage.private_dirty
                                      : 0;

    res.usage.rss = cur.usage.rss > last.usage.rss ? cur.usage.rss - last.usage.rss : 0;
    res.usage.pss = cur.usage.pss > last.usage.pss ? cur.usage.pss - last.usage.pss : 0;
    res.usage.uss = cur.usage.uss > last.usage.uss ? cur.usage.uss - last.usage.uss : 0;
    res.usage.swap = cur.usage.swap > last.usage.swap ? cur.usage.swap - last.usage.swap : 0;
    res.usage.swap_pss =
            cur.usage.swap_pss > last.usage.swap_pss ? cur.usage.swap_pss - last.usage.swap_pss : 0;

    // set vma properties to the same as the current one.
    res.start = cur.start;
    res.end = cur.end;
    res.offset = cur.offset;
    res.flags = cur.flags;
    res.name = cur.name;
    return res;
}

static void diff_workingset(std::vector<Vma>& wss, std::vector<Vma>& old, std::vector<Vma>* res) {
    res->clear();
    auto vma_sorter = [](const Vma& a, const Vma& b) { return a.start < b.start; };
    std::sort(wss.begin(), wss.end(), vma_sorter);
    std::sort(old.begin(), old.end(), vma_sorter);
    if (old.empty()) {
        *res = wss;
        return;
    }

    for (auto& i : wss) {
        bool found_same_vma = false;
        // TODO: This is highly inefficient, fix it if it takes
        // too long. Worst case will be system_server
        for (auto& j : old) {
            if (same_vma(i, j)) {
                res->emplace_back(diff_vma_params(i, j));
                found_same_vma = true;
                break;
            }
        }

        if (!found_same_vma) {
            res->emplace_back(i);
        }
    }

    std::sort(res->begin(), res->end(), vma_sorter);
    return;
}

static int workingset() {
    std::vector<Vma> last_wss = {};
    std::vector<Vma> diff_wss = {};
    uint32_t nr_refresh = 0;

    while (true) {
        std::unique_ptr<ProcMemInfo> proc_mem = std::make_unique<ProcMemInfo>(g_pid, true);
        std::vector<Vma> wss = proc_mem->MapsWithPageIdle();

        diff_workingset(wss, last_wss, &diff_wss);
        diff_wss.erase(std::remove_if(diff_wss.begin(), diff_wss.end(),
                                      [](const auto& v) { return v.usage.rss == 0; }),
                       diff_wss.end());
        if ((nr_refresh % 5) == 0) {
            print_header();
            print_divider();
        }

        for (const auto& v : diff_wss) {
            print_vma(v);
        }

        nr_refresh++;
        if (nr_refresh == g_total) {
            break;
        }

        last_wss = wss;
        sleep(g_delay);
        print_divider();
    }

    return 0;
}

int main(int argc, char* argv[]) {
    struct option longopts[] = {
            {"help", no_argument, nullptr, 'h'},
            {0, 0, nullptr, 0},
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "d:n:h", longopts, nullptr)) != -1) {
        switch (opt) {
            case 'd':
                g_delay = atoi(optarg);
                break;
            case 'n':
                g_total = atoi(optarg);
                break;
            case 'h':
                usage(EXIT_SUCCESS);
            default:
                usage(EXIT_FAILURE);
        }
    }

    if ((argc - 1) < optind) {
        fprintf(stderr, "Invalid arguments: Must provide <pid> at the end\n");
        usage(EXIT_FAILURE);
    }

    g_pid = atoi(argv[optind]);
    if (g_pid <= 0) {
        fprintf(stderr, "Invalid process id %s\n", argv[optind]);
        usage(EXIT_FAILURE);
    }

    if (!::android::meminfo::PageAcct::KernelHasPageIdle()) {
        fprintf(stderr, "Missing support for Idle page tracking in the kernel\n");
        return 0;
    }

    return workingset();
}
