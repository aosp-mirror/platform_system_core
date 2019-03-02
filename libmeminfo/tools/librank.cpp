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

#include <dirent.h>
#include <errno.h>
#include <error.h>
#include <inttypes.h>
#include <linux/kernel-page-flags.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <map>
#include <memory>
#include <vector>

#include <android-base/file.h>
#include <android-base/parseint.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>

#include <meminfo/procmeminfo.h>

using ::android::meminfo::MemUsage;
using ::android::meminfo::ProcMemInfo;
using ::android::meminfo::Vma;

[[noreturn]] static void usage(int exit_status) {
    fprintf(stderr,
            "Usage: %s [ -P | -L ] [ -v | -r | -p | -u | -s | -h ]\n"
            "\n"
            "Sort options:\n"
            "    -v  Sort processes by VSS.\n"
            "    -r  Sort processes by RSS.\n"
            "    -p  Sort processes by PSS.\n"
            "    -u  Sort processes by USS.\n"
            "    -s  Sort processes by swap.\n"
            "        (Default sort order is PSS.)\n"
            "    -a  Show all mappings, including stack, heap and anon.\n"
            "    -P /path  Limit libraries displayed to those in path.\n"
            "    -R  Reverse sort order (default is descending).\n"
            "    -m [r][w][x] Only list pages that exactly match permissions\n"
            "    -c  Only show cached (storage backed) pages\n"
            "    -C  Only show non-cached (ram/swap backed) pages\n"
            "    -k  Only show pages collapsed by KSM\n"
            "    -h  Display this help screen.\n",
            getprogname());
    exit(exit_status);
}

static void add_mem_usage(MemUsage* to, const MemUsage& from) {
    to->vss += from.vss;
    to->rss += from.rss;
    to->pss += from.pss;
    to->uss += from.uss;

    to->swap += from.swap;

    to->private_clean += from.private_clean;
    to->private_dirty += from.private_dirty;

    to->shared_clean += from.shared_clean;
    to->shared_dirty += from.shared_dirty;
}

struct ProcessRecord {
  public:
    ProcessRecord(pid_t pid) : pid_(-1), cmdline_("") {
        std::string fname = ::android::base::StringPrintf("/proc/%d/cmdline", pid);
        std::string cmdline;
        if (!::android::base::ReadFileToString(fname, &cmdline)) {
            fprintf(stderr, "Failed to read cmdline from: %s\n", fname.c_str());
            return;
        }
        // We deliberately don't read the proc/<pid>cmdline file directly into 'cmdline_'
        // because of some processes showing up cmdlines that end with "0x00 0x0A 0x00"
        // e.g. xtra-daemon, lowi-server
        // The .c_str() assignment below then takes care of trimming the cmdline at the first
        // 0x00. This is how original procrank worked (luckily)
        cmdline_ = cmdline.c_str();
        pid_ = pid;
        usage_.clear();
    }

    ~ProcessRecord() = default;

    bool valid() const { return pid_ != -1; }

    // Getters
    pid_t pid() const { return pid_; }
    const std::string& cmdline() const { return cmdline_; }
    const MemUsage& usage() const { return usage_; }

    // Add to the usage
    void AddUsage(const MemUsage& mem_usage) { add_mem_usage(&usage_, mem_usage); }

  private:
    pid_t pid_;
    std::string cmdline_;
    MemUsage usage_;
};

struct LibRecord {
  public:
    LibRecord(const std::string& name) : name_(name) {}
    ~LibRecord() = default;

    const std::string& name() const { return name_; }
    const MemUsage& usage() const { return usage_; }
    const std::map<pid_t, ProcessRecord>& processes() const { return procs_; }
    uint64_t pss() const { return usage_.pss; }
    void AddUsage(const ProcessRecord& proc, const MemUsage& mem_usage) {
        auto [it, inserted] = procs_.insert(std::pair<pid_t, ProcessRecord>(proc.pid(), proc));
        it->second.AddUsage(mem_usage);
        add_mem_usage(&usage_, mem_usage);
    }

  private:
    std::string name_;
    MemUsage usage_;
    std::map<pid_t, ProcessRecord> procs_;
};

// List of every library / map
static std::map<std::string, LibRecord> g_libs;

// List of library/map names that we don't want to show by default
static const std::vector<std::string> g_blacklisted_libs = {"[heap]", "[stack]"};

// Global flags affected by command line
static uint64_t g_pgflags = 0;
static uint64_t g_pgflags_mask = 0;
static uint16_t g_mapflags_mask = 0;
static bool g_all_libs = false;
static bool g_has_swap = false;
static bool g_reverse_sort = false;
static std::string g_prefix_filter = "";

static bool read_all_pids(std::function<bool(pid_t pid)> for_each_pid) {
    std::unique_ptr<DIR, int (*)(DIR*)> procdir(opendir("/proc"), closedir);
    if (!procdir) return false;

    struct dirent* dir;
    pid_t pid;
    while ((dir = readdir(procdir.get()))) {
        if (!::android::base::ParseInt(dir->d_name, &pid)) continue;
        if (!for_each_pid(pid)) return false;
    }

    return true;
}

static bool scan_libs_per_process(pid_t pid) {
    ProcMemInfo pmem(pid, false, g_pgflags, g_pgflags_mask);
    const std::vector<Vma> maps = pmem.Maps();
    if (maps.size() == 0) {
        // nothing to do here, continue
        return true;
    }

    ProcessRecord proc(pid);
    if (!proc.valid()) {
        fprintf(stderr, "Failed to create process record for process: %d\n", pid);
        return false;
    }

    for (auto& map : maps) {
        // skip library / map if prefix for the path doesn't match
        if (!g_prefix_filter.empty() && !::android::base::StartsWith(map.name, g_prefix_filter)) {
            continue;
        }
        // Skip maps based on map permissions
        if (g_mapflags_mask &&
            ((map.flags & (PROT_READ | PROT_WRITE | PROT_EXEC)) != g_mapflags_mask)) {
            continue;
        }

        // skip blacklisted library / map names
        if (!g_all_libs && (std::find(g_blacklisted_libs.begin(), g_blacklisted_libs.end(),
                                      map.name) != g_blacklisted_libs.end())) {
            continue;
        }

        auto [it, inserted] =
            g_libs.insert(std::pair<std::string, LibRecord>(map.name, LibRecord(map.name)));
        it->second.AddUsage(proc, map.usage);

        if (!g_has_swap && map.usage.swap) {
            g_has_swap = true;
        }
    }

    return true;
}

static uint16_t parse_mapflags(const char* mapflags) {
    uint16_t ret = 0;
    for (const char* p = mapflags; *p; p++) {
        switch (*p) {
            case 'r':
                ret |= PROT_READ;
                break;
            case 'w':
                ret |= PROT_WRITE;
                break;
            case 'x':
                ret |= PROT_EXEC;
                break;
            default:
                error(EXIT_FAILURE, 0, "Invalid permissions string: %s, %s", mapflags, p);
        }
    }

    return ret;
}

int main(int argc, char* argv[]) {
    int opt;

    auto pss_sort = [](const ProcessRecord& a, const ProcessRecord& b) {
        return g_reverse_sort ? a.usage().pss < b.usage().pss : a.usage().pss > b.usage().pss;
    };

    auto uss_sort = [](const ProcessRecord& a, const ProcessRecord& b) {
        return g_reverse_sort ? a.usage().uss < b.usage().uss : a.usage().uss > b.usage().uss;
    };

    auto vss_sort = [](const ProcessRecord& a, const ProcessRecord& b) {
        return g_reverse_sort ? a.usage().vss < b.usage().vss : a.usage().vss > b.usage().vss;
    };

    auto rss_sort = [](const ProcessRecord& a, const ProcessRecord& b) {
        return g_reverse_sort ? a.usage().rss < b.usage().rss : a.usage().rss > b.usage().rss;
    };

    auto swap_sort = [](const ProcessRecord& a, const ProcessRecord& b) {
        return g_reverse_sort ? a.usage().swap < b.usage().swap : a.usage().swap > b.usage().swap;
    };

    std::function<bool(const ProcessRecord&, const ProcessRecord&)> sort_func = pss_sort;

    while ((opt = getopt(argc, argv, "acChkm:pP:uvrsR")) != -1) {
        switch (opt) {
            case 'a':
                g_all_libs = true;
                break;
            case 'c':
                g_pgflags = 0;
                g_pgflags_mask = (1 << KPF_SWAPBACKED);
                break;
            case 'C':
                g_pgflags = g_pgflags_mask = (1 << KPF_SWAPBACKED);
                break;
            case 'h':
                usage(EXIT_SUCCESS);
            case 'k':
                g_pgflags = g_pgflags_mask = (1 << KPF_KSM);
                break;
            case 'm':
                g_mapflags_mask = parse_mapflags(optarg);
                break;
            case 'p':
                sort_func = pss_sort;
                break;
            case 'P':
                g_prefix_filter = optarg;
                break;
            case 'u':
                sort_func = uss_sort;
                break;
            case 'v':
                sort_func = vss_sort;
                break;
            case 'r':
                sort_func = rss_sort;
                break;
            case 's':
                sort_func = swap_sort;
                break;
            case 'R':
                g_reverse_sort = true;
                break;
            default:
                usage(EXIT_FAILURE);
        }
    }

    if (!read_all_pids(scan_libs_per_process)) {
        error(EXIT_FAILURE, 0, "Failed to read all pids from the system");
    }

    printf(" %6s   %7s   %6s   %6s   %6s  ", "RSStot", "VSS", "RSS", "PSS", "USS");
    if (g_has_swap) {
        printf(" %6s  ", "Swap");
    }
    printf("Name/PID\n");

    std::vector<LibRecord> v_libs;
    v_libs.reserve(g_libs.size());
    std::transform(g_libs.begin(), g_libs.end(), std::back_inserter(v_libs),
        [] (std::pair<std::string, LibRecord> const& pair) { return pair.second; });

    // sort the libraries by their pss
    std::sort(v_libs.begin(), v_libs.end(),
              [](const LibRecord& l1, const LibRecord& l2) { return l1.pss() > l2.pss(); });

    for (auto& lib : v_libs) {
        printf("%6" PRIu64 "K   %7s   %6s   %6s   %6s  ", lib.pss() / 1024, "", "", "", "");
        if (g_has_swap) {
            printf(" %6s  ", "");
        }
        printf("%s\n", lib.name().c_str());

        // sort all mappings first

        std::vector<ProcessRecord> procs;
        procs.reserve(lib.processes().size());
        std::transform(lib.processes().begin(), lib.processes().end(), std::back_inserter(procs),
            [] (std::pair<pid_t, ProcessRecord> const& pair) { return pair.second; });

        std::sort(procs.begin(), procs.end(), sort_func);

        for (auto& p : procs) {
            const MemUsage& usage = p.usage();
            printf(" %6s  %7" PRIu64 "K  %6" PRIu64 "K  %6" PRIu64 "K  %6" PRIu64 "K  ", "",
                   usage.vss / 1024, usage.rss / 1024, usage.pss / 1024, usage.uss / 1024);
            if (g_has_swap) {
                printf("%6" PRIu64 "K  ", usage.swap / 1024);
            }
            printf("  %s [%d]\n", p.cmdline().c_str(), p.pid());
        }
    }

    return 0;
}
