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
#include <inttypes.h>
#include <linux/kernel-page-flags.h>
#include <linux/oom.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include <iostream>
#include <memory>
#include <sstream>
#include <vector>

#include <android-base/file.h>
#include <android-base/parseint.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>

#include <meminfo/procmeminfo.h>
#include <meminfo/sysmeminfo.h>

using ::android::meminfo::MemUsage;
using ::android::meminfo::ProcMemInfo;

struct ProcessRecord {
  public:
    ProcessRecord(pid_t pid, bool get_wss = false, uint64_t pgflags = 0, uint64_t pgflags_mask = 0)
        : pid_(-1),
          procmem_(nullptr),
          oomadj_(OOM_SCORE_ADJ_MAX + 1),
          cmdline_(""),
          proportional_swap_(0),
          unique_swap_(0),
          zswap_(0) {
        std::unique_ptr<ProcMemInfo> procmem =
                std::make_unique<ProcMemInfo>(pid, get_wss, pgflags, pgflags_mask);
        if (procmem == nullptr) {
            std::cerr << "Failed to create ProcMemInfo for: " << pid << std::endl;
            return;
        }

        std::string fname = ::android::base::StringPrintf("/proc/%d/oom_score_adj", pid);
        auto oomscore_fp =
                std::unique_ptr<FILE, decltype(&fclose)>{fopen(fname.c_str(), "re"), fclose};
        if (oomscore_fp == nullptr) {
            std::cerr << "Failed to open oom_score_adj file: " << fname << std::endl;
            return;
        }

        if (fscanf(oomscore_fp.get(), "%d\n", &oomadj_) != 1) {
            std::cerr << "Failed to read oomadj from: " << fname << std::endl;
            return;
        }

        fname = ::android::base::StringPrintf("/proc/%d/cmdline", pid);
        if (!::android::base::ReadFileToString(fname, &cmdline_)) {
            std::cerr << "Failed to read cmdline from: " << fname << std::endl;
            cmdline_ = "<unknown>";
        }
        // We deliberately don't read the proc/<pid>cmdline file directly into 'cmdline_'
        // because of some processes showing up cmdlines that end with "0x00 0x0A 0x00"
        // e.g. xtra-daemon, lowi-server
        // The .c_str() assignment below then takes care of trimming the cmdline at the first
        // 0x00. This is how original procrank worked (luckily)
        cmdline_.resize(strlen(cmdline_.c_str()));
        procmem_ = std::move(procmem);
        pid_ = pid;
    }

    bool valid() const { return pid_ != -1; }

    void CalculateSwap(const uint16_t* swap_offset_array, float zram_compression_ratio) {
        const std::vector<uint16_t>& swp_offs = procmem_->SwapOffsets();
        for (auto& off : swp_offs) {
            proportional_swap_ += getpagesize() / swap_offset_array[off];
            unique_swap_ += swap_offset_array[off] == 1 ? getpagesize() : 0;
            zswap_ = proportional_swap_ * zram_compression_ratio;
        }
    }

    // Getters
    pid_t pid() const { return pid_; }
    const std::string& cmdline() const { return cmdline_; }
    int32_t oomadj() const { return oomadj_; }
    uint64_t proportional_swap() const { return proportional_swap_; }
    uint64_t unique_swap() const { return unique_swap_; }
    uint64_t zswap() const { return zswap_; }

    // Wrappers to ProcMemInfo
    const std::vector<uint16_t>& SwapOffsets() const { return procmem_->SwapOffsets(); }
    const MemUsage& Usage() const { return procmem_->Usage(); }
    const MemUsage& Wss() const { return procmem_->Wss(); }

  private:
    pid_t pid_;
    std::unique_ptr<ProcMemInfo> procmem_;
    int32_t oomadj_;
    std::string cmdline_;
    uint64_t proportional_swap_;
    uint64_t unique_swap_;
    uint64_t zswap_;
};

// Show working set instead of memory consumption
bool show_wss = false;
// Reset working set of each process
bool reset_wss = false;
// Show per-process oom_score_adj column
bool show_oomadj = false;
// True if the device has swap enabled
bool has_swap = false;
// True, if device has zram enabled
bool has_zram = false;
// If zram is enabled, the compression ratio is zram used / swap used.
float zram_compression_ratio = 0.0;
// Sort process in reverse, default is descending
bool reverse_sort = false;

// Calculated total memory usage across all processes in the system
uint64_t total_pss = 0;
uint64_t total_uss = 0;
uint64_t total_swap = 0;
uint64_t total_pswap = 0;
uint64_t total_uswap = 0;
uint64_t total_zswap = 0;

[[noreturn]] static void usage(int exit_status) {
    std::cerr << "Usage: " << getprogname() << " [ -W ] [ -v | -r | -p | -u | -s | -h ]"
              << std::endl
              << "    -v  Sort by VSS." << std::endl
              << "    -r  Sort by RSS." << std::endl
              << "    -p  Sort by PSS." << std::endl
              << "    -u  Sort by USS." << std::endl
              << "    -s  Sort by swap." << std::endl
              << "        (Default sort order is PSS.)" << std::endl
              << "    -R  Reverse sort order (default is descending)." << std::endl
              << "    -c  Only show cached (storage backed) pages" << std::endl
              << "    -C  Only show non-cached (ram/swap backed) pages" << std::endl
              << "    -k  Only show pages collapsed by KSM" << std::endl
              << "    -w  Display statistics for working set only." << std::endl
              << "    -W  Reset working set of all processes." << std::endl
              << "    -o  Show and sort by oom score against lowmemorykiller thresholds."
              << std::endl
              << "    -h  Display this help screen." << std::endl;
    exit(exit_status);
}

static bool read_all_pids(std::vector<pid_t>* pids, std::function<bool(pid_t pid)> for_each_pid) {
    pids->clear();
    std::unique_ptr<DIR, int (*)(DIR*)> procdir(opendir("/proc"), closedir);
    if (!procdir) return false;

    struct dirent* dir;
    pid_t pid;
    while ((dir = readdir(procdir.get()))) {
        if (!::android::base::ParseInt(dir->d_name, &pid)) continue;
        if (!for_each_pid(pid)) return false;
        pids->push_back(pid);
    }

    return true;
}

static bool count_swap_offsets(const ProcessRecord& proc, uint16_t* swap_offset_array,
                               uint32_t size) {
    const std::vector<uint16_t>& swp_offs = proc.SwapOffsets();
    for (auto& off : swp_offs) {
        if (off >= size) {
            std::cerr << "swap offset " << off << " is out of bounds for process: " << proc.pid()
                      << std::endl;
            return false;
        }

        if (swap_offset_array[off] == USHRT_MAX) {
            std::cerr << "swap offset " << off << " ref count overflow in process: " << proc.pid()
                      << std::endl;
            return false;
        }

        swap_offset_array[off]++;
    }

    return true;
}

static void print_header(std::stringstream& ss) {
    ss.str("");
    ss << ::android::base::StringPrintf("%5s  ", "PID");
    if (show_oomadj) {
        ss << ::android::base::StringPrintf("%5s  ", "oom");
    }

    if (show_wss) {
        ss << ::android::base::StringPrintf("%7s  %7s  %7s  ", "WRss", "WPss", "WUss");
        // now swap statistics here, working set pages by definition shouldn't end up in swap.
    } else {
        ss << ::android::base::StringPrintf("%8s  %7s  %7s  %7s  ", "Vss", "Rss", "Pss", "Uss");
        if (has_swap) {
            ss << ::android::base::StringPrintf("%7s  %7s  %7s  ", "Swap", "PSwap", "USwap");
            if (has_zram) {
                ss << ::android::base::StringPrintf("%7s  ", "ZSwap");
            }
        }
    }

    ss << "cmdline";
}

static void print_process_record(std::stringstream& ss, ProcessRecord& proc) {
    ss << ::android::base::StringPrintf("%5d  ", proc.pid());
    if (show_oomadj) {
        ss << ::android::base::StringPrintf("%5d  ", proc.oomadj());
    }

    if (show_wss) {
        ss << ::android::base::StringPrintf("%6" PRIu64 "K  %6" PRIu64 "K  %6" PRIu64 "K  ",
                                            proc.Wss().rss / 1024, proc.Wss().pss / 1024,
                                            proc.Wss().uss / 1024);
    } else {
        ss << ::android::base::StringPrintf("%7" PRIu64 "K  %6" PRIu64 "K  %6" PRIu64 "K  %6" PRIu64
                                            "K  ",
                                            proc.Usage().vss / 1024, proc.Usage().rss / 1024,
                                            proc.Usage().pss / 1024, proc.Usage().uss / 1024);
        if (has_swap) {
            ss << ::android::base::StringPrintf("%6" PRIu64 "K  ", proc.Usage().swap / 1024);
            ss << ::android::base::StringPrintf("%6" PRIu64 "K  ", proc.proportional_swap() / 1024);
            ss << ::android::base::StringPrintf("%6" PRIu64 "K  ", proc.unique_swap() / 1024);
            if (has_zram) {
                ss << ::android::base::StringPrintf("%6" PRIu64 "K  ", (proc.zswap() / 1024));
            }
        }
    }
}

static void print_processes(std::stringstream& ss, std::vector<ProcessRecord>& procs,
                            uint16_t* swap_offset_array) {
    for (auto& proc : procs) {
        total_pss += show_wss ? proc.Wss().pss : proc.Usage().pss;
        total_uss += show_wss ? proc.Wss().uss : proc.Usage().uss;
        if (!show_wss && has_swap) {
            proc.CalculateSwap(swap_offset_array, zram_compression_ratio);
            total_swap += proc.Usage().swap;
            total_pswap += proc.proportional_swap();
            total_uswap += proc.unique_swap();
            if (has_zram) {
                total_zswap += proc.zswap();
            }
        }

        print_process_record(ss, proc);
        ss << proc.cmdline() << std::endl;
    }
}

static void print_separator(std::stringstream& ss) {
    ss << ::android::base::StringPrintf("%5s  ", "");
    if (show_oomadj) {
        ss << ::android::base::StringPrintf("%5s  ", "");
    }

    if (show_wss) {
        ss << ::android::base::StringPrintf("%7s  %7s  %7s  ", "", "------", "------");
    } else {
        ss << ::android::base::StringPrintf("%8s  %7s  %7s  %7s  ", "", "", "------", "------");
        if (has_swap) {
            ss << ::android::base::StringPrintf("%7s  %7s  %7s  ", "------", "------", "------");
            if (has_zram) {
                ss << ::android::base::StringPrintf("%7s  ", "------");
            }
        }
    }

    ss << ::android::base::StringPrintf("%s", "------");
}

static void print_totals(std::stringstream& ss) {
    ss << ::android::base::StringPrintf("%5s  ", "");
    if (show_oomadj) {
        ss << ::android::base::StringPrintf("%5s  ", "");
    }

    if (show_wss) {
        ss << ::android::base::StringPrintf("%7s  %6" PRIu64 "K  %6" PRIu64 "K  ", "",
                                            total_pss / 1024, total_uss / 1024);
    } else {
        ss << ::android::base::StringPrintf("%8s  %7s  %6" PRIu64 "K  %6" PRIu64 "K  ", "", "",
                                            total_pss / 1024, total_uss / 1024);
        if (has_swap) {
            ss << ::android::base::StringPrintf("%6" PRIu64 "K  ", total_swap / 1024);
            ss << ::android::base::StringPrintf("%6" PRIu64 "K  ", total_pswap / 1024);
            ss << ::android::base::StringPrintf("%6" PRIu64 "K  ", total_uswap / 1024);
            if (has_zram) {
                ss << ::android::base::StringPrintf("%6" PRIu64 "K  ", total_zswap / 1024);
            }
        }
    }
    ss << "TOTAL";
}

static void print_sysmeminfo(std::stringstream& ss, ::android::meminfo::SysMemInfo& smi) {
    if (has_swap) {
        ss << ::android::base::StringPrintf("ZRAM: %" PRIu64 "K physical used for %" PRIu64
                                            "K in swap "
                                            "(%" PRIu64 "K total swap)",
                                            smi.mem_zram_kb(),
                                            (smi.mem_swap_kb() - smi.mem_swap_free_kb()),
                                            smi.mem_swap_kb())
           << std::endl;
    }

    ss << ::android::base::StringPrintf(" RAM: %" PRIu64 "K total, %" PRIu64 "K free, %" PRIu64
                                        "K buffers, "
                                        "%" PRIu64 "K cached, %" PRIu64 "K shmem, %" PRIu64
                                        "K slab",
                                        smi.mem_total_kb(), smi.mem_free_kb(), smi.mem_buffers_kb(),
                                        smi.mem_cached_kb(), smi.mem_shmem_kb(), smi.mem_slab_kb());
}

int main(int argc, char* argv[]) {
    auto pss_sort = [](ProcessRecord& a, ProcessRecord& b) {
        MemUsage stats_a = show_wss ? a.Wss() : a.Usage();
        MemUsage stats_b = show_wss ? b.Wss() : b.Usage();
        return reverse_sort ? stats_a.pss < stats_b.pss : stats_a.pss > stats_b.pss;
    };

    auto uss_sort = [](ProcessRecord& a, ProcessRecord& b) {
        MemUsage stats_a = show_wss ? a.Wss() : a.Usage();
        MemUsage stats_b = show_wss ? b.Wss() : b.Usage();
        return reverse_sort ? stats_a.uss < stats_b.uss : stats_a.uss > stats_b.uss;
    };

    auto rss_sort = [](ProcessRecord& a, ProcessRecord& b) {
        MemUsage stats_a = show_wss ? a.Wss() : a.Usage();
        MemUsage stats_b = show_wss ? b.Wss() : b.Usage();
        return reverse_sort ? stats_a.rss < stats_b.pss : stats_a.pss > stats_b.pss;
    };

    auto vss_sort = [](ProcessRecord& a, ProcessRecord& b) {
        MemUsage stats_a = show_wss ? a.Wss() : a.Usage();
        MemUsage stats_b = show_wss ? b.Wss() : b.Usage();
        return reverse_sort ? stats_a.vss < stats_b.vss : stats_a.vss > stats_b.vss;
    };

    auto swap_sort = [](ProcessRecord& a, ProcessRecord& b) {
        MemUsage stats_a = show_wss ? a.Wss() : a.Usage();
        MemUsage stats_b = show_wss ? b.Wss() : b.Usage();
        return reverse_sort ? stats_a.swap < stats_b.swap : stats_a.swap > stats_b.swap;
    };

    auto oomadj_sort = [](ProcessRecord& a, ProcessRecord& b) {
        return reverse_sort ? a.oomadj() < b.oomadj() : a.oomadj() > b.oomadj();
    };

    // default PSS sort
    std::function<bool(ProcessRecord & a, ProcessRecord & b)> proc_sort = pss_sort;

    // count all pages by default
    uint64_t pgflags = 0;
    uint64_t pgflags_mask = 0;

    int opt;
    while ((opt = getopt(argc, argv, "cChkoprRsuvwW")) != -1) {
        switch (opt) {
            case 'c':
                pgflags = 0;
                pgflags_mask = (1 << KPF_SWAPBACKED);
                break;
            case 'C':
                pgflags = (1 << KPF_SWAPBACKED);
                pgflags_mask = (1 << KPF_SWAPBACKED);
                break;
            case 'h':
                usage(EXIT_SUCCESS);
            case 'k':
                pgflags = (1 << KPF_KSM);
                pgflags_mask = (1 << KPF_KSM);
                break;
            case 'o':
                proc_sort = oomadj_sort;
                show_oomadj = true;
                break;
            case 'p':
                proc_sort = pss_sort;
                break;
            case 'r':
                proc_sort = rss_sort;
                break;
            case 'R':
                reverse_sort = true;
                break;
            case 's':
                proc_sort = swap_sort;
                break;
            case 'u':
                proc_sort = uss_sort;
                break;
            case 'v':
                proc_sort = vss_sort;
                break;
            case 'w':
                show_wss = true;
                break;
            case 'W':
                reset_wss = true;
                break;
            default:
                usage(EXIT_FAILURE);
        }
    }

    std::vector<pid_t> pids;
    std::vector<ProcessRecord> procs;
    if (reset_wss) {
        if (!read_all_pids(&pids,
                           [&](pid_t pid) -> bool { return ProcMemInfo::ResetWorkingSet(pid); })) {
            std::cerr << "Failed to reset working set of all processes" << std::endl;
            exit(EXIT_FAILURE);
        }
        // we are done, all other options passed to procrank are ignored in the presence of '-W'
        return 0;
    }

    ::android::meminfo::SysMemInfo smi;
    if (!smi.ReadMemInfo()) {
        std::cerr << "Failed to get system memory info" << std::endl;
        exit(EXIT_FAILURE);
    }

    // Figure out swap and zram
    uint64_t swap_total = smi.mem_swap_kb() * 1024;
    has_swap = swap_total > 0;
    // Allocate the swap array
    auto swap_offset_array = std::make_unique<uint16_t[]>(swap_total / getpagesize());
    if (has_swap) {
        has_zram = smi.mem_zram_kb() > 0;
        if (has_zram) {
            zram_compression_ratio = static_cast<float>(smi.mem_zram_kb()) /
                                     (smi.mem_swap_kb() - smi.mem_swap_free_kb());
        }
    }

    auto mark_swap_usage = [&](pid_t pid) -> bool {
        ProcessRecord proc(pid, show_wss, pgflags, pgflags_mask);
        if (!proc.valid()) {
            std::cerr << "Failed to create process record for: " << pid << std::endl;
            return false;
        }

        // Skip processes with no memory mappings
        uint64_t vss = proc.Usage().vss;
        if (vss == 0) return true;

        // collect swap_offset counts from all processes in 1st pass
        if (!show_wss && has_swap &&
            !count_swap_offsets(proc, swap_offset_array.get(), swap_total / getpagesize())) {
            std::cerr << "Failed to count swap offsets for process: " << pid << std::endl;
            return false;
        }

        procs.push_back(std::move(proc));
        return true;
    };

    // Get a list of all pids currently running in the system in
    // 1st pass through all processes. Mark each swap offset used by the process as we find them
    // for calculating proportional swap usage later.
    if (!read_all_pids(&pids, mark_swap_usage)) {
        std::cerr << "Failed to read all pids from the system" << std::endl;
        exit(EXIT_FAILURE);
    }

    std::stringstream ss;
    if (procs.empty()) {
        // This would happen in corner cases where procrank is being run to find KSM usage on a
        // system with no KSM and combined with working set determination as follows
        //   procrank -w -u -k
        //   procrank -w -s -k
        //   procrank -w -o -k
        ss << "<empty>" << std::endl << std::endl;
        print_sysmeminfo(ss, smi);
        ss << std::endl;
        std::cout << ss.str();
        return 0;
    }

    // Sort all process records, default is PSS descending
    std::sort(procs.begin(), procs.end(), proc_sort);

    // start dumping output in string stream
    print_header(ss);
    ss << std::endl;

    // 2nd pass to calculate and get per process stats to add them up
    print_processes(ss, procs, swap_offset_array.get());

    // Add separator to output
    print_separator(ss);
    ss << std::endl;

    // Add totals to output
    print_totals(ss);
    ss << std::endl << std::endl;

    // Add system information at the end
    print_sysmeminfo(ss, smi);
    ss << std::endl;

    // dump on the screen
    std::cout << ss.str();

    return 0;
}
