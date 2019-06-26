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

#include <dirent.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <fstream>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include <android-base/stringprintf.h>
#include <dmabufinfo/dmabufinfo.h>

using DmaBuffer = ::android::dmabufinfo::DmaBuffer;

[[noreturn]] static void usage(int exit_status) {
    fprintf(stderr,
            "Usage: %s [PID] \n"
            "\t If PID is supplied, the dmabuf information for this process is shown.\n"
            "\t Otherwise, shows the information for all processes.\n",
            getprogname());

    exit(exit_status);
}

static std::string GetProcessComm(const pid_t pid) {
    std::string pid_path = android::base::StringPrintf("/proc/%d/comm", pid);
    std::ifstream in{pid_path};
    if (!in) return std::string("N/A");
    std::string line;
    std::getline(in, line);
    if (!in) return std::string("N/A");
    return line;
}

static void AddPidsToSet(const std::unordered_map<pid_t, int>& map, std::set<pid_t>* set) {
    for (auto it = map.begin(); it != map.end(); ++it) set->insert(it->first);
}

static void PrintDmaBufInfo(const std::vector<DmaBuffer>& bufs) {
    if (bufs.empty()) {
        printf("dmabuf info not found ¯\\_(ツ)_/¯\n");
        return;
    }

    // Find all unique pids in the input vector, create a set
    std::set<pid_t> pid_set;
    for (int i = 0; i < bufs.size(); i++) {
        AddPidsToSet(bufs[i].fdrefs(), &pid_set);
        AddPidsToSet(bufs[i].maprefs(), &pid_set);
    }

    // Format the header string spaced and separated with '|'
    printf("    Dmabuf Inode |            Size |      Ref Counts |");
    for (auto pid : pid_set) {
        printf("%16s:%-5d |", GetProcessComm(pid).c_str(), pid);
    }
    printf("\n");

    // holds per-process dmabuf size in kB
    std::map<pid_t, uint64_t> per_pid_size = {};
    uint64_t dmabuf_total_size = 0;

    // Iterate through all dmabufs and collect per-process sizes, refs
    for (auto& buf : bufs) {
        printf("%16" PRIu64 " |%13" PRIu64 " kB |%16" PRIu64 " |", buf.inode(), buf.size() / 1024,
               buf.total_refs());
        // Iterate through each process to find out per-process references for each buffer,
        // gather total size used by each process etc.
        for (pid_t pid : pid_set) {
            int pid_refs = 0;
            if (buf.fdrefs().count(pid) == 1) {
                // Get the total number of ref counts the process is holding
                // on this buffer. We don't differentiate between mmap or fd.
                pid_refs += buf.fdrefs().at(pid);
                if (buf.maprefs().count(pid) == 1) {
                    pid_refs += buf.maprefs().at(pid);
                }
            }

            if (pid_refs) {
                // Add up the per-pid total size. Note that if a buffer is mapped
                // in 2 different processes, the size will be shown as mapped or opened
                // in both processes. This is intended for visibility.
                //
                // If one wants to get the total *unique* dma buffers, they can simply
                // sum the size of all dma bufs shown by the tool
                per_pid_size[pid] += buf.size() / 1024;
                printf("%17d refs |", pid_refs);
            } else {
                printf("%22s |", "--");
            }
        }
        dmabuf_total_size += buf.size() / 1024;
        printf("\n");
    }

    printf("------------------------------------\n");
    printf("%-16s  %13" PRIu64 " kB |%16s |", "TOTALS", dmabuf_total_size, "n/a");
    for (auto pid : pid_set) {
        printf("%19" PRIu64 " kB |", per_pid_size[pid]);
    }
    printf("\n");

    return;
}

int main(int argc, char* argv[]) {
    pid_t pid = -1;
    std::vector<DmaBuffer> bufs;
    bool show_all = true;

    if (argc > 1) {
        if (sscanf(argv[1], "%d", &pid) == 1) {
            show_all = false;
        } else {
            usage(EXIT_FAILURE);
        }
    }

    if (show_all) {
        if (!ReadDmaBufInfo(&bufs)) {
            std::cerr << "debugfs entry for dmabuf not available, skipping" << std::endl;
            bufs.clear();
        }
        std::unique_ptr<DIR, int (*)(DIR*)> dir(opendir("/proc"), closedir);
        if (!dir) {
            std::cerr << "Failed to open /proc directory" << std::endl;
            exit(EXIT_FAILURE);
        }
        struct dirent* dent;
        while ((dent = readdir(dir.get()))) {
            if (dent->d_type != DT_DIR) continue;

            int matched = sscanf(dent->d_name, "%d", &pid);
            if (matched != 1) {
                continue;
            }

            if (!AppendDmaBufInfo(pid, &bufs)) {
                std::cerr << "Unable to read dmabuf info for pid " << pid << std::endl;
                exit(EXIT_FAILURE);
            }
        }
    } else {
        if (!ReadDmaBufInfo(pid, &bufs)) {
            std::cerr << "Unable to read dmabuf info" << std::endl;
            exit(EXIT_FAILURE);
        }
    }

    PrintDmaBufInfo(bufs);
    return 0;
}
