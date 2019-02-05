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
#include <stdlib.h>
#include <unistd.h>

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <set>

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

static std::string GetProcessBaseName(pid_t pid) {
    std::string pid_path = android::base::StringPrintf("/proc/%d/comm", pid);
    std::ifstream in{pid_path};
    if (!in) return std::string("N/A");
    std::string line;
    std::getline(in, line);
    if (!in) return std::string("N/A");
    return line;
}

static void AddPidsToSet(const std::unordered_map<pid_t, int>& map, std::set<pid_t>* set)
{
    for (auto it = map.begin(); it != map.end(); ++it)
        set->insert(it->first);
}

static void PrintDmaBufInfo(const std::vector<DmaBuffer>& bufs) {
    std::set<pid_t> pid_set;
    std::map<pid_t, int> pid_column;

    if (bufs.empty()) {
        std::cout << "dmabuf info not found ¯\\_(ツ)_/¯" << std::endl;
        return;
    }

    // Find all unique pids in the input vector, create a set
    for (int i = 0; i < bufs.size(); i++) {
        AddPidsToSet(bufs[i].fdrefs(), &pid_set);
        AddPidsToSet(bufs[i].maprefs(), &pid_set);
    }

    int pid_count = 0;

    std::cout << "\t\t\t\t\t\t";

    // Create a map to convert each unique pid into a column number
    for (auto it = pid_set.begin(); it != pid_set.end(); ++it, ++pid_count) {
        pid_column.insert(std::make_pair(*it, pid_count));
        std::cout << ::android::base::StringPrintf("[pid: % 4d]\t", *it);
    }

    std::cout << std::endl << "\t\t\t\t\t\t";

    for (auto it = pid_set.begin(); it != pid_set.end(); ++it) {
        std::cout << ::android::base::StringPrintf("%16s",
            GetProcessBaseName(*it).c_str());
    }

    std::cout << std::endl << "\tinode\t\tsize\t\tcount\t";
    for (int i = 0; i < pid_count; i++) {
        std::cout << "fd\tmap\t";
    }
    std::cout << std::endl;

    auto fds = std::make_unique<int[]>(pid_count);
    auto maps = std::make_unique<int[]>(pid_count);
    auto pss = std::make_unique<long[]>(pid_count);

    memset(pss.get(), 0, sizeof(long) * pid_count);

    for (auto buf = bufs.begin(); buf != bufs.end(); ++buf) {

        std::cout << ::android::base::StringPrintf("%16lu\t%10" PRIu64 "\t%lu\t",
            buf->inode(),buf->size(), buf->count());

        memset(fds.get(), 0, sizeof(int) * pid_count);
        memset(maps.get(), 0, sizeof(int) * pid_count);

        for (auto it = buf->fdrefs().begin(); it != buf->fdrefs().end(); ++it) {
            fds[pid_column[it->first]] = it->second;
            pss[pid_column[it->first]] += buf->size() * it->second / buf->count();
        }

        for (auto it = buf->maprefs().begin(); it != buf->maprefs().end(); ++it) {
            maps[pid_column[it->first]] = it->second;
            pss[pid_column[it->first]] += buf->size() * it->second / buf->count();
        }

        for (int i = 0; i < pid_count; i++) {
            std::cout << ::android::base::StringPrintf("%d\t%d\t", fds[i], maps[i]);
        }
        std::cout << std::endl;
    }
    std::cout << "-----------------------------------------" << std::endl;
    std::cout << "PSS                                      ";
    for (int i = 0; i < pid_count; i++) {
        std::cout << ::android::base::StringPrintf("%15ldK", pss[i] / 1024);
    }
    std::cout << std::endl;
}

int main(int argc, char* argv[]) {
    pid_t pid = -1;
    std::vector<DmaBuffer> bufs;
    bool show_all = true;

    if (argc > 1) {
        if (sscanf(argv[1], "%d", &pid) == 1) {
            show_all = false;
        }
        else {
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


