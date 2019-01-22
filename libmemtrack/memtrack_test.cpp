/*
 * Copyright (C) 2013 The Android Open Source Project
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include <filesystem>
#include <vector>

#include <android-base/file.h>
#include <android-base/parseint.h>
#include <android-base/stringprintf.h>
#include <memtrack/memtrack.h>

#define DIV_ROUND_UP(x, y) (((x) + (y)-1) / (y))

static void getprocname(pid_t pid, std::string* name) {
    std::string fname = ::android::base::StringPrintf("/proc/%d/cmdline", pid);
    if (!::android::base::ReadFileToString(fname, name)) {
        fprintf(stderr, "Failed to read cmdline from: %s\n", fname.c_str());
        *name = "<unknown>";
    }
}

int main(int /* argc */, char** /* argv */) {
    int ret;
    struct memtrack_proc* p;
    std::vector<pid_t> pids;

    p = memtrack_proc_new();
    if (p == nullptr) {
        fprintf(stderr, "failed to create memtrack process handle\n");
        exit(EXIT_FAILURE);
    }

    for (auto& de : std::filesystem::directory_iterator("/proc")) {
        if (!std::filesystem::is_directory(de.status())) {
            continue;
        }

        pid_t pid;
        if (!::android::base::ParseInt(de.path().filename().string(), &pid)) {
            continue;
        }
        pids.emplace_back(pid);
    }

    for (auto& pid : pids) {
        size_t v1;
        size_t v2;
        size_t v3;
        size_t v4;
        size_t v5;
        size_t v6;
        std::string cmdline;

        getprocname(pid, &cmdline);

        ret = memtrack_proc_get(p, pid);
        if (ret) {
            fprintf(stderr, "failed to get memory info for pid %d: %s (%d)\n", pid, strerror(-ret),
                    ret);
            continue;
        }

        v1 = DIV_ROUND_UP(memtrack_proc_graphics_total(p), 1024);
        v2 = DIV_ROUND_UP(memtrack_proc_graphics_pss(p), 1024);
        v3 = DIV_ROUND_UP(memtrack_proc_gl_total(p), 1024);
        v4 = DIV_ROUND_UP(memtrack_proc_gl_pss(p), 1024);
        v5 = DIV_ROUND_UP(memtrack_proc_other_total(p), 1024);
        v6 = DIV_ROUND_UP(memtrack_proc_other_pss(p), 1024);

        if (v1 | v2 | v3 | v4 | v5 | v6) {
            fprintf(stdout, "%5d %6zu %6zu %6zu %6zu %6zu %6zu %s\n", pid, v1, v2, v3, v4, v5, v6,
                    cmdline.c_str());
        }
    }

    memtrack_proc_destroy(p);

    return ret;
}
