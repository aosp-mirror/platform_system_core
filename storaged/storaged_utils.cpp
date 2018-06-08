/*
 * Copyright (C) 2016 The Android Open Source Project
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

#define LOG_TAG "storaged"

#include <dirent.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/time.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <iomanip>
#include <sstream>
#include <string>
#include <unordered_map>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <log/log_event_list.h>

#include <storaged.h>
#include <storaged_utils.h>

bool cmp_uid_info(const UidInfo& l, const UidInfo& r) {
    // Compare background I/O first.
    for (int i = UID_STATS - 1; i >= 0; i--) {
        uint64_t l_bytes = l.io[i].read_bytes + l.io[i].write_bytes;
        uint64_t r_bytes = r.io[i].read_bytes + r.io[i].write_bytes;
        uint64_t l_chars = l.io[i].rchar + l.io[i].wchar;
        uint64_t r_chars = r.io[i].rchar + r.io[i].wchar;

        if (l_bytes != r_bytes) {
            return l_bytes > r_bytes;
        }
        if (l_chars != r_chars) {
            return l_chars > r_chars;
        }
    }

    return l.name < r.name;
}

void sort_running_uids_info(std::vector<UidInfo> &uids) {
    std::sort(uids.begin(), uids.end(), cmp_uid_info);
}

// Logging functions
void log_console_running_uids_info(const std::vector<UidInfo>& uids, bool flag_dump_task) {
    printf("name/uid fg_rchar fg_wchar fg_rbytes fg_wbytes "
           "bg_rchar bg_wchar bg_rbytes bg_wbytes fg_fsync bg_fsync\n");

    for (const auto& uid : uids) {
        printf("%s %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64
                " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 "\n",
            uid.name.c_str(),
            uid.io[0].rchar, uid.io[0].wchar, uid.io[0].read_bytes, uid.io[0].write_bytes,
            uid.io[1].rchar, uid.io[1].wchar, uid.io[1].read_bytes, uid.io[1].write_bytes,
            uid.io[0].fsync, uid.io[1].fsync);
        if (flag_dump_task) {
            for (const auto& task_it : uid.tasks) {
                const task_info& task = task_it.second;
                printf("-> %s %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64
                        " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 "\n",
                    task.comm.c_str(),
                    task.io[0].rchar, task.io[0].wchar, task.io[0].read_bytes, task.io[0].write_bytes,
                    task.io[1].rchar, task.io[1].wchar, task.io[1].read_bytes, task.io[1].write_bytes,
                    task.io[0].fsync, task.io[1].fsync);
            }
        }
    }
    fflush(stdout);
}

void log_console_perf_history(const vector<int>& perf_history) {
    if (perf_history.size() < 3 ||
        perf_history.size() != perf_history[0] +
                               perf_history[1] +
                               perf_history[2] + (size_t)3) {
        return;
    }

    printf("\nI/O perf history (KB/s) :  most_recent  <---------  least_recent \n");

    std::stringstream line;
    int start = 3;
    int end = 3 + perf_history[0];
    std::copy(perf_history.begin() + start, perf_history.begin() + end,
              std::ostream_iterator<int>(line, " "));
    printf("last 24 hours : %s\n", line.str().c_str());

    line.str("");
    start = end;
    end += perf_history[1];
    std::copy(perf_history.begin() + start, perf_history.begin() + end,
              std::ostream_iterator<int>(line, " "));
    printf("last 7 days   : %s\n", line.str().c_str());

    line.str("");
    start = end;
    std::copy(perf_history.begin() + start, perf_history.end(),
              std::ostream_iterator<int>(line, " "));
    printf("last 52 weeks : %s\n", line.str().c_str());
}

map<string, io_usage> merge_io_usage(const vector<uid_record>& entries) {
    map<string, io_usage> merged_entries;
    for (const auto& record : entries) {
        merged_entries[record.name] += record.ios.uid_ios;
    }
    return merged_entries;
}
