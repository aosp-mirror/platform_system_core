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

bool parse_disk_stats(const char* disk_stats_path, struct disk_stats* stats) {
    // Get time
    struct timespec ts;
    // Use monotonic to exclude suspend time so that we measure IO bytes/sec
    // when system is running.
    int ret = clock_gettime(CLOCK_MONOTONIC, &ts);
    if (ret < 0) {
        PLOG_TO(SYSTEM, ERROR) << "clock_gettime() failed";
        return false;
    }

    std::string buffer;
    if (!android::base::ReadFileToString(disk_stats_path, &buffer)) {
        PLOG_TO(SYSTEM, ERROR) << disk_stats_path << ": ReadFileToString failed.";
        return false;
    }

    // Regular diskstats entries
    std::stringstream ss(buffer);
    for (uint i = 0; i < DISK_STATS_SIZE; ++i) {
        ss >> *((uint64_t*)stats + i);
    }
    // Other entries
    stats->start_time = 0;
    stats->end_time = (uint64_t)ts.tv_sec * SEC_TO_MSEC +
        ts.tv_nsec / (MSEC_TO_USEC * USEC_TO_NSEC);
    stats->counter = 1;
    stats->io_avg = (double)stats->io_in_flight;
    return true;
}

struct disk_perf get_disk_perf(struct disk_stats* stats) {
    struct disk_perf perf;
    memset(&perf, 0, sizeof(struct disk_perf));  // initialize

    if (stats->io_ticks) {
        if (stats->read_ticks) {
            unsigned long long divisor = stats->read_ticks * stats->io_ticks;
            perf.read_perf = ((unsigned long long)SECTOR_SIZE *
                                        stats->read_sectors *
                                        stats->io_in_queue +
                                        (divisor >> 1)) /
                                            divisor;
            perf.read_ios = ((unsigned long long)SEC_TO_MSEC *
                                        stats->read_ios *
                                        stats->io_in_queue +
                                        (divisor >> 1)) /
                                            divisor;
        }
        if (stats->write_ticks) {
            unsigned long long divisor = stats->write_ticks * stats->io_ticks;
                        perf.write_perf = ((unsigned long long)SECTOR_SIZE *
                                                    stats->write_sectors *
                                                    stats->io_in_queue +
                                                    (divisor >> 1)) /
                                                        divisor;
                        perf.write_ios = ((unsigned long long)SEC_TO_MSEC *
                                                    stats->write_ios *
                                                    stats->io_in_queue +
                                                    (divisor >> 1)) /
                                                        divisor;
        }
        perf.queue = (stats->io_in_queue + (stats->io_ticks >> 1)) /
                                stats->io_ticks;
    }
    return perf;
}

struct disk_stats get_inc_disk_stats(struct disk_stats* prev, struct disk_stats* curr) {
    struct disk_stats inc;
    for (uint i = 0; i < DISK_STATS_SIZE; ++i) {
        if (i == DISK_STATS_IO_IN_FLIGHT_IDX) {
            continue;
        }

        *((uint64_t*)&inc + i) =
                *((uint64_t*)curr + i) - *((uint64_t*)prev + i);
    }
    // io_in_flight is exception
    inc.io_in_flight = curr->io_in_flight;

    inc.start_time = prev->end_time;
    inc.end_time = curr->end_time;
    inc.io_avg = curr->io_avg;
    inc.counter = 1;

    return inc;
}

// Add src to dst
void add_disk_stats(struct disk_stats* src, struct disk_stats* dst) {
    if (dst->end_time != 0 && dst->end_time != src->start_time) {
        LOG_TO(SYSTEM, WARNING) << "Two dis-continuous periods of diskstats"
            << " are added. dst end with " << dst->end_time
            << ", src start with " << src->start_time;
    }

    for (uint i = 0; i < DISK_STATS_SIZE; ++i) {
        if (i == DISK_STATS_IO_IN_FLIGHT_IDX) {
            continue;
        }

        *((uint64_t*)dst + i) += *((uint64_t*)src + i);
    }

    dst->io_in_flight = src->io_in_flight;
    if (dst->counter + src->counter) {
        dst->io_avg = ((dst->io_avg * dst->counter) + (src->io_avg * src->counter)) /
                        (dst->counter + src->counter);
    }
    dst->counter += src->counter;
    dst->end_time = src->end_time;
    if (dst->start_time == 0) {
        dst->start_time = src->start_time;
    }
}

static bool cmp_uid_info(struct uid_info l, struct uid_info r) {
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

void sort_running_uids_info(std::vector<struct uid_info> &uids) {
    std::sort(uids.begin(), uids.end(), cmp_uid_info);
}

// Logging functions
void log_console_running_uids_info(std::vector<struct uid_info> uids) {
    printf("name/uid fg_rchar fg_wchar fg_rbytes fg_wbytes "
           "bg_rchar bg_wchar bg_rbytes bg_wbytes fg_fsync bg_fsync\n");

    for (const auto& uid : uids) {
        printf("%s %ju %ju %ju %ju %ju %ju %ju %ju %ju %ju\n", uid.name.c_str(),
            uid.io[0].rchar, uid.io[0].wchar, uid.io[0].read_bytes, uid.io[0].write_bytes,
            uid.io[1].rchar, uid.io[1].wchar, uid.io[1].read_bytes, uid.io[1].write_bytes,
            uid.io[0].fsync, uid.io[1].fsync);
    }
    fflush(stdout);
}

#if DEBUG
void log_debug_disk_perf(struct disk_perf* perf, const char* type) {
    // skip if the input structure are all zeros
    if (perf == NULL) return;
    struct disk_perf zero_cmp;
    memset(&zero_cmp, 0, sizeof(zero_cmp));
    if (memcmp(&zero_cmp, perf, sizeof(struct disk_perf)) == 0) return;

    LOG_TO(SYSTEM, INFO) << "perf(ios) " << type
              << " rd:" << perf->read_perf << "KB/s(" << perf->read_ios << "/s)"
              << " wr:" << perf->write_perf << "KB/s(" << perf->write_ios << "/s)"
              << " q:" << perf->queue;
}
#else
void log_debug_disk_perf(struct disk_perf* /* perf */, const char* /* type */) {}
#endif

void log_event_disk_stats(struct disk_stats* stats, const char* type) {
    // skip if the input structure are all zeros
    if (stats == NULL) return;
    struct disk_stats zero_cmp;
    memset(&zero_cmp, 0, sizeof(zero_cmp));
    // skip event logging diskstats when it is zero increment (all first 11 entries are zero)
    if (memcmp(&zero_cmp, stats, sizeof(uint64_t) * DISK_STATS_SIZE) == 0) return;

    android_log_event_list(EVENTLOGTAG_DISKSTATS)
        << type << stats->start_time << stats->end_time
        << stats->read_ios << stats->read_merges
        << stats->read_sectors << stats->read_ticks
        << stats->write_ios << stats->write_merges
        << stats->write_sectors << stats->write_ticks
        << (uint64_t)stats->io_avg << stats->io_ticks << stats->io_in_queue
        << LOG_ID_EVENTS;
}

