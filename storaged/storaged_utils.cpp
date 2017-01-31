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

bool parse_emmc_ecsd(int ext_csd_fd, struct emmc_info* info) {
    CHECK(ext_csd_fd >= 0);
    struct hex {
        char str[2];
    };
    // List of interesting offsets
    static const size_t EXT_CSD_REV_IDX = 192 * sizeof(hex);
    static const size_t EXT_PRE_EOL_INFO_IDX = 267 * sizeof(hex);
    static const size_t EXT_DEVICE_LIFE_TIME_EST_A_IDX = 268 * sizeof(hex);
    static const size_t EXT_DEVICE_LIFE_TIME_EST_B_IDX = 269 * sizeof(hex);

    // Read file
    CHECK(lseek(ext_csd_fd, 0, SEEK_SET) == 0);
    std::string buffer;
    if (!android::base::ReadFdToString(ext_csd_fd, &buffer)) {
        PLOG_TO(SYSTEM, ERROR) << "ReadFdToString failed.";
        return false;
    }

    if (buffer.length() < EXT_CSD_FILE_MIN_SIZE) {
        LOG_TO(SYSTEM, ERROR) << "EMMC ext csd file has truncated content. "
            << "File length: " << buffer.length();
        return false;
    }

    std::string sub;
    std::stringstream ss;
    // Parse EXT_CSD_REV
    int ext_csd_rev = -1;
    sub = buffer.substr(EXT_CSD_REV_IDX, sizeof(hex));
    ss << sub;
    ss >> std::hex >> ext_csd_rev;
    if (ext_csd_rev < 0) {
        LOG_TO(SYSTEM, ERROR) << "Failure on parsing EXT_CSD_REV.";
        return false;
    }
    ss.clear();

    static const char* ver_str[] = {
        "4.0", "4.1", "4.2", "4.3", "Obsolete", "4.41", "4.5", "5.0"
    };

    strlcpy(info->mmc_ver,
            (ext_csd_rev < (int)(sizeof(ver_str) / sizeof(ver_str[0]))) ?
                           ver_str[ext_csd_rev] :
                           "Unknown",
            MMC_VER_STR_LEN);

    if (ext_csd_rev < 7) {
        return 0;
    }

    // Parse EXT_PRE_EOL_INFO
    info->eol = -1;
    sub = buffer.substr(EXT_PRE_EOL_INFO_IDX, sizeof(hex));
    ss << sub;
    ss >> std::hex >> info->eol;
    if (info->eol < 0) {
        LOG_TO(SYSTEM, ERROR) << "Failure on parsing EXT_PRE_EOL_INFO.";
        return false;
    }
    ss.clear();

    // Parse DEVICE_LIFE_TIME_EST
    info->lifetime_a = -1;
    sub = buffer.substr(EXT_DEVICE_LIFE_TIME_EST_A_IDX, sizeof(hex));
    ss << sub;
    ss >> std::hex >> info->lifetime_a;
    if (info->lifetime_a < 0) {
        LOG_TO(SYSTEM, ERROR) << "Failure on parsing EXT_DEVICE_LIFE_TIME_EST_TYP_A.";
        return false;
    }
    ss.clear();

    info->lifetime_b = -1;
    sub = buffer.substr(EXT_DEVICE_LIFE_TIME_EST_B_IDX, sizeof(hex));
    ss << sub;
    ss >> std::hex >> info->lifetime_b;
    if (info->lifetime_b < 0) {
        LOG_TO(SYSTEM, ERROR) << "Failure on parsing EXT_DEVICE_LIFE_TIME_EST_TYP_B.";
        return false;
    }
    ss.clear();

    return true;
}

static bool cmp_uid_info(struct uid_info l, struct uid_info r) {
    // Compare background I/O first.
    for (int i = UID_STATS_SIZE - 1; i >= 0; i--) {
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
// Sample Output:
//                                       Application        FG Read       FG Write        FG Read       FG Write        BG Read       BG Write        BG Read       BG Write
//                                          NAME/UID     Characters     Characters          Bytes          Bytes     Characters     Characters          Bytes          Bytes
//                                        ----------     ----------     ----------     ----------     ----------     ----------     ----------     ----------     ----------
//                      com.google.android.gsf.login              0              0              0              0       57195097        5137089      176386048        6512640
//           com.google.android.googlequicksearchbox              0              0              0              0        4196821       12123468       34295808       13225984
//                                              1037           4572            537              0              0         131352        5145643       34263040        5144576
//                        com.google.android.youtube           2182             70              0              0       63969383         482939       38731776         466944

    // Title
    printf("Per-UID I/O stats\n");
    printf("                                       Application        FG Read       FG Write        FG Read       FG Write        BG Read       BG Write        BG Read       BG Write\n"
           "                                          NAME/UID     Characters     Characters          Bytes          Bytes     Characters     Characters          Bytes          Bytes\n"
           "                                        ----------     ----------     ----------     ----------     ----------     ----------     ----------     ----------     ----------\n");

    for (const auto& uid : uids) {
        printf("%50s%15ju%15ju%15ju%15ju%15ju%15ju%15ju%15ju\n", uid.name.c_str(),
            uid.io[0].rchar, uid.io[0].wchar, uid.io[0].read_bytes, uid.io[0].write_bytes,
            uid.io[1].rchar, uid.io[1].wchar, uid.io[1].read_bytes, uid.io[1].write_bytes);
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

void log_event_emmc_info(struct emmc_info* info) {
    // skip if the input structure are all zeros
    if (info == NULL) return;
    struct emmc_info zero_cmp;
    memset(&zero_cmp, 0, sizeof(zero_cmp));
    if (memcmp(&zero_cmp, info, sizeof(struct emmc_info)) == 0) return;

    android_log_event_list(EVENTLOGTAG_EMMCINFO)
        << info->mmc_ver << info->eol << info->lifetime_a << info->lifetime_b
        << LOG_ID_EVENTS;
}
