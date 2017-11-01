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

#ifndef _STORAGED_UTILS_H_
#define _STORAGED_UTILS_H_

#include <stdint.h>
#include <string>
#include <unordered_map>
#include <vector>

#include "storaged.h"

// Diskstats
bool parse_disk_stats(const char* disk_stats_path, struct disk_stats* stats);
struct disk_perf get_disk_perf(struct disk_stats* stats);
struct disk_stats get_inc_disk_stats(struct disk_stats* prev, struct disk_stats* curr);
void add_disk_stats(struct disk_stats* src, struct disk_stats* dst);
bool parse_emmc_ecsd(int ext_csd_fd, struct emmc_info* info);

// UID I/O
void sort_running_uids_info(std::vector<struct uid_info> &uids);

// Logging
void log_console_running_uids_info(std::vector<struct uid_info> uids);

void log_debug_disk_perf(struct disk_perf* perf, const char* type);

void log_event_disk_stats(struct disk_stats* stats, const char* type);
void log_event_emmc_info(struct emmc_info* info_);
#endif /* _STORAGED_UTILS_H_ */
