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

#ifndef _STORAGED_UID_MONITOR_H_
#define _STORAGED_UID_MONITOR_H_

#include <stdint.h>

#include <string>
#include <unordered_map>
#include <vector>

enum uid_stat_t {
    FOREGROUND = 0,
    BACKGROUND = 1,
    UID_STATS = 2
};

enum charger_stat_t {
    CHARGER_OFF = 0,
    CHARGER_ON = 1,
    CHARGER_STATS = 2
};

enum io_type_t {
    READ = 0,
    WRITE = 1,
    IO_TYPES = 2
};

struct uid_io_stats {
    uint64_t rchar;                 // characters read
    uint64_t wchar;                 // characters written
    uint64_t read_bytes;            // bytes read (from storage layer)
    uint64_t write_bytes;           // bytes written (to storage layer)
};

struct uid_info {
    uint32_t uid;                   // user id
    std::string name;               // package name
    struct uid_io_stats io[UID_STATS];    // [0]:foreground [1]:background
};

struct uid_io_usage {
    uint64_t bytes[IO_TYPES][UID_STATS][CHARGER_STATS];
};

struct uid_record {
    std::string name;
    struct uid_io_usage ios;
};

class uid_monitor {
private:
    // last dump from /proc/uid_io/stats, uid -> uid_info
    std::unordered_map<uint32_t, struct uid_info> last_uid_io_stats;
    // current io usage for next report, app name -> uid_io_usage
    std::unordered_map<std::string, struct uid_io_usage> curr_io_stats;
    // io usage records, timestamp -> vector of events
    std::map<uint64_t, std::vector<struct uid_record>> records;
    // charger ON/OFF
    charger_stat_t charger_stat;
    // protects curr_io_stats, last_uid_io_stats, records and charger_stat
    sem_t um_lock;

    // reads from /proc/uid_io/stats
    std::unordered_map<uint32_t, struct uid_info> get_uid_io_stats_locked();
    // flushes curr_io_stats to records
    void add_records_locked(uint64_t curr_ts);
    // updates curr_io_stats and set last_uid_io_stats
    void update_curr_io_stats_locked();

public:
    uid_monitor();
    ~uid_monitor();
    // called by storaged main thread
    void init(charger_stat_t stat);
    // called by storaged -u
    std::unordered_map<uint32_t, struct uid_info> get_uid_io_stats();
    // called by dumpsys
    std::map<uint64_t, std::vector<struct uid_record>> dump(
        int hours, uint64_t threshold, bool force_report);
    // called by battery properties listener
    void set_charger_state(charger_stat_t stat);
    // called by storaged periodic_chore or dump with force_report
    void report();
};

#endif /* _STORAGED_UID_MONITOR_H_ */
