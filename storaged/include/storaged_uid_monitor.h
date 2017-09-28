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

#include "storaged.pb.h"

using namespace storaged_proto;

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

struct io_stats {
    uint64_t rchar;                 // characters read
    uint64_t wchar;                 // characters written
    uint64_t read_bytes;            // bytes read (from storage layer)
    uint64_t write_bytes;           // bytes written (to storage layer)
    uint64_t fsync;                 // number of fsync syscalls
};

struct task_info {
    std::string comm;
    pid_t pid;
    struct io_stats io[UID_STATS];
    bool parse_task_io_stats(std::string&& s);
};

struct uid_info {
    uint32_t uid;                   // user id
    std::string name;               // package name
    struct io_stats io[UID_STATS];    // [0]:foreground [1]:background
    std::unordered_map<uint32_t, task_info> tasks; // mapped from pid
    bool parse_uid_io_stats(std::string&& s);
};

struct io_usage {
    uint64_t bytes[IO_TYPES][UID_STATS][CHARGER_STATS];
    bool is_zero() const;
};

struct uid_io_usage {
    struct io_usage uid_ios;
    // mapped from task comm to task io usage
    std::map<std::string, struct io_usage> task_ios;
};

struct uid_record {
    std::string name;
    struct uid_io_usage ios;
};

struct uid_records {
    uint64_t start_ts;
    std::vector<struct uid_record> entries;
};

class lock_t {
    sem_t* mSem;
public:
    lock_t(sem_t* sem) {
        mSem = sem;
        sem_wait(mSem);
    }
    ~lock_t() {
        sem_post(mSem);
    }
};

class uid_monitor {
private:
    // last dump from /proc/uid_io/stats, uid -> uid_info
    std::unordered_map<uint32_t, struct uid_info> last_uid_io_stats;
    // current io usage for next report, app name -> uid_io_usage
    std::unordered_map<std::string, struct uid_io_usage> curr_io_stats;
    // io usage records, end timestamp -> {start timestamp, vector of records}
    std::map<uint64_t, struct uid_records> io_history;
    // charger ON/OFF
    charger_stat_t charger_stat;
    // protects curr_io_stats, last_uid_io_stats, records and charger_stat
    sem_t um_lock;
    // start time for IO records
    uint64_t start_ts;
    // true if UID_IO_STATS_PATH is accessible
    const bool enable;

    // reads from /proc/uid_io/stats
    std::unordered_map<uint32_t, struct uid_info> get_uid_io_stats_locked();
    // flushes curr_io_stats to records
    void add_records_locked(uint64_t curr_ts);
    // updates curr_io_stats and set last_uid_io_stats
    void update_curr_io_stats_locked();
    // restores io_history from protobuf
    void load_uid_io_proto(const UidIOUsage& proto);
    // writes io_history to protobuf
    void update_uid_io_proto(UidIOUsage* proto);

public:
    uid_monitor();
    ~uid_monitor();
    // called by storaged main thread
    void init(charger_stat_t stat, const UidIOUsage& proto);
    // called by storaged -u
    std::unordered_map<uint32_t, struct uid_info> get_uid_io_stats();
    // called by dumpsys
    std::map<uint64_t, struct uid_records> dump(
        double hours, uint64_t threshold, bool force_report,
        UidIOUsage* uid_io_proto);
    // called by battery properties listener
    void set_charger_state(charger_stat_t stat);
    // called by storaged periodic_chore or dump with force_report
    bool enabled() { return enable; };
    void report(UidIOUsage* proto);
};

#endif /* _STORAGED_UID_MONITOR_H_ */
