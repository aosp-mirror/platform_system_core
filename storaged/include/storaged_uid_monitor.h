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

enum {
    UID_FOREGROUND = 0,
    UID_BACKGROUND = 1,
    UID_STATS_SIZE = 2
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
    struct uid_io_stats io[UID_STATS_SIZE];      // [0]:foreground [1]:background
};

struct uid_event {
    std::string name;
    uint64_t fg_read_bytes;
    uint64_t fg_write_bytes;
    uint64_t bg_read_bytes;
    uint64_t bg_write_bytes;
    uint64_t interval;
};

class uid_monitor {
private:
    std::unordered_map<uint32_t, struct uid_info> last_uids;
    std::vector<struct uid_event> events;
    sem_t events_lock;
    void set_last_uids(std::unordered_map<uint32_t, struct uid_info>&& uids, uint64_t ts);
    int interval;  // monitor interval in seconds
    int threshold; // monitor threshold in bytes
    uint64_t last_report_ts; // timestamp of last report in nsec
public:
    uid_monitor();
    ~uid_monitor();
    void set_periodic_chores_params(int intvl, int thold) { interval = intvl; threshold = thold; }
    int get_periodic_chores_interval() { return interval; }
    std::unordered_map<uint32_t, struct uid_info> get_uids();
    void report();
    void add_event(const struct uid_event& event);
    std::vector<struct uid_event> dump_events();
};

#endif /* _STORAGED_UID_MONITOR_H_ */
