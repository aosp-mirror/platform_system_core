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

#include <cutils/multiuser.h>
#include <utils/Mutex.h>

#include "storaged.pb.h"
#include "uid_info.h"

#define FRIEND_TEST(test_case_name, test_name) \
friend class test_case_name##_##test_name##_Test

using namespace std;
using namespace storaged_proto;
using namespace android;
using namespace android::os::storaged;

class uid_info : public UidInfo {
public:
    bool parse_uid_io_stats(string&& s);
};

class io_usage {
public:
    io_usage() : bytes{{{0}}} {};
    uint64_t bytes[IO_TYPES][UID_STATS][CHARGER_STATS];
    bool is_zero() const;
    io_usage& operator+= (const io_usage& stats) {
        for (int i = 0; i < IO_TYPES; i++) {
            for (int j = 0; j < UID_STATS; j++) {
                for (int k = 0; k < CHARGER_STATS; k++) {
                    bytes[i][j][k] += stats.bytes[i][j][k];
                }
            }
        }
        return *this;
    }
};

struct uid_io_usage {
    userid_t user_id;
    io_usage uid_ios;
    // mapped from task comm to task io usage
    map<string, io_usage> task_ios;
};

struct uid_record {
    string name;
    uid_io_usage ios;
};

struct uid_records {
    uint64_t start_ts;
    vector<uid_record> entries;
};

class uid_monitor {
private:
    FRIEND_TEST(storaged_test, uid_monitor);
    FRIEND_TEST(storaged_test, load_uid_io_proto);

    // last dump from /proc/uid_io/stats, uid -> uid_info
    unordered_map<uint32_t, uid_info> last_uid_io_stats_;
    // current io usage for next report, app name -> uid_io_usage
    unordered_map<string, uid_io_usage> curr_io_stats_;
    // io usage records, end timestamp -> {start timestamp, vector of records}
    map<uint64_t, uid_records> io_history_;
    // charger ON/OFF
    charger_stat_t charger_stat_;
    // protects curr_io_stats, last_uid_io_stats, records and charger_stat
    Mutex uidm_mutex_;
    // start time for IO records
    uint64_t start_ts_;
    // true if UID_IO_STATS_PATH is accessible
    const bool enabled_;

    // reads from /proc/uid_io/stats
    unordered_map<uint32_t, uid_info> get_uid_io_stats_locked();
    // flushes curr_io_stats to records
    void add_records_locked(uint64_t curr_ts);
    // updates curr_io_stats and set last_uid_io_stats
    void update_curr_io_stats_locked();
    // writes io_history to protobuf
    void update_uid_io_proto(unordered_map<int, StoragedProto>* protos);

    // Ensure that io_history_ can append |n| items without exceeding
    // MAX_UID_RECORDS_SIZE in size.
    void maybe_shrink_history_for_items(size_t nitems);

public:
    uid_monitor();
    // called by storaged main thread
    void init(charger_stat_t stat);
    // called by storaged -u
    unordered_map<uint32_t, uid_info> get_uid_io_stats();
    // called by dumpsys
    map<uint64_t, uid_records> dump(
        double hours, uint64_t threshold, bool force_report);
    // called by battery properties listener
    void set_charger_state(charger_stat_t stat);
    // called by storaged periodic_chore or dump with force_report
    bool enabled() { return enabled_; };
    void report(unordered_map<int, StoragedProto>* protos);
    // restores io_history from protobuf
    void load_uid_io_proto(userid_t user_id, const UidIOUsage& proto);
    void clear_user_history(userid_t user_id);

    map<uint64_t, uid_records>& io_history() { return io_history_; }

    static constexpr int MAX_UID_RECORDS_SIZE = 1000 * 48; // 1000 uids in 48 hours
};

#endif /* _STORAGED_UID_MONITOR_H_ */
