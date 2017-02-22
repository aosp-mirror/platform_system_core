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

#include <stdint.h>
#include <time.h>

#include <string>
#include <sstream>
#include <unordered_map>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/macros.h>
#include <android-base/stringprintf.h>
#include <log/log_event_list.h>
#include <packagelistparser/packagelistparser.h>

#include "storaged.h"
#include "storaged_uid_monitor.h"

using namespace android;
using namespace android::base;

static bool packagelist_parse_cb(pkg_info* info, void* userdata)
{
    std::unordered_map<uint32_t, struct uid_info>* uids =
        reinterpret_cast<std::unordered_map<uint32_t, struct uid_info>*>(userdata);

    if (uids->find(info->uid) != uids->end()) {
        (*uids)[info->uid].name = info->name;
    }

    packagelist_free(info);
    return true;
}

std::unordered_map<uint32_t, struct uid_info> uid_monitor::get_uid_io_stats()
{
    std::unique_ptr<lock_t> lock(new lock_t(&um_lock));
    return get_uid_io_stats_locked();
};

std::unordered_map<uint32_t, struct uid_info> uid_monitor::get_uid_io_stats_locked()
{
    std::unordered_map<uint32_t, struct uid_info> uid_io_stats;
    std::string buffer;
    if (!android::base::ReadFileToString(UID_IO_STATS_PATH, &buffer)) {
        PLOG_TO(SYSTEM, ERROR) << UID_IO_STATS_PATH << ": ReadFileToString failed";
        return uid_io_stats;
    }

    std::stringstream ss(buffer);
    struct uid_info u;
    bool refresh_uid = false;

    while (ss >> u.uid) {
        ss >> u.io[FOREGROUND].rchar >> u.io[FOREGROUND].wchar
           >> u.io[FOREGROUND].read_bytes >> u.io[FOREGROUND].write_bytes
           >> u.io[BACKGROUND].rchar >> u.io[BACKGROUND].wchar
           >> u.io[BACKGROUND].read_bytes >> u.io[BACKGROUND].write_bytes;

        if (!ss.good()) {
            ss.clear(std::ios_base::badbit);
            break;
        }

        if (last_uid_io_stats.find(u.uid) == last_uid_io_stats.end()) {
            refresh_uid = true;
            u.name = std::to_string(u.uid);
        } else {
            u.name = last_uid_io_stats[u.uid].name;
        }
        uid_io_stats[u.uid] = u;
    }

    if (!ss.eof() || ss.bad()) {
        uid_io_stats.clear();
        LOG_TO(SYSTEM, ERROR) << "read UID IO stats failed";
    }

    if (refresh_uid) {
        packagelist_parse(packagelist_parse_cb, &uid_io_stats);
    }

    return uid_io_stats;
}

static const int MAX_UID_RECORDS_SIZE = 1000 * 48; // 1000 uids in 48 hours

static inline int records_size(
    const std::map<uint64_t, struct uid_records>& curr_records)
{
    int count = 0;
    for (auto const& it : curr_records) {
        count += it.second.entries.size();
    }
    return count;
}

static struct uid_io_usage zero_io_usage;

void uid_monitor::add_records_locked(uint64_t curr_ts)
{
    // remove records more than 5 days old
    if (curr_ts > 5 * DAY_TO_SEC) {
        auto it = records.lower_bound(curr_ts - 5 * DAY_TO_SEC);
        records.erase(records.begin(), it);
    }

    struct uid_records new_records;
    for (const auto& p : curr_io_stats) {
        struct uid_record record = {};
        record.name = p.first;
        record.ios = p.second;
        if (memcmp(&record.ios, &zero_io_usage, sizeof(struct uid_io_usage))) {
            new_records.entries.push_back(record);
        }
    }

    curr_io_stats.clear();
    new_records.start_ts = start_ts;
    start_ts = curr_ts;

    if (new_records.entries.empty())
      return;

    // make some room for new records
    int overflow = records_size(records) +
        new_records.entries.size() - MAX_UID_RECORDS_SIZE;
    while (overflow > 0 && records.size() > 0) {
        auto del_it = records.begin();
        overflow -= del_it->second.entries.size();
        records.erase(records.begin());
    }

    records[curr_ts] = new_records;
}

std::map<uint64_t, struct uid_records> uid_monitor::dump(
    double hours, uint64_t threshold, bool force_report)
{
    if (force_report) {
        report();
    }

    std::unique_ptr<lock_t> lock(new lock_t(&um_lock));

    std::map<uint64_t, struct uid_records> dump_records;
    uint64_t first_ts = 0;

    if (hours != 0) {
        first_ts = time(NULL) - hours * HOUR_TO_SEC;
    }

    for (auto it = records.lower_bound(first_ts); it != records.end(); ++it) {
        const std::vector<struct uid_record>& recs = it->second.entries;
        struct uid_records filtered;

        for (const auto& rec : recs) {
            if (rec.ios.bytes[READ][FOREGROUND][CHARGER_ON] +
                rec.ios.bytes[READ][FOREGROUND][CHARGER_OFF] +
                rec.ios.bytes[READ][BACKGROUND][CHARGER_ON] +
                rec.ios.bytes[READ][BACKGROUND][CHARGER_OFF] +
                rec.ios.bytes[WRITE][FOREGROUND][CHARGER_ON] +
                rec.ios.bytes[WRITE][FOREGROUND][CHARGER_OFF] +
                rec.ios.bytes[WRITE][BACKGROUND][CHARGER_ON] +
                rec.ios.bytes[WRITE][BACKGROUND][CHARGER_OFF] > threshold) {
                filtered.entries.push_back(rec);
            }
        }

        if (filtered.entries.empty())
            continue;

        filtered.start_ts = it->second.start_ts;
        dump_records.insert(
            std::pair<uint64_t, struct uid_records>(it->first, filtered));
    }

    return dump_records;
}

void uid_monitor::update_curr_io_stats_locked()
{
    std::unordered_map<uint32_t, struct uid_info> uid_io_stats =
        get_uid_io_stats_locked();
    if (uid_io_stats.empty()) {
        return;
    }

    for (const auto& it : uid_io_stats) {
        const struct uid_info& uid = it.second;

        if (curr_io_stats.find(uid.name) == curr_io_stats.end()) {
          curr_io_stats[uid.name] = {};
        }

        struct uid_io_usage& usage = curr_io_stats[uid.name];
        int64_t fg_rd_delta = uid.io[FOREGROUND].read_bytes -
            last_uid_io_stats[uid.uid].io[FOREGROUND].read_bytes;
        int64_t bg_rd_delta = uid.io[BACKGROUND].read_bytes -
            last_uid_io_stats[uid.uid].io[BACKGROUND].read_bytes;
        int64_t fg_wr_delta = uid.io[FOREGROUND].write_bytes -
            last_uid_io_stats[uid.uid].io[FOREGROUND].write_bytes;
        int64_t bg_wr_delta = uid.io[BACKGROUND].write_bytes -
            last_uid_io_stats[uid.uid].io[BACKGROUND].write_bytes;

        usage.bytes[READ][FOREGROUND][charger_stat] +=
            (fg_rd_delta < 0) ? uid.io[FOREGROUND].read_bytes : fg_rd_delta;
        usage.bytes[READ][BACKGROUND][charger_stat] +=
            (bg_rd_delta < 0) ? uid.io[BACKGROUND].read_bytes : bg_rd_delta;
        usage.bytes[WRITE][FOREGROUND][charger_stat] +=
            (fg_wr_delta < 0) ? uid.io[FOREGROUND].write_bytes : fg_wr_delta;
        usage.bytes[WRITE][BACKGROUND][charger_stat] +=
            (bg_wr_delta < 0) ? uid.io[BACKGROUND].write_bytes : bg_wr_delta;
    }

    last_uid_io_stats = uid_io_stats;
}

void uid_monitor::report()
{
    std::unique_ptr<lock_t> lock(new lock_t(&um_lock));

    update_curr_io_stats_locked();
    add_records_locked(time(NULL));
}

void uid_monitor::set_charger_state(charger_stat_t stat)
{
    std::unique_ptr<lock_t> lock(new lock_t(&um_lock));

    if (charger_stat == stat) {
        return;
    }

    update_curr_io_stats_locked();
    charger_stat = stat;
}

void uid_monitor::init(charger_stat_t stat)
{
    charger_stat = stat;
    start_ts = time(NULL);
    last_uid_io_stats = get_uid_io_stats();
}

uid_monitor::uid_monitor()
{
    sem_init(&um_lock, 0, 1);
}

uid_monitor::~uid_monitor()
{
    sem_destroy(&um_lock);
}
