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

void uid_monitor::set_last_uids(std::unordered_map<uint32_t, struct uid_info>&& uids,
            uint64_t ts)
{
    last_uids = uids;
    last_report_ts = ts;
}

std::unordered_map<uint32_t, struct uid_info> uid_monitor::get_uids()
{
    std::unordered_map<uint32_t, struct uid_info> uids;
    std::string buffer;
    if (!android::base::ReadFileToString(UID_IO_STATS_PATH, &buffer)) {
        PLOG_TO(SYSTEM, ERROR) << UID_IO_STATS_PATH << ": ReadFileToString failed";
        return uids;
    }

    std::stringstream ss(buffer);
    struct uid_info u;
    bool refresh_uid = false;

    while (ss >> u.uid) {
        ss >> u.io[UID_FOREGROUND].rchar >> u.io[UID_FOREGROUND].wchar
           >> u.io[UID_FOREGROUND].read_bytes >> u.io[UID_FOREGROUND].write_bytes
           >> u.io[UID_BACKGROUND].rchar >> u.io[UID_BACKGROUND].wchar
           >> u.io[UID_BACKGROUND].read_bytes >> u.io[UID_BACKGROUND].write_bytes;

        if (!ss.good()) {
            ss.clear(std::ios_base::badbit);
            break;
        }

        if (last_uids.find(u.uid) == last_uids.end()) {
            refresh_uid = true;
            u.name = std::to_string(u.uid);
        } else {
            u.name = last_uids[u.uid].name;
        }
        uids[u.uid] = u;
    }

    if (!ss.eof() || ss.bad()) {
        uids.clear();
        LOG_TO(SYSTEM, ERROR) << "read UID IO stats failed";
    }

    if (refresh_uid) {
        packagelist_parse(packagelist_parse_cb, &uids);
    }

    return uids;
}

static const int MAX_UID_EVENTS_SIZE = 1000 * 48; // 1000 uids in 48 hours

void uid_monitor::add_events(const std::vector<struct uid_event>& new_events,
                             uint64_t curr_ts)
{
    std::unique_ptr<lock_t> lock(new lock_t(&events_lock));

    // remove events more than 5 days old
    struct uid_event first_event;
    first_event.ts = curr_ts / SEC_TO_USEC - 5 * DAY_TO_SEC;
    auto it = std::upper_bound(events.begin(), events.end(), first_event);
    events.erase(events.begin(), it);

    // make some room for new events
    int overflow = events.size() + new_events.size() - MAX_UID_EVENTS_SIZE;
    if (overflow > 0)
        events.erase(events.begin(), events.begin() + overflow);

    events.insert(events.end(), new_events.begin(), new_events.end());
}

std::vector<struct uid_event> uid_monitor::dump_events(int hours)
{
    std::unique_ptr<lock_t> lock(new lock_t(&events_lock));
    std::vector<struct uid_event> dump_events;
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0) {
        PLOG_TO(SYSTEM, ERROR) << "clock_gettime() failed";
        return dump_events;
    }

    struct uid_event first_event;
    if (hours == 0) {
        first_event.ts = 0; // dump all events
    } else {
        first_event.ts = ts.tv_sec - (uint64_t)hours * HOUR_TO_SEC;
    }
    auto it = std::upper_bound(events.begin(), events.end(), first_event);

    dump_events.assign(it, events.end());

    return dump_events;
}

void uid_monitor::report()
{
    struct timespec ts;

    // Use monotonic to exclude suspend time so that we measure IO bytes/sec
    // when system is running.
    if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0) {
        PLOG_TO(SYSTEM, ERROR) << "clock_gettime() failed";
        return;
    }

    uint64_t curr_ts = ts.tv_sec * NS_PER_SEC + ts.tv_nsec;
    uint64_t ts_delta = curr_ts - last_report_ts;
    uint64_t adjusted_threshold = threshold * ((double)ts_delta / interval / NS_PER_SEC);

    std::unordered_map<uint32_t, struct uid_info> uids = get_uids();
    if (uids.empty()) {
        return;
    }

    std::vector<struct uid_event> new_events;
    for (const auto& it : uids) {
        const struct uid_info& uid = it.second;
        struct uid_event event;

        event.ts = ts.tv_sec;
        event.name = uid.name;
        event.fg_read_bytes = uid.io[UID_FOREGROUND].read_bytes -
            last_uids[uid.uid].io[UID_FOREGROUND].read_bytes;;
        event.fg_write_bytes = uid.io[UID_FOREGROUND].write_bytes -
            last_uids[uid.uid].io[UID_FOREGROUND].write_bytes;;
        event.bg_read_bytes = uid.io[UID_BACKGROUND].read_bytes -
            last_uids[uid.uid].io[UID_BACKGROUND].read_bytes;;
        event.bg_write_bytes = uid.io[UID_BACKGROUND].write_bytes -
            last_uids[uid.uid].io[UID_BACKGROUND].write_bytes;;

        if (event.fg_read_bytes + event.fg_write_bytes +
            event.bg_read_bytes + event.bg_write_bytes == 0) {
            continue;
        }

        new_events.push_back(event);
    }

    add_events(new_events, curr_ts);
    set_last_uids(std::move(uids), curr_ts);
}

uid_monitor::uid_monitor()
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0) {
        PLOG_TO(SYSTEM, ERROR) << "clock_gettime() failed";
        return;
    }
    last_report_ts = ts.tv_sec * NS_PER_SEC + ts.tv_nsec;

    sem_init(&events_lock, 0, 1);
}

uid_monitor::~uid_monitor()
{
    sem_destroy(&events_lock);
}
