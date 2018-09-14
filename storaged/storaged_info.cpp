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

#include <stdio.h>
#include <string.h>
#include <sys/statvfs.h>

#include <numeric>

#include <android-base/file.h>
#include <android-base/parseint.h>
#include <android-base/logging.h>
#include <android-base/strings.h>
#include <log/log_event_list.h>

#include "storaged.h"
#include "storaged_info.h"

using namespace std;
using namespace chrono;
using namespace android::base;
using namespace storaged_proto;

using android::hardware::health::V2_0::IHealth;
using android::hardware::health::V2_0::Result;
using android::hardware::health::V2_0::StorageInfo;

const string emmc_info_t::emmc_sysfs = "/sys/bus/mmc/devices/mmc0:0001/";
const string emmc_info_t::emmc_debugfs = "/d/mmc0/mmc0:0001/ext_csd";
const char* emmc_info_t::emmc_ver_str[9] = {
    "4.0", "4.1", "4.2", "4.3", "Obsolete", "4.41", "4.5", "5.0", "5.1"
};

const string ufs_info_t::health_file = "/sys/devices/soc/624000.ufshc/health";

namespace {

bool FileExists(const std::string& filename)
{
  struct stat buffer;
  return stat(filename.c_str(), &buffer) == 0;
}

} // namespace

storage_info_t* storage_info_t::get_storage_info(const sp<IHealth>& healthService) {
    if (healthService != nullptr) {
        return new health_storage_info_t(healthService);
    }
    if (FileExists(emmc_info_t::emmc_sysfs) ||
        FileExists(emmc_info_t::emmc_debugfs)) {
        return new emmc_info_t;
    }
    if (FileExists(ufs_info_t::health_file)) {
        return new ufs_info_t;
    }
    return new storage_info_t;
}

void storage_info_t::load_perf_history_proto(const IOPerfHistory& perf_history)
{
    Mutex::Autolock _l(si_mutex);

    if (!perf_history.has_day_start_sec() ||
        perf_history.daily_perf_size() > (int)daily_perf.size() ||
        perf_history.weekly_perf_size() > (int)weekly_perf.size()) {
        LOG_TO(SYSTEM, ERROR) << "Invalid IOPerfHistory proto";
        return;
    }

    day_start_tp = {};
    day_start_tp += chrono::seconds(perf_history.day_start_sec());

    nr_samples = perf_history.nr_samples();
    for (auto bw : perf_history.recent_perf()) {
        recent_perf.push_back(bw);
    }

    nr_days = perf_history.nr_days();
    int i = 0;
    for (auto bw : perf_history.daily_perf()) {
        daily_perf[i++] = bw;
    }

    nr_weeks = perf_history.nr_weeks();
    i = 0;
    for (auto bw : perf_history.weekly_perf()) {
        weekly_perf[i++] = bw;
    }
}

void storage_info_t::refresh(IOPerfHistory* perf_history)
{
    struct statvfs buf;
    if (statvfs(userdata_path.c_str(), &buf) != 0) {
        PLOG_TO(SYSTEM, WARNING) << "Failed to get userdata info";
        return;
    }

    userdata_total_kb = buf.f_bsize * buf.f_blocks >> 10;
    userdata_free_kb = buf.f_bfree * buf.f_blocks >> 10;

    Mutex::Autolock _l(si_mutex);

    perf_history->Clear();
    perf_history->set_day_start_sec(
        duration_cast<chrono::seconds>(day_start_tp.time_since_epoch()).count());
    for (const uint32_t& bw : recent_perf) {
        perf_history->add_recent_perf(bw);
    }
    perf_history->set_nr_samples(nr_samples);
    for (const uint32_t& bw : daily_perf) {
        perf_history->add_daily_perf(bw);
    }
    perf_history->set_nr_days(nr_days);
    for (const uint32_t& bw : weekly_perf) {
        perf_history->add_weekly_perf(bw);
    }
    perf_history->set_nr_weeks(nr_weeks);
}

void storage_info_t::publish()
{
    android_log_event_list(EVENTLOGTAG_EMMCINFO)
        << version << eol << lifetime_a << lifetime_b
        << LOG_ID_EVENTS;
}

void storage_info_t::update_perf_history(uint32_t bw,
                                         const time_point<system_clock>& tp)
{
    Mutex::Autolock _l(si_mutex);

    if (tp > day_start_tp &&
        duration_cast<chrono::seconds>(tp - day_start_tp).count() < DAY_TO_SEC) {
        if (nr_samples >= recent_perf.size()) {
            recent_perf.push_back(bw);
        } else {
            recent_perf[nr_samples] = bw;
        }
        nr_samples++;
        return;
    }

    if (nr_samples < recent_perf.size()) {
        recent_perf.erase(recent_perf.begin() + nr_samples, recent_perf.end());
    }

    uint32_t daily_avg_bw = 0;
    if (!recent_perf.empty()) {
        daily_avg_bw = accumulate(recent_perf.begin(), recent_perf.end(), 0) / recent_perf.size();
    }

    day_start_tp = tp - chrono::seconds(duration_cast<chrono::seconds>(
        tp.time_since_epoch()).count() % DAY_TO_SEC);

    nr_samples = 0;
    if (recent_perf.empty())
        recent_perf.resize(1);
    recent_perf[nr_samples++] = bw;

    if (nr_days < WEEK_TO_DAYS) {
        daily_perf[nr_days++] = daily_avg_bw;
        return;
    }

    DCHECK(nr_days > 0);
    uint32_t week_avg_bw = accumulate(daily_perf.begin(),
        daily_perf.begin() + nr_days, 0) / nr_days;

    nr_days = 0;
    daily_perf[nr_days++] = daily_avg_bw;

    if (nr_weeks >= YEAR_TO_WEEKS) {
        nr_weeks = 0;
    }
    weekly_perf[nr_weeks++] = week_avg_bw;
}

vector<int> storage_info_t::get_perf_history()
{
    Mutex::Autolock _l(si_mutex);

    vector<int> ret(3 + recent_perf.size() + daily_perf.size() + weekly_perf.size());

    ret[0] = recent_perf.size();
    ret[1] = daily_perf.size();
    ret[2] = weekly_perf.size();

    int start = 3;
    for (size_t i = 0; i < recent_perf.size(); i++) {
        int idx = (recent_perf.size() + nr_samples - 1 - i) % recent_perf.size();
        ret[start + i] = recent_perf[idx];
    }

    start += recent_perf.size();
    for (size_t i = 0; i < daily_perf.size(); i++) {
        int idx = (daily_perf.size() + nr_days - 1 - i) % daily_perf.size();
        ret[start + i] = daily_perf[idx];
    }

    start += daily_perf.size();
    for (size_t i = 0; i < weekly_perf.size(); i++) {
        int idx = (weekly_perf.size() + nr_weeks - 1 - i) % weekly_perf.size();
        ret[start + i] = weekly_perf[idx];
    }

    return ret;
}

uint32_t storage_info_t::get_recent_perf() {
    Mutex::Autolock _l(si_mutex);
    if (recent_perf.size() == 0) return 0;
    return accumulate(recent_perf.begin(), recent_perf.end(), recent_perf.size() / 2) /
           recent_perf.size();
}

void emmc_info_t::report()
{
    if (!report_sysfs() && !report_debugfs())
        return;

    publish();
}

bool emmc_info_t::report_sysfs()
{
    string buffer;
    uint16_t rev = 0;

    if (!ReadFileToString(emmc_sysfs + "rev", &buffer)) {
        return false;
    }

    if (sscanf(buffer.c_str(), "0x%hx", &rev) < 1 ||
        rev < 7 || rev > ARRAY_SIZE(emmc_ver_str)) {
        return false;
    }

    version = "emmc ";
    version += emmc_ver_str[rev];

    if (!ReadFileToString(emmc_sysfs + "pre_eol_info", &buffer)) {
        return false;
    }

    if (sscanf(buffer.c_str(), "%hx", &eol) < 1 || eol == 0) {
        return false;
    }

    if (!ReadFileToString(emmc_sysfs + "life_time", &buffer)) {
        return false;
    }

    if (sscanf(buffer.c_str(), "0x%hx 0x%hx", &lifetime_a, &lifetime_b) < 2 ||
        (lifetime_a == 0 && lifetime_b == 0)) {
        return false;
    }

    return true;
}

namespace {

const size_t EXT_CSD_FILE_MIN_SIZE = 1024;
/* 2 characters in string for each byte */
const size_t EXT_CSD_REV_IDX = 192 * 2;
const size_t EXT_PRE_EOL_INFO_IDX = 267 * 2;
const size_t EXT_DEVICE_LIFE_TIME_EST_A_IDX = 268 * 2;
const size_t EXT_DEVICE_LIFE_TIME_EST_B_IDX = 269 * 2;

} // namespace

bool emmc_info_t::report_debugfs()
{
    string buffer;
    uint16_t rev = 0;

    if (!ReadFileToString(emmc_debugfs, &buffer) ||
        buffer.length() < (size_t)EXT_CSD_FILE_MIN_SIZE) {
        return false;
    }

    string str = buffer.substr(EXT_CSD_REV_IDX, 2);
    if (!ParseUint(str, &rev) ||
        rev < 7 || rev > ARRAY_SIZE(emmc_ver_str)) {
        return false;
    }

    version = "emmc ";
    version += emmc_ver_str[rev];

    str = buffer.substr(EXT_PRE_EOL_INFO_IDX, 2);
    if (!ParseUint(str, &eol)) {
        return false;
    }

    str = buffer.substr(EXT_DEVICE_LIFE_TIME_EST_A_IDX, 2);
    if (!ParseUint(str, &lifetime_a)) {
        return false;
    }

    str = buffer.substr(EXT_DEVICE_LIFE_TIME_EST_B_IDX, 2);
    if (!ParseUint(str, &lifetime_b)) {
        return false;
    }

    return true;
}

void ufs_info_t::report()
{
    string buffer;
    if (!ReadFileToString(health_file, &buffer)) {
        return;
    }

    vector<string> lines = Split(buffer, "\n");
    if (lines.empty()) {
        return;
    }

    char rev[8];
    if (sscanf(lines[0].c_str(), "ufs version: 0x%7s\n", rev) < 1) {
        return;
    }

    version = "ufs " + string(rev);

    for (size_t i = 1; i < lines.size(); i++) {
        char token[32];
        uint16_t val;
        int ret;
        if ((ret = sscanf(lines[i].c_str(),
                   "Health Descriptor[Byte offset 0x%*d]: %31s = 0x%hx",
                   token, &val)) < 2) {
            continue;
        }

        if (string(token) == "bPreEOLInfo") {
            eol = val;
        } else if (string(token) == "bDeviceLifeTimeEstA") {
            lifetime_a = val;
        } else if (string(token) == "bDeviceLifeTimeEstB") {
            lifetime_b = val;
        }
    }

    if (eol == 0 || (lifetime_a == 0 && lifetime_b == 0)) {
        return;
    }

    publish();
}

void health_storage_info_t::report() {
    auto ret = mHealth->getStorageInfo([this](auto result, const auto& halInfos) {
        if (result == Result::NOT_SUPPORTED) {
            LOG_TO(SYSTEM, DEBUG) << "getStorageInfo is not supported on health HAL.";
            return;
        }
        if (result != Result::SUCCESS || halInfos.size() == 0) {
            LOG_TO(SYSTEM, ERROR) << "getStorageInfo failed with result " << toString(result)
                                  << " and size " << halInfos.size();
            return;
        }
        set_values_from_hal_storage_info(halInfos[0]);
        publish();
    });

    if (!ret.isOk()) {
        LOG_TO(SYSTEM, ERROR) << "getStorageInfo failed with " << ret.description();
    }
}

void health_storage_info_t::set_values_from_hal_storage_info(const StorageInfo& halInfo) {
    eol = halInfo.eol;
    lifetime_a = halInfo.lifetimeA;
    lifetime_b = halInfo.lifetimeB;
    version = halInfo.version;
}
