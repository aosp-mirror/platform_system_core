/*
 * Copyright (C) 2017 The Android Open Source Project
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

#ifndef _STORAGED_INFO_H_
#define _STORAGED_INFO_H_

#include <string.h>

#include <chrono>

#include <aidl/android/hardware/health/IHealth.h>
#include <utils/Mutex.h>

#include "storaged.h"
#include "storaged.pb.h"

#define FRIEND_TEST(test_case_name, test_name) \
friend class test_case_name##_##test_name##_Test

using namespace std;
using namespace android;
using namespace chrono;
using namespace storaged_proto;

class storage_info_t {
  protected:
    FRIEND_TEST(storaged_test, storage_info_t);
    FRIEND_TEST(storaged_test, storage_info_t_proto);
    // emmc lifetime
    uint16_t eol;                   // pre-eol (end of life) information
    uint16_t lifetime_a;            // device life time estimation (type A)
    uint16_t lifetime_b;            // device life time estimation (type B)
    string version;                 // version string
    // free space
    const string userdata_path = "/data";
    uint64_t userdata_total_kb;
    uint64_t userdata_free_kb;
    // io perf history
    time_point<system_clock> day_start_tp;
    vector<uint32_t> recent_perf;
    uint32_t nr_samples;
    vector<uint32_t> daily_perf;
    uint32_t nr_days;
    vector<uint32_t> weekly_perf;
    uint32_t nr_weeks;
    Mutex si_mutex;

    storage_info_t() : eol(0), lifetime_a(0), lifetime_b(0),
        userdata_total_kb(0), userdata_free_kb(0), nr_samples(0),
        daily_perf(WEEK_TO_DAYS, 0), nr_days(0),
        weekly_perf(YEAR_TO_WEEKS, 0), nr_weeks(0) {
            day_start_tp = system_clock::now();
            day_start_tp -= chrono::seconds(duration_cast<chrono::seconds>(
                day_start_tp.time_since_epoch()).count() % DAY_TO_SEC);
    }
    void publish();
    storage_info_t* s_info;

  public:
    static storage_info_t* get_storage_info(
            const shared_ptr<aidl::android::hardware::health::IHealth>& healthService);
    virtual ~storage_info_t(){};
    virtual void report() {};
    void load_perf_history_proto(const IOPerfHistory& perf_history);
    void refresh(IOPerfHistory* perf_history);
    void update_perf_history(uint32_t bw,
                             const time_point<system_clock>& tp);
    vector<int> get_perf_history();
    uint32_t get_recent_perf();
};

class emmc_info_t : public storage_info_t {
private:
    bool report_sysfs();
    bool report_debugfs();
public:
    static const string emmc_sysfs;
    static const string emmc_debugfs;
    static const char* emmc_ver_str[];

    virtual ~emmc_info_t() {}
    virtual void report();
};

class ufs_info_t : public storage_info_t {
public:
    static const string health_file;

    virtual ~ufs_info_t() {}
    virtual void report();
};

class health_storage_info_t : public storage_info_t {
  private:
    using IHealth = aidl::android::hardware::health::IHealth;
    using StorageInfo = aidl::android::hardware::health::StorageInfo;

    shared_ptr<IHealth> mHealth;
    void set_values_from_hal_storage_info(const StorageInfo& halInfo);

  public:
    health_storage_info_t(const shared_ptr<IHealth>& service) : mHealth(service){};
    virtual ~health_storage_info_t() {}
    virtual void report();
};

#endif /* _STORAGED_INFO_H_ */
