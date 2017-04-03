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

#define FRIEND_TEST(test_case_name, test_name) \
friend class test_case_name##_##test_name##_Test

using namespace std;

class storage_info_t {
protected:
    FRIEND_TEST(storaged_test, storage_info_t);
    uint16_t eol;                   // pre-eol (end of life) information
    uint16_t lifetime_a;            // device life time estimation (type A)
    uint16_t lifetime_b;            // device life time estimation (type B)
    string version;                 // version string
    void publish();
public:
    storage_info_t() : eol(0), lifetime_a(0), lifetime_b(0) {}
    virtual ~storage_info_t() {}
    virtual bool report() = 0;
};

class emmc_info_t : public storage_info_t {
private:
    const string emmc_sysfs = "/sys/bus/mmc/devices/mmc0:0001/";
    const string emmc_debugfs = "/d/mmc0/mmc0:0001/ext_csd";
    const char* emmc_ver_str[9] = {
        "4.0", "4.1", "4.2", "4.3", "Obsolete", "4.41", "4.5", "5.0", "5.1"
    };
public:
    virtual ~emmc_info_t() {}
    bool report();
    bool report_sysfs();
    bool report_debugfs();
};

void report_storage_health();

#endif /* _STORAGED_INFO_H_ */
