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
    // emmc lifetime
    uint16_t eol;                   // pre-eol (end of life) information
    uint16_t lifetime_a;            // device life time estimation (type A)
    uint16_t lifetime_b;            // device life time estimation (type B)
    string version;                 // version string
    // free space
    const string userdata_path = "/data";
    uint64_t userdata_total_kb;
    uint64_t userdata_free_kb;

    storage_info_t() : eol(0), lifetime_a(0), lifetime_b(0),
        userdata_total_kb(0), userdata_free_kb(0) {}
    void publish();
    storage_info_t* s_info;
public:
    static storage_info_t* get_storage_info();
    virtual ~storage_info_t() {}
    virtual void report() {};
    void refresh();
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

#endif /* _STORAGED_INFO_H_ */
