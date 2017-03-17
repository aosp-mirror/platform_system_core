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

// two characters in string for each byte
struct str_hex {
    char str[2];
};

class storage_info_t {
protected:
    FRIEND_TEST(storaged_test, storage_info_t);
    uint8_t eol;                    // pre-eol (end of life) information
    uint8_t lifetime_a;             // device life time estimation (type A)
    uint8_t lifetime_b;             // device life time estimation (type B)
    string version;                 // version string
public:
    void publish();
    virtual ~storage_info_t() {}
    virtual bool init() = 0;
    virtual bool update() = 0;
};

class emmc_info_t : public storage_info_t {
private:
    // minimum size of a ext_csd file
    const int EXT_CSD_FILE_MIN_SIZE = 1024;
    // List of interesting offsets
    const size_t EXT_CSD_REV_IDX = 192 * sizeof(str_hex);
    const size_t EXT_PRE_EOL_INFO_IDX = 267 * sizeof(str_hex);
    const size_t EXT_DEVICE_LIFE_TIME_EST_A_IDX = 268 * sizeof(str_hex);
    const size_t EXT_DEVICE_LIFE_TIME_EST_B_IDX = 269 * sizeof(str_hex);

    const char* ext_csd_file = "/d/mmc0/mmc0:0001/ext_csd";
    const char* emmc_ver_str[8] = {
        "4.0", "4.1", "4.2", "4.3", "Obsolete", "4.41", "4.5", "5.0"
    };
public:
    virtual ~emmc_info_t() {}
    bool init();
    bool update();
};

#endif /* _STORAGED_INFO_H_ */
