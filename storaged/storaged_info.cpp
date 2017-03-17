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

#include <string.h>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/parseint.h>
#include <log/log_event_list.h>

#include "storaged.h"

using namespace std;
using namespace android;
using namespace android::base;

void storage_info_t::publish()
{
    if (eol == 0 && lifetime_a == 0 && lifetime_b == 0) {
        return;
    }

    android_log_event_list(EVENTLOGTAG_EMMCINFO)
        << version << eol << lifetime_a << lifetime_b
        << LOG_ID_EVENTS;
}

bool emmc_info_t::init()
{
    string buffer;
    if (!ReadFileToString(ext_csd_file, &buffer) ||
        buffer.length() < (size_t)EXT_CSD_FILE_MIN_SIZE) {
        return false;
    }

    string ver_str = buffer.substr(EXT_CSD_REV_IDX, sizeof(str_hex));
    uint8_t ext_csd_rev;
    if (!ParseUint(ver_str, &ext_csd_rev)) {
        LOG_TO(SYSTEM, ERROR) << "Failure on parsing EXT_CSD_REV.";
        return false;
    }

    version = "emmc ";
    version += (ext_csd_rev < ARRAY_SIZE(emmc_ver_str)) ?
                emmc_ver_str[ext_csd_rev] : "Unknown";

    if (ext_csd_rev < 7) {
        return false;
    }

    return update();
}

bool emmc_info_t::update()
{
    string buffer;
    if (!ReadFileToString(ext_csd_file, &buffer) ||
        buffer.length() < (size_t)EXT_CSD_FILE_MIN_SIZE) {
        return false;
    }

    string str = buffer.substr(EXT_PRE_EOL_INFO_IDX, sizeof(str_hex));
    if (!ParseUint(str, &eol)) {
        LOG_TO(SYSTEM, ERROR) << "Failure on parsing EXT_PRE_EOL_INFO.";
        return false;
    }

    str = buffer.substr(EXT_DEVICE_LIFE_TIME_EST_A_IDX, sizeof(str_hex));
    if (!ParseUint(str, &lifetime_a)) {
        LOG_TO(SYSTEM, ERROR)
            << "Failure on parsing EXT_DEVICE_LIFE_TIME_EST_TYP_A.";
        return false;
    }

    str = buffer.substr(EXT_DEVICE_LIFE_TIME_EST_B_IDX, sizeof(str_hex));
    if (!ParseUint(str, &lifetime_b)) {
        LOG_TO(SYSTEM, ERROR)
            << "Failure on parsing EXT_DEVICE_LIFE_TIME_EST_TYP_B.";
        return false;
    }

    return true;
}
