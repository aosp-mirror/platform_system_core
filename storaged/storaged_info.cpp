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

#include <android-base/file.h>
#include <android-base/parseint.h>
#include <android-base/logging.h>
#include <android-base/strings.h>
#include <log/log_event_list.h>

#include "storaged.h"

using namespace std;
using namespace android::base;

const string emmc_info_t::emmc_sysfs = "/sys/bus/mmc/devices/mmc0:0001/";
const string emmc_info_t::emmc_debugfs = "/d/mmc0/mmc0:0001/ext_csd";
const char* emmc_info_t::emmc_ver_str[9] = {
    "4.0", "4.1", "4.2", "4.3", "Obsolete", "4.41", "4.5", "5.0", "5.1"
};

const string ufs_info_t::health_file = "/sys/devices/soc/624000.ufshc/health";

static bool FileExists(const std::string& filename)
{
  struct stat buffer;
  return stat(filename.c_str(), &buffer) == 0;
}

storage_info_t* storage_info_t::get_storage_info()
{
    if (FileExists(emmc_info_t::emmc_sysfs) ||
        FileExists(emmc_info_t::emmc_debugfs)) {
        return new emmc_info_t;
    }
    if (FileExists(ufs_info_t::health_file)) {
        return new ufs_info_t;
    }
    return new storage_info_t;
}

void storage_info_t::refresh()
{
    struct statvfs buf;
    if (statvfs(userdata_path.c_str(), &buf) != 0) {
        PLOG_TO(SYSTEM, WARNING) << "Failed to get userdata info";
        return;
    }

    userdata_total_kb = buf.f_bsize * buf.f_blocks >> 10;
    userdata_free_kb = buf.f_bfree * buf.f_blocks >> 10;
}

void storage_info_t::publish()
{
    android_log_event_list(EVENTLOGTAG_EMMCINFO)
        << version << eol << lifetime_a << lifetime_b
        << LOG_ID_EVENTS;
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

const size_t EXT_CSD_FILE_MIN_SIZE = 1024;
/* 2 characters in string for each byte */
const size_t EXT_CSD_REV_IDX = 192 * 2;
const size_t EXT_PRE_EOL_INFO_IDX = 267 * 2;
const size_t EXT_DEVICE_LIFE_TIME_EST_A_IDX = 268 * 2;
const size_t EXT_DEVICE_LIFE_TIME_EST_B_IDX = 269 * 2;

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

