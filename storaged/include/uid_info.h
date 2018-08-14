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
#ifndef _UID_INFO_H_
#define _UID_INFO_H_

#include <string>
#include <unordered_map>

#include <binder/Parcelable.h>

namespace android {
namespace os {
namespace storaged {

enum uid_stat_t {
    FOREGROUND = 0,
    BACKGROUND = 1,
    UID_STATS = 2
};

enum charger_stat_t {
    CHARGER_OFF = 0,
    CHARGER_ON = 1,
    CHARGER_STATS = 2
};

enum io_type_t {
    READ = 0,
    WRITE = 1,
    IO_TYPES = 2
};

struct io_stats {
    uint64_t rchar;                 // characters read
    uint64_t wchar;                 // characters written
    uint64_t read_bytes;            // bytes read (from storage layer)
    uint64_t write_bytes;           // bytes written (to storage layer)
    uint64_t fsync;                 // number of fsync syscalls
};

class task_info {
public:
    std::string comm;
    pid_t pid;
    io_stats io[UID_STATS];
    bool parse_task_io_stats(std::string&& s);
};

class UidInfo : public Parcelable {
public:
    uint32_t uid;                     // user id
    std::string name;                 // package name
    io_stats io[UID_STATS];           // [0]:foreground [1]:background
    std::unordered_map<uint32_t, task_info> tasks; // mapped from pid

    status_t writeToParcel(Parcel* parcel) const override;
    status_t readFromParcel(const Parcel* parcel) override;
};

} // namespace storaged
} // namespace os
} // namespace android

#endif /*  _UID_INFO_H_ */