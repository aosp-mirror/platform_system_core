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

#ifndef _INIT_UEVENT_H
#define _INIT_UEVENT_H

#include <string>

namespace android {
namespace init {

struct Uevent {
    std::string action;
    std::string path;
    std::string subsystem;
    std::string firmware;
    std::string partition_name;
    std::string device_name;
    int partition_num;
    int major;
    int minor;
};

}  // namespace init
}  // namespace android

#endif
