/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include "host_init_stubs.h"

// unistd.h
int setgroups(size_t __size, const gid_t* __list) {
    return 0;
}

namespace android {
namespace base {

std::string GetProperty(const std::string&, const std::string& default_value) {
    return default_value;
}

bool GetBoolProperty(const std::string&, bool default_value) {
    return default_value;
}

}  // namespace base
}  // namespace android

namespace android {
namespace init {

// init.h
std::string default_console = "/dev/console";

// property_service.h
uint32_t (*property_set)(const std::string& name, const std::string& value) = nullptr;
uint32_t HandlePropertySet(const std::string&, const std::string&, const std::string&,
                           const ucred&) {
    return 0;
}

// selinux.h
void SelabelInitialize() {}

bool SelabelLookupFileContext(const std::string& key, int type, std::string* result) {
    return false;
}

}  // namespace init
}  // namespace android
