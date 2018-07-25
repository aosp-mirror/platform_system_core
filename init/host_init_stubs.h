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

#ifndef _INIT_HOST_INIT_STUBS_H
#define _INIT_HOST_INIT_STUBS_H

#include <stddef.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <string>

// sys/system_properties.h
#define PROP_VALUE_MAX 92

// unistd.h
int setgroups(size_t __size, const gid_t* __list);

namespace android {
namespace init {

// init.h
extern std::string default_console;

// property_service.h
extern uint32_t (*property_set)(const std::string& name, const std::string& value);
uint32_t HandlePropertySet(const std::string& name, const std::string& value,
                           const std::string& source_context, const ucred& cr, std::string* error);

// selinux.h
bool SelinuxHasVendorInit();
void SelabelInitialize();
bool SelabelLookupFileContext(const std::string& key, int type, std::string* result);

}  // namespace init
}  // namespace android

#endif
