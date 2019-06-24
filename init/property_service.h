/*
 * Copyright (C) 2007 The Android Open Source Project
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

#pragma once

#include <sys/socket.h>

#include <functional>
#include <string>

#include "epoll.h"
#include "result.h"

namespace android {
namespace init {

bool CanReadProperty(const std::string& source_context, const std::string& name);

extern uint32_t (*property_set)(const std::string& name, const std::string& value);

uint32_t HandlePropertySet(const std::string& name, const std::string& value,
                           const std::string& source_context, const ucred& cr, std::string* error);

void property_init();
void property_load_boot_defaults(bool load_debug_prop);
void load_persist_props();
void StartPropertyService(Epoll* epoll);

template <typename F, typename... Args>
Result<int> CallFunctionAndHandleProperties(F&& f, Args&&... args) {
    Result<int> CallFunctionAndHandlePropertiesImpl(const std::function<int()>& f);

    auto func = [&] { return f(args...); };
    return CallFunctionAndHandlePropertiesImpl(func);
}

}  // namespace init
}  // namespace android
