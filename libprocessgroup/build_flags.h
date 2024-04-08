/*
 * Copyright (C) 2024 The Android Open Source Project
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

#ifndef MEMCG_V2_FORCE_ENABLED
#define MEMCG_V2_FORCE_ENABLED false
#endif

#ifndef CGROUP_V2_SYS_APP_ISOLATION
#define CGROUP_V2_SYS_APP_ISOLATION false
#endif

namespace android::libprocessgroup_flags {

inline consteval bool force_memcg_v2() {
    return MEMCG_V2_FORCE_ENABLED;
}

inline consteval bool cgroup_v2_sys_app_isolation() {
    return CGROUP_V2_SYS_APP_ISOLATION;
}

}  // namespace android::libprocessgroup_flags
