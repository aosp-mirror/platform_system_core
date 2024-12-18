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

#include <processgroup/cgroup_descriptor.h>

#include <processgroup/util.h>  // For flag values

CgroupDescriptor::CgroupDescriptor(uint32_t version, const std::string& name,
                                   const std::string& path, mode_t mode, const std::string& uid,
                                   const std::string& gid, uint32_t flags,
                                   uint32_t max_activation_depth)
    : controller_(version, flags, name, path, max_activation_depth),
      mode_(mode),
      uid_(uid),
      gid_(gid) {}

void CgroupDescriptor::set_mounted(bool mounted) {
    uint32_t flags = controller_.flags();
    if (mounted) {
        flags |= CGROUPRC_CONTROLLER_FLAG_MOUNTED;
    } else {
        flags &= ~CGROUPRC_CONTROLLER_FLAG_MOUNTED;
    }
    controller_.set_flags(flags);
}
