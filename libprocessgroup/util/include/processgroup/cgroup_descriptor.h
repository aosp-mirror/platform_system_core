/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include <cstdint>
#include <string>

#include <sys/stat.h>

#include <processgroup/cgroup_controller.h>

// Complete controller description for mounting cgroups
class CgroupDescriptor {
  public:
    CgroupDescriptor(uint32_t version, const std::string& name, const std::string& path,
                     mode_t mode, const std::string& uid, const std::string& gid, uint32_t flags,
                     uint32_t max_activation_depth);

    const CgroupController* controller() const { return &controller_; }
    mode_t mode() const { return mode_; }
    std::string uid() const { return uid_; }
    std::string gid() const { return gid_; }

    void set_mounted(bool mounted);

  private:
    CgroupController controller_;
    mode_t mode_ = 0;
    std::string uid_;
    std::string gid_;
};
