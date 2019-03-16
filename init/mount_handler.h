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

#include <stdio.h>

#include <memory>
#include <set>
#include <string>

#include "epoll.h"

namespace android {
namespace init {

struct MountHandlerEntry {
    MountHandlerEntry(const std::string& blk_device, const std::string& mount_point,
                      const std::string& fs_type);

    bool operator<(const MountHandlerEntry& r) const;

    const std::string blk_device;
    const std::string mount_point;
    const std::string fs_type;
};

class MountHandler {
  public:
    explicit MountHandler(Epoll* epoll);
    MountHandler(const MountHandler&) = delete;
    MountHandler(MountHandler&&) = delete;
    MountHandler& operator=(const MountHandler&) = delete;
    MountHandler& operator=(MountHandler&&) = delete;
    ~MountHandler();

  private:
    void MountHandlerFunction();

    Epoll* epoll_;
    std::unique_ptr<FILE, decltype(&fclose)> fp_;
    std::set<MountHandlerEntry> mounts_;
};

}  // namespace init
}  // namespace android
