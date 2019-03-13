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

#include "mount_handler.h"

#include <ctype.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <string>
#include <utility>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/strings.h>
#include <fs_mgr.h>
#include <fstab/fstab.h>

#include "epoll.h"
#include "property_service.h"

namespace android {
namespace init {

namespace {

MountHandlerEntry ParseMount(const std::string& line) {
    auto fields = android::base::Split(line, " ");
    while (fields.size() < 3) fields.emplace_back("");
    if (fields[0] == "/dev/root") {
        if (android::fs_mgr::Fstab fstab; android::fs_mgr::ReadDefaultFstab(&fstab)) {
            if (auto entry = GetEntryForMountPoint(&fstab, "/")) {
                fields[0] = entry->blk_device;
            }
        }
    }
    if (android::base::StartsWith(fields[0], "/dev/")) {
        if (std::string link; android::base::Readlink(fields[0], &link)) {
            fields[0] = link;
        }
    }
    return MountHandlerEntry(fields[0], fields[1], fields[2]);
}

void SetMountProperty(const MountHandlerEntry& entry, bool add) {
    static constexpr char devblock[] = "/dev/block/";
    if (!android::base::StartsWith(entry.blk_device, devblock)) return;
    std::string value;
    if (add) {
        value = entry.blk_device.substr(strlen(devblock));
        if (android::base::StartsWith(value, "sd")) {
            // All sd partitions inherit their queue characteristics
            // from the whole device reference.  Strip partition number.
            auto it = std::find_if(value.begin(), value.end(), [](char c) { return isdigit(c); });
            if (it != value.end()) value.erase(it, value.end());
        }
        auto queue = "/sys/block/" + value + "/queue";
        struct stat sb;
        if (stat(queue.c_str(), &sb) || !S_ISDIR(sb.st_mode)) value = "";
        if (stat(entry.mount_point.c_str(), &sb) || !S_ISDIR(sb.st_mode)) value = "";
        // Skip the noise associated with APEX until there is a need
        if (android::base::StartsWith(value, "loop")) value = "";
    }
    std::string property =
            "dev.mnt.blk" + ((entry.mount_point == "/") ? "/root" : entry.mount_point);
    std::replace(property.begin(), property.end(), '/', '.');
    if (value.empty() && android::base::GetProperty(property, "").empty()) return;
    property_set(property, value);
}

}  // namespace

MountHandlerEntry::MountHandlerEntry(const std::string& blk_device, const std::string& mount_point,
                                     const std::string& fs_type)
    : blk_device(blk_device), mount_point(mount_point), fs_type(fs_type) {}

bool MountHandlerEntry::operator<(const MountHandlerEntry& r) const {
    if (blk_device < r.blk_device) return true;
    if (blk_device > r.blk_device) return false;
    if (mount_point < r.mount_point) return true;
    if (mount_point > r.mount_point) return false;
    return fs_type < r.fs_type;
}

MountHandler::MountHandler(Epoll* epoll) : epoll_(epoll), fp_(fopen("/proc/mounts", "re"), fclose) {
    if (!fp_) PLOG(FATAL) << "Could not open /proc/mounts";
    auto result = epoll->RegisterHandler(
            fileno(fp_.get()), [this]() { this->MountHandlerFunction(); }, EPOLLERR | EPOLLPRI);
    if (!result) LOG(FATAL) << result.error();
}

MountHandler::~MountHandler() {
    if (fp_) epoll_->UnregisterHandler(fileno(fp_.get())).IgnoreError();
}

void MountHandler::MountHandlerFunction() {
    rewind(fp_.get());
    char* buf = nullptr;
    size_t len = 0;
    auto untouched = mounts_;
    while (getline(&buf, &len, fp_.get()) != -1) {
        auto entry = ParseMount(std::string(buf, len));
        auto match = untouched.find(entry);
        if (match == untouched.end()) {
            SetMountProperty(entry, true);
            mounts_.emplace(std::move(entry));
        } else {
            untouched.erase(match);
        }
    }
    free(buf);
    for (auto entry : untouched) {
        auto match = mounts_.find(entry);
        if (match == mounts_.end()) continue;
        mounts_.erase(match);
        SetMountProperty(entry, false);
    }
}

}  // namespace init
}  // namespace android
