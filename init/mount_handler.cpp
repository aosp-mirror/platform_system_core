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
#include <filesystem>
#include <string>
#include <utility>
#include <vector>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <fs_mgr.h>
#include <fstab/fstab.h>
#include <libdm/dm.h>

#include "epoll.h"

using android::base::Basename;
using android::base::StringPrintf;

namespace android {
namespace init {

namespace {

MountHandlerEntry ParseMount(const std::string& line) {
    auto fields = android::base::Split(line, " ");
    while (fields.size() < 3) fields.emplace_back("");
    if (fields[0] == "/dev/root") {
        auto& dm = dm::DeviceMapper::Instance();
        std::string path;
        if (dm.GetDmDevicePathByName("system", &path) || dm.GetDmDevicePathByName("vroot", &path)) {
            fields[0] = path;
        } else if (android::fs_mgr::Fstab fstab; android::fs_mgr::ReadDefaultFstab(&fstab)) {
            auto entry = GetEntryForMountPoint(&fstab, "/");
            if (entry || (entry = GetEntryForMountPoint(&fstab, "/system"))) {
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

// return sda25 for dm-4, sda25 for sda25, or mmcblk0p24 for mmcblk0p24
std::string GetDiskPart(std::string blockdev) {
    if (blockdev.find('/') != std::string::npos) return {};

    while (android::base::StartsWith(blockdev, "dm-")) {
        auto& dm = dm::DeviceMapper::Instance();
        std::optional<std::string> parent = dm.GetParentBlockDeviceByPath("/dev/block/" + blockdev);
        if (parent) {
            blockdev = android::base::Basename(*parent);
        } else {
            return {};
        }
    }
    return blockdev;
}

// return sda for sda25, or mmcblk0 for mmcblk0p24
std::string GetRootDisk(std::string blockdev) {
    if (blockdev.empty()) return {};
    if (blockdev.find('/') != std::string::npos) return {};

    std::error_code ec;
    for (const auto& entry : std::filesystem::directory_iterator("/sys/block", ec)) {
        const std::string path = entry.path().string();
        if (std::filesystem::exists(StringPrintf("%s/%s", path.c_str(), blockdev.c_str()))) {
            return Basename(path);
        }
    }
    return {};
}

void SetMountProperty(const MountHandlerEntry& entry, bool add) {
    static constexpr char devblock[] = "/dev/block/";
    if (!android::base::StartsWith(entry.blk_device, devblock)) return;
    auto target = entry.blk_device.substr(strlen(devblock));
    std::string diskpart, rootdisk;
    if (add) {
        diskpart = GetDiskPart(target);
        rootdisk = GetRootDisk(diskpart);

        struct stat sb;
        if (stat(entry.mount_point.c_str(), &sb) || !S_ISDIR(sb.st_mode)) rootdisk = "";
        // Clear the noise associated with loopback and APEX.
        if (android::base::StartsWith(target, "loop")) rootdisk = "";
        if (android::base::StartsWith(entry.mount_point, "/apex/")) rootdisk = "";
    }
    auto mount_prop = entry.mount_point;
    if (mount_prop == "/") mount_prop = "/root";
    std::replace(mount_prop.begin(), mount_prop.end(), '/', '.');
    auto blk_mount_prop = "dev.mnt.blk" + mount_prop;
    auto dev_mount_prop = "dev.mnt.dev" + mount_prop;
    auto rootdisk_mount_prop = "dev.mnt.rootdisk" + mount_prop;
    // Set property even if its rootdisk does not change to trigger 'on property:'
    // handling, except for clearing non-existent or already clear property.
    // Goal is reduction of empty properties and associated triggers.
    if (rootdisk.empty() && android::base::GetProperty(blk_mount_prop, "").empty()) return;

    if (rootdisk.empty()) {
        android::base::SetProperty(blk_mount_prop, "");
        android::base::SetProperty(dev_mount_prop, "");
        android::base::SetProperty(rootdisk_mount_prop, "");
        return;
    }

    // 1. dm-N
    //  dev.mnt.dev.data = dm-N
    //  dev.mnt.blk.data = sdaN or mmcblk0pN
    //  dev.mnt.rootdisk.data = sda or mmcblk0
    //
    // 2. sdaN or mmcblk0pN
    //  dev.mnt.dev.data = sdaN or mmcblk0pN
    //  dev.mnt.blk.data = sdaN or mmcblk0pN
    //  dev.mnt.rootdisk.data = sda or mmcblk0
    android::base::SetProperty(dev_mount_prop, target);
    android::base::SetProperty(blk_mount_prop, diskpart);
    android::base::SetProperty(rootdisk_mount_prop, rootdisk);
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
    if (!result.ok()) LOG(FATAL) << result.error();
}

MountHandler::~MountHandler() {
    if (fp_) epoll_->UnregisterHandler(fileno(fp_.get()));
}

void MountHandler::MountHandlerFunction() {
    rewind(fp_.get());
    std::vector<MountHandlerEntry> touched;
    auto untouched = mounts_;
    char* buf = nullptr;
    size_t len = 0;
    while (getline(&buf, &len, fp_.get()) != -1) {
        auto buf_string = std::string(buf);
        if (buf_string.find("/emulated") != std::string::npos) {
            continue;
        }
        auto entry = ParseMount(buf_string);
        auto match = untouched.find(entry);
        if (match == untouched.end()) {
            touched.emplace_back(std::move(entry));
        } else {
            untouched.erase(match);
        }
    }
    free(buf);
    for (auto& entry : untouched) {
        SetMountProperty(entry, false);
        mounts_.erase(entry);
    }
    for (auto& entry : touched) {
        SetMountProperty(entry, true);
        mounts_.emplace(std::move(entry));
    }
}

}  // namespace init
}  // namespace android
