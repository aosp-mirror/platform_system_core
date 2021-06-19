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
#pragma once

#include <optional>
#include <string>

#include <android-base/unique_fd.h>
#include <android/hardware/boot/1.0/IBootControl.h>
#include <fstab/fstab.h>
#include <liblp/liblp.h>

// Logical partitions are only mapped to a block device as needed, and
// immediately unmapped when no longer needed. In order to enforce this we
// require accessing partitions through a Handle abstraction, which may perform
// additional operations after closing its file descriptor.
class PartitionHandle {
  public:
    PartitionHandle() {}
    explicit PartitionHandle(const std::string& path) : path_(path) {}
    PartitionHandle(const std::string& path, std::function<void()>&& closer)
        : path_(path), closer_(std::move(closer)) {}
    PartitionHandle(PartitionHandle&& other) = default;
    PartitionHandle& operator=(PartitionHandle&& other) = default;
    ~PartitionHandle() {
        if (closer_) {
            // Make sure the device is closed first.
            fd_ = {};
            closer_();
        }
    }
    const std::string& path() const { return path_; }
    int fd() const { return fd_.get(); }
    void set_fd(android::base::unique_fd&& fd) { fd_ = std::move(fd); }

  private:
    std::string path_;
    android::base::unique_fd fd_;
    std::function<void()> closer_;
};

class AutoMountMetadata {
  public:
    AutoMountMetadata();
    ~AutoMountMetadata();
    explicit operator bool() const { return mounted_; }

  private:
    android::fs_mgr::Fstab fstab_;
    bool mounted_ = false;
    bool should_unmount_ = false;
};

class FastbootDevice;

// On normal devices, the super partition is always named "super". On retrofit
// devices, the name must be derived from the partition name or current slot.
// This helper assists in choosing the correct super for a given partition
// name.
std::string GetSuperSlotSuffix(FastbootDevice* device, const std::string& partition_name);

std::optional<std::string> FindPhysicalPartition(const std::string& name);
bool LogicalPartitionExists(FastbootDevice* device, const std::string& name,
                            bool* is_zero_length = nullptr);

// If read, partition is readonly. Else it is write only.
bool OpenPartition(FastbootDevice* device, const std::string& name, PartitionHandle* handle,
                   bool read = false);

bool GetSlotNumber(const std::string& slot, android::hardware::boot::V1_0::Slot* number);
std::vector<std::string> ListPartitions(FastbootDevice* device);
bool GetDeviceLockStatus();

// Update all copies of metadata.
bool UpdateAllPartitionMetadata(FastbootDevice* device, const std::string& super_name,
                                const android::fs_mgr::LpMetadata& metadata);
