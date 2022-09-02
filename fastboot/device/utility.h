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

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/unique_fd.h>
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
    bool Open(int flags) {
        flags |= (O_EXCL | O_CLOEXEC | O_BINARY);

        // Attempts to open a second device can fail with EBUSY if the device is already open.
        // Explicitly close any previously opened devices as unique_fd won't close them until
        // after the attempt to open.
        fd_.reset();

        fd_ = android::base::unique_fd(TEMP_FAILURE_RETRY(open(path_.c_str(), flags)));
        if (fd_ < 0) {
            PLOG(ERROR) << "Failed to open block device: " << path_;
            return false;
        }
        flags_ = flags;

        return true;
    }
    bool Reset(int flags) {
        if (fd_.ok() && (flags | O_EXCL | O_CLOEXEC | O_BINARY) == flags_) {
            return true;
        }

        off_t offset = fd_.ok() ? lseek(fd_.get(), 0, SEEK_CUR) : 0;
        if (offset < 0) {
            PLOG(ERROR) << "Failed lseek on block device: " << path_;
            return false;
        }

        sync();

        if (Open(flags) == false) {
            return false;
        }

        if (lseek(fd_.get(), offset, SEEK_SET) != offset) {
            PLOG(ERROR) << "Failed lseek on block device: " << path_;
            return false;
        }

        return true;
    }
  private:
    std::string path_;
    android::base::unique_fd fd_;
    int flags_;
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

// Partition is O_WRONLY by default, caller should pass O_RDONLY for reading.
// Caller may pass additional flags if needed. (O_EXCL | O_CLOEXEC | O_BINARY)
// will be logically ORed internally.
bool OpenPartition(FastbootDevice* device, const std::string& name, PartitionHandle* handle,
                   int flags = O_WRONLY);

bool GetSlotNumber(const std::string& slot, int32_t* number);
std::vector<std::string> ListPartitions(FastbootDevice* device);
bool GetDeviceLockStatus();

// Update all copies of metadata.
bool UpdateAllPartitionMetadata(FastbootDevice* device, const std::string& super_name,
                                const android::fs_mgr::LpMetadata& metadata);
