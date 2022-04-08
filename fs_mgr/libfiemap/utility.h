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

#include <stdint.h>

#include <string>

#include <libfiemap/split_fiemap_writer.h>

namespace android {
namespace fiemap {

// Given a file that will be created, determine the maximum size its containing
// filesystem allows. Note this is a theoretical maximum size; free space is
// ignored entirely.
FiemapStatus DetermineMaximumFileSize(const std::string& file_path, uint64_t* result);

// Given a SplitFiemap, this returns a device path that will work during first-
// stage init (i.e., its path can be found by InitRequiredDevices).
std::string GetDevicePathForFile(android::fiemap::SplitFiemap* file);

// Combine two path components into a single path.
std::string JoinPaths(const std::string& dir, const std::string& file);

// Given a file within an F2FS filesystem, return whether or not the filesystem
// supports the "pin_file" feature, which requires pinning before fallocation.
bool F2fsPinBeforeAllocate(int file_fd, bool* supported);

// Given a major/minor device number, return its canonical name such that
// /dev/block/<name> resolves to the device.
bool BlockDeviceToName(uint32_t major, uint32_t minor, std::string* bdev_name);

// This is the same as F2fsPinBeforeAllocate, however, it will return true
// (and supported = true) for non-f2fs filesystems. It is intended to be used
// in conjunction with ImageManager to reject image requests for reliable use
// cases (such as snapshots or adb remount).
bool FilesystemHasReliablePinning(const std::string& file, bool* supported);

}  // namespace fiemap
}  // namespace android
