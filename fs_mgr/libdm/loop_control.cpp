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

#include "libdm/loop_control.h"

#include <fcntl.h>
#include <linux/loop.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <unistd.h>

#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <android-base/unique_fd.h>

namespace android {
namespace dm {

LoopControl::LoopControl() : control_fd_(-1) {
    control_fd_.reset(TEMP_FAILURE_RETRY(open(kLoopControlDevice, O_RDWR | O_CLOEXEC)));
    if (control_fd_ < 0) {
        PLOG(ERROR) << "Failed to open loop-control";
    }
}

bool LoopControl::Attach(int file_fd, std::string* loopdev) const {
    if (!FindFreeLoopDevice(loopdev)) {
        LOG(ERROR) << "Failed to attach, no free loop devices";
        return false;
    }

    android::base::unique_fd loop_fd(TEMP_FAILURE_RETRY(open(loopdev->c_str(), O_RDWR | O_CLOEXEC)));
    if (loop_fd < 0) {
        PLOG(ERROR) << "Failed to open: " << *loopdev;
        return false;
    }

    int rc = ioctl(loop_fd, LOOP_SET_FD, file_fd);
    if (rc < 0) {
        PLOG(ERROR) << "Failed LOOP_SET_FD";
        return false;
    }
    return true;
}

bool LoopControl::Detach(const std::string& loopdev) const {
    if (loopdev.empty()) {
        LOG(ERROR) << "Must provide a loop device";
        return false;
    }

    android::base::unique_fd loop_fd(TEMP_FAILURE_RETRY(open(loopdev.c_str(), O_RDWR | O_CLOEXEC)));
    if (loop_fd < 0) {
        PLOG(ERROR) << "Failed to open: " << loopdev;
        return false;
    }

    int rc = ioctl(loop_fd, LOOP_CLR_FD, 0);
    if (rc) {
        PLOG(ERROR) << "Failed LOOP_CLR_FD for '" << loopdev << "'";
        return false;
    }
    return true;
}

bool LoopControl::FindFreeLoopDevice(std::string* loopdev) const {
    int rc = ioctl(control_fd_, LOOP_CTL_GET_FREE);
    if (rc < 0) {
        PLOG(ERROR) << "Failed to get free loop device";
        return false;
    }

    // Ueventd on android creates all loop devices as /dev/block/loopX
    // The total number of available devices is determined by 'loop.max_part'
    // kernel command line argument.
    *loopdev = ::android::base::StringPrintf("/dev/block/loop%d", rc);
    return true;
}

LoopDevice::LoopDevice(int fd, bool auto_close) : fd_(fd), owns_fd_(auto_close) {
    Init();
}

LoopDevice::LoopDevice(const std::string& path) : fd_(-1), owns_fd_(true) {
    fd_.reset(open(path.c_str(), O_RDWR | O_CLOEXEC));
    if (fd_ < -1) {
        PLOG(ERROR) << "open failed for " << path;
        return;
    }
    Init();
}

LoopDevice::~LoopDevice() {
    if (valid()) {
        control_.Detach(device_);
    }
    if (!owns_fd_) {
        (void)fd_.release();
    }
}

void LoopDevice::Init() {
    control_.Attach(fd_, &device_);
}

}  // namespace dm
}  // namespace android
