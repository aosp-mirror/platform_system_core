/*
 *  Copyright 2018 Google, Inc
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#ifndef _LIBDM_LOOP_CONTROL_H_
#define _LIBDM_LOOP_CONTROL_H_

#include <string>

#include <android-base/unique_fd.h>

namespace android {
namespace dm {

class LoopControl final {
  public:
    LoopControl();

    // Attaches the file specified by 'file_fd' to the loop device specified
    // by 'loopdev'
    bool Attach(int file_fd, std::string* loopdev) const;

    // Detach the loop device given by 'loopdev' from the attached backing file.
    bool Detach(const std::string& loopdev) const;

    LoopControl(const LoopControl&) = delete;
    LoopControl& operator=(const LoopControl&) = delete;
    LoopControl& operator=(LoopControl&&) = default;
    LoopControl(LoopControl&&) = default;

  private:
    bool FindFreeLoopDevice(std::string* loopdev) const;

    static constexpr const char* kLoopControlDevice = "/dev/loop-control";

    android::base::unique_fd control_fd_;
};

// Create a temporary loop device around a file descriptor or path.
class LoopDevice {
  public:
    // Create a loop device for the given file descriptor. It is closed when
    // LoopDevice is destroyed only if auto_close is true.
    LoopDevice(int fd, bool auto_close = false);
    // Create a loop device for the given file path. It will be opened for
    // reading and writing and closed when the loop device is detached.
    explicit LoopDevice(const std::string& path);
    ~LoopDevice();

    bool valid() const { return fd_ != -1 && !device_.empty(); }
    const std::string& device() const { return device_; }

    LoopDevice(const LoopDevice&) = delete;
    LoopDevice& operator=(const LoopDevice&) = delete;
    LoopDevice& operator=(LoopDevice&&) = default;
    LoopDevice(LoopDevice&&) = default;

  private:
    void Init();

    android::base::unique_fd fd_;
    bool owns_fd_;
    std::string device_;
    LoopControl control_;
};

}  // namespace dm
}  // namespace android

#endif /* _LIBDM_LOOP_CONTROL_H_ */
