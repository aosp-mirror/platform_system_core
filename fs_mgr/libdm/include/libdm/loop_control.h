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

#include <chrono>
#include <string>

#include <android-base/unique_fd.h>

namespace android {
namespace dm {

class LoopControl final {
  public:
    LoopControl();

    // Attaches the file specified by 'file_fd' to the loop device specified
    // by 'loopdev'. It is possible that in between allocating and attaching
    // a loop device, another process attaches to the chosen loop device. If
    // this happens, Attach() will retry for up to |timeout_ms|. The timeout
    // should not be zero.
    //
    // The caller does not have to call WaitForFile(); it is implicitly called.
    // The given |timeout_ms| covers both potential sources of timeout.
    bool Attach(int file_fd, const std::chrono::milliseconds& timeout_ms,
                std::string* loopdev) const;

    // Detach the loop device given by 'loopdev' from the attached backing file.
    bool Detach(const std::string& loopdev) const;

    // Enable Direct I/O on a loop device. This requires kernel 4.9+.
    static bool EnableDirectIo(int fd);

    // Set LO_FLAGS_AUTOCLEAR on a loop device.
    static bool SetAutoClearStatus(int fd);

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
    LoopDevice(android::base::borrowed_fd fd, const std::chrono::milliseconds& timeout_ms,
               bool auto_close = false);
    // Create a loop device for the given file path. It will be opened for
    // reading and writing and closed when the loop device is detached.
    LoopDevice(const std::string& path, const std::chrono::milliseconds& timeout_ms);
    ~LoopDevice();

    bool valid() const { return valid_; }
    const std::string& device() const { return device_; }

    LoopDevice(const LoopDevice&) = delete;
    LoopDevice& operator=(const LoopDevice&) = delete;
    LoopDevice& operator=(LoopDevice&&) = default;
    LoopDevice(LoopDevice&&) = default;

  private:
    void Init(const std::chrono::milliseconds& timeout_ms);

    android::base::borrowed_fd fd_;
    android::base::unique_fd owned_fd_;
    std::string device_;
    LoopControl control_;
    bool valid_ = false;
};

}  // namespace dm
}  // namespace android

#endif /* _LIBDM_LOOP_CONTROL_H_ */
