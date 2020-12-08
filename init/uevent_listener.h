/*
 * Copyright (C) 2017 The Android Open Source Project
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

#ifndef _INIT_UEVENT_LISTENER_H
#define _INIT_UEVENT_LISTENER_H

#include <dirent.h>

#include <chrono>
#include <functional>
#include <optional>

#include <android-base/unique_fd.h>

#include "uevent.h"

#define UEVENT_MSG_LEN 8192

namespace android {
namespace init {

enum class ListenerAction {
    kStop = 0,  // Stop regenerating uevents as we've handled the one(s) we're interested in.
    kContinue,  // Continue regenerating uevents as we haven't seen the one(s) we're interested in.
};

enum class ReadUeventResult {
    kSuccess = 0,  // Uevent was successfully read.
    kFailed,       // Uevent reading has failed.
    kInvalid,      // An Invalid Uevent was read (like say, the msg received is >= UEVENT_MSG_LEN).
};

using ListenerCallback = std::function<ListenerAction(const Uevent&)>;

class UeventListener {
  public:
    UeventListener(size_t uevent_socket_rcvbuf_size);

    void RegenerateUevents(const ListenerCallback& callback) const;
    ListenerAction RegenerateUeventsForPath(const std::string& path,
                                            const ListenerCallback& callback) const;
    void Poll(const ListenerCallback& callback,
              const std::optional<std::chrono::milliseconds> relative_timeout = {}) const;

  private:
    ReadUeventResult ReadUevent(Uevent* uevent) const;
    ListenerAction RegenerateUeventsForDir(DIR* d, const ListenerCallback& callback) const;

    android::base::unique_fd device_fd_;
};

}  // namespace init
}  // namespace android

#endif
