/*
 * Copyright 2020, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include "TrustyIpc.h"

#include <android-base/logging.h>
#include <android-base/unique_fd.h>
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <sys/eventfd.h>
#include <sys/stat.h>
#include <teeui/msg_formatting.h>
#include <trusty/tipc.h>
#include <unistd.h>

#include <fstream>
#include <functional>
#include <future>
#include <iostream>
#include <sstream>
#include <thread>
#include <vector>

#define AT __FILE__ ":" << __LINE__ << ": "

namespace android {
namespace trusty {

using ::teeui::Message;
using ::teeui::msg2tuple_t;
using ::teeui::ReadStream;
using ::teeui::WriteStream;

#ifndef TEEUI_USE_STD_VECTOR
/*
 * TEEUI_USE_STD_VECTOR makes certain wire types like teeui::MsgString and
 * teeui::MsgVector be aliases for std::vector. This is required for thread safe
 * message serialization. Always compile this with -DTEEUI_USE_STD_VECTOR set in
 * CFLAGS of the HAL service.
 */
#error "Must be compiled with -DTEEUI_USE_STD_VECTOR."
#endif

enum class TrustyAppError : int32_t {
    OK,
    ERROR = -1,
    MSG_TOO_LONG = -2,
};

class TrustyApp {
  private:
    android::base::unique_fd handle_;
    void* shm_base_;
    size_t shm_len_;
    static constexpr const int kInvalidHandle = -1;
    /*
     * This mutex serializes communication with the trusted app, not handle_.
     * Calling issueCmd during construction or deletion is undefined behavior.
     */
    std::mutex mutex_;

  public:
    TrustyApp(const std::string& path, const std::string& appname);
    ~TrustyApp();

    ssize_t TrustyRpc(const uint8_t* obegin, const uint8_t* oend, uint8_t* ibegin, uint8_t* iend);

    template <typename Request, typename Response, typename... T>
    std::tuple<TrustyAppError, msg2tuple_t<Response>> issueCmd(const T&... args) {
        std::lock_guard<std::mutex> lock(mutex_);

        if (handle_ == kInvalidHandle) {
            LOG(ERROR) << "TrustyApp not connected";
            return {TrustyAppError::ERROR, {}};
        }

        uint8_t buffer[CONFIRMATIONUI_MAX_MSG_SIZE];
        WriteStream out(buffer);

        out = write(Request(), out, args...);
        if (!out) {
            LOG(ERROR) << AT << "send command failed: message formatting";
            return {TrustyAppError::MSG_TOO_LONG, {}};
        }

        auto rc = TrustyRpc(&buffer[0], const_cast<const uint8_t*>(out.pos()), &buffer[0],
                            &buffer[CONFIRMATIONUI_MAX_MSG_SIZE]);
        if (rc < 0) return {TrustyAppError::ERROR, {}};

        ReadStream in(&buffer[0], rc);
        auto result = read(Response(), in);
        if (!std::get<0>(result)) {
            LOG(ERROR) << "send command failed: message parsing";
            return {TrustyAppError::ERROR, {}};
        }

        return {std::get<0>(result) ? TrustyAppError::OK : TrustyAppError::ERROR,
                tuple_tail(std::move(result))};
    }

    template <typename Request, typename... T> TrustyAppError issueCmd(const T&... args) {
        std::lock_guard<std::mutex> lock(mutex_);

        if (handle_ == kInvalidHandle) {
            LOG(ERROR) << "TrustyApp not connected";
            return TrustyAppError::ERROR;
        }

        uint8_t buffer[CONFIRMATIONUI_MAX_MSG_SIZE];
        WriteStream out(buffer);

        out = write(Request(), out, args...);
        if (!out) {
            LOG(ERROR) << AT << "send command failed: message formatting";
            return TrustyAppError::MSG_TOO_LONG;
        }

        auto rc = TrustyRpc(&buffer[0], const_cast<const uint8_t*>(out.pos()), &buffer[0],
                            &buffer[CONFIRMATIONUI_MAX_MSG_SIZE]);
        if (rc < 0) {
            LOG(ERROR) << "send command failed: " << strerror(errno) << " (" << errno << ")";
            return TrustyAppError::ERROR;
        }

        if (rc > 0) {
            LOG(ERROR) << "Unexpected non zero length response";
            return TrustyAppError::ERROR;
        }
        return TrustyAppError::OK;
    }

    operator bool() const { return handle_ != kInvalidHandle; }
};

}  // namespace trusty
}  // namespace android
