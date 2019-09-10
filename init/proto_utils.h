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

#include <sys/socket.h>
#include <unistd.h>

#include <string>

#include "result.h"

namespace android {
namespace init {

constexpr size_t kBufferSize = 4096;

inline Result<std::string> ReadMessage(int socket) {
    char buffer[kBufferSize] = {};
    auto result = TEMP_FAILURE_RETRY(recv(socket, buffer, sizeof(buffer), 0));
    if (result == 0) {
        return Error();
    } else if (result < 0) {
        return ErrnoError();
    }
    return std::string(buffer, result);
}

template <typename T>
Result<void> SendMessage(int socket, const T& message) {
    std::string message_string;
    if (!message.SerializeToString(&message_string)) {
        return Error() << "Unable to serialize message";
    }

    if (message_string.size() > kBufferSize) {
        return Error() << "Serialized message too long to send";
    }

    if (auto result =
                TEMP_FAILURE_RETRY(send(socket, message_string.c_str(), message_string.size(), 0));
        result != static_cast<long>(message_string.size())) {
        return ErrnoError() << "send() failed to send message contents";
    }
    return {};
}

}  // namespace init
}  // namespace android
