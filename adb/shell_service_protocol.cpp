/*
 * Copyright (C) 2015 The Android Open Source Project
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

#include "shell_protocol.h"

#include <string.h>

#include <algorithm>

#include "adb_io.h"

ShellProtocol::ShellProtocol(borrowed_fd fd) : fd_(fd) {
    buffer_[0] = kIdInvalid;
}

ShellProtocol::~ShellProtocol() {
}

bool ShellProtocol::Read() {
    // Only read a new header if we've finished the last packet.
    if (!bytes_left_) {
        if (!ReadFdExactly(fd_, buffer_, kHeaderSize)) {
            return false;
        }

        length_t packet_length;
        memcpy(&packet_length, &buffer_[1], sizeof(packet_length));
        bytes_left_ = packet_length;
        data_length_ = 0;
    }

    size_t read_length = std::min(bytes_left_, data_capacity());
    if (read_length && !ReadFdExactly(fd_, data(), read_length)) {
        return false;
    }

    bytes_left_ -= read_length;
    data_length_ = read_length;

    return true;
}

bool ShellProtocol::Write(Id id, size_t length) {
    buffer_[0] = id;
    length_t typed_length = length;
    memcpy(&buffer_[1], &typed_length, sizeof(typed_length));

    return WriteFdExactly(fd_, buffer_, kHeaderSize + length);
}
