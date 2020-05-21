/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include "tcp_client.h"
#include "constants.h"

#include <android-base/errors.h>
#include <android-base/logging.h>
#include <android-base/parseint.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>

static constexpr int kDefaultPort = 5554;
static constexpr int kProtocolVersion = 1;
static constexpr int kHandshakeTimeoutMs = 2000;
static constexpr size_t kHandshakeLength = 4;

// Extract the big-endian 8-byte message length into a 64-bit number.
static uint64_t ExtractMessageLength(const void* buffer) {
    uint64_t ret = 0;
    for (int i = 0; i < 8; ++i) {
        ret |= uint64_t{reinterpret_cast<const uint8_t*>(buffer)[i]} << (56 - i * 8);
    }
    return ret;
}

// Encode the 64-bit number into a big-endian 8-byte message length.
static void EncodeMessageLength(uint64_t length, void* buffer) {
    for (int i = 0; i < 8; ++i) {
        reinterpret_cast<uint8_t*>(buffer)[i] = length >> (56 - i * 8);
    }
}

ClientTcpTransport::ClientTcpTransport() {
    service_ = Socket::NewServer(Socket::Protocol::kTcp, kDefaultPort);

    // A workaround to notify recovery to continue its work.
    android::base::SetProperty("sys.usb.ffs.ready", "1");
}

ssize_t ClientTcpTransport::Read(void* data, size_t len) {
    if (len > SSIZE_MAX) {
        return -1;
    }

    size_t total_read = 0;
    do {
        // Read a new message
        while (message_bytes_left_ == 0) {
            if (socket_ == nullptr) {
                ListenFastbootSocket();
            }

            char buffer[8];
            if (socket_->ReceiveAll(buffer, 8, 0) == 8) {
                message_bytes_left_ = ExtractMessageLength(buffer);
            } else {
                // If connection is closed by host, Receive will return 0 immediately.
                socket_.reset(nullptr);
                // In DATA phase, return error.
                if (downloading_) {
                    return -1;
                }
            }
        }

        size_t read_length = len - total_read;
        if (read_length > message_bytes_left_) {
            read_length = message_bytes_left_;
        }
        ssize_t bytes_read =
                socket_->ReceiveAll(reinterpret_cast<char*>(data) + total_read, read_length, 0);
        if (bytes_read == -1) {
            socket_.reset(nullptr);
            return -1;
        } else {
            message_bytes_left_ -= bytes_read;
            total_read += bytes_read;
        }
    // There are more than one DATA phases if the downloading buffer is too
    // large, like a very big system image. All of data phases should be
    // received until the whole buffer is filled in that case.
    } while (downloading_ && total_read < len);

    return total_read;
}

ssize_t ClientTcpTransport::Write(const void* data, size_t len) {
    if (socket_ == nullptr || len > SSIZE_MAX) {
        return -1;
    }

    // Use multi-buffer writes for better performance.
    char header[8];
    EncodeMessageLength(len, header);

    if (!socket_->Send(std::vector<cutils_socket_buffer_t>{{header, 8}, {data, len}})) {
        socket_.reset(nullptr);
        return -1;
    }

    // In DATA phase
    if (android::base::StartsWith(reinterpret_cast<const char*>(data), RESPONSE_DATA)) {
        downloading_ = true;
    } else {
        downloading_ = false;
    }

    return len;
}

int ClientTcpTransport::Close() {
    if (socket_ == nullptr) {
        return -1;
    }
    socket_.reset(nullptr);

    return 0;
}

int ClientTcpTransport::Reset() {
    return Close();
}

void ClientTcpTransport::ListenFastbootSocket() {
    while (true) {
        socket_ = service_->Accept();

        // Handshake
        char buffer[kHandshakeLength + 1];
        buffer[kHandshakeLength] = '\0';
        if (socket_->ReceiveAll(buffer, kHandshakeLength, kHandshakeTimeoutMs) !=
            kHandshakeLength) {
            PLOG(ERROR) << "No Handshake message received";
            socket_.reset(nullptr);
            continue;
        }

        if (memcmp(buffer, "FB", 2) != 0) {
            PLOG(ERROR) << "Unrecognized initialization message";
            socket_.reset(nullptr);
            continue;
        }

        int version = 0;
        if (!android::base::ParseInt(buffer + 2, &version) || version < kProtocolVersion) {
            LOG(ERROR) << "Unknown TCP protocol version " << buffer + 2
                       << ", our version: " << kProtocolVersion;
            socket_.reset(nullptr);
            continue;
        }

        std::string handshake_message(android::base::StringPrintf("FB%02d", kProtocolVersion));
        if (!socket_->Send(handshake_message.c_str(), kHandshakeLength)) {
            PLOG(ERROR) << "Failed to send initialization message";
            socket_.reset(nullptr);
            continue;
        }

        break;
    }
}
