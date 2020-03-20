/*
 * Copyright (C) 2016 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "tcp.h"

#include <android-base/parseint.h>
#include <android-base/stringprintf.h>

namespace tcp {

static constexpr int kProtocolVersion = 1;
static constexpr size_t kHandshakeLength = 4;
static constexpr int kHandshakeTimeoutMs = 2000;

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

class TcpTransport : public Transport {
  public:
    // Factory function so we can return nullptr if initialization fails.
    static std::unique_ptr<TcpTransport> NewTransport(std::unique_ptr<Socket> socket,
                                                      std::string* error);

    ~TcpTransport() override = default;

    ssize_t Read(void* data, size_t length) override;
    ssize_t Write(const void* data, size_t length) override;
    int Close() override;
    int Reset() override;

  private:
    explicit TcpTransport(std::unique_ptr<Socket> sock) : socket_(std::move(sock)) {}

    // Connects to the device and performs the initial handshake. Returns false and fills |error|
    // on failure.
    bool InitializeProtocol(std::string* error);

    std::unique_ptr<Socket> socket_;
    uint64_t message_bytes_left_ = 0;

    DISALLOW_COPY_AND_ASSIGN(TcpTransport);
};

std::unique_ptr<TcpTransport> TcpTransport::NewTransport(std::unique_ptr<Socket> socket,
                                                         std::string* error) {
    std::unique_ptr<TcpTransport> transport(new TcpTransport(std::move(socket)));

    if (!transport->InitializeProtocol(error)) {
        return nullptr;
    }

    return transport;
}

// These error strings are checked in tcp_test.cpp and should be kept in sync.
bool TcpTransport::InitializeProtocol(std::string* error) {
    std::string handshake_message(android::base::StringPrintf("FB%02d", kProtocolVersion));

    if (!socket_->Send(handshake_message.c_str(), kHandshakeLength)) {
        *error = android::base::StringPrintf("Failed to send initialization message (%s)",
                                             Socket::GetErrorMessage().c_str());
        return false;
    }

    char buffer[kHandshakeLength + 1];
    buffer[kHandshakeLength] = '\0';
    if (socket_->ReceiveAll(buffer, kHandshakeLength, kHandshakeTimeoutMs) != kHandshakeLength) {
        *error = android::base::StringPrintf(
                "No initialization message received (%s). Target may not support TCP fastboot",
                Socket::GetErrorMessage().c_str());
        return false;
    }

    if (memcmp(buffer, "FB", 2) != 0) {
        *error = "Unrecognized initialization message. Target may not support TCP fastboot";
        return false;
    }

    int version = 0;
    if (!android::base::ParseInt(buffer + 2, &version) || version < kProtocolVersion) {
        *error = android::base::StringPrintf("Unknown TCP protocol version %s (host version %02d)",
                                             buffer + 2, kProtocolVersion);
        return false;
    }

    error->clear();
    return true;
}

ssize_t TcpTransport::Read(void* data, size_t length) {
    if (socket_ == nullptr) {
        return -1;
    }

    // Unless we're mid-message, read the next 8-byte message length.
    if (message_bytes_left_ == 0) {
        char buffer[8];
        if (socket_->ReceiveAll(buffer, 8, 0) != 8) {
            Close();
            return -1;
        }
        message_bytes_left_ = ExtractMessageLength(buffer);
    }

    // Now read the message (up to |length| bytes).
    if (length > message_bytes_left_) {
        length = message_bytes_left_;
    }
    ssize_t bytes_read = socket_->ReceiveAll(data, length, 0);
    if (bytes_read == -1) {
        Close();
    } else {
        message_bytes_left_ -= bytes_read;
    }
    return bytes_read;
}

ssize_t TcpTransport::Write(const void* data, size_t length) {
    if (socket_ == nullptr) {
        return -1;
    }

    // Use multi-buffer writes for better performance.
    char header[8];
    EncodeMessageLength(length, header);
    if (!socket_->Send(std::vector<cutils_socket_buffer_t>{{header, 8}, {data, length}})) {
        Close();
        return -1;
    }

    return length;
}

int TcpTransport::Close() {
    if (socket_ == nullptr) {
        return 0;
    }

    int result = socket_->Close();
    socket_.reset();
    return result;
}

int TcpTransport::Reset() {
    return 0;
}

std::unique_ptr<Transport> Connect(const std::string& hostname, int port, std::string* error) {
    return internal::Connect(Socket::NewClient(Socket::Protocol::kTcp, hostname, port, error),
                             error);
}

namespace internal {

std::unique_ptr<Transport> Connect(std::unique_ptr<Socket> sock, std::string* error) {
    if (sock == nullptr) {
        // If Socket creation failed |error| is already set.
        return nullptr;
    }

    return TcpTransport::NewTransport(std::move(sock), error);
}

}  // namespace internal

}  // namespace tcp
