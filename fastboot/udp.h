/*
 * Copyright (C) 2015 The Android Open Source Project
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

#pragma once

#include <memory>
#include <string>

#include "socket.h"
#include "transport.h"

namespace udp {

constexpr int kDefaultPort = 5554;

// Returns a newly allocated Transport object connected to |hostname|:|port|. On failure, |error| is
// filled and nullptr is returned.
std::unique_ptr<Transport> Connect(const std::string& hostname, int port, std::string* error);

// Internal namespace for test use only.
namespace internal {

constexpr uint16_t kProtocolVersion = 1;

// This will be negotiated with the device so may end up being smaller.
constexpr uint16_t kHostMaxPacketSize = 8192;

// Retransmission constants. Retransmission timeout must be at least 500ms, and the host must
// attempt to send packets for at least 1 minute once the device has connected. See
// fastboot_protocol.txt for more information.
constexpr int kResponseTimeoutMs = 500;
constexpr int kMaxConnectAttempts = 4;
constexpr int kMaxTransmissionAttempts = 60 * 1000 / kResponseTimeoutMs;

enum Id : uint8_t {
    kIdError = 0x00,
    kIdDeviceQuery = 0x01,
    kIdInitialization = 0x02,
    kIdFastboot = 0x03
};

enum Flag : uint8_t {
    kFlagNone = 0x00,
    kFlagContinuation = 0x01
};

// Creates a UDP Transport object using a given Socket. Used for unit tests to create a Transport
// object that uses a SocketMock.
std::unique_ptr<Transport> Connect(std::unique_ptr<Socket> sock, std::string* error);

}  // namespace internal

}  // namespace udp
