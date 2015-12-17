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

// This file provides a class interface for cross-platform UDP functionality. The main fastboot
// engine should not be using this interface directly, but instead should use a higher-level
// interface that enforces the fastboot UDP protocol.

#ifndef SOCKET_H_
#define SOCKET_H_

#include "android-base/macros.h"

#include <memory>
#include <string>

// UdpSocket interface to be implemented for each platform.
class UdpSocket {
  public:
    // Creates a new client connection. Clients are connected to a specific hostname/port and can
    // only send to that destination.
    // On failure, |error| is filled (if non-null) and nullptr is returned.
    static std::unique_ptr<UdpSocket> NewUdpClient(const std::string& hostname, int port,
                                                   std::string* error);

    // Creates a new server bound to local |port|. This is only meant for testing, during normal
    // fastboot operation the device acts as the server.
    // The server saves sender addresses in Receive(), and uses the most recent address during
    // calls to Send().
    static std::unique_ptr<UdpSocket> NewUdpServer(int port);

    virtual ~UdpSocket() = default;

    // Sends |length| bytes of |data|. Returns the number of bytes actually sent or -1 on error.
    virtual ssize_t Send(const void* data, size_t length) = 0;

    // Waits up to |timeout_ms| to receive up to |length| bytes of data. |timout_ms| of 0 will
    // block forever. Returns the number of bytes received or -1 on error/timeout. On timeout
    // errno will be set to EAGAIN or EWOULDBLOCK.
    virtual ssize_t Receive(void* data, size_t length, int timeout_ms) = 0;

    // Closes the socket. Returns 0 on success, -1 on error.
    virtual int Close() = 0;

  protected:
    // Protected constructor to force factory function use.
    UdpSocket() = default;

    DISALLOW_COPY_AND_ASSIGN(UdpSocket);
};

#endif  // SOCKET_H_
