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

// This file provides a class interface for cross-platform socket functionality. The main fastboot
// engine should not be using this interface directly, but instead should use a higher-level
// interface that enforces the fastboot protocol.

#pragma once

#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <android-base/macros.h>
#include <cutils/sockets.h>
#include <gtest/gtest_prod.h>

// Socket interface to be implemented for each platform.
class Socket {
  public:
    enum class Protocol { kTcp, kUdp };

    // Returns the socket error message. This must be called immediately after a socket failure
    // before any other system calls are made.
    static std::string GetErrorMessage();

    // Creates a new client connection. Clients are connected to a specific hostname/port and can
    // only send to that destination.
    // On failure, |error| is filled (if non-null) and nullptr is returned.
    static std::unique_ptr<Socket> NewClient(Protocol protocol, const std::string& hostname,
                                             int port, std::string* error);

    // Creates a new server bound to local |port|. This is only meant for testing, during normal
    // fastboot operation the device acts as the server.
    // A UDP server saves sender addresses in Receive(), and uses the most recent address during
    // calls to Send().
    static std::unique_ptr<Socket> NewServer(Protocol protocol, int port);

    // Destructor closes the socket if it's open.
    virtual ~Socket();

    // Sends |length| bytes of |data|. For TCP sockets this will continue trying to send until all
    // bytes are transmitted. Returns true on success.
    virtual bool Send(const void* data, size_t length) = 0;

    // Sends |buffers| using multi-buffer write, which can be significantly faster than making
    // multiple calls. For UDP sockets |buffers| are all combined into a single datagram; for
    // TCP sockets this will continue sending until all buffers are fully transmitted. Returns true
    // on success.
    //
    // Note: This is non-functional for UDP server Sockets because it's not currently needed and
    // would require an additional sendto() variation of multi-buffer write.
    virtual bool Send(std::vector<cutils_socket_buffer_t> buffers) = 0;

    // Waits up to |timeout_ms| to receive up to |length| bytes of data. |timout_ms| of 0 will
    // block forever. Returns the number of bytes received or -1 on error/timeout; see
    // ReceiveTimedOut() to distinguish between the two.
    virtual ssize_t Receive(void* data, size_t length, int timeout_ms) = 0;

    // Calls Receive() until exactly |length| bytes have been received or an error occurs.
    virtual ssize_t ReceiveAll(void* data, size_t length, int timeout_ms);

    // Returns true if the last Receive() call timed out normally and can be retried; fatal errors
    // or successful reads will return false.
    bool ReceiveTimedOut() { return receive_timed_out_; }

    // Closes the socket. Returns 0 on success, -1 on error.
    virtual int Close();

    // Accepts an incoming TCP connection. No effect for UDP sockets. Returns a new Socket
    // connected to the client on success, nullptr on failure.
    virtual std::unique_ptr<Socket> Accept() { return nullptr; }

    // Returns the local port the Socket is bound to or -1 on error.
    int GetLocalPort();

  protected:
    // Protected constructor to force factory function use.
    explicit Socket(cutils_socket_t sock);

    // Blocks up to |timeout_ms| until a read is possible on |sock_|, and sets |receive_timed_out_|
    // as appropriate to help distinguish between normal timeouts and fatal errors. Returns true if
    // a subsequent recv() on |sock_| will complete without blocking or if |timeout_ms| <= 0.
    bool WaitForRecv(int timeout_ms);

    cutils_socket_t sock_ = INVALID_SOCKET;
    bool receive_timed_out_ = false;

    // Non-class functions we want to override during tests to verify functionality. Implementation
    // should call this rather than using socket_send_buffers() directly.
    std::function<ssize_t(cutils_socket_t, cutils_socket_buffer_t*, size_t)>
            socket_send_buffers_function_ = &socket_send_buffers;

  private:
    FRIEND_TEST(SocketTest, TestTcpSendBuffers);
    FRIEND_TEST(SocketTest, TestUdpSendBuffers);

    DISALLOW_COPY_AND_ASSIGN(Socket);
};
