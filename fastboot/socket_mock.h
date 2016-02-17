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

#ifndef SOCKET_MOCK_H_
#define SOCKET_MOCK_H_

#include <memory>
#include <queue>
#include <string>

#include <android-base/macros.h>

#include "socket.h"

// A mock Socket implementation to be used for testing. Tests can set expectations for messages
// to be sent and provide messages to be received in order to verify protocol behavior.
//
// Example: testing sending "foo" and receiving "bar".
//   SocketMock mock;
//   mock.ExpectSend("foo");
//   mock.AddReceive("bar");
//   EXPECT_TRUE(DoFooBar(&mock));
//
// Example: testing sending "foo" and expecting "bar", but receiving "baz" instead.
//   SocketMock mock;
//   mock.ExpectSend("foo");
//   mock.AddReceive("baz");
//   EXPECT_FALSE(DoFooBar(&mock));
class SocketMock : public Socket {
  public:
    SocketMock();
    ~SocketMock() override;

    bool Send(const void* data, size_t length) override;
    bool Send(std::vector<cutils_socket_buffer_t> buffers) override;
    ssize_t Receive(void* data, size_t length, int timeout_ms) override;
    int Close() override;
    virtual std::unique_ptr<Socket> Accept();

    // Adds an expectation for Send().
    void ExpectSend(std::string message);

    // Adds an expectation for Send() that returns false.
    void ExpectSendFailure(std::string message);

    // Adds data to provide for Receive().
    void AddReceive(std::string message);

    // Adds a Receive() timeout after which ReceiveTimedOut() will return true.
    void AddReceiveTimeout();

    // Adds a Receive() failure after which ReceiveTimedOut() will return false.
    void AddReceiveFailure();

    // Adds a Socket to return from Accept().
    void AddAccept(std::unique_ptr<Socket> sock);

  private:
    enum class EventType { kSend, kReceive, kAccept };

    struct Event {
        Event(EventType _type, std::string _message, ssize_t _status,
              std::unique_ptr<Socket> _sock);

        EventType type;
        std::string message;
        bool status;  // Return value for Send() or timeout status for Receive().
        std::unique_ptr<Socket> sock;
    };

    std::queue<Event> events_;

    DISALLOW_COPY_AND_ASSIGN(SocketMock);
};

#endif  // SOCKET_MOCK_H_
