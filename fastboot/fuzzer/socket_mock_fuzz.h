/*
 * Copyright (C) 2021 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#pragma once

#include <memory>
#include <queue>
#include <string>

#include <android-base/macros.h>

#include "socket.h"

class SocketMockFuzz : public Socket {
  public:
    SocketMockFuzz();
    ~SocketMockFuzz() override;

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

    DISALLOW_COPY_AND_ASSIGN(SocketMockFuzz);
};
