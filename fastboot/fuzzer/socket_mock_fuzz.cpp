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

#include "socket_mock_fuzz.h"

SocketMockFuzz::SocketMockFuzz() : Socket(INVALID_SOCKET) {}

SocketMockFuzz::~SocketMockFuzz() {}

bool SocketMockFuzz::Send(const void* data, size_t length) {
    if (events_.empty()) {
        return false;
    }

    if (events_.front().type != EventType::kSend) {
        return false;
    }

    std::string message(reinterpret_cast<const char*>(data), length);
    if (events_.front().message != message) {
        return false;
    }

    bool return_value = events_.front().status;
    events_.pop();
    return return_value;
}

// Mock out multi-buffer send to be one large send, since that's what it should looks like from
// the user's perspective.
bool SocketMockFuzz::Send(std::vector<cutils_socket_buffer_t> buffers) {
    std::string data;
    for (const auto& buffer : buffers) {
        data.append(reinterpret_cast<const char*>(buffer.data), buffer.length);
    }
    return Send(data.data(), data.size());
}

ssize_t SocketMockFuzz::Receive(void* data, size_t length, int /*timeout_ms*/) {
    if (events_.empty()) {
        return -1;
    }

    const Event& event = events_.front();
    if (event.type != EventType::kReceive) {
        return -1;
    }

    const std::string& message = event.message;
    if (message.length() > length) {
        return -1;
    }

    receive_timed_out_ = event.status;
    ssize_t return_value = message.length();

    // Empty message indicates failure.
    if (message.empty()) {
        return_value = -1;
    } else {
        memcpy(data, message.data(), message.length());
    }

    events_.pop();
    return return_value;
}

int SocketMockFuzz::Close() {
    return 0;
}

std::unique_ptr<Socket> SocketMockFuzz::Accept() {
    if (events_.empty()) {
        return nullptr;
    }

    if (events_.front().type != EventType::kAccept) {
        return nullptr;
    }

    std::unique_ptr<Socket> sock = std::move(events_.front().sock);
    events_.pop();
    return sock;
}

void SocketMockFuzz::ExpectSend(std::string message) {
    events_.push(Event(EventType::kSend, std::move(message), true, nullptr));
}

void SocketMockFuzz::ExpectSendFailure(std::string message) {
    events_.push(Event(EventType::kSend, std::move(message), false, nullptr));
}

void SocketMockFuzz::AddReceive(std::string message) {
    events_.push(Event(EventType::kReceive, std::move(message), false, nullptr));
}

void SocketMockFuzz::AddReceiveTimeout() {
    events_.push(Event(EventType::kReceive, "", true, nullptr));
}

void SocketMockFuzz::AddReceiveFailure() {
    events_.push(Event(EventType::kReceive, "", false, nullptr));
}

void SocketMockFuzz::AddAccept(std::unique_ptr<Socket> sock) {
    events_.push(Event(EventType::kAccept, "", false, std::move(sock)));
}

SocketMockFuzz::Event::Event(EventType _type, std::string _message, ssize_t _status,
                             std::unique_ptr<Socket> _sock)
    : type(_type), message(_message), status(_status), sock(std::move(_sock)) {}
