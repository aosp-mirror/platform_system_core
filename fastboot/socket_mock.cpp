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

#include "socket_mock.h"

#include <gtest/gtest.h>

SocketMock::SocketMock() : Socket(INVALID_SOCKET) {}

SocketMock::~SocketMock() {
    if (!events_.empty()) {
        ADD_FAILURE() << events_.size() << " event(s) were not handled";
    }
}

ssize_t SocketMock::Send(const void* data, size_t length) {
    if (events_.empty()) {
        ADD_FAILURE() << "Send() was called when no message was expected";
        return -1;
    }

    if (events_.front().type != EventType::kSend) {
        ADD_FAILURE() << "Send() was called out-of-order";
        return -1;
    }

    std::string message(reinterpret_cast<const char*>(data), length);
    if (events_.front().message != message) {
        ADD_FAILURE() << "Send() expected " << events_.front().message << ", but got " << message;
        return -1;
    }

    ssize_t return_value = events_.front().return_value;
    events_.pop();
    return return_value;
}

ssize_t SocketMock::Receive(void* data, size_t length, int /*timeout_ms*/) {
    if (events_.empty()) {
        ADD_FAILURE() << "Receive() was called when no message was ready";
        return -1;
    }

    if (events_.front().type != EventType::kReceive) {
        ADD_FAILURE() << "Receive() was called out-of-order";
        return -1;
    }

    if (events_.front().return_value > static_cast<ssize_t>(length)) {
        ADD_FAILURE() << "Receive(): not enough bytes (" << length << ") for "
                      << events_.front().message;
        return -1;
    }

    ssize_t return_value = events_.front().return_value;
    if (return_value > 0) {
        memcpy(data, events_.front().message.data(), return_value);
    }
    events_.pop();
    return return_value;
}

int SocketMock::Close() {
    return 0;
}

std::unique_ptr<Socket> SocketMock::Accept() {
    if (events_.empty()) {
        ADD_FAILURE() << "Accept() was called when no socket was ready";
        return nullptr;
    }

    if (events_.front().type != EventType::kAccept) {
        ADD_FAILURE() << "Accept() was called out-of-order";
        return nullptr;
    }

    std::unique_ptr<Socket> sock = std::move(events_.front().sock);
    events_.pop();
    return sock;
}

void SocketMock::ExpectSend(std::string message) {
    ssize_t return_value = message.length();
    events_.push(Event(EventType::kSend, std::move(message), return_value, nullptr));
}

void SocketMock::ExpectSendFailure(std::string message) {
    events_.push(Event(EventType::kSend, std::move(message), -1, nullptr));
}

void SocketMock::AddReceive(std::string message) {
    ssize_t return_value = message.length();
    events_.push(Event(EventType::kReceive, std::move(message), return_value, nullptr));
}

void SocketMock::AddReceiveFailure() {
    events_.push(Event(EventType::kReceive, "", -1, nullptr));
}

void SocketMock::AddAccept(std::unique_ptr<Socket> sock) {
    events_.push(Event(EventType::kAccept, "", 0, std::move(sock)));
}

SocketMock::Event::Event(EventType _type, std::string _message, ssize_t _return_value,
                         std::unique_ptr<Socket> _sock)
        : type(_type), message(_message), return_value(_return_value), sock(std::move(_sock)) {}
