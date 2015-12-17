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

#include "socket.h"

#include <errno.h>
#include <netdb.h>

#include <android-base/stringprintf.h>
#include <cutils/sockets.h>

class UnixUdpSocket : public UdpSocket {
  public:
    enum class Type { kClient, kServer };

    UnixUdpSocket(int fd, Type type);
    ~UnixUdpSocket() override;

    ssize_t Send(const void* data, size_t length) override;
    ssize_t Receive(void* data, size_t length, int timeout_ms) override;
    int Close() override;

  private:
    int fd_;
    int receive_timeout_ms_ = 0;
    std::unique_ptr<sockaddr_storage> addr_;
    socklen_t addr_size_ = 0;

    DISALLOW_COPY_AND_ASSIGN(UnixUdpSocket);
};

UnixUdpSocket::UnixUdpSocket(int fd, Type type) : fd_(fd) {
    // Only servers need to remember addresses; clients are connected to a server in NewUdpClient()
    // so will send to that server without needing to specify the address again.
    if (type == Type::kServer) {
        addr_.reset(new sockaddr_storage);
        addr_size_ = sizeof(*addr_);
        memset(addr_.get(), 0, addr_size_);
    }
}

UnixUdpSocket::~UnixUdpSocket() {
    Close();
}

ssize_t UnixUdpSocket::Send(const void* data, size_t length) {
    return TEMP_FAILURE_RETRY(
            sendto(fd_, data, length, 0, reinterpret_cast<sockaddr*>(addr_.get()), addr_size_));
}

ssize_t UnixUdpSocket::Receive(void* data, size_t length, int timeout_ms) {
    // Only set socket timeout if it's changed.
    if (receive_timeout_ms_ != timeout_ms) {
        timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        if (setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
            return -1;
        }
        receive_timeout_ms_ = timeout_ms;
    }

    socklen_t* addr_size_ptr = nullptr;
    if (addr_ != nullptr) {
        // Reset addr_size as it may have been modified by previous recvfrom() calls.
        addr_size_ = sizeof(*addr_);
        addr_size_ptr = &addr_size_;
    }
    return TEMP_FAILURE_RETRY(recvfrom(fd_, data, length, 0,
                                       reinterpret_cast<sockaddr*>(addr_.get()), addr_size_ptr));
}

int UnixUdpSocket::Close() {
    int result = 0;
    if (fd_ != -1) {
        result = close(fd_);
        fd_ = -1;
    }
    return result;
}

std::unique_ptr<UdpSocket> UdpSocket::NewUdpClient(const std::string& host, int port,
                                                   std::string* error) {
    int getaddrinfo_error = 0;
    int fd = socket_network_client_timeout(host.c_str(), port, SOCK_DGRAM, 0, &getaddrinfo_error);
    if (fd == -1) {
        if (error) {
            *error = android::base::StringPrintf(
                    "Failed to connect to %s:%d: %s", host.c_str(), port,
                    getaddrinfo_error ? gai_strerror(getaddrinfo_error) : strerror(errno));
        }
        return nullptr;
    }

    return std::unique_ptr<UdpSocket>(new UnixUdpSocket(fd, UnixUdpSocket::Type::kClient));
}

std::unique_ptr<UdpSocket> UdpSocket::NewUdpServer(int port) {
    int fd = socket_inaddr_any_server(port, SOCK_DGRAM);
    if (fd == -1) {
        // This is just used in testing, no need for an error message.
        return nullptr;
    }

    return std::unique_ptr<UdpSocket>(new UnixUdpSocket(fd, UnixUdpSocket::Type::kServer));
}
