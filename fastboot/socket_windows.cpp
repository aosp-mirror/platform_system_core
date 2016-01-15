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

#include <winsock2.h>
#include <ws2tcpip.h>

#include <memory>

#include <android-base/stringprintf.h>
#include <cutils/sockets.h>

// Windows UDP socket functionality.
class WindowsUdpSocket : public UdpSocket {
  public:
    enum class Type { kClient, kServer };

    WindowsUdpSocket(SOCKET sock, Type type);
    ~WindowsUdpSocket() override;

    ssize_t Send(const void* data, size_t len) override;
    ssize_t Receive(void* data, size_t len, int timeout_ms) override;
    int Close() override;

  private:
    SOCKET sock_;
    int receive_timeout_ms_ = 0;
    std::unique_ptr<sockaddr_storage> addr_;
    int addr_size_ = 0;

    DISALLOW_COPY_AND_ASSIGN(WindowsUdpSocket);
};

WindowsUdpSocket::WindowsUdpSocket(SOCKET sock, Type type) : sock_(sock) {
    // Only servers need to remember addresses; clients are connected to a server in NewUdpClient()
    // so will send to that server without needing to specify the address again.
    if (type == Type::kServer) {
        addr_.reset(new sockaddr_storage);
        addr_size_ = sizeof(*addr_);
        memset(addr_.get(), 0, addr_size_);
    }
}

WindowsUdpSocket::~WindowsUdpSocket() {
    Close();
}

ssize_t WindowsUdpSocket::Send(const void* data, size_t len) {
    return sendto(sock_, reinterpret_cast<const char*>(data), len, 0,
                  reinterpret_cast<sockaddr*>(addr_.get()), addr_size_);
}

ssize_t WindowsUdpSocket::Receive(void* data, size_t len, int timeout_ms) {
    // Only set socket timeout if it's changed.
    if (receive_timeout_ms_ != timeout_ms) {
        if (setsockopt(sock_, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout_ms),
                       sizeof(timeout_ms)) < 0) {
            return -1;
        }
        receive_timeout_ms_ = timeout_ms;
    }

    int* addr_size_ptr = nullptr;
    if (addr_ != nullptr) {
        // Reset addr_size as it may have been modified by previous recvfrom() calls.
        addr_size_ = sizeof(*addr_);
        addr_size_ptr = &addr_size_;
    }
    int result = recvfrom(sock_, reinterpret_cast<char*>(data), len, 0,
                          reinterpret_cast<sockaddr*>(addr_.get()), addr_size_ptr);
    if (result < 0 && WSAGetLastError() == WSAETIMEDOUT) {
        errno = EAGAIN;
    }
    return result;
}

int WindowsUdpSocket::Close() {
    int result = 0;
    if (sock_ != INVALID_SOCKET) {
        result = closesocket(sock_);
        sock_ = INVALID_SOCKET;
    }
    return result;
}

std::unique_ptr<UdpSocket> UdpSocket::NewUdpClient(const std::string& host, int port,
                                                   std::string* error) {
    SOCKET sock = socket_network_client(host.c_str(), port, SOCK_DGRAM);
    if (sock == INVALID_SOCKET) {
        if (error) {
            *error = android::base::StringPrintf("Failed to connect to %s:%d (error %d)",
                                                 host.c_str(), port, WSAGetLastError());
        }
        return nullptr;
    }

    return std::unique_ptr<UdpSocket>(new WindowsUdpSocket(sock, WindowsUdpSocket::Type::kClient));
}

// This functionality is currently only used by tests so we don't need any error messages.
std::unique_ptr<UdpSocket> UdpSocket::NewUdpServer(int port) {
    SOCKET sock = socket_inaddr_any_server(port, SOCK_DGRAM);
    if (sock == INVALID_SOCKET) {
        return nullptr;
    }

    return std::unique_ptr<UdpSocket>(new WindowsUdpSocket(sock, WindowsUdpSocket::Type::kServer));
}
