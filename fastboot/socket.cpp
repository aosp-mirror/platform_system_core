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

#include <android-base/stringprintf.h>

Socket::Socket(cutils_socket_t sock) : sock_(sock) {}

Socket::~Socket() {
    Close();
}

int Socket::Close() {
    int ret = 0;

    if (sock_ != INVALID_SOCKET) {
        ret = socket_close(sock_);
        sock_ = INVALID_SOCKET;
    }

    return ret;
}

bool Socket::SetReceiveTimeout(int timeout_ms) {
    if (timeout_ms != receive_timeout_ms_) {
        if (socket_set_receive_timeout(sock_, timeout_ms) == 0) {
            receive_timeout_ms_ = timeout_ms;
            return true;
        }
        return false;
    }

    return true;
}

ssize_t Socket::ReceiveAll(void* data, size_t length, int timeout_ms) {
    size_t total = 0;

    while (total < length) {
        ssize_t bytes = Receive(reinterpret_cast<char*>(data) + total, length - total, timeout_ms);

        if (bytes == -1) {
            if (total == 0) {
                return -1;
            }
            break;
        }
        total += bytes;
    }

    return total;
}

// Implements the Socket interface for UDP.
class UdpSocket : public Socket {
  public:
    enum class Type { kClient, kServer };

    UdpSocket(Type type, cutils_socket_t sock);

    ssize_t Send(const void* data, size_t length) override;
    ssize_t Receive(void* data, size_t length, int timeout_ms) override;

  private:
    std::unique_ptr<sockaddr_storage> addr_;
    socklen_t addr_size_ = 0;

    DISALLOW_COPY_AND_ASSIGN(UdpSocket);
};

UdpSocket::UdpSocket(Type type, cutils_socket_t sock) : Socket(sock) {
    // Only servers need to remember addresses; clients are connected to a server in NewClient()
    // so will send to that server without needing to specify the address again.
    if (type == Type::kServer) {
        addr_.reset(new sockaddr_storage);
        addr_size_ = sizeof(*addr_);
        memset(addr_.get(), 0, addr_size_);
    }
}

ssize_t UdpSocket::Send(const void* data, size_t length) {
    return TEMP_FAILURE_RETRY(sendto(sock_, reinterpret_cast<const char*>(data), length, 0,
                                     reinterpret_cast<sockaddr*>(addr_.get()), addr_size_));
}

ssize_t UdpSocket::Receive(void* data, size_t length, int timeout_ms) {
    if (!SetReceiveTimeout(timeout_ms)) {
        return -1;
    }

    socklen_t* addr_size_ptr = nullptr;
    if (addr_ != nullptr) {
        // Reset addr_size as it may have been modified by previous recvfrom() calls.
        addr_size_ = sizeof(*addr_);
        addr_size_ptr = &addr_size_;
    }

    return TEMP_FAILURE_RETRY(recvfrom(sock_, reinterpret_cast<char*>(data), length, 0,
                                       reinterpret_cast<sockaddr*>(addr_.get()), addr_size_ptr));
}

// Implements the Socket interface for TCP.
class TcpSocket : public Socket {
  public:
    TcpSocket(cutils_socket_t sock) : Socket(sock) {}

    ssize_t Send(const void* data, size_t length) override;
    ssize_t Receive(void* data, size_t length, int timeout_ms) override;

    std::unique_ptr<Socket> Accept() override;

  private:
    DISALLOW_COPY_AND_ASSIGN(TcpSocket);
};

ssize_t TcpSocket::Send(const void* data, size_t length) {
    size_t total = 0;

    while (total < length) {
        ssize_t bytes = TEMP_FAILURE_RETRY(
                send(sock_, reinterpret_cast<const char*>(data) + total, length - total, 0));

        if (bytes == -1) {
            if (total == 0) {
                return -1;
            }
            break;
        }
        total += bytes;
    }

    return total;
}

ssize_t TcpSocket::Receive(void* data, size_t length, int timeout_ms) {
    if (!SetReceiveTimeout(timeout_ms)) {
        return -1;
    }

    return TEMP_FAILURE_RETRY(recv(sock_, reinterpret_cast<char*>(data), length, 0));
}

std::unique_ptr<Socket> TcpSocket::Accept() {
    cutils_socket_t handler = accept(sock_, nullptr, nullptr);
    if (handler == INVALID_SOCKET) {
        return nullptr;
    }
    return std::unique_ptr<TcpSocket>(new TcpSocket(handler));
}

std::unique_ptr<Socket> Socket::NewClient(Protocol protocol, const std::string& host, int port,
                                          std::string* error) {
    if (protocol == Protocol::kUdp) {
        cutils_socket_t sock = socket_network_client(host.c_str(), port, SOCK_DGRAM);
        if (sock != INVALID_SOCKET) {
            return std::unique_ptr<UdpSocket>(new UdpSocket(UdpSocket::Type::kClient, sock));
        }
    } else {
        cutils_socket_t sock = socket_network_client(host.c_str(), port, SOCK_STREAM);
        if (sock != INVALID_SOCKET) {
            return std::unique_ptr<TcpSocket>(new TcpSocket(sock));
        }
    }

    if (error) {
        *error = android::base::StringPrintf("Failed to connect to %s:%d", host.c_str(), port);
    }
    return nullptr;
}

// This functionality is currently only used by tests so we don't need any error messages.
std::unique_ptr<Socket> Socket::NewServer(Protocol protocol, int port) {
    if (protocol == Protocol::kUdp) {
        cutils_socket_t sock = socket_inaddr_any_server(port, SOCK_DGRAM);
        if (sock != INVALID_SOCKET) {
            return std::unique_ptr<UdpSocket>(new UdpSocket(UdpSocket::Type::kServer, sock));
        }
    } else {
        cutils_socket_t sock = socket_inaddr_any_server(port, SOCK_STREAM);
        if (sock != INVALID_SOCKET) {
            return std::unique_ptr<TcpSocket>(new TcpSocket(sock));
        }
    }

    return nullptr;
}
