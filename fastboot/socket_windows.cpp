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

static int GetProtocol(int sock_type) {
    switch (sock_type) {
        case SOCK_DGRAM:
            return IPPROTO_UDP;
        case SOCK_STREAM:
            return IPPROTO_TCP;
        default:
            // 0 lets the system decide which protocol to use.
            return 0;
    }
}

// Windows implementation of this libcutils function. This function does not make any calls to
// WSAStartup() or WSACleanup() so that must be handled by the caller.
// TODO(dpursell): share this code with adb.
static SOCKET socket_network_client(const std::string& host, int port, int type) {
    // First resolve the host and port parameters into a usable network address.
    addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = type;
    hints.ai_protocol = GetProtocol(type);

    addrinfo* address = nullptr;
    getaddrinfo(host.c_str(), android::base::StringPrintf("%d", port).c_str(), &hints, &address);
    if (address == nullptr) {
        return INVALID_SOCKET;
    }

    // Now create and connect the socket.
    SOCKET sock = socket(address->ai_family, address->ai_socktype, address->ai_protocol);
    if (sock == INVALID_SOCKET) {
        freeaddrinfo(address);
        return INVALID_SOCKET;
    }

    if (connect(sock, address->ai_addr, address->ai_addrlen) == SOCKET_ERROR) {
        closesocket(sock);
        freeaddrinfo(address);
        return INVALID_SOCKET;
    }

    freeaddrinfo(address);
    return sock;
}

// Windows implementation of this libcutils function. This implementation creates a dual-stack
// server socket that can accept incoming IPv4 or IPv6 packets. This function does not make any
// calls to WSAStartup() or WSACleanup() so that must be handled by the caller.
// TODO(dpursell): share this code with adb.
static SOCKET socket_inaddr_any_server(int port, int type) {
    SOCKET sock = socket(AF_INET6, type, GetProtocol(type));
    if (sock == INVALID_SOCKET) {
        return INVALID_SOCKET;
    }

    // Enforce exclusive addresses (1), and enable dual-stack so both IPv4 and IPv6 work (2).
    // (1) https://msdn.microsoft.com/en-us/library/windows/desktop/ms740621(v=vs.85).aspx.
    // (2) https://msdn.microsoft.com/en-us/library/windows/desktop/bb513665(v=vs.85).aspx.
    int exclusive = 1;
    DWORD v6_only = 0;
    if (setsockopt(sock, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, reinterpret_cast<const char*>(&exclusive),
                   sizeof(exclusive)) == SOCKET_ERROR ||
        setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, reinterpret_cast<const char*>(&v6_only),
                   sizeof(v6_only)) == SOCKET_ERROR) {
        closesocket(sock);
        return INVALID_SOCKET;
    }

    // Bind the socket to our local port.
    sockaddr_in6 addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(port);
    addr.sin6_addr = in6addr_any;
    if (bind(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) {
        closesocket(sock);
        return INVALID_SOCKET;
    }

    return sock;
}

// Documentation at https://msdn.microsoft.com/en-us/library/windows/desktop/ms741549(v=vs.85).aspx
// claims WSACleanup() should be called before program exit, but general consensus seems to be that
// it hasn't actually been necessary for a long time, possibly since Windows 3.1.
//
// Both adb (1) and Chrome (2) purposefully avoid WSACleanup(), and since no adverse affects have
// been found we may as well do the same here to keep this code simpler.
// (1) https://android.googlesource.com/platform/system/core.git/+/master/adb/sysdeps_win32.cpp#816
// (2) https://code.google.com/p/chromium/codesearch#chromium/src/net/base/winsock_init.cc&l=35
static bool InitWinsock() {
    static bool init_success = false;

    if (!init_success) {
        WSADATA wsaData;
        init_success = (WSAStartup(MAKEWORD(2, 2), &wsaData) == 0);
    }

    return init_success;
}

std::unique_ptr<UdpSocket> UdpSocket::NewUdpClient(const std::string& host, int port,
                                                   std::string* error) {
    if (!InitWinsock()) {
        if (error) {
            *error = android::base::StringPrintf("Failed to initialize Winsock (error %d)",
                                                 WSAGetLastError());
        }
        return nullptr;
    }

    SOCKET sock = socket_network_client(host, port, SOCK_DGRAM);
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
    if (!InitWinsock()) {
        return nullptr;
    }

    SOCKET sock = socket_inaddr_any_server(port, SOCK_DGRAM);
    if (sock == INVALID_SOCKET) {
        return nullptr;
    }

    return std::unique_ptr<UdpSocket>(new WindowsUdpSocket(sock, WindowsUdpSocket::Type::kServer));
}
