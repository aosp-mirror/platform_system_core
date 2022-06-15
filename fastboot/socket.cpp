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

#include <android-base/errors.h>
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

ssize_t Socket::ReceiveAll(void* data, size_t length, int timeout_ms) {
    size_t total = 0;

    while (total < length) {
        ssize_t bytes = Receive(reinterpret_cast<char*>(data) + total, length - total, timeout_ms);

        // Returns 0 only when the peer has disconnected because our requested length is not 0. So
        // we return immediately to avoid dead loop here.
        if (bytes <= 0) {
            if (total == 0) {
                return -1;
            }
            break;
        }
        total += bytes;
    }

    return total;
}

int Socket::GetLocalPort() {
    return socket_get_local_port(sock_);
}

// According to Windows setsockopt() documentation, if a Windows socket times out during send() or
// recv() the state is indeterminate and should not be used. Our UDP protocol relies on being able
// to re-send after a timeout, so we must use select() rather than SO_RCVTIMEO.
// See https://msdn.microsoft.com/en-us/library/windows/desktop/ms740476(v=vs.85).aspx.
bool Socket::WaitForRecv(int timeout_ms) {
    receive_timed_out_ = false;

    // In our usage |timeout_ms| <= 0 means block forever, so just return true immediately and let
    // the subsequent recv() do the blocking.
    if (timeout_ms <= 0) {
        return true;
    }

    // select() doesn't always check this case and will block for |timeout_ms| if we let it.
    if (sock_ == INVALID_SOCKET) {
        return false;
    }

    fd_set read_set;
    FD_ZERO(&read_set);
    FD_SET(sock_, &read_set);

    timeval timeout;
    timeout.tv_sec = timeout_ms / 1000;
    timeout.tv_usec = (timeout_ms % 1000) * 1000;

    int result = TEMP_FAILURE_RETRY(select(sock_ + 1, &read_set, nullptr, nullptr, &timeout));

    if (result == 0) {
        receive_timed_out_ = true;
    }
    return result == 1;
}

// Implements the Socket interface for UDP.
class UdpSocket : public Socket {
  public:
    enum class Type { kClient, kServer };

    UdpSocket(Type type, cutils_socket_t sock);

    bool Send(const void* data, size_t length) override;
    bool Send(std::vector<cutils_socket_buffer_t> buffers) override;
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

bool UdpSocket::Send(const void* data, size_t length) {
    return TEMP_FAILURE_RETRY(sendto(sock_, reinterpret_cast<const char*>(data), length, 0,
                                     reinterpret_cast<sockaddr*>(addr_.get()), addr_size_)) ==
           static_cast<ssize_t>(length);
}

bool UdpSocket::Send(std::vector<cutils_socket_buffer_t> buffers) {
    size_t total_length = 0;
    for (const auto& buffer : buffers) {
        total_length += buffer.length;
    }

    return TEMP_FAILURE_RETRY(socket_send_buffers_function_(
                   sock_, buffers.data(), buffers.size())) == static_cast<ssize_t>(total_length);
}

ssize_t UdpSocket::Receive(void* data, size_t length, int timeout_ms) {
    if (!WaitForRecv(timeout_ms)) {
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
    explicit TcpSocket(cutils_socket_t sock) : Socket(sock) {}

    bool Send(const void* data, size_t length) override;
    bool Send(std::vector<cutils_socket_buffer_t> buffers) override;
    ssize_t Receive(void* data, size_t length, int timeout_ms) override;

    std::unique_ptr<Socket> Accept() override;

  private:
    DISALLOW_COPY_AND_ASSIGN(TcpSocket);
};

bool TcpSocket::Send(const void* data, size_t length) {
    while (length > 0) {
        ssize_t sent =
                TEMP_FAILURE_RETRY(send(sock_, reinterpret_cast<const char*>(data), length, 0));

        if (sent == -1) {
            return false;
        }
        length -= sent;
    }

    return true;
}

bool TcpSocket::Send(std::vector<cutils_socket_buffer_t> buffers) {
    while (!buffers.empty()) {
        ssize_t sent = TEMP_FAILURE_RETRY(
                socket_send_buffers_function_(sock_, buffers.data(), buffers.size()));

        if (sent == -1) {
            return false;
        }

        // Adjust the buffers to skip past the bytes we've just sent.
        auto iter = buffers.begin();
        while (sent > 0) {
            if (iter->length > static_cast<size_t>(sent)) {
                // Incomplete buffer write; adjust the buffer to point to the next byte to send.
                iter->length -= sent;
                iter->data = reinterpret_cast<const char*>(iter->data) + sent;
                break;
            }

            // Complete buffer write; move on to the next buffer.
            sent -= iter->length;
            ++iter;
        }

        // Shortcut the common case: we've written everything remaining.
        if (iter == buffers.end()) {
            break;
        }
        buffers.erase(buffers.begin(), iter);
    }

    return true;
}

ssize_t TcpSocket::Receive(void* data, size_t length, int timeout_ms) {
    if (!WaitForRecv(timeout_ms)) {
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

std::string Socket::GetErrorMessage() {
#if defined(_WIN32)
    DWORD error_code = WSAGetLastError();
#else
    int error_code = errno;
#endif
    return android::base::SystemErrorCodeToString(error_code);
}
