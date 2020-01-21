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

// This file implements the fastboot UDP protocol; see fastboot_protocol.txt for documentation.

#include "udp.h"

#include <errno.h>
#include <stdio.h>

#include <list>
#include <memory>
#include <vector>

#include <android-base/macros.h>
#include <android-base/stringprintf.h>

#include "socket.h"

namespace udp {

using namespace internal;

constexpr size_t kMinPacketSize = 512;
constexpr size_t kHeaderSize = 4;

enum Index {
    kIndexId = 0,
    kIndexFlags = 1,
    kIndexSeqH = 2,
    kIndexSeqL = 3,
};

// Extracts a big-endian uint16_t from a byte array.
static uint16_t ExtractUint16(const uint8_t* bytes) {
    return (static_cast<uint16_t>(bytes[0]) << 8) | bytes[1];
}

// Packet header handling.
class Header {
  public:
    Header();
    ~Header() = default;

    uint8_t id() const { return bytes_[kIndexId]; }
    const uint8_t* bytes() const { return bytes_; }

    void Set(uint8_t id, uint16_t sequence, Flag flag);

    // Checks whether |response| is a match for this header.
    bool Matches(const uint8_t* response);

  private:
    uint8_t bytes_[kHeaderSize];
};

Header::Header() {
    Set(kIdError, 0, kFlagNone);
}

void Header::Set(uint8_t id, uint16_t sequence, Flag flag) {
    bytes_[kIndexId] = id;
    bytes_[kIndexFlags] = flag;
    bytes_[kIndexSeqH] = sequence >> 8;
    bytes_[kIndexSeqL] = sequence;
}

bool Header::Matches(const uint8_t* response) {
    // Sequence numbers must be the same to match, but the response ID can either be the same
    // or an error response which is always accepted.
    return bytes_[kIndexSeqH] == response[kIndexSeqH] &&
           bytes_[kIndexSeqL] == response[kIndexSeqL] &&
           (bytes_[kIndexId] == response[kIndexId] || response[kIndexId] == kIdError);
}

// Implements the Transport interface to work with the fastboot engine.
class UdpTransport : public Transport {
  public:
    // Factory function so we can return nullptr if initialization fails.
    static std::unique_ptr<UdpTransport> NewTransport(std::unique_ptr<Socket> socket,
                                                      std::string* error);
    ~UdpTransport() override = default;

    ssize_t Read(void* data, size_t length) override;
    ssize_t Write(const void* data, size_t length) override;
    int Close() override;
    int Reset() override;

  private:
    explicit UdpTransport(std::unique_ptr<Socket> socket) : socket_(std::move(socket)) {}

    // Performs the UDP initialization procedure. Returns true on success.
    bool InitializeProtocol(std::string* error);

    // Sends |length| bytes from |data| and waits for the response packet up to |attempts| times.
    // Continuation packets are handled automatically and any return data is written to |rx_data|.
    // Excess bytes that cannot fit in |rx_data| are dropped.
    // On success, returns the number of response data bytes received, which may be greater than
    // |rx_length|. On failure, returns -1 and fills |error| on failure.
    ssize_t SendData(Id id, const uint8_t* tx_data, size_t tx_length, uint8_t* rx_data,
                     size_t rx_length, int attempts, std::string* error);

    // Helper for SendData(); sends a single packet and handles the response. |header| specifies
    // the initial outgoing packet information but may be modified by this function.
    ssize_t SendSinglePacketHelper(Header* header, const uint8_t* tx_data, size_t tx_length,
                                   uint8_t* rx_data, size_t rx_length, int attempts,
                                   std::string* error);

    std::unique_ptr<Socket> socket_;
    int sequence_ = -1;
    size_t max_data_length_ = kMinPacketSize - kHeaderSize;
    std::vector<uint8_t> rx_packet_;

    DISALLOW_COPY_AND_ASSIGN(UdpTransport);
};

std::unique_ptr<UdpTransport> UdpTransport::NewTransport(std::unique_ptr<Socket> socket,
                                                         std::string* error) {
    std::unique_ptr<UdpTransport> transport(new UdpTransport(std::move(socket)));

    if (!transport->InitializeProtocol(error)) {
        return nullptr;
    }

    return transport;
}

bool UdpTransport::InitializeProtocol(std::string* error) {
    uint8_t rx_data[4];

    sequence_ = 0;
    rx_packet_.resize(kMinPacketSize);

    // First send the query packet to sync with the target. Only attempt this a small number of
    // times so we can fail out quickly if the target isn't available.
    ssize_t rx_bytes = SendData(kIdDeviceQuery, nullptr, 0, rx_data, sizeof(rx_data),
                                kMaxConnectAttempts, error);
    if (rx_bytes == -1) {
        return false;
    } else if (rx_bytes < 2) {
        *error = "invalid query response from target";
        return false;
    }
    // The first two bytes contain the next expected sequence number.
    sequence_ = ExtractUint16(rx_data);

    // Now send the initialization packet with our version and maximum packet size.
    uint8_t init_data[] = {kProtocolVersion >> 8, kProtocolVersion & 0xFF,
                           kHostMaxPacketSize >> 8, kHostMaxPacketSize & 0xFF};
    rx_bytes = SendData(kIdInitialization, init_data, sizeof(init_data), rx_data, sizeof(rx_data),
                        kMaxTransmissionAttempts, error);
    if (rx_bytes == -1) {
        return false;
    } else if (rx_bytes < 4) {
        *error = "invalid initialization response from target";
        return false;
    }

    // The first two data bytes contain the version, the second two bytes contain the target max
    // supported packet size, which must be at least 512 bytes.
    uint16_t version = ExtractUint16(rx_data);
    if (version < kProtocolVersion) {
        *error = android::base::StringPrintf("target reported invalid protocol version %d",
                                             version);
        return false;
    }
    uint16_t packet_size = ExtractUint16(rx_data + 2);
    if (packet_size < kMinPacketSize) {
        *error = android::base::StringPrintf("target reported invalid packet size %d", packet_size);
        return false;
    }

    packet_size = std::min(kHostMaxPacketSize, packet_size);
    max_data_length_ = packet_size - kHeaderSize;
    rx_packet_.resize(packet_size);

    return true;
}

// SendData() is just responsible for chunking |data| into packets until it's all been sent.
// Per-packet timeout/retransmission logic is done in SendSinglePacketHelper().
ssize_t UdpTransport::SendData(Id id, const uint8_t* tx_data, size_t tx_length, uint8_t* rx_data,
                               size_t rx_length, int attempts, std::string* error) {
    if (socket_ == nullptr) {
        *error = "socket is closed";
        return -1;
    }

    Header header;
    size_t packet_data_length;
    ssize_t ret = 0;
    // We often send header-only packets with no data as part of the protocol, so always send at
    // least once even if |length| == 0, then repeat until we've sent all of |data|.
    do {
        // Set the continuation flag and truncate packet data if needed.
        if (tx_length > max_data_length_) {
            packet_data_length = max_data_length_;
            header.Set(id, sequence_, kFlagContinuation);
        } else {
            packet_data_length = tx_length;
            header.Set(id, sequence_, kFlagNone);
        }

        ssize_t bytes = SendSinglePacketHelper(&header, tx_data, packet_data_length, rx_data,
                                               rx_length, attempts, error);

        // Advance our read and write buffers for the next packet. Keep going even if we run out
        // of receive buffer space so we can detect overflows.
        if (bytes == -1) {
            return -1;
        } else if (static_cast<size_t>(bytes) < rx_length) {
            rx_data += bytes;
            rx_length -= bytes;
        } else {
            rx_data = nullptr;
            rx_length = 0;
        }

        tx_length -= packet_data_length;
        tx_data += packet_data_length;

        ret += bytes;
    } while (tx_length > 0);

    return ret;
}

ssize_t UdpTransport::SendSinglePacketHelper(
        Header* header, const uint8_t* tx_data, size_t tx_length, uint8_t* rx_data,
        size_t rx_length, const int attempts, std::string* error) {
    ssize_t total_data_bytes = 0;
    error->clear();

    int attempts_left = attempts;
    while (attempts_left > 0) {
        if (!socket_->Send({{header->bytes(), kHeaderSize}, {tx_data, tx_length}})) {
            *error = Socket::GetErrorMessage();
            return -1;
        }

        // Keep receiving until we get a matching response or we timeout.
        ssize_t bytes = 0;
        do {
            bytes = socket_->Receive(rx_packet_.data(), rx_packet_.size(), kResponseTimeoutMs);
            if (bytes == -1) {
                if (socket_->ReceiveTimedOut()) {
                    break;
                }
                *error = Socket::GetErrorMessage();
                return -1;
            } else if (bytes < static_cast<ssize_t>(kHeaderSize)) {
                *error = "protocol error: incomplete header";
                return -1;
            }
        } while (!header->Matches(rx_packet_.data()));

        if (socket_->ReceiveTimedOut()) {
            --attempts_left;
            continue;
        }
        ++sequence_;

        // Save to |error| or |rx_data| as appropriate.
        if (rx_packet_[kIndexId] == kIdError) {
            error->append(rx_packet_.data() + kHeaderSize, rx_packet_.data() + bytes);
        } else {
            total_data_bytes += bytes - kHeaderSize;
            size_t rx_data_bytes = std::min<size_t>(bytes - kHeaderSize, rx_length);
            if (rx_data_bytes > 0) {
                memcpy(rx_data, rx_packet_.data() + kHeaderSize, rx_data_bytes);
                rx_data += rx_data_bytes;
                rx_length -= rx_data_bytes;
            }
        }

        // If the response has a continuation flag we need to prompt for more data by sending
        // an empty packet.
        if (rx_packet_[kIndexFlags] & kFlagContinuation) {
            // We got a valid response so reset our attempt counter.
            attempts_left = attempts;
            header->Set(rx_packet_[kIndexId], sequence_, kFlagNone);
            tx_data = nullptr;
            tx_length = 0;
            continue;
        }

        break;
    }

    if (attempts_left <= 0) {
        *error = "no response from target";
        return -1;
    }

    if (rx_packet_[kIndexId] == kIdError) {
        *error = "target reported error: " + *error;
        return -1;
    }

    return total_data_bytes;
}

ssize_t UdpTransport::Read(void* data, size_t length) {
    // Read from the target by sending an empty packet.
    std::string error;
    ssize_t bytes = SendData(kIdFastboot, nullptr, 0, reinterpret_cast<uint8_t*>(data), length,
                             kMaxTransmissionAttempts, &error);

    if (bytes == -1) {
        fprintf(stderr, "UDP error: %s\n", error.c_str());
        return -1;
    } else if (static_cast<size_t>(bytes) > length) {
        // Fastboot protocol error: the target sent more data than our fastboot engine was prepared
        // to receive.
        fprintf(stderr, "UDP error: receive overflow, target sent too much fastboot data\n");
        return -1;
    }

    return bytes;
}

ssize_t UdpTransport::Write(const void* data, size_t length) {
    std::string error;
    ssize_t bytes = SendData(kIdFastboot, reinterpret_cast<const uint8_t*>(data), length, nullptr,
                             0, kMaxTransmissionAttempts, &error);

    if (bytes == -1) {
        fprintf(stderr, "UDP error: %s\n", error.c_str());
        return -1;
    } else if (bytes > 0) {
        // UDP protocol error: only empty ACK packets are allowed when writing to a device.
        fprintf(stderr, "UDP error: target sent fastboot data out-of-turn\n");
        return -1;
    }

    return length;
}

int UdpTransport::Close() {
    if (socket_ == nullptr) {
        return 0;
    }

    int result = socket_->Close();
    socket_.reset();
    return result;
}

int UdpTransport::Reset() {
    return 0;
}

std::unique_ptr<Transport> Connect(const std::string& hostname, int port, std::string* error) {
    return internal::Connect(Socket::NewClient(Socket::Protocol::kUdp, hostname, port, error),
                             error);
}

namespace internal {

std::unique_ptr<Transport> Connect(std::unique_ptr<Socket> sock, std::string* error) {
    if (sock == nullptr) {
        // If Socket creation failed |error| is already set.
        return nullptr;
    }

    return UdpTransport::NewTransport(std::move(sock), error);
}

}  // namespace internal

}  // namespace udp
