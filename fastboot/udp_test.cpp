/*
 * Copyright (C) 2015 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "udp.h"

#include <gtest/gtest.h>

#include "socket.h"
#include "socket_mock.h"

using namespace udp;
using namespace udp::internal;

// Some possible corner case sequence numbers we want to check.
static const uint16_t kTestSequenceNumbers[] = {0x0000, 0x0001, 0x00FF, 0x0100,
                                                0x7FFF, 0x8000, 0xFFFF};

// Converts |value| to a binary big-endian string.
static std::string PacketValue(uint16_t value) {
    return std::string{static_cast<char>(value >> 8), static_cast<char>(value)};
}

// Returns an Error packet.
static std::string ErrorPacket(uint16_t sequence, const std::string& message = "",
                               char flags = kFlagNone) {
    return std::string{kIdError, flags} + PacketValue(sequence) + message;
}

// Returns a Query packet with no data.
static std::string QueryPacket(uint16_t sequence) {
    return std::string{kIdDeviceQuery, kFlagNone} + PacketValue(sequence);
}

// Returns a Query packet with a 2-byte |new_sequence|.
static std::string QueryPacket(uint16_t sequence, uint16_t new_sequence) {
    return std::string{kIdDeviceQuery, kFlagNone} + PacketValue(sequence) +
           PacketValue(new_sequence);
}

// Returns an Init packet with a 2-byte |version| and |max_packet_size|.
static std::string InitPacket(uint16_t sequence, uint16_t version, uint16_t max_packet_size) {
    return std::string{kIdInitialization, kFlagNone} + PacketValue(sequence) +
           PacketValue(version) + PacketValue(max_packet_size);
}

// Returns a Fastboot packet with |data|.
static std::string FastbootPacket(uint16_t sequence, const std::string& data = "",
                                  char flags = kFlagNone) {
    return std::string{kIdFastboot, flags} + PacketValue(sequence) + data;
}

// Fixture class to test protocol initialization. Usage is to set up the expected calls to the
// SocketMock object then call UdpConnect() and check the result.
class UdpConnectTest : public ::testing::Test {
  public:
    UdpConnectTest() : mock_socket_(new SocketMock) {}

    // Run the initialization, return whether it was successful or not. This passes ownership of
    // the current |mock_socket_| but allocates a new one for re-use.
    bool UdpConnect(std::string* error = nullptr) {
        std::string local_error;
        if (error == nullptr) {
            error = &local_error;
        }
        std::unique_ptr<Transport> transport(Connect(std::move(mock_socket_), error));
        mock_socket_.reset(new SocketMock);
        return transport != nullptr && error->empty();
    }

  protected:
    std::unique_ptr<SocketMock> mock_socket_;
};

// Tests a successful protocol initialization with various starting sequence numbers.
TEST_F(UdpConnectTest, InitializationSuccess) {
    for (uint16_t seq : kTestSequenceNumbers) {
        mock_socket_->ExpectSend(QueryPacket(0));
        mock_socket_->AddReceive(QueryPacket(0, seq));
        mock_socket_->ExpectSend(InitPacket(seq, kProtocolVersion, kHostMaxPacketSize));
        mock_socket_->AddReceive(InitPacket(seq, kProtocolVersion, 1024));

        EXPECT_TRUE(UdpConnect());
    }
}

// Tests continuation packets during initialization.
TEST_F(UdpConnectTest, InitializationContinuationSuccess) {
    mock_socket_->ExpectSend(QueryPacket(0));
    mock_socket_->AddReceive(std::string{kIdDeviceQuery, kFlagContinuation, 0, 0, 0x44});
    mock_socket_->ExpectSend(std::string{kIdDeviceQuery, kFlagNone, 0, 1});
    mock_socket_->AddReceive(std::string{kIdDeviceQuery, kFlagNone, 0, 1, 0x55});

    mock_socket_->ExpectSend(InitPacket(0x4455, kProtocolVersion, kHostMaxPacketSize));
    mock_socket_->AddReceive(std::string{kIdInitialization, kFlagContinuation, 0x44, 0x55, 0});
    mock_socket_->ExpectSend(std::string{kIdInitialization, kFlagNone, 0x44, 0x56});
    mock_socket_->AddReceive(std::string{kIdInitialization, kFlagContinuation, 0x44, 0x56, 1});
    mock_socket_->ExpectSend(std::string{kIdInitialization, kFlagNone, 0x44, 0x57});
    mock_socket_->AddReceive(std::string{kIdInitialization, kFlagContinuation, 0x44, 0x57, 2});
    mock_socket_->ExpectSend(std::string{kIdInitialization, kFlagNone, 0x44, 0x58});
    mock_socket_->AddReceive(std::string{kIdInitialization, kFlagNone, 0x44, 0x58, 0});

    EXPECT_TRUE(UdpConnect());
}


// Tests a mismatched version number; as long as the minimum of the two versions is supported
// we should allow the connection.
TEST_F(UdpConnectTest, InitializationVersionMismatch) {
    mock_socket_->ExpectSend(QueryPacket(0));
    mock_socket_->AddReceive(QueryPacket(0, 0));
    mock_socket_->ExpectSend(InitPacket(0, kProtocolVersion, kHostMaxPacketSize));
    mock_socket_->AddReceive(InitPacket(0, 2, 1024));

    EXPECT_TRUE(UdpConnect());

    mock_socket_->ExpectSend(QueryPacket(0));
    mock_socket_->AddReceive(QueryPacket(0, 0));
    mock_socket_->ExpectSend(InitPacket(0, kProtocolVersion, kHostMaxPacketSize));
    mock_socket_->AddReceive(InitPacket(0, 0, 1024));

    EXPECT_FALSE(UdpConnect());
}

TEST_F(UdpConnectTest, QueryResponseTimeoutFailure) {
    for (int i = 0; i < kMaxConnectAttempts; ++i) {
        mock_socket_->ExpectSend(QueryPacket(0));
        mock_socket_->AddReceiveTimeout();
    }

    EXPECT_FALSE(UdpConnect());
}

TEST_F(UdpConnectTest, QueryResponseReceiveFailure) {
    mock_socket_->ExpectSend(QueryPacket(0));
    mock_socket_->AddReceiveFailure();

    EXPECT_FALSE(UdpConnect());
}

TEST_F(UdpConnectTest, InitResponseTimeoutFailure) {
    mock_socket_->ExpectSend(QueryPacket(0));
    mock_socket_->AddReceive(QueryPacket(0, 0));
    for (int i = 0; i < kMaxTransmissionAttempts; ++i) {
        mock_socket_->ExpectSend(InitPacket(0, kProtocolVersion, kHostMaxPacketSize));
        mock_socket_->AddReceiveTimeout();
    }

    EXPECT_FALSE(UdpConnect());
}

TEST_F(UdpConnectTest, InitResponseReceiveFailure) {
    mock_socket_->ExpectSend(QueryPacket(0));
    mock_socket_->AddReceive(QueryPacket(0, 0));
    mock_socket_->ExpectSend(InitPacket(0, kProtocolVersion, kHostMaxPacketSize));
    mock_socket_->AddReceiveFailure();

    EXPECT_FALSE(UdpConnect());
}

// Tests that we can recover up to the maximum number of allowed retries.
TEST_F(UdpConnectTest, ResponseRecovery) {
    // The device query packet can recover from up to (kMaxConnectAttempts - 1) timeouts.
    for (int i = 0; i < kMaxConnectAttempts - 1; ++i) {
        mock_socket_->ExpectSend(QueryPacket(0));
        mock_socket_->AddReceiveTimeout();
    }
    mock_socket_->ExpectSend(QueryPacket(0));
    mock_socket_->AddReceive(QueryPacket(0, 0));

    // Subsequent packets try up to (kMaxTransmissionAttempts - 1) times.
    for (int i = 0; i < kMaxTransmissionAttempts - 1; ++i) {
        mock_socket_->ExpectSend(InitPacket(0, kProtocolVersion, kHostMaxPacketSize));
        mock_socket_->AddReceiveTimeout();
    }
    mock_socket_->ExpectSend(InitPacket(0, kProtocolVersion, kHostMaxPacketSize));
    mock_socket_->AddReceive(InitPacket(0, kProtocolVersion, 1024));

    EXPECT_TRUE(UdpConnect());
}

// Tests that the host can handle receiving additional bytes for forward compatibility.
TEST_F(UdpConnectTest, ExtraResponseDataSuccess) {
    mock_socket_->ExpectSend(QueryPacket(0));
    mock_socket_->AddReceive(QueryPacket(0, 0) + "foo");
    mock_socket_->ExpectSend(InitPacket(0, kProtocolVersion, kHostMaxPacketSize));
    mock_socket_->AddReceive(InitPacket(0, kProtocolVersion, 1024) + "bar");

    EXPECT_TRUE(UdpConnect());
}

// Tests mismatched response sequence numbers. A wrong sequence number is interpreted as a previous
// retransmission and just ignored so we should be able to recover.
TEST_F(UdpConnectTest, WrongSequenceRecovery) {
    mock_socket_->ExpectSend(QueryPacket(0));
    mock_socket_->AddReceive(QueryPacket(1, 0));
    mock_socket_->AddReceive(QueryPacket(0, 0));

    mock_socket_->ExpectSend(InitPacket(0, kProtocolVersion, kHostMaxPacketSize));
    mock_socket_->AddReceive(InitPacket(1, kProtocolVersion, 1024));
    mock_socket_->AddReceive(InitPacket(0, kProtocolVersion, 1024));

    EXPECT_TRUE(UdpConnect());
}

// Tests mismatched response IDs. This should also be interpreted as a retransmission and ignored.
TEST_F(UdpConnectTest, WrongIdRecovery) {
    mock_socket_->ExpectSend(QueryPacket(0));
    mock_socket_->AddReceive(FastbootPacket(0));
    mock_socket_->AddReceive(QueryPacket(0, 0));

    mock_socket_->ExpectSend(InitPacket(0, kProtocolVersion, kHostMaxPacketSize));
    mock_socket_->AddReceive(FastbootPacket(0));
    mock_socket_->AddReceive(InitPacket(0, kProtocolVersion, 1024));

    EXPECT_TRUE(UdpConnect());
}

// Tests an invalid query response. Query responses must have at least 2 bytes of data.
TEST_F(UdpConnectTest, InvalidQueryResponseFailure) {
    std::string error;

    mock_socket_->ExpectSend(QueryPacket(0));
    mock_socket_->AddReceive(QueryPacket(0));

    EXPECT_FALSE(UdpConnect(&error));
    EXPECT_EQ("invalid query response from target", error);

    mock_socket_->ExpectSend(QueryPacket(0));
    mock_socket_->AddReceive(QueryPacket(0) + std::string{0x00});

    EXPECT_FALSE(UdpConnect(&error));
    EXPECT_EQ("invalid query response from target", error);
}

// Tests an invalid initialization response. Max packet size must be at least 512 bytes.
TEST_F(UdpConnectTest, InvalidInitResponseFailure) {
    std::string error;

    mock_socket_->ExpectSend(QueryPacket(0));
    mock_socket_->AddReceive(QueryPacket(0, 0));
    mock_socket_->ExpectSend(InitPacket(0, kProtocolVersion, kHostMaxPacketSize));
    mock_socket_->AddReceive(InitPacket(0, kProtocolVersion, 511));

    EXPECT_FALSE(UdpConnect(&error));
    EXPECT_EQ("target reported invalid packet size 511", error);

    mock_socket_->ExpectSend(QueryPacket(0));
    mock_socket_->AddReceive(QueryPacket(0, 0));
    mock_socket_->ExpectSend(InitPacket(0, kProtocolVersion, kHostMaxPacketSize));
    mock_socket_->AddReceive(InitPacket(0, 0, 1024));

    EXPECT_FALSE(UdpConnect(&error));
    EXPECT_EQ("target reported invalid protocol version 0", error);
}

TEST_F(UdpConnectTest, ErrorResponseFailure) {
    std::string error;

    mock_socket_->ExpectSend(QueryPacket(0));
    mock_socket_->AddReceive(ErrorPacket(0, "error1"));

    EXPECT_FALSE(UdpConnect(&error));
    EXPECT_NE(std::string::npos, error.find("error1"));

    mock_socket_->ExpectSend(QueryPacket(0));
    mock_socket_->AddReceive(QueryPacket(0, 0));
    mock_socket_->ExpectSend(InitPacket(0, kProtocolVersion, kHostMaxPacketSize));
    mock_socket_->AddReceive(ErrorPacket(0, "error2"));

    EXPECT_FALSE(UdpConnect(&error));
    EXPECT_NE(std::string::npos, error.find("error2"));
}

// Tests an error response with continuation flag.
TEST_F(UdpConnectTest, ErrorContinuationFailure) {
    std::string error;

    mock_socket_->ExpectSend(QueryPacket(0));
    mock_socket_->AddReceive(ErrorPacket(0, "error1", kFlagContinuation));
    mock_socket_->ExpectSend(ErrorPacket(1));
    mock_socket_->AddReceive(ErrorPacket(1, " ", kFlagContinuation));
    mock_socket_->ExpectSend(ErrorPacket(2));
    mock_socket_->AddReceive(ErrorPacket(2, "error2"));

    EXPECT_FALSE(UdpConnect(&error));
    EXPECT_NE(std::string::npos, error.find("error1 error2"));
}

// Fixture class to test UDP Transport read/write functionality.
class UdpTest : public ::testing::Test {
  public:
    void SetUp() override {
        // Create |transport_| starting at sequence 0 with 512 byte max packet size. Tests can call
        // InitializeTransport() again to change settings.
        ASSERT_TRUE(InitializeTransport(0, 512));
    }

    // Sets up |mock_socket_| to correctly initialize the protocol and creates |transport_|. This
    // can be called multiple times in a test if needed.
    bool InitializeTransport(uint16_t starting_sequence, int device_max_packet_size = 512) {
        mock_socket_ = new SocketMock;
        mock_socket_->ExpectSend(QueryPacket(0));
        mock_socket_->AddReceive(QueryPacket(0, starting_sequence));
        mock_socket_->ExpectSend(
                InitPacket(starting_sequence, kProtocolVersion, kHostMaxPacketSize));
        mock_socket_->AddReceive(
                InitPacket(starting_sequence, kProtocolVersion, device_max_packet_size));

        std::string error;
        transport_ = Connect(std::unique_ptr<Socket>(mock_socket_), &error);
        return transport_ != nullptr && error.empty();
    }

    // Writes |message| to |transport_|, returns true on success.
    bool Write(const std::string& message) {
        return transport_->Write(message.data(), message.length()) ==
                static_cast<ssize_t>(message.length());
    }

    // Reads from |transport_|, returns true if it matches |message|.
    bool Read(const std::string& message) {
        std::string buffer(message.length(), '\0');
        return transport_->Read(&buffer[0], buffer.length()) ==
                static_cast<ssize_t>(message.length()) && buffer == message;
    }

  protected:
    // |mock_socket_| is a raw pointer here because we transfer ownership to |transport_| but we
    // need to retain a pointer to set send and receive expectations.
    SocketMock* mock_socket_ = nullptr;
    std::unique_ptr<Transport> transport_;
};

// Tests sequence behavior with various starting sequence numbers.
TEST_F(UdpTest, SequenceIncrementCheck) {
    for (uint16_t seq : kTestSequenceNumbers) {
        ASSERT_TRUE(InitializeTransport(seq));

        for (int i = 0; i < 10; ++i) {
            mock_socket_->ExpectSend(FastbootPacket(++seq, "foo"));
            mock_socket_->AddReceive(FastbootPacket(seq, ""));
            mock_socket_->ExpectSend(FastbootPacket(++seq, ""));
            mock_socket_->AddReceive(FastbootPacket(seq, "bar"));

            EXPECT_TRUE(Write("foo"));
            EXPECT_TRUE(Read("bar"));
        }
    }
}

// Tests sending and receiving a few small packets.
TEST_F(UdpTest, ReadAndWriteSmallPackets) {
    mock_socket_->ExpectSend(FastbootPacket(1, "foo"));
    mock_socket_->AddReceive(FastbootPacket(1, ""));
    mock_socket_->ExpectSend(FastbootPacket(2, ""));
    mock_socket_->AddReceive(FastbootPacket(2, "bar"));

    EXPECT_TRUE(Write("foo"));
    EXPECT_TRUE(Read("bar"));

    mock_socket_->ExpectSend(FastbootPacket(3, "12345 67890"));
    mock_socket_->AddReceive(FastbootPacket(3));
    mock_socket_->ExpectSend(FastbootPacket(4, "\x01\x02\x03\x04\x05"));
    mock_socket_->AddReceive(FastbootPacket(4));

    EXPECT_TRUE(Write("12345 67890"));
    EXPECT_TRUE(Write("\x01\x02\x03\x04\x05"));

    // Reads are done by sending empty packets.
    mock_socket_->ExpectSend(FastbootPacket(5));
    mock_socket_->AddReceive(FastbootPacket(5, "foo bar baz"));
    mock_socket_->ExpectSend(FastbootPacket(6));
    mock_socket_->AddReceive(FastbootPacket(6, "\x01\x02\x03\x04\x05"));

    EXPECT_TRUE(Read("foo bar baz"));
    EXPECT_TRUE(Read("\x01\x02\x03\x04\x05"));
}

TEST_F(UdpTest, ResponseTimeoutFailure) {
    for (int i = 0; i < kMaxTransmissionAttempts; ++i) {
        mock_socket_->ExpectSend(FastbootPacket(1, "foo"));
        mock_socket_->AddReceiveTimeout();
    }

    EXPECT_FALSE(Write("foo"));
}

TEST_F(UdpTest, ResponseReceiveFailure) {
    mock_socket_->ExpectSend(FastbootPacket(1, "foo"));
    mock_socket_->AddReceiveFailure();

    EXPECT_FALSE(Write("foo"));
}

TEST_F(UdpTest, ResponseTimeoutRecovery) {
    for (int i = 0; i < kMaxTransmissionAttempts - 1; ++i) {
        mock_socket_->ExpectSend(FastbootPacket(1, "foo"));
        mock_socket_->AddReceiveTimeout();
    }
    mock_socket_->ExpectSend(FastbootPacket(1, "foo"));
    mock_socket_->AddReceive(FastbootPacket(1, ""));

    EXPECT_TRUE(Write("foo"));
}

// Tests continuation packets for various max packet sizes.
// The important part of this test is that regardless of what kind of packet fragmentation happens
// at the socket layer, a single call to Transport::Read() and Transport::Write() is all the
// fastboot code needs to do.
TEST_F(UdpTest, ContinuationPackets) {
    for (uint16_t max_packet_size : {512, 1024, 1200}) {
        ASSERT_TRUE(InitializeTransport(0, max_packet_size));

        // Initialize the data we want to send. Use (size - 4) to leave room for the header.
        size_t max_data_size = max_packet_size - 4;
        std::string data(max_data_size * 3, '\0');
        for (size_t i = 0; i < data.length(); ++i) {
            data[i] = i;
        }
        std::string chunks[] = {data.substr(0, max_data_size),
                                data.substr(max_data_size, max_data_size),
                                data.substr(max_data_size * 2, max_data_size)};

        // Write data: split into 3 UDP packets, each of which will be ACKed.
        mock_socket_->ExpectSend(FastbootPacket(1, chunks[0], kFlagContinuation));
        mock_socket_->AddReceive(FastbootPacket(1));
        mock_socket_->ExpectSend(FastbootPacket(2, chunks[1], kFlagContinuation));
        mock_socket_->AddReceive(FastbootPacket(2));
        mock_socket_->ExpectSend(FastbootPacket(3, chunks[2]));
        mock_socket_->AddReceive(FastbootPacket(3));
        EXPECT_TRUE(Write(data));

        // Same thing for reading the data.
        mock_socket_->ExpectSend(FastbootPacket(4));
        mock_socket_->AddReceive(FastbootPacket(4, chunks[0], kFlagContinuation));
        mock_socket_->ExpectSend(FastbootPacket(5));
        mock_socket_->AddReceive(FastbootPacket(5, chunks[1], kFlagContinuation));
        mock_socket_->ExpectSend(FastbootPacket(6));
        mock_socket_->AddReceive(FastbootPacket(6, chunks[2]));
        EXPECT_TRUE(Read(data));
    }
}

// Tests that the continuation bit is respected even if the packet isn't max size.
TEST_F(UdpTest, SmallContinuationPackets) {
    mock_socket_->ExpectSend(FastbootPacket(1));
    mock_socket_->AddReceive(FastbootPacket(1, "foo", kFlagContinuation));
    mock_socket_->ExpectSend(FastbootPacket(2));
    mock_socket_->AddReceive(FastbootPacket(2, "bar"));

    EXPECT_TRUE(Read("foobar"));
}

// Tests receiving an error packet mid-continuation.
TEST_F(UdpTest, ContinuationPacketError) {
    mock_socket_->ExpectSend(FastbootPacket(1));
    mock_socket_->AddReceive(FastbootPacket(1, "foo", kFlagContinuation));
    mock_socket_->ExpectSend(FastbootPacket(2));
    mock_socket_->AddReceive(ErrorPacket(2, "test error"));

    EXPECT_FALSE(Read("foo"));
}

// Tests timeout during a continuation sequence.
TEST_F(UdpTest, ContinuationTimeoutRecovery) {
    mock_socket_->ExpectSend(FastbootPacket(1));
    mock_socket_->AddReceive(FastbootPacket(1, "foo", kFlagContinuation));
    mock_socket_->ExpectSend(FastbootPacket(2));
    mock_socket_->AddReceiveTimeout();
    mock_socket_->ExpectSend(FastbootPacket(2));
    mock_socket_->AddReceive(FastbootPacket(2, "bar"));

    EXPECT_TRUE(Read("foobar"));
}

// Tests read overflow returns -1 to indicate the failure.
TEST_F(UdpTest, MultipleReadPacket) {
    mock_socket_->ExpectSend(FastbootPacket(1));
    mock_socket_->AddReceive(FastbootPacket(1, "foobarbaz"));

    char buffer[3];
    EXPECT_EQ(-1, transport_->Read(buffer, 3));
}

// Tests that packets arriving out-of-order are ignored.
TEST_F(UdpTest, IgnoreOutOfOrderPackets) {
    mock_socket_->ExpectSend(FastbootPacket(1));
    mock_socket_->AddReceive(FastbootPacket(0, "sequence too low"));
    mock_socket_->AddReceive(FastbootPacket(2, "sequence too high"));
    mock_socket_->AddReceive(QueryPacket(1));
    mock_socket_->AddReceive(FastbootPacket(1, "correct"));

    EXPECT_TRUE(Read("correct"));
}

// Tests that an error response with the correct sequence number causes immediate failure.
TEST_F(UdpTest, ErrorResponse) {
    // Error packets with the wrong sequence number should be ignored like any other packet.
    mock_socket_->ExpectSend(FastbootPacket(1, "foo"));
    mock_socket_->AddReceive(ErrorPacket(0, "ignored error"));
    mock_socket_->AddReceive(FastbootPacket(1));

    EXPECT_TRUE(Write("foo"));

    // Error packets with the correct sequence should abort immediately without retransmission.
    mock_socket_->ExpectSend(FastbootPacket(2, "foo"));
    mock_socket_->AddReceive(ErrorPacket(2, "test error"));

    EXPECT_FALSE(Write("foo"));
}

// Tests that attempting to use a closed transport returns -1 without making any socket calls.
TEST_F(UdpTest, CloseTransport) {
    char buffer[32];
    EXPECT_EQ(0, transport_->Close());
    EXPECT_EQ(-1, transport_->Write("foo", 3));
    EXPECT_EQ(-1, transport_->Read(buffer, sizeof(buffer)));
}
