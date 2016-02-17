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

#include "tcp.h"

#include <gtest/gtest.h>

#include "socket_mock.h"

TEST(TcpConnectTest, TestSuccess) {
    std::unique_ptr<SocketMock> mock(new SocketMock);
    mock->ExpectSend("FB01");
    mock->AddReceive("FB01");

    std::string error;
    EXPECT_NE(nullptr, tcp::internal::Connect(std::move(mock), &error));
    EXPECT_EQ("", error);
}

TEST(TcpConnectTest, TestNewerVersionSuccess) {
    std::unique_ptr<SocketMock> mock(new SocketMock);
    mock->ExpectSend("FB01");
    mock->AddReceive("FB99");

    std::string error;
    EXPECT_NE(nullptr, tcp::internal::Connect(std::move(mock), &error));
    EXPECT_EQ("", error);
}

TEST(TcpConnectTest, TestSendFailure) {
    std::unique_ptr<SocketMock> mock(new SocketMock);
    mock->ExpectSendFailure("FB01");

    std::string error;
    EXPECT_EQ(nullptr, tcp::internal::Connect(std::move(mock), &error));
    EXPECT_NE(std::string::npos, error.find("Failed to send initialization message"));
}

TEST(TcpConnectTest, TestNoResponseFailure) {
    std::unique_ptr<SocketMock> mock(new SocketMock);
    mock->ExpectSend("FB01");
    mock->AddReceiveFailure();

    std::string error;
    EXPECT_EQ(nullptr, tcp::internal::Connect(std::move(mock), &error));
    EXPECT_NE(std::string::npos, error.find("No initialization message received"));
}

TEST(TcpConnectTest, TestBadResponseFailure) {
    std::unique_ptr<SocketMock> mock(new SocketMock);
    mock->ExpectSend("FB01");
    mock->AddReceive("XX01");

    std::string error;
    EXPECT_EQ(nullptr, tcp::internal::Connect(std::move(mock), &error));
    EXPECT_NE(std::string::npos, error.find("Unrecognized initialization message"));
}

TEST(TcpConnectTest, TestUnknownVersionFailure) {
    std::unique_ptr<SocketMock> mock(new SocketMock);
    mock->ExpectSend("FB01");
    mock->AddReceive("FB00");

    std::string error;
    EXPECT_EQ(nullptr, tcp::internal::Connect(std::move(mock), &error));
    EXPECT_EQ("Unknown TCP protocol version 00 (host version 01)", error);
}

// Fixture to configure a SocketMock for a successful TCP connection.
class TcpTest : public ::testing::Test {
  protected:
    void SetUp() override {
        mock_ = new SocketMock;
        mock_->ExpectSend("FB01");
        mock_->AddReceive("FB01");

        std::string error;
        transport_ = tcp::internal::Connect(std::unique_ptr<Socket>(mock_), &error);
        ASSERT_NE(nullptr, transport_);
        ASSERT_EQ("", error);
    };

    // Writes |message| to |transport_|, returns true on success.
    bool Write(const std::string& message) {
        return transport_->Write(message.data(), message.length()) ==
               static_cast<ssize_t>(message.length());
    }

    // Reads from |transport_|, returns true if it matches |message|.
    bool Read(const std::string& message) {
        std::string buffer(message.length(), '\0');
        return transport_->Read(&buffer[0], buffer.length()) ==
                       static_cast<ssize_t>(message.length()) &&
               buffer == message;
    }

    // Use a raw SocketMock* here because we pass ownership to the Transport object, but we still
    // need access to configure mock expectations.
    SocketMock* mock_ = nullptr;
    std::unique_ptr<Transport> transport_;
};

TEST_F(TcpTest, TestWriteSuccess) {
    mock_->ExpectSend(std::string{0, 0, 0, 0, 0, 0, 0, 3} + "foo");

    EXPECT_TRUE(Write("foo"));
}

TEST_F(TcpTest, TestReadSuccess) {
    mock_->AddReceive(std::string{0, 0, 0, 0, 0, 0, 0, 3});
    mock_->AddReceive("foo");

    EXPECT_TRUE(Read("foo"));
}

// Tests that fragmented TCP reads are handled properly.
TEST_F(TcpTest, TestReadFragmentSuccess) {
    mock_->AddReceive(std::string{0, 0, 0, 0});
    mock_->AddReceive(std::string{0, 0, 0, 3});
    mock_->AddReceive("f");
    mock_->AddReceive("o");
    mock_->AddReceive("o");

    EXPECT_TRUE(Read("foo"));
}

TEST_F(TcpTest, TestLargeWriteSuccess) {
    // 0x100000 = 1MiB.
    std::string data(0x100000, '\0');
    for (size_t i = 0; i < data.length(); ++i) {
        data[i] = i;
    }
    mock_->ExpectSend(std::string{0, 0, 0, 0, 0, 0x10, 0, 0} + data);

    EXPECT_TRUE(Write(data));
}

TEST_F(TcpTest, TestLargeReadSuccess) {
    // 0x100000 = 1MiB.
    std::string data(0x100000, '\0');
    for (size_t i = 0; i < data.length(); ++i) {
        data[i] = i;
    }
    mock_->AddReceive(std::string{0, 0, 0, 0, 0, 0x10, 0, 0});
    mock_->AddReceive(data);

    EXPECT_TRUE(Read(data));
}

// Tests a few sample fastboot protocol commands.
TEST_F(TcpTest, TestFastbootProtocolSuccess) {
    mock_->ExpectSend(std::string{0, 0, 0, 0, 0, 0, 0, 14} + "getvar:version");
    mock_->AddReceive(std::string{0, 0, 0, 0, 0, 0, 0, 7});
    mock_->AddReceive("OKAY0.4");

    mock_->ExpectSend(std::string{0, 0, 0, 0, 0, 0, 0, 10} + "getvar:all");
    mock_->AddReceive(std::string{0, 0, 0, 0, 0, 0, 0, 16});
    mock_->AddReceive("INFOversion: 0.4");
    mock_->AddReceive(std::string{0, 0, 0, 0, 0, 0, 0, 12});
    mock_->AddReceive("INFOfoo: bar");
    mock_->AddReceive(std::string{0, 0, 0, 0, 0, 0, 0, 4});
    mock_->AddReceive("OKAY");

    EXPECT_TRUE(Write("getvar:version"));
    EXPECT_TRUE(Read("OKAY0.4"));

    EXPECT_TRUE(Write("getvar:all"));
    EXPECT_TRUE(Read("INFOversion: 0.4"));
    EXPECT_TRUE(Read("INFOfoo: bar"));
    EXPECT_TRUE(Read("OKAY"));
}

TEST_F(TcpTest, TestReadLengthFailure) {
    mock_->AddReceiveFailure();

    char buffer[16];
    EXPECT_EQ(-1, transport_->Read(buffer, sizeof(buffer)));
}

TEST_F(TcpTest, TestReadDataFailure) {
    mock_->AddReceive(std::string{0, 0, 0, 0, 0, 0, 0, 3});
    mock_->AddReceiveFailure();

    char buffer[16];
    EXPECT_EQ(-1, transport_->Read(buffer, sizeof(buffer)));
}

TEST_F(TcpTest, TestWriteFailure) {
    mock_->ExpectSendFailure(std::string{0, 0, 0, 0, 0, 0, 0, 3} + "foo");

    EXPECT_EQ(-1, transport_->Write("foo", 3));
}

TEST_F(TcpTest, TestTransportClose) {
    EXPECT_EQ(0, transport_->Close());

    // After closing, Transport Read()/Write() should return -1 without actually attempting any
    // network operations.
    char buffer[16];
    EXPECT_EQ(-1, transport_->Read(buffer, sizeof(buffer)));
    EXPECT_EQ(-1, transport_->Write("foo", 3));
}
