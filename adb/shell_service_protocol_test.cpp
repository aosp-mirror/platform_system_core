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

#include "shell_protocol.h"

#include <gtest/gtest.h>

#include <signal.h>
#include <string.h>

#include "sysdeps.h"

class ShellProtocolTest : public ::testing::Test {
  public:
    static void SetUpTestCase() {
#if !defined(_WIN32)
        // This is normally done in main.cpp.
        saved_sigpipe_handler_ = signal(SIGPIPE, SIG_IGN);
#endif
    }

    static void TearDownTestCase() {
#if !defined(_WIN32)
        signal(SIGPIPE, saved_sigpipe_handler_);
#endif
    }

    // Initializes the socketpair and ShellProtocols needed for testing.
    void SetUp() {
        int fds[2];
        ASSERT_EQ(0, adb_socketpair(fds));
        read_fd_ = fds[0];
        write_fd_ = fds[1];

        write_protocol_ = new ShellProtocol(write_fd_);
        ASSERT_TRUE(write_protocol_ != nullptr);

        read_protocol_ = new ShellProtocol(read_fd_);
        ASSERT_TRUE(read_protocol_ != nullptr);
    }

    // Cleans up FDs and ShellProtocols. If an FD is closed manually during a
    // test, set it to -1 to prevent TearDown() trying to close it again.
    void TearDown() {
        for (int fd : {read_fd_, write_fd_}) {
            if (fd >= 0) {
                adb_close(fd);
            }
        }
        for (ShellProtocol* protocol : {read_protocol_, write_protocol_}) {
            if (protocol) {
                delete protocol;
            }
        }
    }

    // Fakes the buffer size so we can test filling buffers.
    void SetReadDataCapacity(size_t size) {
        read_protocol_->buffer_end_ = read_protocol_->data() + size;
    }

#if !defined(_WIN32)
    static sig_t saved_sigpipe_handler_;
#endif

    int read_fd_ = -1, write_fd_ = -1;
    ShellProtocol *read_protocol_ = nullptr, *write_protocol_ = nullptr;
};

#if !defined(_WIN32)
sig_t ShellProtocolTest::saved_sigpipe_handler_ = nullptr;
#endif

namespace {

// Returns true if the packet contains the given values. `data` can't be null.
bool PacketEquals(const ShellProtocol* protocol, ShellProtocol::Id id,
                    const void* data, size_t data_length) {
    // Note that passing memcmp null is bad, even if data_length is 0.
    return (protocol->id() == id &&
            protocol->data_length() == data_length &&
            !memcmp(data, protocol->data(), data_length));
}

}  // namespace

// Tests data that can fit in a single packet.
TEST_F(ShellProtocolTest, FullPacket) {
    ShellProtocol::Id id = ShellProtocol::kIdStdout;
    char data[] = "abc 123 \0\r\n";

    memcpy(write_protocol_->data(), data, sizeof(data));
    ASSERT_TRUE(write_protocol_->Write(id, sizeof(data)));

    ASSERT_TRUE(read_protocol_->Read());
    ASSERT_TRUE(PacketEquals(read_protocol_, id, data, sizeof(data)));
}

// Tests data that has to be read multiple times due to smaller read buffer.
TEST_F(ShellProtocolTest, ReadBufferOverflow) {
    ShellProtocol::Id id = ShellProtocol::kIdStdin;

    memcpy(write_protocol_->data(), "1234567890", 10);
    ASSERT_TRUE(write_protocol_->Write(id, 10));

    SetReadDataCapacity(4);
    ASSERT_TRUE(read_protocol_->Read());
    ASSERT_TRUE(PacketEquals(read_protocol_, id, "1234", 4));
    ASSERT_TRUE(read_protocol_->Read());
    ASSERT_TRUE(PacketEquals(read_protocol_, id, "5678", 4));
    ASSERT_TRUE(read_protocol_->Read());
    ASSERT_TRUE(PacketEquals(read_protocol_, id, "90", 2));
}

// Tests a zero length packet.
TEST_F(ShellProtocolTest, ZeroLengthPacket) {
    ShellProtocol::Id id = ShellProtocol::kIdStderr;

    ASSERT_TRUE(write_protocol_->Write(id, 0));
    ASSERT_TRUE(read_protocol_->Read());
    char buf[1];
    ASSERT_TRUE(PacketEquals(read_protocol_, id, buf, 0));
}

// Tests exit code packets.
TEST_F(ShellProtocolTest, ExitCodePacket) {
    write_protocol_->data()[0] = 20;
    ASSERT_TRUE(write_protocol_->Write(ShellProtocol::kIdExit, 1));

    ASSERT_TRUE(read_protocol_->Read());
    ASSERT_EQ(ShellProtocol::kIdExit, read_protocol_->id());
    ASSERT_EQ(20, read_protocol_->data()[0]);
}

// Tests writing to a closed pipe.
TEST_F(ShellProtocolTest, WriteToClosedPipeFail) {
    adb_close(read_fd_);
    read_fd_ = -1;

    ASSERT_FALSE(write_protocol_->Write(ShellProtocol::kIdStdout, 0));
}

// Tests writing to a closed FD.
TEST_F(ShellProtocolTest, WriteToClosedFdFail) {
    adb_close(write_fd_);
    write_fd_ = -1;

    ASSERT_FALSE(write_protocol_->Write(ShellProtocol::kIdStdout, 0));
}

// Tests reading from a closed pipe.
TEST_F(ShellProtocolTest, ReadFromClosedPipeFail) {
    adb_close(write_fd_);
    write_fd_ = -1;

    ASSERT_FALSE(read_protocol_->Read());
}

// Tests reading from a closed FD.
TEST_F(ShellProtocolTest, ReadFromClosedFdFail) {
    adb_close(read_fd_);
    read_fd_ = -1;

    ASSERT_FALSE(read_protocol_->Read());
}

// Tests reading from a closed pipe that has a packet waiting. This checks that
// even if the pipe closes before we can fully read its contents we will still
// be able to access the last packets.
TEST_F(ShellProtocolTest, ReadPacketFromClosedPipe) {
    ShellProtocol::Id id = ShellProtocol::kIdStdout;
    char data[] = "foo bar";

    memcpy(write_protocol_->data(), data, sizeof(data));
    ASSERT_TRUE(write_protocol_->Write(id, sizeof(data)));
    adb_close(write_fd_);
    write_fd_ = -1;

    // First read should grab the packet.
    ASSERT_TRUE(read_protocol_->Read());
    ASSERT_TRUE(PacketEquals(read_protocol_, id, data, sizeof(data)));

    // Second read should fail.
    ASSERT_FALSE(read_protocol_->Read());
}
