/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include <sysutils/FrameworkListener.h>

#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <algorithm>
#include <memory>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <cutils/sockets.h>
#include <gtest/gtest.h>

using android::base::unique_fd;

namespace {

std::string testSocketPath() {
    const testing::TestInfo* const test_info =
            testing::UnitTest::GetInstance()->current_test_info();
    return std::string(ANDROID_SOCKET_DIR "/") + std::string(test_info->test_case_name()) +
           std::string(".") + std::string(test_info->name());
}

unique_fd serverSocket(const std::string& path) {
    unlink(path.c_str());

    unique_fd fd(socket(PF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0));
    EXPECT_GE(fd.get(), 0);

    struct sockaddr_un addr = {.sun_family = AF_UNIX};
    strlcpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path));

    EXPECT_EQ(bind(fd.get(), reinterpret_cast<sockaddr*>(&addr), sizeof(addr)), 0)
            << "bind() to " << path << " failed: " << strerror(errno);
    EXPECT_EQ(android_get_control_socket(path.c_str()), -1);

    return fd;
}

unique_fd clientSocket(const std::string& path) {
    unique_fd fd(socket(PF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0));
    EXPECT_GE(fd.get(), 0);

    struct sockaddr_un addr = {.sun_family = AF_UNIX};
    strlcpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path));

    EXPECT_EQ(0, connect(fd.get(), reinterpret_cast<sockaddr*>(&addr), sizeof(addr)))
            << "connect() to " << path << " failed: " << strerror(errno);

    return fd;
}

void sendCmd(int fd, const char* cmd) {
    EXPECT_TRUE(android::base::WriteFully(fd, cmd, strlen(cmd) + 1))
            << "write() to socket failed: " << strerror(errno);
}

std::string recvReply(int fd) {
    pollfd fds = {.fd = fd, .events = POLLIN};
    int poll_events = poll(&fds, 1, -1);
    EXPECT_EQ(1, poll_events);

    // Technically, this one-shot read() is incorrect: we should keep on
    // reading the socket until we get a \0. But this is also how
    // FrameworkListener::onDataAvailable() reads, and it works because
    // replies are always send with a single write() call, and clients
    // always read replies before queueing the next command.
    char buf[1024];
    ssize_t len = read(fd, buf, sizeof(buf));
    EXPECT_GE(len, 0) << "read() from socket failed: " << strerror(errno);
    return len > 0 ? std::string(buf, buf + len) : "";
}

// Test command which echoes back all its arguments as a comma-separated list.
// Always returns error code 42
//
// TODO: enable testing replies with addErrno=true and useCmdNum=true
class TestCommand : public FrameworkCommand {
  public:
    TestCommand() : FrameworkCommand("test") {}
    ~TestCommand() override {}

    int runCommand(SocketClient* cli, int argc, char** argv) {
        std::vector<std::string> args(argv, argv + argc);
        std::string reply = android::base::Join(args, ',');
        cli->sendMsg(42, reply.c_str(), /*addErrno=*/false, /*useCmdNum=*/false);
        return 0;
    }
};

// A test listener with a single command.
class TestListener : public FrameworkListener {
  public:
    TestListener(int fd) : FrameworkListener(fd) {
        registerCmd(new TestCommand);  // Leaked :-(
    }
};

}  // unnamed namespace

class FrameworkListenerTest : public testing::Test {
  public:
    FrameworkListenerTest() {
        mSocketPath = testSocketPath();
        mSserverFd = serverSocket(mSocketPath);
        mListener = std::make_unique<TestListener>(mSserverFd.get());
        EXPECT_EQ(0, mListener->startListener());
    }

    ~FrameworkListenerTest() override {
        EXPECT_EQ(0, mListener->stopListener());

        // Wouldn't it be cool if unique_fd had an option for taking care of this?
        unlink(mSocketPath.c_str());
    }

    void testCommand(const char* command, const char* expected) {
        unique_fd client_fd = clientSocket(mSocketPath);
        sendCmd(client_fd.get(), command);

        std::string reply = recvReply(client_fd.get());
        EXPECT_EQ(std::string(expected) + '\0', reply);
    }

  protected:
    std::string mSocketPath;
    unique_fd mSserverFd;
    std::unique_ptr<TestListener> mListener;
};

TEST_F(FrameworkListenerTest, DoesNothing) {
    // Let the test harness start and stop a FrameworkListener
    // without sending any commands through it.
}

TEST_F(FrameworkListenerTest, DispatchesValidCommands) {
    testCommand("test", "42 test");
    testCommand("test arg1 arg2", "42 test,arg1,arg2");
    testCommand("test \"arg1 still_arg1\" arg2", "42 test,arg1 still_arg1,arg2");
    testCommand("test \"escaped quote: '\\\"'\"", "42 test,escaped quote: '\"'");

    // Perhaps this behavior was unintended, but would be good to detect any
    // changes, in case anyone depends on it.
    testCommand("test   ", "42 test,,,");
}

TEST_F(FrameworkListenerTest, RejectsInvalidCommands) {
    testCommand("unknown arg1 arg2", "500 Command not recognized");
    testCommand("test \"arg1 arg2", "500 Unclosed quotes error");
    testCommand("test \\a", "500 Unsupported escape sequence");
}
