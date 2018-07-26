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

#include "shell_service.h"

#include <gtest/gtest.h>

#include <signal.h>

#include <string>
#include <vector>

#include <android-base/strings.h>

#include "adb.h"
#include "adb_io.h"
#include "shell_protocol.h"
#include "sysdeps.h"

class ShellServiceTest : public ::testing::Test {
  public:
    static void SetUpTestCase() {
        // This is normally done in main.cpp.
        saved_sigpipe_handler_ = signal(SIGPIPE, SIG_IGN);

    }

    static void TearDownTestCase() {
        signal(SIGPIPE, saved_sigpipe_handler_);
    }

    // Helpers to start and cleanup a subprocess. Cleanup normally does not
    // need to be called manually unless multiple subprocesses are run from
    // a single test.
    void StartTestSubprocess(const char* command, SubprocessType type,
                             SubprocessProtocol protocol);
    void CleanupTestSubprocess();

    virtual void TearDown() override {
        void CleanupTestSubprocess();
    }

    static sighandler_t saved_sigpipe_handler_;

    int subprocess_fd_ = -1;
};

sighandler_t ShellServiceTest::saved_sigpipe_handler_ = nullptr;

void ShellServiceTest::StartTestSubprocess(
        const char* command, SubprocessType type, SubprocessProtocol protocol) {
    subprocess_fd_ = StartSubprocess(command, nullptr, type, protocol);
    ASSERT_TRUE(subprocess_fd_ >= 0);
}

void ShellServiceTest::CleanupTestSubprocess() {
    if (subprocess_fd_ >= 0) {
        adb_close(subprocess_fd_);
        subprocess_fd_ = -1;
    }
}

namespace {

// Reads raw data from |fd| until it closes or errors.
std::string ReadRaw(int fd) {
    char buffer[1024];
    char *cur_ptr = buffer, *end_ptr = buffer + sizeof(buffer);

    while (1) {
        int bytes = adb_read(fd, cur_ptr, end_ptr - cur_ptr);
        if (bytes <= 0) {
            return std::string(buffer, cur_ptr);
        }
        cur_ptr += bytes;
    }
}

// Reads shell protocol data from |fd| until it closes or errors. Fills
// |stdout| and |stderr| with their respective data, and returns the exit code
// read from the protocol or -1 if an exit code packet was not received.
int ReadShellProtocol(int fd, std::string* stdout, std::string* stderr) {
    int exit_code = -1;
    stdout->clear();
    stderr->clear();

    ShellProtocol* protocol = new ShellProtocol(fd);
    while (protocol->Read()) {
        switch (protocol->id()) {
            case ShellProtocol::kIdStdout:
                stdout->append(protocol->data(), protocol->data_length());
                break;
            case ShellProtocol::kIdStderr:
                stderr->append(protocol->data(), protocol->data_length());
                break;
            case ShellProtocol::kIdExit:
                EXPECT_EQ(-1, exit_code) << "Multiple exit packets received";
                EXPECT_EQ(1u, protocol->data_length());
                exit_code = protocol->data()[0];
                break;
            default:
                ADD_FAILURE() << "Unidentified packet ID: " << protocol->id();
        }
    }
    delete protocol;

    return exit_code;
}

// Checks if each line in |lines| exists in the same order in |output|. Blank
// lines in |output| are ignored for simplicity.
bool ExpectLinesEqual(const std::string& output,
                      const std::vector<std::string>& lines) {
    auto output_lines = android::base::Split(output, "\r\n");
    size_t i = 0;

    for (const std::string& line : lines) {
        // Skip empty lines in output.
        while (i < output_lines.size() && output_lines[i].empty()) {
            ++i;
        }
        if (i >= output_lines.size()) {
            ADD_FAILURE() << "Ran out of output lines";
            return false;
        }
        EXPECT_EQ(line, output_lines[i]);
        ++i;
    }

    while (i < output_lines.size() && output_lines[i].empty()) {
        ++i;
    }
    EXPECT_EQ(i, output_lines.size()) << "Found unmatched output lines";
    return true;
}

}  // namespace

// Tests a raw subprocess with no protocol.
TEST_F(ShellServiceTest, RawNoProtocolSubprocess) {
    // [ -t 0 ] checks if stdin is connected to a terminal.
    ASSERT_NO_FATAL_FAILURE(StartTestSubprocess(
            "echo foo; echo bar >&2; [ -t 0 ]; echo $?",
            SubprocessType::kRaw, SubprocessProtocol::kNone));

    // [ -t 0 ] == 0 means we have a terminal (PTY). Even when requesting a raw subprocess, without
    // the shell protocol we should always force a PTY to ensure proper cleanup.
    ExpectLinesEqual(ReadRaw(subprocess_fd_), {"foo", "bar", "0"});
}

// Tests a PTY subprocess with no protocol.
TEST_F(ShellServiceTest, PtyNoProtocolSubprocess) {
    // [ -t 0 ] checks if stdin is connected to a terminal.
    ASSERT_NO_FATAL_FAILURE(StartTestSubprocess(
            "echo foo; echo bar >&2; [ -t 0 ]; echo $?",
            SubprocessType::kPty, SubprocessProtocol::kNone));

    // [ -t 0 ] == 0 means we have a terminal (PTY).
    ExpectLinesEqual(ReadRaw(subprocess_fd_), {"foo", "bar", "0"});
}

// Tests a raw subprocess with the shell protocol.
TEST_F(ShellServiceTest, RawShellProtocolSubprocess) {
    ASSERT_NO_FATAL_FAILURE(StartTestSubprocess(
            "echo foo; echo bar >&2; echo baz; exit 24",
            SubprocessType::kRaw, SubprocessProtocol::kShell));

    std::string stdout, stderr;
    EXPECT_EQ(24, ReadShellProtocol(subprocess_fd_, &stdout, &stderr));
    ExpectLinesEqual(stdout, {"foo", "baz"});
    ExpectLinesEqual(stderr, {"bar"});
}

// Tests a PTY subprocess with the shell protocol.
TEST_F(ShellServiceTest, PtyShellProtocolSubprocess) {
    ASSERT_NO_FATAL_FAILURE(StartTestSubprocess(
            "echo foo; echo bar >&2; echo baz; exit 50",
            SubprocessType::kPty, SubprocessProtocol::kShell));

    // PTY always combines stdout and stderr but the shell protocol should
    // still give us an exit code.
    std::string stdout, stderr;
    EXPECT_EQ(50, ReadShellProtocol(subprocess_fd_, &stdout, &stderr));
    ExpectLinesEqual(stdout, {"foo", "bar", "baz"});
    ExpectLinesEqual(stderr, {});
}

// Tests an interactive PTY session.
TEST_F(ShellServiceTest, InteractivePtySubprocess) {
    ASSERT_NO_FATAL_FAILURE(StartTestSubprocess(
            "", SubprocessType::kPty, SubprocessProtocol::kShell));

    // Use variable substitution so echoed input is different from output.
    const char* commands[] = {"TEST_STR=abc123",
                              "echo --${TEST_STR}--",
                              "exit"};

    ShellProtocol* protocol = new ShellProtocol(subprocess_fd_);
    for (std::string command : commands) {
        // Interactive shell requires a newline to complete each command.
        command.push_back('\n');
        memcpy(protocol->data(), command.data(), command.length());
        ASSERT_TRUE(protocol->Write(ShellProtocol::kIdStdin, command.length()));
    }
    delete protocol;

    std::string stdout, stderr;
    EXPECT_EQ(0, ReadShellProtocol(subprocess_fd_, &stdout, &stderr));
    // An unpredictable command prompt makes parsing exact output difficult but
    // it should at least contain echoed input and the expected output.
    for (const char* command : commands) {
        EXPECT_FALSE(stdout.find(command) == std::string::npos);
    }
    EXPECT_FALSE(stdout.find("--abc123--") == std::string::npos);
}

// Tests closing raw subprocess stdin.
TEST_F(ShellServiceTest, CloseClientStdin) {
    ASSERT_NO_FATAL_FAILURE(StartTestSubprocess(
            "cat; echo TEST_DONE",
            SubprocessType::kRaw, SubprocessProtocol::kShell));

    std::string input = "foo\nbar";
    ShellProtocol* protocol = new ShellProtocol(subprocess_fd_);
    memcpy(protocol->data(), input.data(), input.length());
    ASSERT_TRUE(protocol->Write(ShellProtocol::kIdStdin, input.length()));
    ASSERT_TRUE(protocol->Write(ShellProtocol::kIdCloseStdin, 0));
    delete protocol;

    std::string stdout, stderr;
    EXPECT_EQ(0, ReadShellProtocol(subprocess_fd_, &stdout, &stderr));
    ExpectLinesEqual(stdout, {"foo", "barTEST_DONE"});
    ExpectLinesEqual(stderr, {});
}

// Tests that nothing breaks when the stdin/stdout pipe closes.
TEST_F(ShellServiceTest, CloseStdinStdoutSubprocess) {
    ASSERT_NO_FATAL_FAILURE(StartTestSubprocess(
            "exec 0<&-; exec 1>&-; echo bar >&2",
            SubprocessType::kRaw, SubprocessProtocol::kShell));

    std::string stdout, stderr;
    EXPECT_EQ(0, ReadShellProtocol(subprocess_fd_, &stdout, &stderr));
    ExpectLinesEqual(stdout, {});
    ExpectLinesEqual(stderr, {"bar"});
}

// Tests that nothing breaks when the stderr pipe closes.
TEST_F(ShellServiceTest, CloseStderrSubprocess) {
    ASSERT_NO_FATAL_FAILURE(StartTestSubprocess(
            "exec 2>&-; echo foo",
            SubprocessType::kRaw, SubprocessProtocol::kShell));

    std::string stdout, stderr;
    EXPECT_EQ(0, ReadShellProtocol(subprocess_fd_, &stdout, &stderr));
    ExpectLinesEqual(stdout, {"foo"});
    ExpectLinesEqual(stderr, {});
}
