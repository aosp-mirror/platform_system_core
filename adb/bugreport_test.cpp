/*
 * Copyright (C) 2016 The Android Open Source Project
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

#include "bugreport.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

using ::testing::_;
using ::testing::DoAll;
using ::testing::ElementsAre;
using ::testing::HasSubstr;
using ::testing::Return;
using ::testing::SetArgPointee;
using ::testing::StrEq;
using ::testing::internal::CaptureStderr;
using ::testing::internal::GetCapturedStderr;

// Empty function so tests don't need to be linked against
// file_sync_service.cpp, which requires
// SELinux and its transitive dependencies...
bool do_sync_pull(const std::vector<const char*>& srcs, const char* dst, bool copy_attrs,
                  const char* name) {
    ADD_FAILURE() << "do_sync_pull() should have been mocked";
    return false;
}

// Implemented in commandline.cpp
int usage() {
    return -42;
}

// Implemented in commandline.cpp
int send_shell_command(TransportType transport_type, const char* serial, const std::string& command,
                       bool disable_shell_protocol, std::string* output, std::string* err) {
    ADD_FAILURE() << "send_shell_command() should have been mocked";
    return -42;
}

class BugreportMock : public Bugreport {
  public:
    MOCK_METHOD6(SendShellCommand,
                 int(TransportType transport_type, const char* serial, const std::string& command,
                     bool disable_shell_protocol, std::string* output, std::string* err));
    MOCK_METHOD4(DoSyncPull, bool(const std::vector<const char*>& srcs, const char* dst,
                                  bool copy_attrs, const char* name));
};

class BugreportTest : public ::testing::Test {
  public:
    BugreportMock br_;
};

// Tests when called with invalid number of argumnts
TEST_F(BugreportTest, InvalidNumberArgs) {
    const char* args[1024] = {"bugreport", "to", "principal"};
    ASSERT_EQ(-42, br_.DoIt(kTransportLocal, "HannibalLecter", 3, args));
}

// Tests the legacy 'adb bugreport' option
TEST_F(BugreportTest, FlatFileFormat) {
    EXPECT_CALL(br_, SendShellCommand(kTransportLocal, "HannibalLecter", "bugreport", false,
                                      nullptr, nullptr))
        .WillOnce(Return(0));

    const char* args[1024] = {"bugreport"};
    ASSERT_EQ(0, br_.DoIt(kTransportLocal, "HannibalLecter", 1, args));
}

// Tests 'adb bugreport file.zip' when it succeeds
TEST_F(BugreportTest, Ok) {
    EXPECT_CALL(
        br_, SendShellCommand(kTransportLocal, "HannibalLecter", "bugreportz", false, _, nullptr))
        .WillOnce(DoAll(SetArgPointee<4>("OK:/device/bugreport.zip"), Return(0)));
    EXPECT_CALL(br_, DoSyncPull(ElementsAre(StrEq("/device/bugreport.zip")), StrEq("file.zip"),
                                true, StrEq("file.zip")))
        .WillOnce(Return(true));

    const char* args[1024] = {"bugreport", "file.zip"};
    ASSERT_EQ(0, br_.DoIt(kTransportLocal, "HannibalLecter", 2, args));
}

// Tests 'adb bugreport file' when it succeeds
TEST_F(BugreportTest, OkNoExtension) {
    EXPECT_CALL(
        br_, SendShellCommand(kTransportLocal, "HannibalLecter", "bugreportz", false, _, nullptr))
        .WillOnce(DoAll(SetArgPointee<4>("OK:/device/bugreport.zip"), Return(0)));
    EXPECT_CALL(br_, DoSyncPull(ElementsAre(StrEq("/device/bugreport.zip")), StrEq("file.zip"),
                                true, StrEq("file.zip")))
        .WillOnce(Return(true));

    const char* args[1024] = {"bugreport", "file"};
    ASSERT_EQ(0, br_.DoIt(kTransportLocal, "HannibalLecter", 2, args));
}

// Tests 'adb bugreport file.zip' when the bugreport itself failed
TEST_F(BugreportTest, BugreportzReturnedFail) {
    EXPECT_CALL(
        br_, SendShellCommand(kTransportLocal, "HannibalLecter", "bugreportz", false, _, nullptr))
        .WillOnce(DoAll(SetArgPointee<4>("FAIL:D'OH!"), Return(0)));

    CaptureStderr();
    const char* args[1024] = {"bugreport", "file.zip"};
    ASSERT_EQ(-1, br_.DoIt(kTransportLocal, "HannibalLecter", 2, args));
    ASSERT_THAT(GetCapturedStderr(), HasSubstr("D'OH"));
}

// Tests 'adb bugreport file.zip' when the bugreportz returned an unsupported
// response.
TEST_F(BugreportTest, BugreportzReturnedUnsupported) {
    EXPECT_CALL(
        br_, SendShellCommand(kTransportLocal, "HannibalLecter", "bugreportz", false, _, nullptr))
        .WillOnce(DoAll(SetArgPointee<4>("bugreportz? What am I, a zombie?"), Return(0)));

    CaptureStderr();
    const char* args[1024] = {"bugreport", "file.zip"};
    ASSERT_EQ(-1, br_.DoIt(kTransportLocal, "HannibalLecter", 2, args));
    ASSERT_THAT(GetCapturedStderr(), HasSubstr("bugreportz? What am I, a zombie?"));
}

// Tests 'adb bugreport file.zip' when the bugreportz command fails
TEST_F(BugreportTest, BugreportzFailed) {
    EXPECT_CALL(
        br_, SendShellCommand(kTransportLocal, "HannibalLecter", "bugreportz", false, _, nullptr))
        .WillOnce(Return(666));

    const char* args[1024] = {"bugreport", "file.zip"};
    ASSERT_EQ(666, br_.DoIt(kTransportLocal, "HannibalLecter", 2, args));
}

// Tests 'adb bugreport file.zip' when the bugreport could not be pulled
TEST_F(BugreportTest, PullFails) {
    EXPECT_CALL(
        br_, SendShellCommand(kTransportLocal, "HannibalLecter", "bugreportz", false, _, nullptr))
        .WillOnce(DoAll(SetArgPointee<4>("OK:/device/bugreport.zip"), Return(0)));
    EXPECT_CALL(br_, DoSyncPull(ElementsAre(StrEq("/device/bugreport.zip")), StrEq("file.zip"),
                                true, StrEq("file.zip")))
        .WillOnce(Return(false));

    const char* args[1024] = {"bugreport", "file.zip"};
    ASSERT_EQ(1, br_.DoIt(kTransportLocal, "HannibalLecter", 2, args));
}
