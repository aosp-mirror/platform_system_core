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
using ::testing::Action;
using ::testing::ActionInterface;
using ::testing::DoAll;
using ::testing::ElementsAre;
using ::testing::HasSubstr;
using ::testing::MakeAction;
using ::testing::Return;
using ::testing::StrEq;
using ::testing::WithArg;
using ::testing::internal::CaptureStderr;
using ::testing::internal::GetCapturedStderr;

// Empty function so tests don't need to be linked against file_sync_service.cpp, which requires
// SELinux and its transitive dependencies...
bool do_sync_pull(const std::vector<const char*>& srcs, const char* dst, bool copy_attrs,
                  const char* name) {
    ADD_FAILURE() << "do_sync_pull() should have been mocked";
    return false;
}

// Empty functions so tests don't need to be linked against commandline.cpp
DefaultStandardStreamsCallback DEFAULT_STANDARD_STREAMS_CALLBACK(nullptr, nullptr);
int usage() {
    return -42;
}
int send_shell_command(TransportType transport_type, const char* serial, const std::string& command,
                       bool disable_shell_protocol, StandardStreamsCallbackInterface* callback) {
    ADD_FAILURE() << "send_shell_command() should have been mocked";
    return -42;
}

// gmock black magic to provide a WithArg<4>(WriteOnStdout(output)) matcher
typedef void OnStandardStreamsCallbackFunction(StandardStreamsCallbackInterface*);

class OnStandardStreamsCallbackAction : public ActionInterface<OnStandardStreamsCallbackFunction> {
  public:
    explicit OnStandardStreamsCallbackAction(const std::string& output) : output_(output) {
    }
    virtual Result Perform(const ArgumentTuple& args) {
        ::std::tr1::get<0>(args)->OnStdout(output_.c_str(), output_.size());
    }

  private:
    std::string output_;
};

Action<OnStandardStreamsCallbackFunction> WriteOnStdout(const std::string& output) {
    return MakeAction(new OnStandardStreamsCallbackAction(output));
}

typedef int CallbackDoneFunction(StandardStreamsCallbackInterface*);

class CallbackDoneAction : public ActionInterface<CallbackDoneFunction> {
  public:
    virtual Result Perform(const ArgumentTuple& args) {
        int status = ::std::tr1::get<0>(args)->Done(123);  // Value passed does not matter
        return status;
    }
};

Action<CallbackDoneFunction> ReturnCallbackDone() {
    return MakeAction(new CallbackDoneAction());
}

class BugreportMock : public Bugreport {
  public:
    MOCK_METHOD5(SendShellCommand,
                 int(TransportType transport_type, const char* serial, const std::string& command,
                     bool disable_shell_protocol, StandardStreamsCallbackInterface* callback));
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
    EXPECT_CALL(br_, SendShellCommand(kTransportLocal, "HannibalLecter", "bugreport", false, _))
        .WillOnce(Return(0));

    const char* args[1024] = {"bugreport"};
    ASSERT_EQ(0, br_.DoIt(kTransportLocal, "HannibalLecter", 1, args));
}

// Tests 'adb bugreport file.zip' when it succeeds
TEST_F(BugreportTest, Ok) {
    EXPECT_CALL(br_, SendShellCommand(kTransportLocal, "HannibalLecter", "bugreportz", false, _))
        .WillOnce(DoAll(WithArg<4>(WriteOnStdout("OK:/device/bugreport.zip")),
                        WithArg<4>(ReturnCallbackDone())));
    EXPECT_CALL(br_, DoSyncPull(ElementsAre(StrEq("/device/bugreport.zip")), StrEq("file.zip"),
                                true, StrEq("file.zip")))
        .WillOnce(Return(true));

    const char* args[1024] = {"bugreport", "file.zip"};
    ASSERT_EQ(0, br_.DoIt(kTransportLocal, "HannibalLecter", 2, args));
}

// Tests 'adb bugreport file' when it succeeds
TEST_F(BugreportTest, OkNoExtension) {
    EXPECT_CALL(br_, SendShellCommand(kTransportLocal, "HannibalLecter", "bugreportz", false, _))
        .WillOnce(DoAll(WithArg<4>(WriteOnStdout("OK:/device/bugreport.zip")),
                        WithArg<4>(ReturnCallbackDone())));
    EXPECT_CALL(br_, DoSyncPull(ElementsAre(StrEq("/device/bugreport.zip")), StrEq("file.zip"),
                                true, StrEq("file.zip")))
        .WillOnce(Return(true));

    const char* args[1024] = {"bugreport", "file"};
    ASSERT_EQ(0, br_.DoIt(kTransportLocal, "HannibalLecter", 2, args));
}

// Tests 'adb bugreport file.zip' when it succeeds but response was sent in
// multiple buffer writers.
TEST_F(BugreportTest, OkSplitBuffer) {
    EXPECT_CALL(br_, SendShellCommand(kTransportLocal, "HannibalLecter", "bugreportz", false, _))
        .WillOnce(DoAll(WithArg<4>(WriteOnStdout("OK:/device")),
                        WithArg<4>(WriteOnStdout("/bugreport.zip")),
                        WithArg<4>(ReturnCallbackDone())));
    EXPECT_CALL(br_, DoSyncPull(ElementsAre(StrEq("/device/bugreport.zip")), StrEq("file.zip"),
                                true, StrEq("file.zip")))
        .WillOnce(Return(true));

    const char* args[1024] = {"bugreport", "file.zip"};
    ASSERT_EQ(0, br_.DoIt(kTransportLocal, "HannibalLecter", 2, args));
}

// Tests 'adb bugreport file.zip' when the bugreport itself failed
TEST_F(BugreportTest, BugreportzReturnedFail) {
    EXPECT_CALL(br_, SendShellCommand(kTransportLocal, "HannibalLecter", "bugreportz", false, _))
        .WillOnce(DoAll(WithArg<4>(WriteOnStdout("FAIL:D'OH!")), WithArg<4>(ReturnCallbackDone())));

    CaptureStderr();
    const char* args[1024] = {"bugreport", "file.zip"};
    ASSERT_EQ(-1, br_.DoIt(kTransportLocal, "HannibalLecter", 2, args));
    ASSERT_THAT(GetCapturedStderr(), HasSubstr("D'OH"));
}

// Tests 'adb bugreport file.zip' when the bugreport itself failed but response
// was sent in
// multiple buffer writes
TEST_F(BugreportTest, BugreportzReturnedFailSplitBuffer) {
    EXPECT_CALL(br_, SendShellCommand(kTransportLocal, "HannibalLecter", "bugreportz", false, _))
        .WillOnce(DoAll(WithArg<4>(WriteOnStdout("FAIL")), WithArg<4>(WriteOnStdout(":D'OH!")),
                        WithArg<4>(ReturnCallbackDone())));

    CaptureStderr();
    const char* args[1024] = {"bugreport", "file.zip"};
    ASSERT_EQ(-1, br_.DoIt(kTransportLocal, "HannibalLecter", 2, args));
    ASSERT_THAT(GetCapturedStderr(), HasSubstr("D'OH"));
}

// Tests 'adb bugreport file.zip' when the bugreportz returned an unsupported
// response.
TEST_F(BugreportTest, BugreportzReturnedUnsupported) {
    EXPECT_CALL(br_, SendShellCommand(kTransportLocal, "HannibalLecter", "bugreportz", false, _))
        .WillOnce(DoAll(WithArg<4>(WriteOnStdout("bugreportz? What am I, a zombie?")),
                        WithArg<4>(ReturnCallbackDone())));

    CaptureStderr();
    const char* args[1024] = {"bugreport", "file.zip"};
    ASSERT_EQ(-1, br_.DoIt(kTransportLocal, "HannibalLecter", 2, args));
    ASSERT_THAT(GetCapturedStderr(), HasSubstr("bugreportz? What am I, a zombie?"));
}

// Tests 'adb bugreport file.zip' when the bugreportz command fails
TEST_F(BugreportTest, BugreportzFailed) {
    EXPECT_CALL(br_, SendShellCommand(kTransportLocal, "HannibalLecter", "bugreportz", false, _))
        .WillOnce(Return(666));

    const char* args[1024] = {"bugreport", "file.zip"};
    ASSERT_EQ(666, br_.DoIt(kTransportLocal, "HannibalLecter", 2, args));
}

// Tests 'adb bugreport file.zip' when the bugreport could not be pulled
TEST_F(BugreportTest, PullFails) {
    EXPECT_CALL(br_, SendShellCommand(kTransportLocal, "HannibalLecter", "bugreportz", false, _))
        .WillOnce(DoAll(WithArg<4>(WriteOnStdout("OK:/device/bugreport.zip")),
                        WithArg<4>(ReturnCallbackDone())));
    EXPECT_CALL(br_, DoSyncPull(ElementsAre(StrEq("/device/bugreport.zip")), StrEq("file.zip"),
                                true, StrEq("file.zip")))
        .WillOnce(Return(false));

    const char* args[1024] = {"bugreport", "file.zip"};
    ASSERT_EQ(1, br_.DoIt(kTransportLocal, "HannibalLecter", 2, args));
}
