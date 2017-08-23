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

#include <android-base/strings.h>
#include <android-base/test_utils.h>

#include "sysdeps.h"
#include "adb_utils.h"

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
using ::testing::internal::CaptureStdout;
using ::testing::internal::GetCapturedStderr;
using ::testing::internal::GetCapturedStdout;

// Empty function so tests don't need to be linked against file_sync_service.cpp, which requires
// SELinux and its transitive dependencies...
bool do_sync_pull(const std::vector<const char*>& srcs, const char* dst, bool copy_attrs,
                  const char* name) {
    ADD_FAILURE() << "do_sync_pull() should have been mocked";
    return false;
}

// Empty functions so tests don't need to be linked against commandline.cpp
DefaultStandardStreamsCallback DEFAULT_STANDARD_STREAMS_CALLBACK(nullptr, nullptr);

int send_shell_command(const std::string& command, bool disable_shell_protocol,
                       StandardStreamsCallbackInterface* callback) {
    ADD_FAILURE() << "send_shell_command() should have been mocked";
    return -42;
}

enum StreamType {
    kStreamStdout,
    kStreamStderr,
};

// gmock black magic to provide a WithArg<2>(WriteOnStdout(output)) matcher
typedef void OnStandardStreamsCallbackFunction(StandardStreamsCallbackInterface*);

class OnStandardStreamsCallbackAction : public ActionInterface<OnStandardStreamsCallbackFunction> {
  public:
    explicit OnStandardStreamsCallbackAction(StreamType type, const std::string& output)
        : type_(type), output_(output) {
    }
    virtual Result Perform(const ArgumentTuple& args) {
        if (type_ == kStreamStdout) {
            ::std::tr1::get<0>(args)->OnStdout(output_.c_str(), output_.size());
        }
        if (type_ == kStreamStderr) {
            ::std::tr1::get<0>(args)->OnStderr(output_.c_str(), output_.size());
        }
    }

  private:
    StreamType type_;
    std::string output_;
};

// Matcher used to emulated StandardStreamsCallbackInterface.OnStdout(buffer,
// length)
Action<OnStandardStreamsCallbackFunction> WriteOnStdout(const std::string& output) {
    return MakeAction(new OnStandardStreamsCallbackAction(kStreamStdout, output));
}

// Matcher used to emulated StandardStreamsCallbackInterface.OnStderr(buffer,
// length)
Action<OnStandardStreamsCallbackFunction> WriteOnStderr(const std::string& output) {
    return MakeAction(new OnStandardStreamsCallbackAction(kStreamStderr, output));
}

typedef int CallbackDoneFunction(StandardStreamsCallbackInterface*);

class CallbackDoneAction : public ActionInterface<CallbackDoneFunction> {
  public:
    explicit CallbackDoneAction(int status) : status_(status) {
    }
    virtual Result Perform(const ArgumentTuple& args) {
        int status = ::std::tr1::get<0>(args)->Done(status_);
        return status;
    }

  private:
    int status_;
};

// Matcher used to emulated StandardStreamsCallbackInterface.Done(status)
Action<CallbackDoneFunction> ReturnCallbackDone(int status = -1337) {
    return MakeAction(new CallbackDoneAction(status));
}

class BugreportMock : public Bugreport {
  public:
    MOCK_METHOD3(SendShellCommand, int(const std::string& command, bool disable_shell_protocol,
                                       StandardStreamsCallbackInterface* callback));
    MOCK_METHOD4(DoSyncPull, bool(const std::vector<const char*>& srcs, const char* dst,
                                  bool copy_attrs, const char* name));
    MOCK_METHOD2(UpdateProgress, void(const std::string&, int));
};

class BugreportTest : public ::testing::Test {
  public:
    void SetUp() {
        if (!getcwd(&cwd_)) {
            ADD_FAILURE() << "getcwd failed: " << strerror(errno);
            return;
        }
    }

    void ExpectBugreportzVersion(const std::string& version) {
        EXPECT_CALL(br_, SendShellCommand("bugreportz -v", false, _))
            .WillOnce(DoAll(WithArg<2>(WriteOnStderr(version.c_str())),
                            WithArg<2>(ReturnCallbackDone(0))));
    }

    void ExpectProgress(int progress_percentage, const std::string& file = "file.zip") {
        EXPECT_CALL(br_, UpdateProgress(StrEq("generating " + file), progress_percentage));
    }

    BugreportMock br_;
    std::string cwd_;  // TODO: make it static
};

// Tests when called with invalid number of arguments
TEST_F(BugreportTest, InvalidNumberArgs) {
    const char* args[] = {"bugreport", "to", "principal"};
    ASSERT_EQ(1, br_.DoIt(3, args));
}

// Tests the 'adb bugreport' option when the device does not support 'bugreportz' - it falls back
// to the flat-file format ('bugreport' binary on device)
TEST_F(BugreportTest, NoArgumentsPreNDevice) {
    // clang-format off
    EXPECT_CALL(br_, SendShellCommand("bugreportz -v", false, _))
        .WillOnce(DoAll(WithArg<2>(WriteOnStderr("")),
                        // Write some bogus output on stdout to make sure it's ignored
                        WithArg<2>(WriteOnStdout("Dude, where is my bugreportz?")),
                        WithArg<2>(ReturnCallbackDone(0))));
    // clang-format on
    std::string bugreport = "Reported the bug was.";
    CaptureStdout();
    EXPECT_CALL(br_, SendShellCommand("bugreport", false, _))
        .WillOnce(DoAll(WithArg<2>(WriteOnStdout(bugreport)), Return(0)));

    const char* args[] = {"bugreport"};
    ASSERT_EQ(0, br_.DoIt(1, args));
    ASSERT_THAT(GetCapturedStdout(), StrEq(bugreport));
}

// Tests the 'adb bugreport' option when the device supports 'bugreportz' version 1.0 - it will
// save the bugreport in the current directory with the name provided by the device.
TEST_F(BugreportTest, NoArgumentsNDevice) {
    ExpectBugreportzVersion("1.0");

    std::string dest_file =
        android::base::StringPrintf("%s%cda_bugreport.zip", cwd_.c_str(), OS_PATH_SEPARATOR);
    EXPECT_CALL(br_, SendShellCommand("bugreportz", false, _))
        .WillOnce(DoAll(WithArg<2>(WriteOnStdout("OK:/device/da_bugreport.zip")),
                        WithArg<2>(ReturnCallbackDone())));
    EXPECT_CALL(br_, DoSyncPull(ElementsAre(StrEq("/device/da_bugreport.zip")), StrEq(dest_file),
                                false, StrEq("pulling da_bugreport.zip")))
        .WillOnce(Return(true));

    const char* args[] = {"bugreport"};
    ASSERT_EQ(0, br_.DoIt(1, args));
}

// Tests the 'adb bugreport' option when the device supports 'bugreportz' version 1.1 - it will
// save the bugreport in the current directory with the name provided by the device.
TEST_F(BugreportTest, NoArgumentsPostNDevice) {
    ExpectBugreportzVersion("1.1");
    std::string dest_file =
        android::base::StringPrintf("%s%cda_bugreport.zip", cwd_.c_str(), OS_PATH_SEPARATOR);
    ExpectProgress(50, "da_bugreport.zip");
    EXPECT_CALL(br_, SendShellCommand("bugreportz -p", false, _))
        .WillOnce(DoAll(WithArg<2>(WriteOnStdout("BEGIN:/device/da_bugreport.zip\n")),
                        WithArg<2>(WriteOnStdout("PROGRESS:50/100\n")),
                        WithArg<2>(WriteOnStdout("OK:/device/da_bugreport.zip\n")),
                        WithArg<2>(ReturnCallbackDone())));
    EXPECT_CALL(br_, DoSyncPull(ElementsAre(StrEq("/device/da_bugreport.zip")), StrEq(dest_file),
                                false, StrEq("pulling da_bugreport.zip")))
        .WillOnce(Return(true));

    const char* args[] = {"bugreport"};
    ASSERT_EQ(0, br_.DoIt(1, args));
}

// Tests 'adb bugreport file.zip' when it succeeds and device does not support progress.
TEST_F(BugreportTest, OkNDevice) {
    ExpectBugreportzVersion("1.0");
    EXPECT_CALL(br_, SendShellCommand("bugreportz", false, _))
        .WillOnce(DoAll(WithArg<2>(WriteOnStdout("OK:/device/bugreport.zip")),
                        WithArg<2>(ReturnCallbackDone())));
    EXPECT_CALL(br_, DoSyncPull(ElementsAre(StrEq("/device/bugreport.zip")), StrEq("file.zip"),
                                false, StrEq("pulling file.zip")))
        .WillOnce(Return(true));

    const char* args[] = {"bugreport", "file.zip"};
    ASSERT_EQ(0, br_.DoIt(2, args));
}

// Tests 'adb bugreport file.zip' when it succeeds but response was sent in
// multiple buffer writers and without progress updates.
TEST_F(BugreportTest, OkNDeviceSplitBuffer) {
    ExpectBugreportzVersion("1.0");
    EXPECT_CALL(br_, SendShellCommand("bugreportz", false, _))
        .WillOnce(DoAll(WithArg<2>(WriteOnStdout("OK:/device")),
                        WithArg<2>(WriteOnStdout("/bugreport.zip")),
                        WithArg<2>(ReturnCallbackDone())));
    EXPECT_CALL(br_, DoSyncPull(ElementsAre(StrEq("/device/bugreport.zip")), StrEq("file.zip"),
                                false, StrEq("pulling file.zip")))
        .WillOnce(Return(true));

    const char* args[] = {"bugreport", "file.zip"};
    ASSERT_EQ(0, br_.DoIt(2, args));
}

// Tests 'adb bugreport file.zip' when it succeeds and displays progress.
TEST_F(BugreportTest, OkProgress) {
    ExpectBugreportzVersion("1.1");
    ExpectProgress(1);
    ExpectProgress(10);
    ExpectProgress(50);
    ExpectProgress(99);
    // clang-format off
    EXPECT_CALL(br_, SendShellCommand("bugreportz -p", false, _))
        // NOTE: DoAll accepts at most 10 arguments, and we're almost reached that limit...
        .WillOnce(DoAll(
            // Name might change on OK, so make sure the right one is picked.
            WithArg<2>(WriteOnStdout("BEGIN:/device/bugreport___NOT.zip\n")),
            // Progress line in one write
            WithArg<2>(WriteOnStdout("PROGRESS:1/100\n")),
            // Add some bogus lines
            WithArg<2>(WriteOnStdout("\nDUDE:SWEET\n\nBLA\n\nBLA\nBLA\n\n")),
            // Multiple progress lines in one write
            WithArg<2>(WriteOnStdout("PROGRESS:10/100\nPROGRESS:50/100\n")),
            // Progress line in multiple writes
            WithArg<2>(WriteOnStdout("PROG")),
            WithArg<2>(WriteOnStdout("RESS:99")),
            WithArg<2>(WriteOnStdout("/100\n")),
            // Split last message as well, just in case
            WithArg<2>(WriteOnStdout("OK:/device/bugreport")),
            WithArg<2>(WriteOnStdout(".zip")),
            WithArg<2>(ReturnCallbackDone())));
    // clang-format on
    EXPECT_CALL(br_, DoSyncPull(ElementsAre(StrEq("/device/bugreport.zip")), StrEq("file.zip"),
                                false, StrEq("pulling file.zip")))
        .WillOnce(Return(true));

    const char* args[] = {"bugreport", "file.zip"};
    ASSERT_EQ(0, br_.DoIt(2, args));
}

// Tests 'adb bugreport file.zip' when it succeeds and displays progress, even if progress recedes.
TEST_F(BugreportTest, OkProgressAlwaysForward) {
    ExpectBugreportzVersion("1.1");
    ExpectProgress(1);
    ExpectProgress(50);
    ExpectProgress(75);
    // clang-format off
    EXPECT_CALL(br_, SendShellCommand("bugreportz -p", false, _))
        // NOTE: DoAll accepts at most 10 arguments, and we're almost reached that limit...
        .WillOnce(DoAll(
            WithArg<2>(WriteOnStdout("BEGIN:/device/bugreport.zip\n")),
            WithArg<2>(WriteOnStdout("PROGRESS:1/100\n")), // 1%
            WithArg<2>(WriteOnStdout("PROGRESS:50/100\n")), // 50%
            // 25% should be ignored becaused it receded.
            WithArg<2>(WriteOnStdout("PROGRESS:25/100\n")), // 25%
            WithArg<2>(WriteOnStdout("PROGRESS:75/100\n")), // 75%
            // 75% should be ignored becaused it didn't change.
            WithArg<2>(WriteOnStdout("PROGRESS:75/100\n")), // 75%
            // Try a receeding percentage with a different max progress
            WithArg<2>(WriteOnStdout("PROGRESS:700/1000\n")), // 70%
            WithArg<2>(WriteOnStdout("OK:/device/bugreport.zip")),
            WithArg<2>(ReturnCallbackDone())));
    // clang-format on
    EXPECT_CALL(br_, DoSyncPull(ElementsAre(StrEq("/device/bugreport.zip")), StrEq("file.zip"),
                                false, StrEq("pulling file.zip")))
        .WillOnce(Return(true));

    const char* args[] = {"bugreport", "file.zip"};
    ASSERT_EQ(0, br_.DoIt(2, args));
}

// Tests 'adb bugreport file.zip' when it succeeds and displays the initial progress of 0%
TEST_F(BugreportTest, OkProgressZeroPercentIsNotIgnored) {
    ExpectBugreportzVersion("1.1");
    ExpectProgress(0);
    ExpectProgress(1);
    // clang-format off
    EXPECT_CALL(br_, SendShellCommand("bugreportz -p", false, _))
        // NOTE: DoAll accepts at most 10 arguments, and we're almost reached that limit...
        .WillOnce(DoAll(
            WithArg<2>(WriteOnStdout("BEGIN:/device/bugreport.zip\n")),
            WithArg<2>(WriteOnStdout("PROGRESS:1/100000\n")),
            WithArg<2>(WriteOnStdout("PROGRESS:1/100\n")), // 1%
            WithArg<2>(WriteOnStdout("OK:/device/bugreport.zip")),
            WithArg<2>(ReturnCallbackDone())));
    // clang-format on
    EXPECT_CALL(br_, DoSyncPull(ElementsAre(StrEq("/device/bugreport.zip")), StrEq("file.zip"),
                                false, StrEq("pulling file.zip")))
        .WillOnce(Return(true));

    const char* args[] = {"bugreport", "file.zip"};
    ASSERT_EQ(0, br_.DoIt(2, args));
}

// Tests 'adb bugreport dir' when it succeeds and destination is a directory.
TEST_F(BugreportTest, OkDirectory) {
    ExpectBugreportzVersion("1.1");
    TemporaryDir td;
    std::string dest_file =
        android::base::StringPrintf("%s%cda_bugreport.zip", td.path, OS_PATH_SEPARATOR);

    EXPECT_CALL(br_, SendShellCommand("bugreportz -p", false, _))
        .WillOnce(DoAll(WithArg<2>(WriteOnStdout("BEGIN:/device/da_bugreport.zip\n")),
                        WithArg<2>(WriteOnStdout("OK:/device/da_bugreport.zip")),
                        WithArg<2>(ReturnCallbackDone())));
    EXPECT_CALL(br_, DoSyncPull(ElementsAre(StrEq("/device/da_bugreport.zip")), StrEq(dest_file),
                                false, StrEq("pulling da_bugreport.zip")))
        .WillOnce(Return(true));

    const char* args[] = {"bugreport", td.path};
    ASSERT_EQ(0, br_.DoIt(2, args));
}

// Tests 'adb bugreport file' when it succeeds
TEST_F(BugreportTest, OkNoExtension) {
    ExpectBugreportzVersion("1.1");
    EXPECT_CALL(br_, SendShellCommand("bugreportz -p", false, _))
        .WillOnce(DoAll(WithArg<2>(WriteOnStdout("OK:/device/bugreport.zip\n")),
                        WithArg<2>(ReturnCallbackDone())));
    EXPECT_CALL(br_, DoSyncPull(ElementsAre(StrEq("/device/bugreport.zip")), StrEq("file.zip"),
                                false, StrEq("pulling file.zip")))
        .WillOnce(Return(true));

    const char* args[] = {"bugreport", "file"};
    ASSERT_EQ(0, br_.DoIt(2, args));
}

// Tests 'adb bugreport dir' when it succeeds and destination is a directory and device runs N.
TEST_F(BugreportTest, OkNDeviceDirectory) {
    ExpectBugreportzVersion("1.0");
    TemporaryDir td;
    std::string dest_file =
        android::base::StringPrintf("%s%cda_bugreport.zip", td.path, OS_PATH_SEPARATOR);

    EXPECT_CALL(br_, SendShellCommand("bugreportz", false, _))
        .WillOnce(DoAll(WithArg<2>(WriteOnStdout("BEGIN:/device/da_bugreport.zip\n")),
                        WithArg<2>(WriteOnStdout("OK:/device/da_bugreport.zip")),
                        WithArg<2>(ReturnCallbackDone())));
    EXPECT_CALL(br_, DoSyncPull(ElementsAre(StrEq("/device/da_bugreport.zip")), StrEq(dest_file),
                                false, StrEq("pulling da_bugreport.zip")))
        .WillOnce(Return(true));

    const char* args[] = {"bugreport", td.path};
    ASSERT_EQ(0, br_.DoIt(2, args));
}

// Tests 'adb bugreport file.zip' when the bugreport itself failed
TEST_F(BugreportTest, BugreportzReturnedFail) {
    ExpectBugreportzVersion("1.1");
    EXPECT_CALL(br_, SendShellCommand("bugreportz -p", false, _))
        .WillOnce(
            DoAll(WithArg<2>(WriteOnStdout("FAIL:D'OH!\n")), WithArg<2>(ReturnCallbackDone())));

    CaptureStderr();
    const char* args[] = {"bugreport", "file.zip"};
    ASSERT_EQ(-1, br_.DoIt(2, args));
    ASSERT_THAT(GetCapturedStderr(), HasSubstr("D'OH!"));
}

// Tests 'adb bugreport file.zip' when the bugreport itself failed but response
// was sent in
// multiple buffer writes
TEST_F(BugreportTest, BugreportzReturnedFailSplitBuffer) {
    ExpectBugreportzVersion("1.1");
    EXPECT_CALL(br_, SendShellCommand("bugreportz -p", false, _))
        .WillOnce(DoAll(WithArg<2>(WriteOnStdout("FAIL")), WithArg<2>(WriteOnStdout(":D'OH!\n")),
                        WithArg<2>(ReturnCallbackDone())));

    CaptureStderr();
    const char* args[] = {"bugreport", "file.zip"};
    ASSERT_EQ(-1, br_.DoIt(2, args));
    ASSERT_THAT(GetCapturedStderr(), HasSubstr("D'OH!"));
}

// Tests 'adb bugreport file.zip' when the bugreportz returned an unsupported
// response.
TEST_F(BugreportTest, BugreportzReturnedUnsupported) {
    ExpectBugreportzVersion("1.1");
    EXPECT_CALL(br_, SendShellCommand("bugreportz -p", false, _))
        .WillOnce(DoAll(WithArg<2>(WriteOnStdout("bugreportz? What am I, a zombie?")),
                        WithArg<2>(ReturnCallbackDone())));

    CaptureStderr();
    const char* args[] = {"bugreport", "file.zip"};
    ASSERT_EQ(-1, br_.DoIt(2, args));
    ASSERT_THAT(GetCapturedStderr(), HasSubstr("bugreportz? What am I, a zombie?"));
}

// Tests 'adb bugreport file.zip' when the bugreportz -v command failed
TEST_F(BugreportTest, BugreportzVersionFailed) {
    EXPECT_CALL(br_, SendShellCommand("bugreportz -v", false, _)).WillOnce(Return(666));

    const char* args[] = {"bugreport", "file.zip"};
    ASSERT_EQ(666, br_.DoIt(2, args));
}

// Tests 'adb bugreport file.zip' when the bugreportz -v returns status 0 but with no output.
TEST_F(BugreportTest, BugreportzVersionEmpty) {
    ExpectBugreportzVersion("");

    const char* args[] = {"bugreport", "file.zip"};
    ASSERT_EQ(-1, br_.DoIt(2, args));
}

// Tests 'adb bugreport file.zip' when the main bugreportz command failed
TEST_F(BugreportTest, BugreportzFailed) {
    ExpectBugreportzVersion("1.1");
    EXPECT_CALL(br_, SendShellCommand("bugreportz -p", false, _)).WillOnce(Return(666));

    const char* args[] = {"bugreport", "file.zip"};
    ASSERT_EQ(666, br_.DoIt(2, args));
}

// Tests 'adb bugreport file.zip' when the bugreport could not be pulled
TEST_F(BugreportTest, PullFails) {
    ExpectBugreportzVersion("1.1");
    EXPECT_CALL(br_, SendShellCommand("bugreportz -p", false, _))
        .WillOnce(DoAll(WithArg<2>(WriteOnStdout("OK:/device/bugreport.zip")),
                        WithArg<2>(ReturnCallbackDone())));
    EXPECT_CALL(br_, DoSyncPull(ElementsAre(StrEq("/device/bugreport.zip")), StrEq("file.zip"),
                                false, HasSubstr("file.zip")))
        .WillOnce(Return(false));

    const char* args[] = {"bugreport", "file.zip"};
    ASSERT_EQ(1, br_.DoIt(2, args));
}
