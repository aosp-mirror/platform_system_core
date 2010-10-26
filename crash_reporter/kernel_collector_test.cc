// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <unistd.h>

#include "base/file_util.h"
#include "base/string_util.h"
#include "crash-reporter/kernel_collector.h"
#include "crash-reporter/system_logging_mock.h"
#include "gflags/gflags.h"
#include "gtest/gtest.h"

static int s_crashes = 0;
static bool s_metrics = false;

static const char kTestKCrash[] = "test/kcrash";
static const char kTestCrashDirectory[] = "test/crash_directory";

void CountCrash() {
  ++s_crashes;
}

bool IsMetrics() {
  return s_metrics;
}

class KernelCollectorTest : public ::testing::Test {
  void SetUp() {
    s_crashes = 0;
    s_metrics = true;
    collector_.Initialize(CountCrash,
                          IsMetrics,
                          &logging_);
    mkdir("test", 0777);
    test_kcrash_ = FilePath(kTestKCrash);
    collector_.OverridePreservedDumpPath(test_kcrash_);
    unlink(kTestKCrash);
    mkdir(kTestCrashDirectory, 0777);
  }
 protected:
  void WriteStringToFile(const FilePath &file_path,
                         const char *data) {
    ASSERT_EQ(strlen(data),
              file_util::WriteFile(file_path, data, strlen(data)));
  }

  void SetUpSuccessfulCollect();
  void CheckPreservedDumpClear();

  SystemLoggingMock logging_;
  KernelCollector collector_;
  FilePath test_kcrash_;
};

TEST_F(KernelCollectorTest, LoadPreservedDump) {
  ASSERT_FALSE(file_util::PathExists(test_kcrash_));
  std::string dump;
  ASSERT_FALSE(collector_.LoadPreservedDump(&dump));
  WriteStringToFile(test_kcrash_, "");
  ASSERT_TRUE(collector_.LoadPreservedDump(&dump));
  ASSERT_EQ("", dump);
  WriteStringToFile(test_kcrash_, "something");
  ASSERT_TRUE(collector_.LoadPreservedDump(&dump));
  ASSERT_EQ("something", dump);
}

TEST_F(KernelCollectorTest, EnableMissingKernel) {
  ASSERT_FALSE(collector_.Enable());
  ASSERT_FALSE(collector_.IsEnabled());
  ASSERT_EQ(std::string::npos,
            logging_.log().find("Enabling kernel crash handling"));
  ASSERT_NE(std::string::npos,
            logging_.log().find("Kernel does not support crash dumping"));
  ASSERT_EQ(s_crashes, 0);
}

TEST_F(KernelCollectorTest, EnableOK) {
  WriteStringToFile(test_kcrash_, "");
  ASSERT_TRUE(collector_.Enable());
  ASSERT_TRUE(collector_.IsEnabled());
  ASSERT_NE(std::string::npos,
            logging_.log().find("Enabling kernel crash handling"));
  ASSERT_EQ(s_crashes, 0);
}

TEST_F(KernelCollectorTest, ClearPreservedDump) {
  std::string dump;
  ASSERT_FALSE(file_util::PathExists(test_kcrash_));
  WriteStringToFile(test_kcrash_, "something");
  ASSERT_TRUE(collector_.LoadPreservedDump(&dump));
  ASSERT_EQ("something", dump);
  ASSERT_TRUE(collector_.ClearPreservedDump());
  ASSERT_TRUE(collector_.LoadPreservedDump(&dump));
  ASSERT_EQ(KernelCollector::kClearingSequence, dump);
}

TEST_F(KernelCollectorTest, CollectPreservedFileMissing) {
  ASSERT_FALSE(collector_.Collect());
  ASSERT_NE(logging_.log().find("Unable to read test/kcrash"),
            std::string::npos);
  ASSERT_EQ(0, s_crashes);
}

TEST_F(KernelCollectorTest, CollectNoCrash) {
  WriteStringToFile(test_kcrash_, "");
  ASSERT_FALSE(collector_.Collect());
  ASSERT_EQ(logging_.log().find("Collected kernel crash"),
            std::string::npos);
  ASSERT_EQ(0, s_crashes);
}

TEST_F(KernelCollectorTest, CollectBadDirectory) {
  WriteStringToFile(test_kcrash_, "something");
  ASSERT_TRUE(collector_.Collect());
  ASSERT_NE(logging_.log().find(
      "Unable to create appropriate crash directory"), std::string::npos);
  ASSERT_EQ(1, s_crashes);
}

void KernelCollectorTest::SetUpSuccessfulCollect() {
  collector_.ForceCrashDirectory(kTestCrashDirectory);
  WriteStringToFile(test_kcrash_, "something");
  ASSERT_EQ(0, s_crashes);
}

void KernelCollectorTest::CheckPreservedDumpClear() {
  // Make sure the preserved dump is now clear.
  std::string dump;
  ASSERT_TRUE(collector_.LoadPreservedDump(&dump));
  ASSERT_EQ(KernelCollector::kClearingSequence, dump);
}

TEST_F(KernelCollectorTest, CollectOptedOut) {
  SetUpSuccessfulCollect();
  s_metrics = false;
  ASSERT_TRUE(collector_.Collect());
  ASSERT_NE(std::string::npos, logging_.log().find("(ignoring)"));
  ASSERT_EQ(0, s_crashes);

  CheckPreservedDumpClear();
}

TEST_F(KernelCollectorTest, CollectOK) {
  SetUpSuccessfulCollect();
  ASSERT_TRUE(collector_.Collect());
  ASSERT_EQ(1, s_crashes);
  ASSERT_NE(std::string::npos, logging_.log().find("(handling)"));
  static const char kNamePrefix[] = "Stored kcrash to ";
  size_t pos = logging_.log().find(kNamePrefix);
  ASSERT_NE(std::string::npos, pos);
  pos += strlen(kNamePrefix);
  std::string filename = logging_.log().substr(pos, std::string::npos);
  // Take the name up until \n
  size_t end_pos = filename.find_first_of("\n");
  ASSERT_NE(std::string::npos, end_pos);
  filename = filename.substr(0, end_pos);
  ASSERT_EQ(0, filename.find(kTestCrashDirectory));
  ASSERT_TRUE(file_util::PathExists(FilePath(filename)));
  std::string contents;
  ASSERT_TRUE(file_util::ReadFileToString(FilePath(filename), &contents));
  ASSERT_EQ("something", contents);

  CheckPreservedDumpClear();
}

TEST_F(KernelCollectorTest, ComputeKernelStackSignature) {
  const char kBugToPanic[] =
      "<4>[ 6066.829029]  [<79039d16>] ? run_timer_softirq+0x165/0x1e6\n"
      "<4>[ 6066.829029]  [<790340af>] ignore_old_stack+0xa6/0x143\n"
      "<0>[ 6066.829029] EIP: [<b82d7c15>] ieee80211_stop_tx_ba_session+"
          "0xa3/0xb5 [mac80211] SS:ESP 0068:7951febc\n"
      "<0>[ 6066.829029] CR2: 00000000323038a7\n"
      "<4>[ 6066.845422] ---[ end trace 12b058bb46c43500 ]---\n"
      "<0>[ 6066.845747] Kernel panic - not syncing: Fatal exception "
          "in interrupt\n"
      "<0>[ 6066.846902] Call Trace:\n"
      "<4>[ 6066.846902]  [<7937a07b>] ? printk+0x14/0x19\n"
      "<4>[ 6066.949779]  [<79379fc1>] panic+0x3e/0xe4\n"
      "<4>[ 6066.949971]  [<7937c5c5>] oops_end+0x73/0x81\n"
      "<4>[ 6066.950208]  [<7901b260>] no_context+0x10d/0x117\n";
  std::string signature;
  EXPECT_TRUE(
      collector_.ComputeKernelStackSignature(kBugToPanic, &signature, false));
  EXPECT_EQ("kernel-ieee80211_stop_tx_ba_session-DE253569", signature);

  const char kPCButNoStack[] =
      "<0>[ 6066.829029] EIP: [<b82d7c15>] ieee80211_stop_tx_ba_session+";
  EXPECT_TRUE(
      collector_.ComputeKernelStackSignature(kPCButNoStack, &signature, false));
  EXPECT_EQ("kernel-ieee80211_stop_tx_ba_session-00000000", signature);

  const char kStackButNoPC[] =
      "<4>[ 6066.829029]  [<790340af>] __do_softirq+0xa6/0x143\n";
  EXPECT_TRUE(
      collector_.ComputeKernelStackSignature(kStackButNoPC, &signature, false));
  EXPECT_EQ("kernel--83615F0A", signature);

  const char kMissingEverything[] =
      "<4>[ 6066.829029]  [<790340af>] ? __do_softirq+0xa6/0x143\n";
  EXPECT_FALSE(
      collector_.ComputeKernelStackSignature(kMissingEverything,
                                             &signature,
                                             false));

  const char kBreakmeBug[] =
      "<4>[  180.492137]  [<790970c6>] ? handle_mm_fault+0x67f/0x96d\n"
      "<4>[  180.492137]  [<790dcdfe>] ? proc_reg_write+0x5f/0x73\n"
      "<4>[  180.492137]  [<790e2224>] ? write_breakme+0x0/0x108\n"
      "<4>[  180.492137]  [<790dcd9f>] ? proc_reg_write+0x0/0x73\n"
      "<4>[  180.492137]  [<790ac0aa>] vfs_write+0x85/0xe4\n"
      "<0>[  180.492137] Code: c6 44 05 b2 00 89 d8 e8 0c ef 09 00 85 c0 75 "
      "0b c7 00 00 00 00 00 e9 8e 00 00 00 ba e6 75 4b 79 89 d8 e8 f1 ee 09 "
      "00 85 c0 75 04 <0f> 0b eb fe ba 58 47 49 79 89 d8 e8 dd ee 09 00 85 "
      "c0 75 0a 68\n"
      "<0>[  180.492137] EIP: [<790e22a4>] write_breakme+0x80/0x108 SS:ESP "
          "0068:aa3e9efc\n"
      "<4>[  180.501800] ---[ end trace 2a6b72965e1b1523 ]---\n"
      "<0>[  180.502026] Kernel panic - not syncing: Fatal exception\n"
      "<4>[  180.502026] Call Trace:\n"
      "<4>[  180.502806]  [<79379aba>] ? printk+0x14/0x1a\n"
      "<4>[  180.503033]  [<79379a00>] panic+0x3e/0xe4\n"
      "<4>[  180.503287]  [<7937c005>] oops_end+0x73/0x81\n"
      "<4>[  180.503520]  [<790055dd>] die+0x58/0x5e\n"
      "<4>[  180.503538]  [<7937b96c>] do_trap+0x8e/0xa7\n"
      "<4>[  180.503555]  [<79003d70>] ? do_invalid_op+0x0/0x80\n";

  EXPECT_TRUE(
      collector_.ComputeKernelStackSignature(kBreakmeBug, &signature, false));
  EXPECT_EQ("kernel-write_breakme-122AB3CD", signature);

  const char kPCLineTooOld[] =
      "<4>[  174.492137]  [<790970c6>] ignored_function+0x67f/0x96d\n"
      "<4>[  175.492137]  [<790970c6>] ignored_function2+0x67f/0x96d\n"
      "<0>[  174.492137] EIP: [<790e22a4>] write_breakme+0x80/0x108 SS:ESP "
          "0068:aa3e9efc\n"
      "<4>[  180.501800] ---[ end trace 2a6b72965e1b1523 ]---\n"
      "<4>[  180.502026] Call Trace:\n"
      "<0>[  180.502026] Kernel panic - not syncing: Fatal exception\n"
      "<4>[  180.502806]  [<79379aba>] printk+0x14/0x1a\n";

  EXPECT_TRUE(
      collector_.ComputeKernelStackSignature(kPCLineTooOld, &signature, false));
  EXPECT_EQ("kernel-Fatal exception-ED4C84FE", signature);

  // Panic without EIP line.
  const char kExamplePanicOnly[] =
      "<0>[   87.485611] Kernel panic - not syncing: Testing panic\n"
      "<4>[   87.485630] Pid: 2825, comm: bash Tainted: G         "
          "C 2.6.32.23+drm33.10 #1\n"
      "<4>[   87.485639] Call Trace:\n"
      "<4>[   87.485660]  [<8133f71d>] ? printk+0x14/0x17\n"
      "<4>[   87.485674]  [<8133f663>] panic+0x3e/0xe4\n"
      "<4>[   87.485689]  [<810d062e>] write_breakme+0xaa/0x124\n";
  EXPECT_TRUE(
      collector_.ComputeKernelStackSignature(kExamplePanicOnly,
                                             &signature,
                                             false));
  EXPECT_EQ("kernel-Testing panic-E0FC3552", signature);

  // Long message.
  const char kTruncatedMessage[] =
      "<0>[   87.485611] Kernel panic - not syncing: 01234567890123456789"
          "01234567890123456789X\n";
  EXPECT_TRUE(
      collector_.ComputeKernelStackSignature(kTruncatedMessage,
                                             &signature,
                                             false));
  EXPECT_EQ("kernel-0123456789012345678901234567890123456789-00000000",
            signature);

}

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
