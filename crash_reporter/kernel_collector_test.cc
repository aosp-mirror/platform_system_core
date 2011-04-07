// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <unistd.h>

#include "base/file_util.h"
#include "base/string_util.h"
#include "chromeos/syslog_logging.h"
#include "chromeos/test_helpers.h"
#include "crash-reporter/kernel_collector.h"
#include "gflags/gflags.h"
#include "gtest/gtest.h"

static int s_crashes = 0;
static bool s_metrics = false;

static const char kTestKCrash[] = "test/kcrash";
static const char kTestCrashDirectory[] = "test/crash_directory";

using chromeos::FindLog;

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
                          IsMetrics);
    mkdir("test", 0777);
    test_kcrash_ = FilePath(kTestKCrash);
    collector_.OverridePreservedDumpPath(test_kcrash_);
    unlink(kTestKCrash);
    mkdir(kTestCrashDirectory, 0777);
    chromeos::ClearLog();
  }
 protected:
  void WriteStringToFile(const FilePath &file_path,
                         const char *data) {
    ASSERT_EQ(strlen(data),
              file_util::WriteFile(file_path, data, strlen(data)));
  }

  void SetUpSuccessfulCollect();
  void CheckPreservedDumpClear();
  void ComputeKernelStackSignatureCommon();

  KernelCollector collector_;
  FilePath test_kcrash_;
};

TEST_F(KernelCollectorTest, ComputeKernelStackSignatureBase) {
  // Make sure the normal build architecture is detected
  EXPECT_TRUE(collector_.GetArch() != KernelCollector::archUnknown);
}

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
  ASSERT_TRUE(FindLog(
      "Kernel does not support crash dumping"));
  ASSERT_EQ(s_crashes, 0);
}

TEST_F(KernelCollectorTest, EnableOK) {
  WriteStringToFile(test_kcrash_, "");
  ASSERT_TRUE(collector_.Enable());
  ASSERT_TRUE(collector_.IsEnabled());
  ASSERT_TRUE(FindLog("Enabling kernel crash handling"));
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

TEST_F(KernelCollectorTest, StripSensitiveDataBasic) {
  // Basic tests of StripSensitiveData...

  // Make sure we work OK with a string w/ no MAC addresses.
  const std::string kCrashWithNoMacsOrig =
      "<7>[111566.131728] PM: Entering mem sleep\n";
  std::string crash_with_no_macs(kCrashWithNoMacsOrig);
  collector_.StripSensitiveData(&crash_with_no_macs);
  EXPECT_EQ(kCrashWithNoMacsOrig, crash_with_no_macs);

  // Make sure that we handle the case where there's nothing before/after the
  // MAC address.
  const std::string kJustAMacOrig =
      "11:22:33:44:55:66";
  const std::string kJustAMacStripped =
      "00:00:00:00:00:01";
  std::string just_a_mac(kJustAMacOrig);
  collector_.StripSensitiveData(&just_a_mac);
  EXPECT_EQ(kJustAMacStripped, just_a_mac);

  // Test MAC addresses crammed together to make sure it gets both of them.
  //
  // I'm not sure that the code does ideal on these two test cases (they don't
  // look like two MAC addresses to me), but since we don't see them I think
  // it's OK to behave as shown here.
  const std::string kCrammedMacs1Orig =
      "11:22:33:44:55:66:11:22:33:44:55:66";
  const std::string kCrammedMacs1Stripped =
      "00:00:00:00:00:01:00:00:00:00:00:01";
  std::string crammed_macs_1(kCrammedMacs1Orig);
  collector_.StripSensitiveData(&crammed_macs_1);
  EXPECT_EQ(kCrammedMacs1Stripped, crammed_macs_1);

  const std::string kCrammedMacs2Orig =
      "11:22:33:44:55:6611:22:33:44:55:66";
  const std::string kCrammedMacs2Stripped =
      "00:00:00:00:00:0100:00:00:00:00:01";
  std::string crammed_macs_2(kCrammedMacs2Orig);
  collector_.StripSensitiveData(&crammed_macs_2);
  EXPECT_EQ(kCrammedMacs2Stripped, crammed_macs_2);

  // Test case-sensitiveness (we shouldn't be case-senstive).
  const std::string kCapsMacOrig =
      "AA:BB:CC:DD:EE:FF";
  const std::string kCapsMacStripped =
      "00:00:00:00:00:01";
  std::string caps_mac(kCapsMacOrig);
  collector_.StripSensitiveData(&caps_mac);
  EXPECT_EQ(kCapsMacStripped, caps_mac);

  const std::string kLowerMacOrig =
      "aa:bb:cc:dd:ee:ff";
  const std::string kLowerMacStripped =
      "00:00:00:00:00:01";
  std::string lower_mac(kLowerMacOrig);
  collector_.StripSensitiveData(&lower_mac);
  EXPECT_EQ(kLowerMacStripped, lower_mac);
}

TEST_F(KernelCollectorTest, StripSensitiveDataBulk) {
  // Test calling StripSensitiveData w/ lots of MAC addresses in the "log".

  // Test that stripping code handles more than 256 unique MAC addresses, since
  // that overflows past the last byte...
  // We'll write up some code that generates 258 unique MAC addresses.  Sorta
  // cheating since the code is very similar to the current code in
  // StripSensitiveData(), but would catch if someone changed that later.
  std::string lotsa_macs_orig;
  std::string lotsa_macs_stripped;
  int i;
  for (i = 0; i < 258; i++) {
    lotsa_macs_orig += StringPrintf(" 11:11:11:11:%02X:%02x",
                                  (i & 0xff00) >> 8, i & 0x00ff);
    lotsa_macs_stripped += StringPrintf(" 00:00:00:00:%02X:%02x",
                                     ((i+1) & 0xff00) >> 8, (i+1) & 0x00ff);
  }
  std::string lotsa_macs(lotsa_macs_orig);
  collector_.StripSensitiveData(&lotsa_macs);
  EXPECT_EQ(lotsa_macs_stripped, lotsa_macs);
}

TEST_F(KernelCollectorTest, StripSensitiveDataSample) {
  // Test calling StripSensitiveData w/ some actual lines from a real crash;
  // included two MAC addresses (though replaced them with some bogusness).
  const std::string kCrashWithMacsOrig =
      "<6>[111567.195339] ata1.00: ACPI cmd ef/10:03:00:00:00:a0 (SET FEATURES)"
        " filtered out\n"
      "<7>[108539.540144] wlan0: authenticate with 11:22:33:44:55:66 (try 1)\n"
      "<7>[108539.554973] wlan0: associate with 11:22:33:44:55:66 (try 1)\n"
      "<6>[110136.587583] usb0: register 'QCUSBNet2k' at usb-0000:00:1d.7-2,"
        " QCUSBNet Ethernet Device, 99:88:77:66:55:44\n"
      "<7>[110964.314648] wlan0: deauthenticated from 11:22:33:44:55:66"
        " (Reason: 6)\n"
      "<7>[110964.325057] phy0: Removed STA 11:22:33:44:55:66\n"
      "<7>[110964.325115] phy0: Destroyed STA 11:22:33:44:55:66\n"
      "<6>[110969.219172] usb0: register 'QCUSBNet2k' at usb-0000:00:1d.7-2,"
        " QCUSBNet Ethernet Device, 99:88:77:66:55:44\n"
      "<7>[111566.131728] PM: Entering mem sleep\n";
  const std::string kCrashWithMacsStripped =
      "<6>[111567.195339] ata1.00: ACPI cmd ef/10:03:00:00:00:a0 (SET FEATURES)"
        " filtered out\n"
      "<7>[108539.540144] wlan0: authenticate with 00:00:00:00:00:01 (try 1)\n"
      "<7>[108539.554973] wlan0: associate with 00:00:00:00:00:01 (try 1)\n"
      "<6>[110136.587583] usb0: register 'QCUSBNet2k' at usb-0000:00:1d.7-2,"
        " QCUSBNet Ethernet Device, 00:00:00:00:00:02\n"
      "<7>[110964.314648] wlan0: deauthenticated from 00:00:00:00:00:01"
        " (Reason: 6)\n"
      "<7>[110964.325057] phy0: Removed STA 00:00:00:00:00:01\n"
      "<7>[110964.325115] phy0: Destroyed STA 00:00:00:00:00:01\n"
      "<6>[110969.219172] usb0: register 'QCUSBNet2k' at usb-0000:00:1d.7-2,"
        " QCUSBNet Ethernet Device, 00:00:00:00:00:02\n"
      "<7>[111566.131728] PM: Entering mem sleep\n";
  std::string crash_with_macs(kCrashWithMacsOrig);
  collector_.StripSensitiveData(&crash_with_macs);
  EXPECT_EQ(kCrashWithMacsStripped, crash_with_macs);
}

TEST_F(KernelCollectorTest, CollectPreservedFileMissing) {
  ASSERT_FALSE(collector_.Collect());
  ASSERT_TRUE(FindLog("Unable to read test/kcrash"));
  ASSERT_EQ(0, s_crashes);
}

TEST_F(KernelCollectorTest, CollectNoCrash) {
  WriteStringToFile(test_kcrash_, "");
  ASSERT_FALSE(collector_.Collect());
  ASSERT_FALSE(FindLog("Collected kernel crash"));
  ASSERT_EQ(0, s_crashes);
}

TEST_F(KernelCollectorTest, CollectBadDirectory) {
  WriteStringToFile(test_kcrash_, "something");
  ASSERT_TRUE(collector_.Collect());
  ASSERT_TRUE(FindLog(
      "Unable to create appropriate crash directory"));
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
  ASSERT_TRUE(FindLog("(ignoring - no consent)"));
  ASSERT_EQ(0, s_crashes);

  CheckPreservedDumpClear();
}

TEST_F(KernelCollectorTest, CollectOK) {
  SetUpSuccessfulCollect();
  ASSERT_TRUE(collector_.Collect());
  ASSERT_EQ(1, s_crashes);
  ASSERT_TRUE(FindLog("(handling)"));
  static const char kNamePrefix[] = "Stored kcrash to ";
  std::string log = chromeos::GetLog();
  size_t pos = log.find(kNamePrefix);
  ASSERT_NE(std::string::npos, pos);
  pos += strlen(kNamePrefix);
  std::string filename = log.substr(pos, std::string::npos);
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

// Perform tests which are common across architectures
void KernelCollectorTest::ComputeKernelStackSignatureCommon() {
  std::string signature;

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

TEST_F(KernelCollectorTest, ComputeKernelStackSignatureARM) {
  const char kBugToPanic[] =
      "<5>[  123.412524] Modules linked in:\n"
      "<5>[  123.412534] CPU: 0    Tainted: G        W    "
          "(2.6.37-01030-g51cee64 #153)\n"
      "<5>[  123.412552] PC is at write_breakme+0xd0/0x1b4\n"
      "<5>[  123.412560] LR is at write_breakme+0xc8/0x1b4\n"
      "<5>[  123.412569] pc : [<c0058220>]    lr : [<c005821c>]    "
          "psr: 60000013\n"
      "<5>[  123.412574] sp : f4e0ded8  ip : c04d104c  fp : 000e45e0\n"
      "<5>[  123.412581] r10: 400ff000  r9 : f4e0c000  r8 : 00000004\n"
      "<5>[  123.412589] r7 : f4e0df80  r6 : f4820c80  r5 : 00000004  "
          "r4 : f4e0dee8\n"
      "<5>[  123.412598] r3 : 00000000  r2 : f4e0decc  r1 : c05f88a9  "
          "r0 : 00000039\n"
      "<5>[  123.412608] Flags: nZCv  IRQs on  FIQs on  Mode SVC_32  ISA "
          "ARM  Segment user\n"
      "<5>[  123.412617] Control: 10c53c7d  Table: 34dcc04a  DAC: 00000015\n"
      "<0>[  123.412626] Process bash (pid: 1014, stack limit = 0xf4e0c2f8)\n"
      "<0>[  123.412634] Stack: (0xf4e0ded8 to 0xf4e0e000)\n"
      "<0>[  123.412641] dec0:                                              "
          "         f4e0dee8 c0183678\n"
      "<0>[  123.412654] dee0: 00000000 00000000 00677562 0000081f c06a6a78 "
          "400ff000 f4e0dfb0 00000000\n"
      "<0>[  123.412666] df00: bec7ab44 000b1719 bec7ab0c c004f498 bec7a314 "
          "c024acc8 00000001 c018359c\n"
      "<0>[  123.412679] df20: f4e0df34 c04d10fc f5803c80 271beb39 000e45e0 "
          "f5803c80 c018359c c017bfe0\n"
      "<0>[  123.412691] df40: 00000004 f4820c80 400ff000 f4e0df80 00000004 "
          "f4e0c000 00000000 c01383e4\n"
      "<0>[  123.412703] df60: f4820c80 400ff000 f4820c80 400ff000 00000000 "
          "00000000 00000004 c0138578\n"
      "<0>[  123.412715] df80: 00000000 00000000 00000004 00000000 00000004 "
          "402f95d0 00000004 00000004\n"
      "<0>[  123.412727] dfa0: c0054984 c00547c0 00000004 402f95d0 00000001 "
          "400ff000 00000004 00000000\n"
      "<0>[  123.412739] dfc0: 00000004 402f95d0 00000004 00000004 400ff000 "
          "000c194c bec7ab58 000e45e0\n"
      "<0>[  123.412751] dfe0: 00000000 bec7aad8 40232520 40284e9c 60000010 "
          "00000001 00000000 00000000\n"
      "<5>[   39.496577] Backtrace:\n"
      "<5>[  123.412782] [<c0058220>] (__bug+0x20/0x2c) from [<c0183678>] "
          "(write_breakme+0xdc/0x1bc)\n"
      "<5>[  123.412798] [<c0183678>] (write_breakme+0xdc/0x1bc) from "
          "[<c017bfe0>] (proc_reg_write+0x88/0x9c)\n";
  std::string signature;

  collector_.SetArch(KernelCollector::archArm);
  EXPECT_TRUE(
      collector_.ComputeKernelStackSignature(kBugToPanic, &signature, false));
  EXPECT_EQ("kernel-write_breakme-97D3E92F", signature);

  ComputeKernelStackSignatureCommon();
}


TEST_F(KernelCollectorTest, ComputeKernelStackSignatureX86) {
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

  collector_.SetArch(KernelCollector::archX86);
  EXPECT_TRUE(
      collector_.ComputeKernelStackSignature(kBugToPanic, &signature, false));
  EXPECT_EQ("kernel-ieee80211_stop_tx_ba_session-DE253569", signature);

  const char kPCButNoStack[] =
      "<0>[ 6066.829029] EIP: [<b82d7c15>] ieee80211_stop_tx_ba_session+";
  EXPECT_TRUE(
      collector_.ComputeKernelStackSignature(kPCButNoStack, &signature, false));
  EXPECT_EQ("kernel-ieee80211_stop_tx_ba_session-00000000", signature);

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
  ComputeKernelStackSignatureCommon();
}

int main(int argc, char **argv) {
  SetUpTests(&argc, argv, false);
  return RUN_ALL_TESTS();
}
