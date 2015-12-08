/*
 * Copyright (C) 2012 The Android Open Source Project
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

#include "kernel_collector_test.h"

#include <unistd.h>

#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <brillo/syslog_logging.h>
#include <gtest/gtest.h>

using base::FilePath;
using base::StringPrintf;
using brillo::FindLog;
using brillo::GetLog;

namespace {

int s_crashes = 0;
bool s_metrics = false;

void CountCrash() {
  ++s_crashes;
}

bool IsMetrics() {
  return s_metrics;
}

}  // namespace

class KernelCollectorTest : public ::testing::Test {
 protected:
  void WriteStringToFile(const FilePath &file_path,
                         const char *data) {
    ASSERT_EQ(strlen(data), base::WriteFile(file_path, data, strlen(data)));
  }

  void SetUpSuccessfulCollect();
  void ComputeKernelStackSignatureCommon();

  const FilePath &kcrash_file() const { return test_kcrash_; }
  const FilePath &test_crash_directory() const { return test_crash_directory_; }

  KernelCollectorMock collector_;

 private:
  void SetUp() override {
    s_crashes = 0;
    s_metrics = true;

    EXPECT_CALL(collector_, SetUpDBus()).WillRepeatedly(testing::Return());

    collector_.Initialize(CountCrash, IsMetrics);
    ASSERT_TRUE(scoped_temp_dir_.CreateUniqueTempDir());
    test_kcrash_ = scoped_temp_dir_.path().Append("kcrash");
    ASSERT_TRUE(base::CreateDirectory(test_kcrash_));
    collector_.OverridePreservedDumpPath(test_kcrash_);

    test_kcrash_ = test_kcrash_.Append("dmesg-ramoops-0");
    ASSERT_FALSE(base::PathExists(test_kcrash_));

    test_crash_directory_ = scoped_temp_dir_.path().Append("crash_directory");
    ASSERT_TRUE(base::CreateDirectory(test_crash_directory_));
    brillo::ClearLog();
  }

  FilePath test_kcrash_;
  FilePath test_crash_directory_;
  base::ScopedTempDir scoped_temp_dir_;
};

TEST_F(KernelCollectorTest, ComputeKernelStackSignatureBase) {
  // Make sure the normal build architecture is detected
  EXPECT_NE(KernelCollector::kArchUnknown, collector_.arch());
}

TEST_F(KernelCollectorTest, LoadPreservedDump) {
  ASSERT_FALSE(base::PathExists(kcrash_file()));
  std::string dump;
  dump.clear();

  WriteStringToFile(kcrash_file(),
      "CrashRecordWithoutRamoopsHeader\n<6>[    0.078852]");
  ASSERT_TRUE(collector_.LoadParameters());
  ASSERT_TRUE(collector_.LoadPreservedDump(&dump));
  ASSERT_EQ("CrashRecordWithoutRamoopsHeader\n<6>[    0.078852]", dump);

  WriteStringToFile(kcrash_file(), "====1.1\nsomething");
  ASSERT_TRUE(collector_.LoadParameters());
  ASSERT_TRUE(collector_.LoadPreservedDump(&dump));
  ASSERT_EQ("something", dump);

  WriteStringToFile(kcrash_file(), "\x01\x02\xfe\xff random blob");
  ASSERT_TRUE(collector_.LoadParameters());
  ASSERT_FALSE(collector_.LoadPreservedDump(&dump));
  ASSERT_EQ("", dump);
}

TEST_F(KernelCollectorTest, EnableMissingKernel) {
  ASSERT_FALSE(collector_.Enable());
  ASSERT_FALSE(collector_.is_enabled());
  ASSERT_TRUE(FindLog(
      "Kernel does not support crash dumping"));
  ASSERT_EQ(s_crashes, 0);
}

TEST_F(KernelCollectorTest, EnableOK) {
  WriteStringToFile(kcrash_file(), "");
  EXPECT_CALL(collector_, DumpDirMounted()).WillOnce(::testing::Return(true));
  ASSERT_TRUE(collector_.Enable());
  ASSERT_TRUE(collector_.is_enabled());
  ASSERT_TRUE(FindLog("Enabling kernel crash handling"));
  ASSERT_EQ(s_crashes, 0);
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
  ASSERT_FALSE(FindLog("Stored kcrash to "));
  ASSERT_EQ(0, s_crashes);
}

void KernelCollectorTest::SetUpSuccessfulCollect() {
  collector_.ForceCrashDirectory(test_crash_directory());
  WriteStringToFile(kcrash_file(), "====1.1\nsomething");
  ASSERT_EQ(0, s_crashes);
}

TEST_F(KernelCollectorTest, CollectOptedOut) {
  SetUpSuccessfulCollect();
  s_metrics = false;
  ASSERT_TRUE(collector_.Collect());
  ASSERT_TRUE(FindLog("(ignoring - no consent)"));
  ASSERT_EQ(0, s_crashes);
}

TEST_F(KernelCollectorTest, CollectOK) {
  SetUpSuccessfulCollect();
  ASSERT_TRUE(collector_.Collect());
  ASSERT_EQ(1, s_crashes);
  ASSERT_TRUE(FindLog("(handling)"));
  static const char kNamePrefix[] = "Stored kcrash to ";
  std::string log = brillo::GetLog();
  size_t pos = log.find(kNamePrefix);
  ASSERT_NE(std::string::npos, pos)
      << "Did not find string \"" << kNamePrefix << "\" in log: {\n"
      << log << "}";
  pos += strlen(kNamePrefix);
  std::string filename = log.substr(pos, std::string::npos);
  // Take the name up until \n
  size_t end_pos = filename.find_first_of("\n");
  ASSERT_NE(std::string::npos, end_pos);
  filename = filename.substr(0, end_pos);
  ASSERT_EQ(0, filename.find(test_crash_directory().value()));
  ASSERT_TRUE(base::PathExists(FilePath(filename)));
  std::string contents;
  ASSERT_TRUE(base::ReadFileToString(FilePath(filename), &contents));
  ASSERT_EQ("something", contents);
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

  collector_.set_arch(KernelCollector::kArchArm);
  EXPECT_TRUE(
      collector_.ComputeKernelStackSignature(kBugToPanic, &signature, false));
  EXPECT_EQ("kernel-write_breakme-97D3E92F", signature);

  ComputeKernelStackSignatureCommon();
}

TEST_F(KernelCollectorTest, ComputeKernelStackSignatureMIPS) {
  const char kBugToPanic[] =
      "<5>[ 3378.472000] lkdtm: Performing direct entry BUG\n"
      "<5>[ 3378.476000] Kernel bug detected[#1]:\n"
      "<5>[ 3378.484000] CPU: 0 PID: 185 Comm: dash Not tainted 3.14.0 #1\n"
      "<5>[ 3378.488000] task: 8fed5220 ti: 8ec4a000 task.ti: 8ec4a000\n"
      "<5>[ 3378.496000] $ 0   : 00000000 804018b8 804010f0 7785b507\n"
      "<5>[ 3378.500000] $ 4   : 8061ab64 81204478 81205b20 00000000\n"
      "<5>[ 3378.508000] $ 8   : 80830000 20746365 72746e65 55422079\n"
      "<5>[ 3378.512000] $12   : 8ec4be94 000000fc 00000000 00000048\n"
      "<5>[ 3378.520000] $16   : 00000004 8ef54000 80710000 00000002\n"
      "<5>[ 3378.528000] $20   : 7765b6d4 00000004 7fffffff 00000002\n"
      "<5>[ 3378.532000] $24   : 00000001 803dc0dc                  \n"
      "<5>[ 3378.540000] $28   : 8ec4a000 8ec4be20 7775438d 804018b8\n"
      "<5>[ 3378.544000] Hi    : 00000000\n"
      "<5>[ 3378.548000] Lo    : 49bf8080\n"
      "<5>[ 3378.552000] epc   : 804010f0 lkdtm_do_action+0x68/0x3f8\n"
      "<5>[ 3378.560000]     Not tainted\n"
      "<5>[ 3378.564000] ra    : 804018b8 direct_entry+0x110/0x154\n"
      "<5>[ 3378.568000] Status: 3100dc03 KERNEL EXL IE \n"
      "<5>[ 3378.572000] Cause : 10800024\n"
      "<5>[ 3378.576000] PrId  : 0001a120 (MIPS interAptiv (multi))\n"
      "<5>[ 3378.580000] Modules linked in: uinput cfg80211 nf_conntrack_ipv6 "
          "nf_defrag_ipv6 ip6table_filter ip6_tables pcnet32 mii fuse "
          "ppp_async ppp_generic slhc tun\n"
      "<5>[ 3378.600000] Process dash (pid: 185, threadinfo=8ec4a000, "
          "task=8fed5220, tls=77632490)\n"
      "<5>[ 3378.608000] Stack : 00000006 ffffff9c 00000000 00000000 00000000 "
          "00000000 8083454a 00000022\n"
      "<5>          7765baa1 00001fee 80710000 8ef54000 8ec4bf08 00000002 "
          "7765b6d4 00000004\n"
      "<5>          7fffffff 00000002 7775438d 805e5158 7fffffff 00000002 "
          "00000000 7785b507\n"
      "<5>          806a96bc 00000004 8ef54000 8ec4bf08 00000002 804018b8 "
          "80710000 806a98bc\n"
      "<5>          00000002 00000020 00000004 8d515600 77756450 00000004 "
          "8ec4bf08 802377e4\n"
      "<5>          ...\n"
      "<5>[ 3378.652000] Call Trace:\n"
      "<5>[ 3378.656000] [<804010f0>] lkdtm_do_action+0x68/0x3f8\n"
      "<5>[ 3378.660000] [<804018b8>] direct_entry+0x110/0x154\n"
      "<5>[ 3378.664000] [<802377e4>] vfs_write+0xe0/0x1bc\n"
      "<5>[ 3378.672000] [<80237f90>] SyS_write+0x78/0xf8\n"
      "<5>[ 3378.676000] [<80111888>] handle_sys+0x128/0x14c\n"
      "<5>[ 3378.680000] \n"
      "<5>[ 3378.684000] \n"
      "<5>Code: 3c04806b  0c1793aa  248494f0 <000c000d> 3c04806b  248494fc  "
          "0c04cc7f  2405017a  08100514 \n"
      "<5>[ 3378.696000] ---[ end trace 75067432f24bbc93 ]---\n";
  std::string signature;

  collector_.set_arch(KernelCollector::kArchMips);
  EXPECT_TRUE(
      collector_.ComputeKernelStackSignature(kBugToPanic, &signature, false));
  EXPECT_EQ("kernel-lkdtm_do_action-5E600A6B", signature);

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

  collector_.set_arch(KernelCollector::kArchX86);
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

  // Panic from hung task.
  const char kHungTaskBreakMe[] =
      "<3>[  720.459157] INFO: task bash:2287 blocked blah blah\n"
      "<5>[  720.459282] Call Trace:\n"
      "<5>[  720.459307]  [<810a457b>] ? __dentry_open+0x186/0x23e\n"
      "<5>[  720.459323]  [<810b9c71>] ? mntput_no_expire+0x29/0xe2\n"
      "<5>[  720.459336]  [<810b9d48>] ? mntput+0x1e/0x20\n"
      "<5>[  720.459350]  [<810ad135>] ? path_put+0x1a/0x1d\n"
      "<5>[  720.459366]  [<8137cacc>] schedule+0x4d/0x4f\n"
      "<5>[  720.459379]  [<8137ccfb>] schedule_timeout+0x26/0xaf\n"
      "<5>[  720.459394]  [<8102127e>] ? should_resched+0xd/0x27\n"
      "<5>[  720.459409]  [<81174d1f>] ? _copy_from_user+0x3c/0x50\n"
      "<5>[  720.459423]  [<8137cd9e>] "
      "schedule_timeout_uninterruptible+0x1a/0x1c\n"
      "<5>[  720.459438]  [<810dee63>] write_breakme+0xb3/0x178\n"
      "<5>[  720.459453]  [<810dedb0>] ? meminfo_proc_show+0x2f2/0x2f2\n"
      "<5>[  720.459467]  [<810d94ae>] proc_reg_write+0x6d/0x87\n"
      "<5>[  720.459481]  [<810d9441>] ? proc_reg_poll+0x76/0x76\n"
      "<5>[  720.459493]  [<810a5e9e>] vfs_write+0x79/0xa5\n"
      "<5>[  720.459505]  [<810a6011>] sys_write+0x40/0x65\n"
      "<5>[  720.459519]  [<8137e677>] sysenter_do_call+0x12/0x26\n"
      "<0>[  720.459530] Kernel panic - not syncing: hung_task: blocked tasks\n"
      "<5>[  720.459768] Pid: 31, comm: khungtaskd Tainted: "
      "G         C  3.0.8 #1\n"
      "<5>[  720.459998] Call Trace:\n"
      "<5>[  720.460140]  [<81378a35>] panic+0x53/0x14a\n"
      "<5>[  720.460312]  [<8105f875>] watchdog+0x15b/0x1a0\n"
      "<5>[  720.460495]  [<8105f71a>] ? hung_task_panic+0x16/0x16\n"
      "<5>[  720.460693]  [<81043af3>] kthread+0x67/0x6c\n"
      "<5>[  720.460862]  [<81043a8c>] ? __init_kthread_worker+0x2d/0x2d\n"
      "<5>[  720.461106]  [<8137eb9e>] kernel_thread_helper+0x6/0x10\n";

  EXPECT_TRUE(
      collector_.ComputeKernelStackSignature(kHungTaskBreakMe,
                                             &signature,
                                             false));

  EXPECT_EQ("kernel-(HANG)-hung_task: blocked tasks-600B37EA", signature);

  // Panic with all question marks in the last stack trace.
  const char kUncertainStackTrace[] =
      "<0>[56279.689669] ------------[ cut here ]------------\n"
      "<2>[56279.689677] kernel BUG at /build/x86-alex/tmp/portage/"
      "sys-kernel/chromeos-kernel-0.0.1-r516/work/chromeos-kernel-0.0.1/"
      "kernel/timer.c:844!\n"
      "<0>[56279.689683] invalid opcode: 0000 [#1] SMP \n"
      "<0>[56279.689688] last sysfs file: /sys/power/state\n"
      "<5>[56279.689692] Modules linked in: nls_iso8859_1 nls_cp437 vfat fat "
      "gobi usbnet tsl2583(C) industrialio(C) snd_hda_codec_realtek "
      "snd_hda_intel i2c_dev snd_hda_codec snd_hwdep qcserial snd_pcm usb_wwan "
      "i2c_i801 snd_timer nm10_gpio snd_page_alloc rtc_cmos fuse "
      "nf_conntrack_ipv6 nf_defrag_ipv6 uvcvideo videodev ip6table_filter "
      "ath9k ip6_tables ipv6 mac80211 ath9k_common ath9k_hw ath cfg80211 "
      "xt_mark\n"
      "<5>[56279.689731] \n"
      "<5>[56279.689738] Pid: 24607, comm: powerd_suspend Tainted: G        "
      "WC  2.6.38.3+ #1 SAMSUNG ELECTRONICS CO., LTD. Alex/G100          \n"
      "<5>[56279.689748] EIP: 0060:[<8103e3ea>] EFLAGS: 00210286 CPU: 3\n"
      "<5>[56279.689758] EIP is at add_timer+0xd/0x1b\n"
      "<5>[56279.689762] EAX: f5e00684 EBX: f5e003c0 ECX: 00000002 EDX: "
      "00200246\n"
      "<5>[56279.689767] ESI: f5e003c0 EDI: d28bc03c EBP: d2be5e40 ESP: "
      "d2be5e40\n"
      "<5>[56279.689772]  DS: 007b ES: 007b FS: 00d8 GS: 00e0 SS: 0068\n"
      "<0>[56279.689778] Process powerd_suspend (pid: 24607, ti=d2be4000 "
      "task=f5dc9b60 task.ti=d2be4000)\n"
      "<0>[56279.689782] Stack:\n"
      "<5>[56279.689785]  d2be5e4c f8dccced f4ac02c0 d2be5e70 f8ddc752 "
      "f5e003c0 f4ac0458 f4ac092c\n"
      "<5>[56279.689797]  f4ac043c f4ac02c0 f4ac0000 f4ac007c d2be5e7c "
      "f8dd4a33 f4ac0164 d2be5e94\n"
      "<5>[56279.689809]  f87e0304 f69ff0cc f4ac0164 f87e02a4 f4ac0164 "
      "d2be5eb0 81248968 00000000\n"
      "<0>[56279.689821] Call Trace:\n"
      "<5>[56279.689840]  [<f8dccced>] ieee80211_sta_restart+0x25/0x8c "
      "[mac80211]\n"
      "<5>[56279.689854]  [<f8ddc752>] ieee80211_reconfig+0x2e9/0x339 "
      "[mac80211]\n"
      "<5>[56279.689869]  [<f8dd4a33>] ieee80211_aes_cmac+0x182d/0x184e "
      "[mac80211]\n"
      "<5>[56279.689883]  [<f87e0304>] cfg80211_get_dev_from_info+0x29b/0x2c0 "
      "[cfg80211]\n"
      "<5>[56279.689895]  [<f87e02a4>] ? "
      "cfg80211_get_dev_from_info+0x23b/0x2c0 [cfg80211]\n"
      "<5>[56279.689904]  [<81248968>] legacy_resume+0x25/0x5d\n"
      "<5>[56279.689910]  [<812490ae>] device_resume+0xdd/0x110\n"
      "<5>[56279.689917]  [<812491c2>] dpm_resume_end+0xe1/0x271\n"
      "<5>[56279.689925]  [<81060481>] suspend_devices_and_enter+0x18b/0x1de\n"
      "<5>[56279.689932]  [<810605ba>] enter_state+0xe6/0x132\n"
      "<5>[56279.689939]  [<8105fd4b>] state_store+0x91/0x9d\n"
      "<5>[56279.689945]  [<8105fcba>] ? state_store+0x0/0x9d\n"
      "<5>[56279.689953]  [<81178fb1>] kobj_attr_store+0x16/0x22\n"
      "<5>[56279.689961]  [<810eea5e>] sysfs_write_file+0xc1/0xec\n"
      "<5>[56279.689969]  [<810af443>] vfs_write+0x8f/0x101\n"
      "<5>[56279.689975]  [<810ee99d>] ? sysfs_write_file+0x0/0xec\n"
      "<5>[56279.689982]  [<810af556>] sys_write+0x40/0x65\n"
      "<5>[56279.689989]  [<81002d57>] sysenter_do_call+0x12/0x26\n"
      "<0>[56279.689993] Code: c1 d3 e2 4a 89 55 f4 f7 d2 21 f2 6a 00 31 c9 89 "
      "d8 e8 6e fd ff ff 5a 8d 65 f8 5b 5e 5d c3 55 89 e5 3e 8d 74 26 00 83 38 "
      "00 74 04 <0f> 0b eb fe 8b 50 08 e8 6f ff ff ff 5d c3 55 89 e5 3e 8d 74 "
      "26 \n"
      "<0>[56279.690009] EIP: [<8103e3ea>] add_timer+0xd/0x1b SS:ESP "
      "0068:d2be5e40\n"
      "<4>[56279.690113] ---[ end trace b71141bb67c6032a ]---\n"
      "<7>[56279.694069] wlan0: deauthenticated from 00:00:00:00:00:01 "
      "(Reason: 6)\n"
      "<0>[56279.703465] Kernel panic - not syncing: Fatal exception\n"
      "<5>[56279.703471] Pid: 24607, comm: powerd_suspend Tainted: G      D "
      "WC  2.6.38.3+ #1\n"
      "<5>[56279.703475] Call Trace:\n"
      "<5>[56279.703483]  [<8136648c>] ? panic+0x55/0x152\n"
      "<5>[56279.703491]  [<810057fa>] ? oops_end+0x73/0x81\n"
      "<5>[56279.703497]  [<81005a44>] ? die+0xed/0xf5\n"
      "<5>[56279.703503]  [<810033cb>] ? do_trap+0x7a/0x80\n"
      "<5>[56279.703509]  [<8100369b>] ? do_invalid_op+0x0/0x80\n"
      "<5>[56279.703515]  [<81003711>] ? do_invalid_op+0x76/0x80\n"
      "<5>[56279.703522]  [<8103e3ea>] ? add_timer+0xd/0x1b\n"
      "<5>[56279.703529]  [<81025e23>] ? check_preempt_curr+0x2e/0x69\n"
      "<5>[56279.703536]  [<8102ef28>] ? ttwu_post_activation+0x5a/0x11b\n"
      "<5>[56279.703543]  [<8102fa8d>] ? try_to_wake_up+0x213/0x21d\n"
      "<5>[56279.703550]  [<81368b7f>] ? error_code+0x67/0x6c\n"
      "<5>[56279.703557]  [<8103e3ea>] ? add_timer+0xd/0x1b\n"
      "<5>[56279.703577]  [<f8dccced>] ? ieee80211_sta_restart+0x25/0x8c "
      "[mac80211]\n"
      "<5>[56279.703591]  [<f8ddc752>] ? ieee80211_reconfig+0x2e9/0x339 "
      "[mac80211]\n"
      "<5>[56279.703605]  [<f8dd4a33>] ? ieee80211_aes_cmac+0x182d/0x184e "
      "[mac80211]\n"
      "<5>[56279.703618]  [<f87e0304>] ? "
      "cfg80211_get_dev_from_info+0x29b/0x2c0 [cfg80211]\n"
      "<5>[56279.703630]  [<f87e02a4>] ? "
      "cfg80211_get_dev_from_info+0x23b/0x2c0 [cfg80211]\n"
      "<5>[56279.703637]  [<81248968>] ? legacy_resume+0x25/0x5d\n"
      "<5>[56279.703643]  [<812490ae>] ? device_resume+0xdd/0x110\n"
      "<5>[56279.703649]  [<812491c2>] ? dpm_resume_end+0xe1/0x271\n"
      "<5>[56279.703657]  [<81060481>] ? "
      "suspend_devices_and_enter+0x18b/0x1de\n"
      "<5>[56279.703663]  [<810605ba>] ? enter_state+0xe6/0x132\n"
      "<5>[56279.703670]  [<8105fd4b>] ? state_store+0x91/0x9d\n"
      "<5>[56279.703676]  [<8105fcba>] ? state_store+0x0/0x9d\n"
      "<5>[56279.703683]  [<81178fb1>] ? kobj_attr_store+0x16/0x22\n"
      "<5>[56279.703690]  [<810eea5e>] ? sysfs_write_file+0xc1/0xec\n"
      "<5>[56279.703697]  [<810af443>] ? vfs_write+0x8f/0x101\n"
      "<5>[56279.703703]  [<810ee99d>] ? sysfs_write_file+0x0/0xec\n"
      "<5>[56279.703709]  [<810af556>] ? sys_write+0x40/0x65\n"
      "<5>[56279.703716]  [<81002d57>] ? sysenter_do_call+0x12/0x26\n";

  EXPECT_TRUE(
      collector_.ComputeKernelStackSignature(kUncertainStackTrace,
                                             &signature,
                                             false));
  // The first trace contains only uncertain entries and its hash is 00000000,
  // so, if we used that, the signature would be kernel-add_timer-00000000.
  // Instead we use the second-to-last trace for the hash.
  EXPECT_EQ("kernel-add_timer-B5178878", signature);

  ComputeKernelStackSignatureCommon();
}
