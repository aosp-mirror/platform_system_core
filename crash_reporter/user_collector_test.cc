// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <unistd.h>

#include "base/file_util.h"
#include "chromeos/syslog_logging.h"
#include "chromeos/test_helpers.h"
#include "crash-reporter/user_collector.h"
#include "gflags/gflags.h"
#include "gtest/gtest.h"

static int s_crashes = 0;
static bool s_metrics = false;

static const char kFilePath[] = "/my/path";

using chromeos::FindLog;

void CountCrash() {
  ++s_crashes;
}

bool IsMetrics() {
  return s_metrics;
}

class UserCollectorTest : public ::testing::Test {
  void SetUp() {
    s_crashes = 0;
    collector_.Initialize(CountCrash,
                          kFilePath,
                          IsMetrics,
                          false);
    file_util::Delete(FilePath("test"), true);
    mkdir("test", 0777);
    collector_.set_core_pattern_file("test/core_pattern");
    collector_.set_core_pipe_limit_file("test/core_pipe_limit");
    pid_ = getpid();
    chromeos::ClearLog();
  }
 protected:
  void ExpectFileEquals(const char *golden,
                        const char *file_path) {
    std::string contents;
    EXPECT_TRUE(file_util::ReadFileToString(FilePath(file_path),
                                            &contents));
    EXPECT_EQ(golden, contents);
  }

  UserCollector collector_;
  pid_t pid_;
};

TEST_F(UserCollectorTest, EnableOK) {
  ASSERT_TRUE(collector_.Enable());
  ExpectFileEquals("|/my/path --user=%p:%s:%e", "test/core_pattern");
  ExpectFileEquals("4", "test/core_pipe_limit");
  ASSERT_EQ(s_crashes, 0);
  EXPECT_TRUE(FindLog("Enabling user crash handling"));
}

TEST_F(UserCollectorTest, EnableNoPatternFileAccess) {
  collector_.set_core_pattern_file("/does_not_exist");
  ASSERT_FALSE(collector_.Enable());
  ASSERT_EQ(s_crashes, 0);
  EXPECT_TRUE(FindLog("Enabling user crash handling"));
  EXPECT_TRUE(FindLog("Unable to write /does_not_exist"));
}

TEST_F(UserCollectorTest, EnableNoPipeLimitFileAccess) {
  collector_.set_core_pipe_limit_file("/does_not_exist");
  ASSERT_FALSE(collector_.Enable());
  ASSERT_EQ(s_crashes, 0);
  // Core pattern should not be written if we cannot access the pipe limit
  // or otherwise we may set a pattern that results in infinite recursion.
  ASSERT_FALSE(file_util::PathExists(FilePath("test/core_pattern")));
  EXPECT_TRUE(FindLog("Enabling user crash handling"));
  EXPECT_TRUE(FindLog("Unable to write /does_not_exist"));
}

TEST_F(UserCollectorTest, DisableOK) {
  ASSERT_TRUE(collector_.Disable());
  ExpectFileEquals("core", "test/core_pattern");
  ASSERT_EQ(s_crashes, 0);
  EXPECT_TRUE(FindLog("Disabling user crash handling"));
}

TEST_F(UserCollectorTest, DisableNoFileAccess) {
  collector_.set_core_pattern_file("/does_not_exist");
  ASSERT_FALSE(collector_.Disable());
  ASSERT_EQ(s_crashes, 0);
  EXPECT_TRUE(FindLog("Disabling user crash handling"));
  EXPECT_TRUE(FindLog("Unable to write /does_not_exist"));
}

TEST_F(UserCollectorTest, ParseCrashAttributes) {
  pid_t pid;
  int signal;
  std::string exec_name;
  EXPECT_TRUE(collector_.ParseCrashAttributes("123456:11:foobar",
                                              &pid, &signal, &exec_name));
  EXPECT_EQ(123456, pid);
  EXPECT_EQ(11, signal);
  EXPECT_EQ("foobar", exec_name);

  EXPECT_FALSE(collector_.ParseCrashAttributes("123456:11",
                                               &pid, &signal, &exec_name));

  EXPECT_TRUE(collector_.ParseCrashAttributes("123456:11:exec:extra",
                                              &pid, &signal, &exec_name));
  EXPECT_EQ("exec:extra", exec_name);

  EXPECT_FALSE(collector_.ParseCrashAttributes("12345p:11:foobar",
                                              &pid, &signal, &exec_name));

  EXPECT_FALSE(collector_.ParseCrashAttributes("123456:1 :foobar",
                                              &pid, &signal, &exec_name));

  EXPECT_FALSE(collector_.ParseCrashAttributes("123456::foobar",
                                              &pid, &signal, &exec_name));
}

TEST_F(UserCollectorTest, ShouldDumpDeveloperImageOverridesConsent) {
  std::string reason;
  EXPECT_TRUE(collector_.ShouldDump(false, true, false,
                                    "chrome-wm", &reason));
  EXPECT_EQ("developer build - not testing - always dumping", reason);

  // When running a crash test, behave as normal.
  EXPECT_FALSE(collector_.ShouldDump(false, true, true,
                                    "chrome-wm", &reason));
  EXPECT_EQ("ignoring - no consent", reason);
}

TEST_F(UserCollectorTest, ShouldDumpChromeOverridesDeveloperImage) {
  std::string reason;
  EXPECT_FALSE(collector_.ShouldDump(false, true, false,
                                     "chrome", &reason));
  EXPECT_EQ("ignoring - chrome crash", reason);
}

TEST_F(UserCollectorTest, ShouldDumpUseConsentProductionImage) {
  std::string result;
  EXPECT_FALSE(collector_.ShouldDump(false, false, false,
                                     "chrome-wm", &result));
  EXPECT_EQ("ignoring - no consent", result);

  EXPECT_TRUE(collector_.ShouldDump(true, false, false,
                                    "chrome-wm", &result));
  EXPECT_EQ("handling", result);
}

TEST_F(UserCollectorTest, HandleCrashWithoutConsent) {
  s_metrics = false;
  collector_.HandleCrash("20:10:ignored", "foobar");
  EXPECT_TRUE(FindLog(
      "Received crash notification for foobar[20] sig 10"));
  ASSERT_EQ(s_crashes, 0);
}

TEST_F(UserCollectorTest, HandleNonChromeCrashWithConsent) {
  s_metrics = true;
  collector_.HandleCrash("5:2:ignored", "chromeos-wm");
  EXPECT_TRUE(FindLog(
      "Received crash notification for chromeos-wm[5] sig 2"));
  ASSERT_EQ(s_crashes, 1);
}

TEST_F(UserCollectorTest, HandleChromeCrashWithConsent) {
  s_metrics = true;
  collector_.HandleCrash("5:2:ignored", "chrome");
  EXPECT_TRUE(FindLog(
      "Received crash notification for chrome[5] sig 2"));
  EXPECT_TRUE(FindLog("(ignoring - chrome crash)"));
  ASSERT_EQ(s_crashes, 0);
}

TEST_F(UserCollectorTest, HandleSuppliedChromeCrashWithConsent) {
  s_metrics = true;
  collector_.HandleCrash("0:2:chrome", NULL);
  EXPECT_TRUE(FindLog(
      "Received crash notification for supplied_chrome[0] sig 2"));
  EXPECT_TRUE(FindLog("(ignoring - chrome crash)"));
  ASSERT_EQ(s_crashes, 0);
}

TEST_F(UserCollectorTest, GetProcessPath) {
  FilePath path = collector_.GetProcessPath(100);
  ASSERT_EQ("/proc/100", path.value());
}

TEST_F(UserCollectorTest, GetSymlinkTarget) {
  FilePath result;
  ASSERT_FALSE(collector_.GetSymlinkTarget(FilePath("/does_not_exist"),
                                           &result));
  ASSERT_TRUE(FindLog(
      "Readlink failed on /does_not_exist with 2"));
  std::string long_link;
  for (int i = 0; i < 50; ++i)
    long_link += "0123456789";
  long_link += "/gold";

  for (size_t len = 1; len <= long_link.size(); ++len) {
    std::string this_link;
    static const char kLink[] = "test/this_link";
    this_link.assign(long_link.c_str(), len);
    ASSERT_EQ(len, this_link.size());
    unlink(kLink);
    ASSERT_EQ(0, symlink(this_link.c_str(), kLink));
    ASSERT_TRUE(collector_.GetSymlinkTarget(FilePath(kLink), &result));
    ASSERT_EQ(this_link, result.value());
  }
}

TEST_F(UserCollectorTest, GetExecutableBaseNameFromPid) {
  std::string base_name;
  EXPECT_FALSE(collector_.GetExecutableBaseNameFromPid(0, &base_name));
  EXPECT_TRUE(FindLog(
      "Readlink failed on /proc/0/exe with 2"));
  EXPECT_TRUE(FindLog(
      "GetSymlinkTarget failed - Path /proc/0 DirectoryExists: 0"));
  EXPECT_TRUE(FindLog("stat /proc/0/exe failed: -1 2"));

  chromeos::ClearLog();
  pid_t my_pid = getpid();
  EXPECT_TRUE(collector_.GetExecutableBaseNameFromPid(my_pid, &base_name));
  EXPECT_FALSE(FindLog("Readlink failed"));
  EXPECT_EQ("user_collector_test", base_name);
}

TEST_F(UserCollectorTest, GetIdFromStatus) {
  int id = 1;
  EXPECT_FALSE(collector_.GetIdFromStatus(UserCollector::kUserId,
                                          UserCollector::kIdEffective,
                                          "nothing here",
                                          &id));
  EXPECT_EQ(id, 1);

  // Not enough parameters.
  EXPECT_FALSE(collector_.GetIdFromStatus(UserCollector::kUserId,
                                          UserCollector::kIdReal,
                                          "line 1\nUid:\t1\n", &id));

  const char valid_contents[] = "\nUid:\t1\t2\t3\t4\nGid:\t5\t6\t7\t8\n";
  EXPECT_TRUE(collector_.GetIdFromStatus(UserCollector::kUserId,
                                         UserCollector::kIdReal,
                                         valid_contents,
                                         &id));
  EXPECT_EQ(1, id);

  EXPECT_TRUE(collector_.GetIdFromStatus(UserCollector::kUserId,
                                         UserCollector::kIdEffective,
                                         valid_contents,
                                         &id));
  EXPECT_EQ(2, id);

  EXPECT_TRUE(collector_.GetIdFromStatus(UserCollector::kUserId,
                                         UserCollector::kIdFileSystem,
                                         valid_contents,
                                         &id));
  EXPECT_EQ(4, id);

  EXPECT_TRUE(collector_.GetIdFromStatus(UserCollector::kGroupId,
                                         UserCollector::kIdEffective,
                                         valid_contents,
                                         &id));
  EXPECT_EQ(6, id);

  EXPECT_TRUE(collector_.GetIdFromStatus(UserCollector::kGroupId,
                                         UserCollector::kIdSet,
                                         valid_contents,
                                         &id));
  EXPECT_EQ(7, id);

  EXPECT_FALSE(collector_.GetIdFromStatus(UserCollector::kGroupId,
                                          UserCollector::IdKind(5),
                                          valid_contents,
                                          &id));
  EXPECT_FALSE(collector_.GetIdFromStatus(UserCollector::kGroupId,
                                          UserCollector::IdKind(-1),
                                          valid_contents,
                                          &id));

  // Fail if junk after number
  EXPECT_FALSE(collector_.GetIdFromStatus(UserCollector::kUserId,
                                          UserCollector::kIdReal,
                                          "Uid:\t1f\t2\t3\t4\n",
                                          &id));
  EXPECT_TRUE(collector_.GetIdFromStatus(UserCollector::kUserId,
                                         UserCollector::kIdReal,
                                         "Uid:\t1\t2\t3\t4\n",
                                         &id));
  EXPECT_EQ(1, id);

  // Fail if more than 4 numbers.
  EXPECT_FALSE(collector_.GetIdFromStatus(UserCollector::kUserId,
                                          UserCollector::kIdReal,
                                          "Uid:\t1\t2\t3\t4\t5\n",
                                          &id));
}

TEST_F(UserCollectorTest, GetUserInfoFromName) {
  gid_t gid = 100;
  uid_t uid = 100;
  EXPECT_TRUE(collector_.GetUserInfoFromName("root", &uid, &gid));
  EXPECT_EQ(0, uid);
  EXPECT_EQ(0, gid);
}

TEST_F(UserCollectorTest, CopyOffProcFilesBadPath) {
  // Try a path that is not writable.
  ASSERT_FALSE(collector_.CopyOffProcFiles(pid_, FilePath("/bad/path")));
  EXPECT_TRUE(FindLog("Could not create /bad/path"));
}

TEST_F(UserCollectorTest, CopyOffProcFilesBadPid) {
  FilePath container_path("test/container");
  ASSERT_FALSE(collector_.CopyOffProcFiles(0, container_path));
  EXPECT_TRUE(FindLog("Path /proc/0 does not exist"));
}

TEST_F(UserCollectorTest, CopyOffProcFilesOK) {
  FilePath container_path("test/container");
  ASSERT_TRUE(collector_.CopyOffProcFiles(pid_, container_path));
  EXPECT_FALSE(FindLog("Could not copy"));
  static struct {
    const char *name;
    bool exists;
  } expectations[] = {
    { "auxv", true },
    { "cmdline", true },
    { "environ", true },
    { "maps", true },
    { "mem", false },
    { "mounts", false },
    { "sched", false },
    { "status", true }
  };
  for (unsigned i = 0; i < sizeof(expectations)/sizeof(expectations[0]); ++i) {
    EXPECT_EQ(expectations[i].exists,
              file_util::PathExists(
                  container_path.Append(expectations[i].name)));
  }
}

int main(int argc, char **argv) {
  SetUpTests(&argc, argv, false);
  return RUN_ALL_TESTS();
}
