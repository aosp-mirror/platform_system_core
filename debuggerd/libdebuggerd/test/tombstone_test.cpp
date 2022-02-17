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

#include <stdlib.h>
#include <sys/mman.h>
#include <time.h>

#include <memory>
#include <string>

#include <android-base/file.h>
#include <android-base/properties.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "libdebuggerd/utility.h"

#include "UnwinderMock.h"
#include "host_signal_fixup.h"
#include "log_fake.h"

#include "gwp_asan.cpp"

using ::testing::MatchesRegex;

class TombstoneTest : public ::testing::Test {
 protected:
  virtual void SetUp() {
    unwinder_mock_.reset(new UnwinderMock());

    char tmp_file[256];
    const char data_template[] = "/data/local/tmp/debuggerd_memory_testXXXXXX";
    memcpy(tmp_file, data_template, sizeof(data_template));
    int tombstone_fd = mkstemp(tmp_file);
    if (tombstone_fd == -1) {
      const char tmp_template[] = "/tmp/debuggerd_memory_testXXXXXX";
      memcpy(tmp_file, tmp_template, sizeof(tmp_template));
      tombstone_fd = mkstemp(tmp_file);
      if (tombstone_fd == -1) {
        abort();
      }
    }
    if (unlink(tmp_file) == -1) {
      abort();
    }

    log_.tfd = tombstone_fd;
    amfd_data_.clear();
    log_.amfd_data = &amfd_data_;
    log_.crashed_tid = 12;
    log_.current_tid = 12;
    log_.should_retrieve_logcat = false;

    resetLogs();
  }

  virtual void TearDown() {
    if (log_.tfd >= 0) {
      close(log_.tfd);
    }
  }

  std::unique_ptr<UnwinderMock> unwinder_mock_;

  log_t log_;
  std::string amfd_data_;
};

class GwpAsanCrashDataTest : public GwpAsanCrashData {
public:
  GwpAsanCrashDataTest(
      gwp_asan::Error error,
      const gwp_asan::AllocationMetadata *responsible_allocation) :
      GwpAsanCrashData(nullptr, ProcessInfo{}, ThreadInfo{}) {
    is_gwp_asan_responsible_ = true;
    error_ = error;
    responsible_allocation_ = responsible_allocation;
    error_string_ = gwp_asan::ErrorToString(error_);
  }

  void SetCrashAddress(uintptr_t crash_address) {
    crash_address_ = crash_address;
  }
};

TEST_F(TombstoneTest, gwp_asan_cause_uaf_exact) {
  gwp_asan::AllocationMetadata meta;
  meta.Addr = 0x1000;
  meta.RequestedSize = 32;

  GwpAsanCrashDataTest crash_data(gwp_asan::Error::USE_AFTER_FREE, &meta);
  crash_data.SetCrashAddress(0x1000);

  crash_data.DumpCause(&log_);
  ASSERT_TRUE(lseek(log_.tfd, 0, SEEK_SET) == 0);
  std::string tombstone_contents;
  ASSERT_TRUE(android::base::ReadFdToString(log_.tfd, &tombstone_contents));
  ASSERT_THAT(tombstone_contents, MatchesRegex("Cause: \\[GWP-ASan\\]: Use After Free, 0 bytes "
                                               "into a 32-byte allocation at 0x[a-fA-F0-9]+\n"));
}

TEST_F(TombstoneTest, gwp_asan_cause_double_free) {
  gwp_asan::AllocationMetadata meta;
  meta.Addr = 0x1000;
  meta.RequestedSize = 32;

  GwpAsanCrashDataTest crash_data(gwp_asan::Error::DOUBLE_FREE, &meta);
  crash_data.SetCrashAddress(0x1000);

  crash_data.DumpCause(&log_);
  ASSERT_TRUE(lseek(log_.tfd, 0, SEEK_SET) == 0);
  std::string tombstone_contents;
  ASSERT_TRUE(android::base::ReadFdToString(log_.tfd, &tombstone_contents));
  ASSERT_THAT(tombstone_contents, MatchesRegex("Cause: \\[GWP-ASan\\]: Double Free, 0 bytes into a "
                                               "32-byte allocation at 0x[a-fA-F0-9]+\n"));
}

TEST_F(TombstoneTest, gwp_asan_cause_overflow) {
  gwp_asan::AllocationMetadata meta;
  meta.Addr = 0x1000;
  meta.RequestedSize = 32;

  GwpAsanCrashDataTest crash_data(gwp_asan::Error::BUFFER_OVERFLOW, &meta);
  crash_data.SetCrashAddress(0x1025);

  crash_data.DumpCause(&log_);
  ASSERT_TRUE(lseek(log_.tfd, 0, SEEK_SET) == 0);
  std::string tombstone_contents;
  ASSERT_TRUE(android::base::ReadFdToString(log_.tfd, &tombstone_contents));
  ASSERT_THAT(
      tombstone_contents,
      MatchesRegex(
          "Cause: \\[GWP-ASan\\]: Buffer Overflow, 5 bytes right of a 32-byte "
          "allocation at 0x[a-fA-F0-9]+\n"));
}

TEST_F(TombstoneTest, gwp_asan_cause_underflow) {
  gwp_asan::AllocationMetadata meta;
  meta.Addr = 0x1000;
  meta.RequestedSize = 32;

  GwpAsanCrashDataTest crash_data(gwp_asan::Error::BUFFER_UNDERFLOW, &meta);
  crash_data.SetCrashAddress(0xffe);

  crash_data.DumpCause(&log_);
  ASSERT_TRUE(lseek(log_.tfd, 0, SEEK_SET) == 0);
  std::string tombstone_contents;
  ASSERT_TRUE(android::base::ReadFdToString(log_.tfd, &tombstone_contents));
  ASSERT_THAT(
      tombstone_contents,
      MatchesRegex(
          "Cause: \\[GWP-ASan\\]: Buffer Underflow, 2 bytes left of a 32-byte "
          "allocation at 0x[a-fA-F0-9]+\n"));
}

TEST_F(TombstoneTest, gwp_asan_cause_invalid_free_inside) {
  gwp_asan::AllocationMetadata meta;
  meta.Addr = 0x1000;
  meta.RequestedSize = 32;

  GwpAsanCrashDataTest crash_data(gwp_asan::Error::INVALID_FREE, &meta);
  crash_data.SetCrashAddress(0x1001);

  crash_data.DumpCause(&log_);
  ASSERT_TRUE(lseek(log_.tfd, 0, SEEK_SET) == 0);
  std::string tombstone_contents;
  ASSERT_TRUE(android::base::ReadFdToString(log_.tfd, &tombstone_contents));
  ASSERT_THAT(
      tombstone_contents,
      MatchesRegex(
          "Cause: \\[GWP-ASan\\]: Invalid \\(Wild\\) Free, 1 byte into a 32-byte "
          "allocation at 0x[a-fA-F0-9]+\n"));
}

TEST_F(TombstoneTest, gwp_asan_cause_invalid_free_outside) {
  gwp_asan::AllocationMetadata meta;
  meta.Addr = 0x1000;
  meta.RequestedSize = 32;

  GwpAsanCrashDataTest crash_data(gwp_asan::Error::INVALID_FREE, &meta);
  crash_data.SetCrashAddress(0x1021);

  crash_data.DumpCause(&log_);
  ASSERT_TRUE(lseek(log_.tfd, 0, SEEK_SET) == 0);
  std::string tombstone_contents;
  ASSERT_TRUE(android::base::ReadFdToString(log_.tfd, &tombstone_contents));
  ASSERT_THAT(
      tombstone_contents,
      MatchesRegex(
          "Cause: \\[GWP-ASan\\]: Invalid \\(Wild\\) Free, 33 bytes right of a 32-byte "
          "allocation at 0x[a-fA-F0-9]+\n"));
}
