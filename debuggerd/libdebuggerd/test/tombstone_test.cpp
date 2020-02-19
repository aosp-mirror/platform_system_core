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

// Include tombstone.cpp to define log_tag before GWP-ASan includes log.
#include "tombstone.cpp"

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

TEST_F(TombstoneTest, single_map) {
#if defined(__LP64__)
  unwinder_mock_->MockAddMap(0x123456789abcd000UL, 0x123456789abdf000UL, 0, 0, "", 0);
#else
  unwinder_mock_->MockAddMap(0x1234000, 0x1235000, 0, 0, "", 0);
#endif

  dump_all_maps(&log_, unwinder_mock_.get(), 0);

  std::string tombstone_contents;
  ASSERT_TRUE(lseek(log_.tfd, 0, SEEK_SET) == 0);
  ASSERT_TRUE(android::base::ReadFdToString(log_.tfd, &tombstone_contents));
  const char* expected_dump = \
"\nmemory map (1 entry):\n"
#if defined(__LP64__)
"    12345678'9abcd000-12345678'9abdefff ---         0     12000\n";
#else
"    01234000-01234fff ---         0      1000\n";
#endif
  ASSERT_STREQ(expected_dump, tombstone_contents.c_str());

  ASSERT_STREQ("", amfd_data_.c_str());

  // Verify that the log buf is empty, and no error messages.
  ASSERT_STREQ("", getFakeLogBuf().c_str());
  ASSERT_STREQ("", getFakeLogPrint().c_str());
}

TEST_F(TombstoneTest, single_map_elf_build_id) {
  uint64_t build_id_offset;
#if defined(__LP64__)
  build_id_offset = 0x123456789abcd000UL;
  unwinder_mock_->MockAddMap(build_id_offset, 0x123456789abdf000UL, 0, PROT_READ,
                             "/system/lib/libfake.so", 0);
#else
  build_id_offset = 0x1234000;
  unwinder_mock_->MockAddMap(0x1234000, 0x1235000, 0, PROT_READ, "/system/lib/libfake.so", 0);
#endif

  unwinder_mock_->MockSetBuildID(
      build_id_offset,
      std::string{static_cast<char>(0xab), static_cast<char>(0xcd), static_cast<char>(0xef),
                  static_cast<char>(0x12), static_cast<char>(0x34), static_cast<char>(0x56),
                  static_cast<char>(0x78), static_cast<char>(0x90), static_cast<char>(0xab),
                  static_cast<char>(0xcd), static_cast<char>(0xef), static_cast<char>(0x12),
                  static_cast<char>(0x34), static_cast<char>(0x56), static_cast<char>(0x78),
                  static_cast<char>(0x90)});
  dump_all_maps(&log_, unwinder_mock_.get(), 0);

  std::string tombstone_contents;
  ASSERT_TRUE(lseek(log_.tfd, 0, SEEK_SET) == 0);
  ASSERT_TRUE(android::base::ReadFdToString(log_.tfd, &tombstone_contents));
  const char* expected_dump = \
"\nmemory map (1 entry):\n"
#if defined(__LP64__)
"    12345678'9abcd000-12345678'9abdefff r--         0     12000  /system/lib/libfake.so (BuildId: abcdef1234567890abcdef1234567890)\n";
#else
"    01234000-01234fff r--         0      1000  /system/lib/libfake.so (BuildId: abcdef1234567890abcdef1234567890)\n";
#endif
  ASSERT_STREQ(expected_dump, tombstone_contents.c_str());

  ASSERT_STREQ("", amfd_data_.c_str());

  // Verify that the log buf is empty, and no error messages.
  ASSERT_STREQ("", getFakeLogBuf().c_str());
  ASSERT_STREQ("", getFakeLogPrint().c_str());
}

TEST_F(TombstoneTest, multiple_maps) {
  unwinder_mock_->MockAddMap(0xa234000, 0xa235000, 0, 0, "", 0);
  unwinder_mock_->MockAddMap(0xa334000, 0xa335000, 0xf000, PROT_READ, "", 0);
  unwinder_mock_->MockAddMap(0xa434000, 0xa435000, 0x1000, PROT_WRITE, "", 0xd000);
  unwinder_mock_->MockAddMap(0xa534000, 0xa535000, 0x3000, PROT_EXEC, "", 0x2000);
  unwinder_mock_->MockAddMap(0xa634000, 0xa635000, 0, PROT_READ | PROT_WRITE | PROT_EXEC,
                             "/system/lib/fake.so", 0);

  dump_all_maps(&log_, unwinder_mock_.get(), 0);

  std::string tombstone_contents;
  ASSERT_TRUE(lseek(log_.tfd, 0, SEEK_SET) == 0);
  ASSERT_TRUE(android::base::ReadFdToString(log_.tfd, &tombstone_contents));
  const char* expected_dump =
      "\nmemory map (5 entries):\n"
#if defined(__LP64__)
      "    00000000'0a234000-00000000'0a234fff ---         0      1000\n"
      "    00000000'0a334000-00000000'0a334fff r--      f000      1000\n"
      "    00000000'0a434000-00000000'0a434fff -w-      1000      1000  (load bias 0xd000)\n"
      "    00000000'0a534000-00000000'0a534fff --x      3000      1000  (load bias 0x2000)\n"
      "    00000000'0a634000-00000000'0a634fff rwx         0      1000  /system/lib/fake.so\n";
#else
      "    0a234000-0a234fff ---         0      1000\n"
      "    0a334000-0a334fff r--      f000      1000\n"
      "    0a434000-0a434fff -w-      1000      1000  (load bias 0xd000)\n"
      "    0a534000-0a534fff --x      3000      1000  (load bias 0x2000)\n"
      "    0a634000-0a634fff rwx         0      1000  /system/lib/fake.so\n";
#endif
  ASSERT_STREQ(expected_dump, tombstone_contents.c_str());

  ASSERT_STREQ("", amfd_data_.c_str());

  // Verify that the log buf is empty, and no error messages.
  ASSERT_STREQ("", getFakeLogBuf().c_str());
  ASSERT_STREQ("", getFakeLogPrint().c_str());
}

TEST_F(TombstoneTest, multiple_maps_fault_address_before) {
  unwinder_mock_->MockAddMap(0xa434000, 0xa435000, 0x1000, PROT_WRITE, "", 0xd000);
  unwinder_mock_->MockAddMap(0xa534000, 0xa535000, 0x3000, PROT_EXEC, "", 0x2000);
  unwinder_mock_->MockAddMap(0xa634000, 0xa635000, 0, PROT_READ | PROT_WRITE | PROT_EXEC,
                             "/system/lib/fake.so", 0);

  dump_all_maps(&log_, unwinder_mock_.get(), 0x1000);

  std::string tombstone_contents;
  ASSERT_TRUE(lseek(log_.tfd, 0, SEEK_SET) == 0);
  ASSERT_TRUE(android::base::ReadFdToString(log_.tfd, &tombstone_contents));
  const char* expected_dump =
      "\nmemory map (3 entries):\n"
#if defined(__LP64__)
      "--->Fault address falls at 00000000'00001000 before any mapped regions\n"
      "    00000000'0a434000-00000000'0a434fff -w-      1000      1000  (load bias 0xd000)\n"
      "    00000000'0a534000-00000000'0a534fff --x      3000      1000  (load bias 0x2000)\n"
      "    00000000'0a634000-00000000'0a634fff rwx         0      1000  /system/lib/fake.so\n";
#else
      "--->Fault address falls at 00001000 before any mapped regions\n"
      "    0a434000-0a434fff -w-      1000      1000  (load bias 0xd000)\n"
      "    0a534000-0a534fff --x      3000      1000  (load bias 0x2000)\n"
      "    0a634000-0a634fff rwx         0      1000  /system/lib/fake.so\n";
#endif
  ASSERT_STREQ(expected_dump, tombstone_contents.c_str());

  ASSERT_STREQ("", amfd_data_.c_str());

  // Verify that the log buf is empty, and no error messages.
  ASSERT_STREQ("", getFakeLogBuf().c_str());
  ASSERT_STREQ("", getFakeLogPrint().c_str());
}

TEST_F(TombstoneTest, multiple_maps_fault_address_between) {
  unwinder_mock_->MockAddMap(0xa434000, 0xa435000, 0x1000, PROT_WRITE, "", 0xd000);
  unwinder_mock_->MockAddMap(0xa534000, 0xa535000, 0x3000, PROT_EXEC, "", 0x2000);
  unwinder_mock_->MockAddMap(0xa634000, 0xa635000, 0, PROT_READ | PROT_WRITE | PROT_EXEC,
                             "/system/lib/fake.so", 0);

  dump_all_maps(&log_, unwinder_mock_.get(), 0xa533000);

  std::string tombstone_contents;
  ASSERT_TRUE(lseek(log_.tfd, 0, SEEK_SET) == 0);
  ASSERT_TRUE(android::base::ReadFdToString(log_.tfd, &tombstone_contents));
  const char* expected_dump =
      "\nmemory map (3 entries): (fault address prefixed with --->)\n"
#if defined(__LP64__)
      "    00000000'0a434000-00000000'0a434fff -w-      1000      1000  (load bias 0xd000)\n"
      "--->Fault address falls at 00000000'0a533000 between mapped regions\n"
      "    00000000'0a534000-00000000'0a534fff --x      3000      1000  (load bias 0x2000)\n"
      "    00000000'0a634000-00000000'0a634fff rwx         0      1000  /system/lib/fake.so\n";
#else
      "    0a434000-0a434fff -w-      1000      1000  (load bias 0xd000)\n"
      "--->Fault address falls at 0a533000 between mapped regions\n"
      "    0a534000-0a534fff --x      3000      1000  (load bias 0x2000)\n"
      "    0a634000-0a634fff rwx         0      1000  /system/lib/fake.so\n";
#endif
  ASSERT_STREQ(expected_dump, tombstone_contents.c_str());

  ASSERT_STREQ("", amfd_data_.c_str());

  // Verify that the log buf is empty, and no error messages.
  ASSERT_STREQ("", getFakeLogBuf().c_str());
  ASSERT_STREQ("", getFakeLogPrint().c_str());
}

TEST_F(TombstoneTest, multiple_maps_fault_address_in_map) {
  unwinder_mock_->MockAddMap(0xa434000, 0xa435000, 0x1000, PROT_WRITE, "", 0xd000);
  unwinder_mock_->MockAddMap(0xa534000, 0xa535000, 0x3000, PROT_EXEC, "", 0x2000);
  unwinder_mock_->MockAddMap(0xa634000, 0xa635000, 0, PROT_READ | PROT_WRITE | PROT_EXEC,
                             "/system/lib/fake.so", 0);

  dump_all_maps(&log_, unwinder_mock_.get(), 0xa534040);

  std::string tombstone_contents;
  ASSERT_TRUE(lseek(log_.tfd, 0, SEEK_SET) == 0);
  ASSERT_TRUE(android::base::ReadFdToString(log_.tfd, &tombstone_contents));
  const char* expected_dump =
      "\nmemory map (3 entries): (fault address prefixed with --->)\n"
#if defined(__LP64__)
      "    00000000'0a434000-00000000'0a434fff -w-      1000      1000  (load bias 0xd000)\n"
      "--->00000000'0a534000-00000000'0a534fff --x      3000      1000  (load bias 0x2000)\n"
      "    00000000'0a634000-00000000'0a634fff rwx         0      1000  /system/lib/fake.so\n";
#else
      "    0a434000-0a434fff -w-      1000      1000  (load bias 0xd000)\n"
      "--->0a534000-0a534fff --x      3000      1000  (load bias 0x2000)\n"
      "    0a634000-0a634fff rwx         0      1000  /system/lib/fake.so\n";
#endif
  ASSERT_STREQ(expected_dump, tombstone_contents.c_str());

  ASSERT_STREQ("", amfd_data_.c_str());

  // Verify that the log buf is empty, and no error messages.
  ASSERT_STREQ("", getFakeLogBuf().c_str());
  ASSERT_STREQ("", getFakeLogPrint().c_str());
}

TEST_F(TombstoneTest, multiple_maps_fault_address_after) {
  unwinder_mock_->MockAddMap(0xa434000, 0xa435000, 0x1000, PROT_WRITE, "", 0xd000);
  unwinder_mock_->MockAddMap(0xa534000, 0xa535000, 0x3000, PROT_EXEC, "", 0x2000);
  unwinder_mock_->MockAddMap(0xa634000, 0xa635000, 0, PROT_READ | PROT_WRITE | PROT_EXEC,
                             "/system/lib/fake.so", 0);

#if defined(__LP64__)
  uint64_t addr = 0x12345a534040UL;
#else
  uint64_t addr = 0xf534040UL;
#endif
  dump_all_maps(&log_, unwinder_mock_.get(), addr);

  std::string tombstone_contents;
  ASSERT_TRUE(lseek(log_.tfd, 0, SEEK_SET) == 0);
  ASSERT_TRUE(android::base::ReadFdToString(log_.tfd, &tombstone_contents));
  const char* expected_dump =
      "\nmemory map (3 entries): (fault address prefixed with --->)\n"
#if defined(__LP64__)
      "    00000000'0a434000-00000000'0a434fff -w-      1000      1000  (load bias 0xd000)\n"
      "    00000000'0a534000-00000000'0a534fff --x      3000      1000  (load bias 0x2000)\n"
      "    00000000'0a634000-00000000'0a634fff rwx         0      1000  /system/lib/fake.so\n"
      "--->Fault address falls at 00001234'5a534040 after any mapped regions\n";
#else
      "    0a434000-0a434fff -w-      1000      1000  (load bias 0xd000)\n"
      "    0a534000-0a534fff --x      3000      1000  (load bias 0x2000)\n"
      "    0a634000-0a634fff rwx         0      1000  /system/lib/fake.so\n"
      "--->Fault address falls at 0f534040 after any mapped regions\n";
#endif
  ASSERT_STREQ(expected_dump, tombstone_contents.c_str());

  ASSERT_STREQ("", amfd_data_.c_str());

  // Verify that the log buf is empty, and no error messages.
  ASSERT_STREQ("", getFakeLogBuf().c_str());
  ASSERT_STREQ("", getFakeLogPrint().c_str());
}

TEST_F(TombstoneTest, dump_log_file_error) {
  log_.should_retrieve_logcat = true;
  dump_log_file(&log_, 123, "/fake/filename", 10);

  std::string tombstone_contents;
  ASSERT_TRUE(lseek(log_.tfd, 0, SEEK_SET) == 0);
  ASSERT_TRUE(android::base::ReadFdToString(log_.tfd, &tombstone_contents));
  ASSERT_STREQ("", tombstone_contents.c_str());

  ASSERT_STREQ("", getFakeLogBuf().c_str());
  ASSERT_STREQ("6 DEBUG Unable to open /fake/filename: Permission denied\n\n",
               getFakeLogPrint().c_str());

  ASSERT_STREQ("", amfd_data_.c_str());
}

TEST_F(TombstoneTest, dump_header_info) {
  dump_header_info(&log_);

  std::string expected = android::base::StringPrintf(
      "Build fingerprint: '%s'\nRevision: '%s'\n",
      android::base::GetProperty("ro.build.fingerprint", "unknown").c_str(),
      android::base::GetProperty("ro.revision", "unknown").c_str());
  expected += android::base::StringPrintf("ABI: '%s'\n", ABI_STRING);
  ASSERT_STREQ(expected.c_str(), amfd_data_.c_str());
}

TEST_F(TombstoneTest, dump_thread_info_uid) {
  dump_thread_info(&log_, ThreadInfo{.uid = 1,
                                     .tid = 3,
                                     .thread_name = "some_thread",
                                     .pid = 2,
                                     .process_name = "some_process"});
  std::string expected = "pid: 2, tid: 3, name: some_thread  >>> some_process <<<\nuid: 1\n";
  ASSERT_STREQ(expected.c_str(), amfd_data_.c_str());
}

TEST_F(TombstoneTest, dump_timestamp) {
  setenv("TZ", "UTC", 1);
  tzset();
  dump_timestamp(&log_, 0);
  ASSERT_STREQ("Timestamp: 1970-01-01 00:00:00+0000\n", amfd_data_.c_str());
}

class GwpAsanCrashDataTest : public GwpAsanCrashData {
public:
  GwpAsanCrashDataTest(
      gwp_asan::Error error,
      const gwp_asan::AllocationMetadata *responsible_allocation) :
      GwpAsanCrashData(nullptr, 0u, 0u, ThreadInfo{}) {
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
  meta.Size = 32;

  GwpAsanCrashDataTest crash_data(gwp_asan::Error::USE_AFTER_FREE, &meta);
  crash_data.SetCrashAddress(0x1000);

  crash_data.DumpCause(&log_);
  ASSERT_TRUE(lseek(log_.tfd, 0, SEEK_SET) == 0);
  std::string tombstone_contents;
  ASSERT_TRUE(android::base::ReadFdToString(log_.tfd, &tombstone_contents));
  ASSERT_THAT(tombstone_contents,
              MatchesRegex("Cause: \\[GWP-ASan\\]: Use After Free on a 32-byte "
                           "allocation at 0x[a-fA-F0-9]+\n"));
}

TEST_F(TombstoneTest, gwp_asan_cause_double_free) {
  gwp_asan::AllocationMetadata meta;
  meta.Addr = 0x1000;
  meta.Size = 32;

  GwpAsanCrashDataTest crash_data(gwp_asan::Error::DOUBLE_FREE, &meta);
  crash_data.SetCrashAddress(0x1000);

  crash_data.DumpCause(&log_);
  ASSERT_TRUE(lseek(log_.tfd, 0, SEEK_SET) == 0);
  std::string tombstone_contents;
  ASSERT_TRUE(android::base::ReadFdToString(log_.tfd, &tombstone_contents));
  ASSERT_THAT(tombstone_contents,
              MatchesRegex("Cause: \\[GWP-ASan\\]: Double Free on a 32-byte "
                           "allocation at 0x[a-fA-F0-9]+\n"));
}

TEST_F(TombstoneTest, gwp_asan_cause_overflow) {
  gwp_asan::AllocationMetadata meta;
  meta.Addr = 0x1000;
  meta.Size = 32;

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
  meta.Size = 32;

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
  meta.Size = 32;

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
  meta.Size = 32;

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

