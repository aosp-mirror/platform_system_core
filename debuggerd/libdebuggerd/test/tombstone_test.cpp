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

#include <memory>
#include <string>

#include <android-base/file.h>
#include <android-base/properties.h>
#include <gtest/gtest.h>

#include "libdebuggerd/utility.h"

#include "BacktraceMock.h"
#include "elf_fake.h"
#include "host_signal_fixup.h"
#include "log_fake.h"

#include "tombstone.cpp"

void dump_registers(log_t*, pid_t) {
}

void dump_memory_and_code(log_t*, Backtrace*) {
}

void dump_backtrace_to_log(Backtrace*, log_t*, char const*) {
}

class TombstoneTest : public ::testing::Test {
 protected:
  virtual void SetUp() {
    map_mock_.reset(new BacktraceMapMock());

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
    elf_set_fake_build_id("");
  }

  virtual void TearDown() {
    if (log_.tfd >= 0) {
      close(log_.tfd);
    }
  }

  std::unique_ptr<BacktraceMapMock> map_mock_;

  log_t log_;
  std::string amfd_data_;
};

TEST_F(TombstoneTest, single_map) {
  backtrace_map_t map;
#if defined(__LP64__)
  map.start = 0x123456789abcd000UL;
  map.end = 0x123456789abdf000UL;
#else
  map.start = 0x1234000;
  map.end = 0x1235000;
#endif
  map_mock_->AddMap(map);

  dump_all_maps(&log_, map_mock_.get(), nullptr, 0);

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
  backtrace_map_t map;
#if defined(__LP64__)
  map.start = 0x123456789abcd000UL;
  map.end = 0x123456789abdf000UL;
#else
  map.start = 0x1234000;
  map.end = 0x1235000;
#endif
  map.flags = PROT_READ;
  map.name = "/system/lib/libfake.so";
  map_mock_->AddMap(map);

  elf_set_fake_build_id("abcdef1234567890abcdef1234567890");
  dump_all_maps(&log_, map_mock_.get(), nullptr, 0);

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

// Even though build id is present, it should not be printed in either of
// these cases.
TEST_F(TombstoneTest, single_map_no_build_id) {
  backtrace_map_t map;
#if defined(__LP64__)
  map.start = 0x123456789abcd000UL;
  map.end = 0x123456789abdf000UL;
#else
  map.start = 0x1234000;
  map.end = 0x1235000;
#endif
  map.flags = PROT_WRITE;
  map_mock_->AddMap(map);

  map.name = "/system/lib/libfake.so";
  map_mock_->AddMap(map);

  elf_set_fake_build_id("abcdef1234567890abcdef1234567890");
  dump_all_maps(&log_, map_mock_.get(), nullptr, 0);

  std::string tombstone_contents;
  ASSERT_TRUE(lseek(log_.tfd, 0, SEEK_SET) == 0);
  ASSERT_TRUE(android::base::ReadFdToString(log_.tfd, &tombstone_contents));
  const char* expected_dump = \
"\nmemory map (2 entries):\n"
#if defined(__LP64__)
"    12345678'9abcd000-12345678'9abdefff -w-         0     12000\n"
"    12345678'9abcd000-12345678'9abdefff -w-         0     12000  /system/lib/libfake.so\n";
#else
"    01234000-01234fff -w-         0      1000\n"
"    01234000-01234fff -w-         0      1000  /system/lib/libfake.so\n";
#endif
  ASSERT_STREQ(expected_dump, tombstone_contents.c_str());

  ASSERT_STREQ("", amfd_data_.c_str());

  // Verify that the log buf is empty, and no error messages.
  ASSERT_STREQ("", getFakeLogBuf().c_str());
  ASSERT_STREQ("", getFakeLogPrint().c_str());
}

TEST_F(TombstoneTest, multiple_maps) {
  backtrace_map_t map;

  map.start = 0xa234000;
  map.end = 0xa235000;
  map_mock_->AddMap(map);

  map.start = 0xa334000;
  map.end = 0xa335000;
  map.offset = 0xf000;
  map.flags = PROT_READ;
  map_mock_->AddMap(map);

  map.start = 0xa434000;
  map.end = 0xa435000;
  map.offset = 0x1000;
  map.load_bias = 0xd000;
  map.flags = PROT_WRITE;
  map_mock_->AddMap(map);

  map.start = 0xa534000;
  map.end = 0xa535000;
  map.offset = 0x3000;
  map.load_bias = 0x2000;
  map.flags = PROT_EXEC;
  map_mock_->AddMap(map);

  map.start = 0xa634000;
  map.end = 0xa635000;
  map.offset = 0;
  map.load_bias = 0;
  map.flags = PROT_READ | PROT_WRITE | PROT_EXEC;
  map.name = "/system/lib/fake.so";
  map_mock_->AddMap(map);

  dump_all_maps(&log_, map_mock_.get(), nullptr, 0);

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
  backtrace_map_t map;

  map.start = 0xa434000;
  map.end = 0xa435000;
  map.offset = 0x1000;
  map.load_bias = 0xd000;
  map.flags = PROT_WRITE;
  map_mock_->AddMap(map);

  map.start = 0xa534000;
  map.end = 0xa535000;
  map.offset = 0x3000;
  map.load_bias = 0x2000;
  map.flags = PROT_EXEC;
  map_mock_->AddMap(map);

  map.start = 0xa634000;
  map.end = 0xa635000;
  map.offset = 0;
  map.load_bias = 0;
  map.flags = PROT_READ | PROT_WRITE | PROT_EXEC;
  map.name = "/system/lib/fake.so";
  map_mock_->AddMap(map);

  dump_all_maps(&log_, map_mock_.get(), nullptr, 0x1000);

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
  backtrace_map_t map;

  map.start = 0xa434000;
  map.end = 0xa435000;
  map.offset = 0x1000;
  map.load_bias = 0xd000;
  map.flags = PROT_WRITE;
  map_mock_->AddMap(map);

  map.start = 0xa534000;
  map.end = 0xa535000;
  map.offset = 0x3000;
  map.load_bias = 0x2000;
  map.flags = PROT_EXEC;
  map_mock_->AddMap(map);

  map.start = 0xa634000;
  map.end = 0xa635000;
  map.offset = 0;
  map.load_bias = 0;
  map.flags = PROT_READ | PROT_WRITE | PROT_EXEC;
  map.name = "/system/lib/fake.so";
  map_mock_->AddMap(map);

  dump_all_maps(&log_, map_mock_.get(), nullptr, 0xa533000);

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
  backtrace_map_t map;

  map.start = 0xa434000;
  map.end = 0xa435000;
  map.offset = 0x1000;
  map.load_bias = 0xd000;
  map.flags = PROT_WRITE;
  map_mock_->AddMap(map);

  map.start = 0xa534000;
  map.end = 0xa535000;
  map.offset = 0x3000;
  map.load_bias = 0x2000;
  map.flags = PROT_EXEC;
  map_mock_->AddMap(map);

  map.start = 0xa634000;
  map.end = 0xa635000;
  map.offset = 0;
  map.load_bias = 0;
  map.flags = PROT_READ | PROT_WRITE | PROT_EXEC;
  map.name = "/system/lib/fake.so";
  map_mock_->AddMap(map);

  dump_all_maps(&log_, map_mock_.get(), nullptr, 0xa534040);

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
  backtrace_map_t map;

  map.start = 0xa434000;
  map.end = 0xa435000;
  map.offset = 0x1000;
  map.load_bias = 0xd000;
  map.flags = PROT_WRITE;
  map_mock_->AddMap(map);

  map.start = 0xa534000;
  map.end = 0xa535000;
  map.offset = 0x3000;
  map.load_bias = 0x2000;
  map.flags = PROT_EXEC;
  map_mock_->AddMap(map);

  map.start = 0xa634000;
  map.end = 0xa635000;
  map.offset = 0;
  map.load_bias = 0;
  map.flags = PROT_READ | PROT_WRITE | PROT_EXEC;
  map.name = "/system/lib/fake.so";
  map_mock_->AddMap(map);

#if defined(__LP64__)
  uint64_t addr = 0x12345a534040UL;
#else
  uint64_t addr = 0xf534040UL;
#endif
  dump_all_maps(&log_, map_mock_.get(), nullptr, addr);

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
