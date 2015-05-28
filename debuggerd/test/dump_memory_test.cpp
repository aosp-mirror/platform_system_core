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

#include <gtest/gtest.h>
#include <base/file.h>

#include "BacktraceMock.h"
#include "log_fake.h"
#include "utility.h"

const char g_expected_full_dump[] =
"\nmemory near r1:\n"
#if defined(__LP64__)
"    0000000012345658 0706050403020100 0f0e0d0c0b0a0908  ................\n"
"    0000000012345668 1716151413121110 1f1e1d1c1b1a1918  ................\n"
"    0000000012345678 2726252423222120 2f2e2d2c2b2a2928   !\"#$%&'()*+,-./\n"
"    0000000012345688 3736353433323130 3f3e3d3c3b3a3938  0123456789:;<=>?\n"
"    0000000012345698 4746454443424140 4f4e4d4c4b4a4948  @ABCDEFGHIJKLMNO\n"
"    00000000123456a8 5756555453525150 5f5e5d5c5b5a5958  PQRSTUVWXYZ[\\]^_\n"
"    00000000123456b8 6766656463626160 6f6e6d6c6b6a6968  `abcdefghijklmno\n"
"    00000000123456c8 7776757473727170 7f7e7d7c7b7a7978  pqrstuvwxyz{|}~.\n"
"    00000000123456d8 8786858483828180 8f8e8d8c8b8a8988  ................\n"
"    00000000123456e8 9796959493929190 9f9e9d9c9b9a9998  ................\n"
"    00000000123456f8 a7a6a5a4a3a2a1a0 afaeadacabaaa9a8  ................\n"
"    0000000012345708 b7b6b5b4b3b2b1b0 bfbebdbcbbbab9b8  ................\n"
"    0000000012345718 c7c6c5c4c3c2c1c0 cfcecdcccbcac9c8  ................\n"
"    0000000012345728 d7d6d5d4d3d2d1d0 dfdedddcdbdad9d8  ................\n"
"    0000000012345738 e7e6e5e4e3e2e1e0 efeeedecebeae9e8  ................\n"
"    0000000012345748 f7f6f5f4f3f2f1f0 fffefdfcfbfaf9f8  ................\n";
#else
"    12345658 03020100 07060504 0b0a0908 0f0e0d0c  ................\n"
"    12345668 13121110 17161514 1b1a1918 1f1e1d1c  ................\n"
"    12345678 23222120 27262524 2b2a2928 2f2e2d2c   !\"#$%&'()*+,-./\n"
"    12345688 33323130 37363534 3b3a3938 3f3e3d3c  0123456789:;<=>?\n"
"    12345698 43424140 47464544 4b4a4948 4f4e4d4c  @ABCDEFGHIJKLMNO\n"
"    123456a8 53525150 57565554 5b5a5958 5f5e5d5c  PQRSTUVWXYZ[\\]^_\n"
"    123456b8 63626160 67666564 6b6a6968 6f6e6d6c  `abcdefghijklmno\n"
"    123456c8 73727170 77767574 7b7a7978 7f7e7d7c  pqrstuvwxyz{|}~.\n"
"    123456d8 83828180 87868584 8b8a8988 8f8e8d8c  ................\n"
"    123456e8 93929190 97969594 9b9a9998 9f9e9d9c  ................\n"
"    123456f8 a3a2a1a0 a7a6a5a4 abaaa9a8 afaeadac  ................\n"
"    12345708 b3b2b1b0 b7b6b5b4 bbbab9b8 bfbebdbc  ................\n"
"    12345718 c3c2c1c0 c7c6c5c4 cbcac9c8 cfcecdcc  ................\n"
"    12345728 d3d2d1d0 d7d6d5d4 dbdad9d8 dfdedddc  ................\n"
"    12345738 e3e2e1e0 e7e6e5e4 ebeae9e8 efeeedec  ................\n"
"    12345748 f3f2f1f0 f7f6f5f4 fbfaf9f8 fffefdfc  ................\n";
#endif

const char g_expected_partial_dump[] = \
"\nmemory near pc:\n"
#if defined(__LP64__)
"    00000000123455e0 0706050403020100 0f0e0d0c0b0a0908  ................\n"
"    00000000123455f0 1716151413121110 1f1e1d1c1b1a1918  ................\n"
"    0000000012345600 2726252423222120 2f2e2d2c2b2a2928   !\"#$%&'()*+,-./\n"
"    0000000012345610 3736353433323130 3f3e3d3c3b3a3938  0123456789:;<=>?\n"
"    0000000012345620 4746454443424140 4f4e4d4c4b4a4948  @ABCDEFGHIJKLMNO\n"
"    0000000012345630 5756555453525150 5f5e5d5c5b5a5958  PQRSTUVWXYZ[\\]^_\n"
"    0000000012345640 6766656463626160 ----------------  `abcdefg........\n"
"    0000000012345650 ---------------- ----------------  ................\n"
"    0000000012345660 ---------------- ----------------  ................\n"
"    0000000012345670 ---------------- ----------------  ................\n"
"    0000000012345680 ---------------- ----------------  ................\n"
"    0000000012345690 ---------------- ----------------  ................\n"
"    00000000123456a0 ---------------- ----------------  ................\n"
"    00000000123456b0 ---------------- ----------------  ................\n"
"    00000000123456c0 ---------------- ----------------  ................\n"
"    00000000123456d0 ---------------- ----------------  ................\n";
#else
"    123455e0 03020100 07060504 0b0a0908 0f0e0d0c  ................\n"
"    123455f0 13121110 17161514 1b1a1918 1f1e1d1c  ................\n"
"    12345600 23222120 27262524 2b2a2928 2f2e2d2c   !\"#$%&'()*+,-./\n"
"    12345610 33323130 37363534 3b3a3938 3f3e3d3c  0123456789:;<=>?\n"
"    12345620 43424140 47464544 4b4a4948 4f4e4d4c  @ABCDEFGHIJKLMNO\n"
"    12345630 53525150 57565554 5b5a5958 5f5e5d5c  PQRSTUVWXYZ[\\]^_\n"
"    12345640 63626160 67666564 -------- --------  `abcdefg........\n"
"    12345650 -------- -------- -------- --------  ................\n"
"    12345660 -------- -------- -------- --------  ................\n"
"    12345670 -------- -------- -------- --------  ................\n"
"    12345680 -------- -------- -------- --------  ................\n"
"    12345690 -------- -------- -------- --------  ................\n"
"    123456a0 -------- -------- -------- --------  ................\n"
"    123456b0 -------- -------- -------- --------  ................\n"
"    123456c0 -------- -------- -------- --------  ................\n"
"    123456d0 -------- -------- -------- --------  ................\n";
#endif

class DumpMemoryTest : public ::testing::Test {
 protected:
  virtual void SetUp() {
    map_mock_.reset(new BacktraceMapMock());
    backtrace_mock_.reset(new BacktraceMock(map_mock_.get()));

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
    log_.amfd = -1;
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

  std::unique_ptr<BacktraceMapMock> map_mock_;
  std::unique_ptr<BacktraceMock> backtrace_mock_;

  log_t log_;
};

TEST_F(DumpMemoryTest, aligned_addr) {
  uint8_t buffer[256];
  for (size_t i = 0; i < sizeof(buffer); i++) {
    buffer[i] = i;
  }
  backtrace_mock_->SetReadData(buffer, sizeof(buffer));

  dump_memory(&log_, backtrace_mock_.get(), 0x12345678, "memory near %.2s:", "r1");

  std::string tombstone_contents;
  ASSERT_TRUE(lseek(log_.tfd, 0, SEEK_SET) == 0);
  ASSERT_TRUE(android::base::ReadFdToString(log_.tfd, &tombstone_contents));
  ASSERT_STREQ(g_expected_full_dump, tombstone_contents.c_str());

  // Verify that the log buf is empty, and no error messages.
  ASSERT_STREQ("", getFakeLogBuf().c_str());
  ASSERT_STREQ("", getFakeLogPrint().c_str());
}

TEST_F(DumpMemoryTest, partial_read) {
  uint8_t buffer[256];
  for (size_t i = 0; i < sizeof(buffer); i++) {
    buffer[i] = i;
  }
  backtrace_mock_->SetReadData(buffer, sizeof(buffer));
  backtrace_mock_->SetPartialReadAmount(96);

  dump_memory(&log_, backtrace_mock_.get(), 0x12345679, "memory near %.2s:", "r1");

  std::string tombstone_contents;
  ASSERT_TRUE(lseek(log_.tfd, 0, SEEK_SET) == 0);
  ASSERT_TRUE(android::base::ReadFdToString(log_.tfd, &tombstone_contents));
  ASSERT_STREQ(g_expected_full_dump, tombstone_contents.c_str());

  // Verify that the log buf is empty, and no error messages.
  ASSERT_STREQ("", getFakeLogBuf().c_str());
  ASSERT_STREQ("", getFakeLogPrint().c_str());
}

TEST_F(DumpMemoryTest, unaligned_addr) {
  uint8_t buffer[256];
  for (size_t i = 0; i < sizeof(buffer); i++) {
    buffer[i] = i;
  }
  backtrace_mock_->SetReadData(buffer, sizeof(buffer));

  dump_memory(&log_, backtrace_mock_.get(), 0x12345679, "memory near %.2s:", "r1");

  std::string tombstone_contents;
  ASSERT_TRUE(lseek(log_.tfd, 0, SEEK_SET) == 0);
  ASSERT_TRUE(android::base::ReadFdToString(log_.tfd, &tombstone_contents));
  ASSERT_STREQ(g_expected_full_dump, tombstone_contents.c_str());

  // Verify that the log buf is empty, and no error messages.
  ASSERT_STREQ("", getFakeLogBuf().c_str());
  ASSERT_STREQ("", getFakeLogPrint().c_str());
}

TEST_F(DumpMemoryTest, memory_unreadable) {
  dump_memory(&log_, backtrace_mock_.get(), 0xa2345678, "memory near pc:");

  std::string tombstone_contents;
  ASSERT_TRUE(lseek(log_.tfd, 0, SEEK_SET) == 0);
  ASSERT_TRUE(android::base::ReadFdToString(log_.tfd, &tombstone_contents));
  const char* expected_dump = \
"\nmemory near pc:\n"
#if defined(__LP64__)
"    00000000a2345658 ---------------- ----------------  ................\n"
"    00000000a2345668 ---------------- ----------------  ................\n"
"    00000000a2345678 ---------------- ----------------  ................\n"
"    00000000a2345688 ---------------- ----------------  ................\n"
"    00000000a2345698 ---------------- ----------------  ................\n"
"    00000000a23456a8 ---------------- ----------------  ................\n"
"    00000000a23456b8 ---------------- ----------------  ................\n"
"    00000000a23456c8 ---------------- ----------------  ................\n"
"    00000000a23456d8 ---------------- ----------------  ................\n"
"    00000000a23456e8 ---------------- ----------------  ................\n"
"    00000000a23456f8 ---------------- ----------------  ................\n"
"    00000000a2345708 ---------------- ----------------  ................\n"
"    00000000a2345718 ---------------- ----------------  ................\n"
"    00000000a2345728 ---------------- ----------------  ................\n"
"    00000000a2345738 ---------------- ----------------  ................\n"
"    00000000a2345748 ---------------- ----------------  ................\n";
#else
"    a2345658 -------- -------- -------- --------  ................\n"
"    a2345668 -------- -------- -------- --------  ................\n"
"    a2345678 -------- -------- -------- --------  ................\n"
"    a2345688 -------- -------- -------- --------  ................\n"
"    a2345698 -------- -------- -------- --------  ................\n"
"    a23456a8 -------- -------- -------- --------  ................\n"
"    a23456b8 -------- -------- -------- --------  ................\n"
"    a23456c8 -------- -------- -------- --------  ................\n"
"    a23456d8 -------- -------- -------- --------  ................\n"
"    a23456e8 -------- -------- -------- --------  ................\n"
"    a23456f8 -------- -------- -------- --------  ................\n"
"    a2345708 -------- -------- -------- --------  ................\n"
"    a2345718 -------- -------- -------- --------  ................\n"
"    a2345728 -------- -------- -------- --------  ................\n"
"    a2345738 -------- -------- -------- --------  ................\n"
"    a2345748 -------- -------- -------- --------  ................\n";
#endif
  ASSERT_STREQ(expected_dump, tombstone_contents.c_str());

  // Verify that the log buf is empty, and no error messages.
  ASSERT_STREQ("", getFakeLogBuf().c_str());
  ASSERT_STREQ("", getFakeLogPrint().c_str());
}

TEST_F(DumpMemoryTest, memory_partially_unreadable) {
  uint8_t buffer[104];
  for (size_t i = 0; i < sizeof(buffer); i++) {
    buffer[i] = i;
  }
  backtrace_mock_->SetReadData(buffer, sizeof(buffer));

  dump_memory(&log_, backtrace_mock_.get(), 0x12345600, "memory near pc:");

  std::string tombstone_contents;
  ASSERT_TRUE(lseek(log_.tfd, 0, SEEK_SET) == 0);
  ASSERT_TRUE(android::base::ReadFdToString(log_.tfd, &tombstone_contents));
  ASSERT_STREQ(g_expected_partial_dump, tombstone_contents.c_str());

  // Verify that the log buf is empty, and no error messages.
  ASSERT_STREQ("", getFakeLogBuf().c_str());
  ASSERT_STREQ("", getFakeLogPrint().c_str());
}

TEST_F(DumpMemoryTest, memory_partially_unreadable_unaligned_return) {
  uint8_t buffer[104];
  for (size_t i = 0; i < sizeof(buffer); i++) {
    buffer[i] = i;
  }
  backtrace_mock_->SetReadData(buffer, sizeof(buffer));
  backtrace_mock_->SetPartialReadAmount(102);

  dump_memory(&log_, backtrace_mock_.get(), 0x12345600, "memory near pc:");

  std::string tombstone_contents;
  ASSERT_TRUE(lseek(log_.tfd, 0, SEEK_SET) == 0);
  ASSERT_TRUE(android::base::ReadFdToString(log_.tfd, &tombstone_contents));
  ASSERT_STREQ(g_expected_partial_dump, tombstone_contents.c_str());

#if defined(__LP64__)
  ASSERT_STREQ("DEBUG Bytes read 102, is not a multiple of 8\n", getFakeLogPrint().c_str());
#else
  ASSERT_STREQ("DEBUG Bytes read 102, is not a multiple of 4\n", getFakeLogPrint().c_str());
#endif

  // Verify that the log buf is empty, and no error messages.
  ASSERT_STREQ("", getFakeLogBuf().c_str());
}

TEST_F(DumpMemoryTest, memory_partially_unreadable_two_unaligned_reads) {
  uint8_t buffer[106];
  for (size_t i = 0; i < sizeof(buffer); i++) {
    buffer[i] = i;
  }
  backtrace_mock_->SetReadData(buffer, sizeof(buffer));
  backtrace_mock_->SetPartialReadAmount(45);

  dump_memory(&log_, backtrace_mock_.get(), 0x12345600, "memory near pc:");

  std::string tombstone_contents;
  ASSERT_TRUE(lseek(log_.tfd, 0, SEEK_SET) == 0);
  ASSERT_TRUE(android::base::ReadFdToString(log_.tfd, &tombstone_contents));
  ASSERT_STREQ(g_expected_partial_dump, tombstone_contents.c_str());

#if defined(__LP64__)
  ASSERT_STREQ("DEBUG Bytes read 45, is not a multiple of 8\n"
               "DEBUG Bytes after second read 106, is not a multiple of 8\n",
               getFakeLogPrint().c_str());
#else
  ASSERT_STREQ("DEBUG Bytes read 45, is not a multiple of 4\n"
               "DEBUG Bytes after second read 106, is not a multiple of 4\n",
               getFakeLogPrint().c_str());
#endif

  // Verify that the log buf is empty, and no error messages.
  ASSERT_STREQ("", getFakeLogBuf().c_str());
}

TEST_F(DumpMemoryTest, address_low_fence) {
  uint8_t buffer[256];
  memset(buffer, 0, sizeof(buffer));
  backtrace_mock_->SetReadData(buffer, sizeof(buffer));

  dump_memory(&log_, backtrace_mock_.get(), 0x1000, "memory near %.2s:", "r1");

  std::string tombstone_contents;
  ASSERT_TRUE(lseek(log_.tfd, 0, SEEK_SET) == 0);
  ASSERT_TRUE(android::base::ReadFdToString(log_.tfd, &tombstone_contents));
  const char* expected_dump = \
"\nmemory near r1:\n"
#if defined(__LP64__)
"    0000000000001000 0000000000000000 0000000000000000  ................\n"
"    0000000000001010 0000000000000000 0000000000000000  ................\n"
"    0000000000001020 0000000000000000 0000000000000000  ................\n"
"    0000000000001030 0000000000000000 0000000000000000  ................\n"
"    0000000000001040 0000000000000000 0000000000000000  ................\n"
"    0000000000001050 0000000000000000 0000000000000000  ................\n"
"    0000000000001060 0000000000000000 0000000000000000  ................\n"
"    0000000000001070 0000000000000000 0000000000000000  ................\n"
"    0000000000001080 0000000000000000 0000000000000000  ................\n"
"    0000000000001090 0000000000000000 0000000000000000  ................\n"
"    00000000000010a0 0000000000000000 0000000000000000  ................\n"
"    00000000000010b0 0000000000000000 0000000000000000  ................\n"
"    00000000000010c0 0000000000000000 0000000000000000  ................\n"
"    00000000000010d0 0000000000000000 0000000000000000  ................\n"
"    00000000000010e0 0000000000000000 0000000000000000  ................\n"
"    00000000000010f0 0000000000000000 0000000000000000  ................\n";
#else
"    00001000 00000000 00000000 00000000 00000000  ................\n"
"    00001010 00000000 00000000 00000000 00000000  ................\n"
"    00001020 00000000 00000000 00000000 00000000  ................\n"
"    00001030 00000000 00000000 00000000 00000000  ................\n"
"    00001040 00000000 00000000 00000000 00000000  ................\n"
"    00001050 00000000 00000000 00000000 00000000  ................\n"
"    00001060 00000000 00000000 00000000 00000000  ................\n"
"    00001070 00000000 00000000 00000000 00000000  ................\n"
"    00001080 00000000 00000000 00000000 00000000  ................\n"
"    00001090 00000000 00000000 00000000 00000000  ................\n"
"    000010a0 00000000 00000000 00000000 00000000  ................\n"
"    000010b0 00000000 00000000 00000000 00000000  ................\n"
"    000010c0 00000000 00000000 00000000 00000000  ................\n"
"    000010d0 00000000 00000000 00000000 00000000  ................\n"
"    000010e0 00000000 00000000 00000000 00000000  ................\n"
"    000010f0 00000000 00000000 00000000 00000000  ................\n";
#endif
  ASSERT_STREQ(expected_dump, tombstone_contents.c_str());

  // Verify that the log buf is empty, and no error messages.
  ASSERT_STREQ("", getFakeLogBuf().c_str());
  ASSERT_STREQ("", getFakeLogPrint().c_str());
}

TEST_F(DumpMemoryTest, memory_address_too_low) {
  uint8_t buffer[256];
  memset(buffer, 0, sizeof(buffer));
  backtrace_mock_->SetReadData(buffer, sizeof(buffer));

  dump_memory(&log_, backtrace_mock_.get(), 0, "memory near %.2s:", "r1");

  std::string tombstone_contents;
  ASSERT_TRUE(lseek(log_.tfd, 0, SEEK_SET) == 0);
  ASSERT_TRUE(android::base::ReadFdToString(log_.tfd, &tombstone_contents));
  ASSERT_STREQ("", tombstone_contents.c_str());

  // Verify that the log buf is empty, and no error messages.
  ASSERT_STREQ("", getFakeLogBuf().c_str());
  ASSERT_STREQ("", getFakeLogPrint().c_str());
}

TEST_F(DumpMemoryTest, memory_address_too_high) {
  uint8_t buffer[256];
  memset(buffer, 0, sizeof(buffer));
  backtrace_mock_->SetReadData(buffer, sizeof(buffer));

#if defined(__LP64__)
  dump_memory(&log_, backtrace_mock_.get(), 0x4000000000000000UL, "memory near %.2s:", "r1");
  dump_memory(&log_, backtrace_mock_.get(), 0x4000000000000000UL - 32, "memory near %.2s:", "r1");
  dump_memory(&log_, backtrace_mock_.get(), 0x4000000000000000UL - 216, "memory near %.2s:", "r1");
#else
  dump_memory(&log_, backtrace_mock_.get(), 0xffff0000, "memory near %.2s:", "r1");
  dump_memory(&log_, backtrace_mock_.get(), 0xffff0000 - 32, "memory near %.2s:", "r1");
  dump_memory(&log_, backtrace_mock_.get(), 0xffff0000 - 220, "memory near %.2s:", "r1");
#endif

  std::string tombstone_contents;
  ASSERT_TRUE(lseek(log_.tfd, 0, SEEK_SET) == 0);
  ASSERT_TRUE(android::base::ReadFdToString(log_.tfd, &tombstone_contents));
  ASSERT_STREQ("", tombstone_contents.c_str());

  // Verify that the log buf is empty, and no error messages.
  ASSERT_STREQ("", getFakeLogBuf().c_str());
  ASSERT_STREQ("", getFakeLogPrint().c_str());
}

TEST_F(DumpMemoryTest, memory_address_would_overflow) {
  uint8_t buffer[256];
  memset(buffer, 0, sizeof(buffer));
  backtrace_mock_->SetReadData(buffer, sizeof(buffer));

#if defined(__LP64__)
  dump_memory(&log_, backtrace_mock_.get(), 0xfffffffffffffff0, "memory near %.2s:", "r1");
#else
  dump_memory(&log_, backtrace_mock_.get(), 0xfffffff0, "memory near %.2s:", "r1");
#endif

  std::string tombstone_contents;
  ASSERT_TRUE(lseek(log_.tfd, 0, SEEK_SET) == 0);
  ASSERT_TRUE(android::base::ReadFdToString(log_.tfd, &tombstone_contents));
  ASSERT_STREQ("", tombstone_contents.c_str());

  // Verify that the log buf is empty, and no error messages.
  ASSERT_STREQ("", getFakeLogBuf().c_str());
  ASSERT_STREQ("", getFakeLogPrint().c_str());
}

TEST_F(DumpMemoryTest, memory_address_nearly_too_high) {
  uint8_t buffer[256];
  for (size_t i = 0; i < sizeof(buffer); i++) {
    buffer[i] = i;
  }
  backtrace_mock_->SetReadData(buffer, sizeof(buffer));

#if defined(__LP64__)
  dump_memory(&log_, backtrace_mock_.get(), 0x4000000000000000UL - 224, "memory near %.2s:", "r4");
#else
  dump_memory(&log_, backtrace_mock_.get(), 0xffff0000 - 224, "memory near %.2s:", "r4");
#endif

  std::string tombstone_contents;
  ASSERT_TRUE(lseek(log_.tfd, 0, SEEK_SET) == 0);
  ASSERT_TRUE(android::base::ReadFdToString(log_.tfd, &tombstone_contents));
  const char* expected_dump = \
"\nmemory near r4:\n"
#if defined(__LP64__)
"    3fffffffffffff00 0706050403020100 0f0e0d0c0b0a0908  ................\n"
"    3fffffffffffff10 1716151413121110 1f1e1d1c1b1a1918  ................\n"
"    3fffffffffffff20 2726252423222120 2f2e2d2c2b2a2928   !\"#$%&'()*+,-./\n"
"    3fffffffffffff30 3736353433323130 3f3e3d3c3b3a3938  0123456789:;<=>?\n"
"    3fffffffffffff40 4746454443424140 4f4e4d4c4b4a4948  @ABCDEFGHIJKLMNO\n"
"    3fffffffffffff50 5756555453525150 5f5e5d5c5b5a5958  PQRSTUVWXYZ[\\]^_\n"
"    3fffffffffffff60 6766656463626160 6f6e6d6c6b6a6968  `abcdefghijklmno\n"
"    3fffffffffffff70 7776757473727170 7f7e7d7c7b7a7978  pqrstuvwxyz{|}~.\n"
"    3fffffffffffff80 8786858483828180 8f8e8d8c8b8a8988  ................\n"
"    3fffffffffffff90 9796959493929190 9f9e9d9c9b9a9998  ................\n"
"    3fffffffffffffa0 a7a6a5a4a3a2a1a0 afaeadacabaaa9a8  ................\n"
"    3fffffffffffffb0 b7b6b5b4b3b2b1b0 bfbebdbcbbbab9b8  ................\n"
"    3fffffffffffffc0 c7c6c5c4c3c2c1c0 cfcecdcccbcac9c8  ................\n"
"    3fffffffffffffd0 d7d6d5d4d3d2d1d0 dfdedddcdbdad9d8  ................\n"
"    3fffffffffffffe0 e7e6e5e4e3e2e1e0 efeeedecebeae9e8  ................\n"
"    3ffffffffffffff0 f7f6f5f4f3f2f1f0 fffefdfcfbfaf9f8  ................\n";
#else
"    fffeff00 03020100 07060504 0b0a0908 0f0e0d0c  ................\n"
"    fffeff10 13121110 17161514 1b1a1918 1f1e1d1c  ................\n"
"    fffeff20 23222120 27262524 2b2a2928 2f2e2d2c   !\"#$%&'()*+,-./\n"
"    fffeff30 33323130 37363534 3b3a3938 3f3e3d3c  0123456789:;<=>?\n"
"    fffeff40 43424140 47464544 4b4a4948 4f4e4d4c  @ABCDEFGHIJKLMNO\n"
"    fffeff50 53525150 57565554 5b5a5958 5f5e5d5c  PQRSTUVWXYZ[\\]^_\n"
"    fffeff60 63626160 67666564 6b6a6968 6f6e6d6c  `abcdefghijklmno\n"
"    fffeff70 73727170 77767574 7b7a7978 7f7e7d7c  pqrstuvwxyz{|}~.\n"
"    fffeff80 83828180 87868584 8b8a8988 8f8e8d8c  ................\n"
"    fffeff90 93929190 97969594 9b9a9998 9f9e9d9c  ................\n"
"    fffeffa0 a3a2a1a0 a7a6a5a4 abaaa9a8 afaeadac  ................\n"
"    fffeffb0 b3b2b1b0 b7b6b5b4 bbbab9b8 bfbebdbc  ................\n"
"    fffeffc0 c3c2c1c0 c7c6c5c4 cbcac9c8 cfcecdcc  ................\n"
"    fffeffd0 d3d2d1d0 d7d6d5d4 dbdad9d8 dfdedddc  ................\n"
"    fffeffe0 e3e2e1e0 e7e6e5e4 ebeae9e8 efeeedec  ................\n"
"    fffefff0 f3f2f1f0 f7f6f5f4 fbfaf9f8 fffefdfc  ................\n";
#endif
  ASSERT_STREQ(expected_dump, tombstone_contents.c_str());

  // Verify that the log buf is empty, and no error messages.
  ASSERT_STREQ("", getFakeLogBuf().c_str());
  ASSERT_STREQ("", getFakeLogPrint().c_str());
}
