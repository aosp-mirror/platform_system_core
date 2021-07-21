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
#include <gtest/gtest.h>
#include <unwindstack/Memory.h>

#include "libdebuggerd/utility.h"

#include "log_fake.h"

const char g_expected_full_dump[] =
"\nmemory near r1:\n"
#if defined(__LP64__)
"    0000000012345650 0706050403020100 0f0e0d0c0b0a0908  ................\n"
"    0000000012345660 1716151413121110 1f1e1d1c1b1a1918  ................\n"
"    0000000012345670 2726252423222120 2f2e2d2c2b2a2928   !\"#$%&'()*+,-./\n"
"    0000000012345680 3736353433323130 3f3e3d3c3b3a3938  0123456789:;<=>?\n"
"    0000000012345690 4746454443424140 4f4e4d4c4b4a4948  @ABCDEFGHIJKLMNO\n"
"    00000000123456a0 5756555453525150 5f5e5d5c5b5a5958  PQRSTUVWXYZ[\\]^_\n"
"    00000000123456b0 6766656463626160 6f6e6d6c6b6a6968  `abcdefghijklmno\n"
"    00000000123456c0 7776757473727170 7f7e7d7c7b7a7978  pqrstuvwxyz{|}~.\n"
"    00000000123456d0 8786858483828180 8f8e8d8c8b8a8988  ................\n"
"    00000000123456e0 9796959493929190 9f9e9d9c9b9a9998  ................\n"
"    00000000123456f0 a7a6a5a4a3a2a1a0 afaeadacabaaa9a8  ................\n"
"    0000000012345700 b7b6b5b4b3b2b1b0 bfbebdbcbbbab9b8  ................\n"
"    0000000012345710 c7c6c5c4c3c2c1c0 cfcecdcccbcac9c8  ................\n"
"    0000000012345720 d7d6d5d4d3d2d1d0 dfdedddcdbdad9d8  ................\n"
"    0000000012345730 e7e6e5e4e3e2e1e0 efeeedecebeae9e8  ................\n"
"    0000000012345740 f7f6f5f4f3f2f1f0 fffefdfcfbfaf9f8  ................\n";
#else
"    12345650 03020100 07060504 0b0a0908 0f0e0d0c  ................\n"
"    12345660 13121110 17161514 1b1a1918 1f1e1d1c  ................\n"
"    12345670 23222120 27262524 2b2a2928 2f2e2d2c   !\"#$%&'()*+,-./\n"
"    12345680 33323130 37363534 3b3a3938 3f3e3d3c  0123456789:;<=>?\n"
"    12345690 43424140 47464544 4b4a4948 4f4e4d4c  @ABCDEFGHIJKLMNO\n"
"    123456a0 53525150 57565554 5b5a5958 5f5e5d5c  PQRSTUVWXYZ[\\]^_\n"
"    123456b0 63626160 67666564 6b6a6968 6f6e6d6c  `abcdefghijklmno\n"
"    123456c0 73727170 77767574 7b7a7978 7f7e7d7c  pqrstuvwxyz{|}~.\n"
"    123456d0 83828180 87868584 8b8a8988 8f8e8d8c  ................\n"
"    123456e0 93929190 97969594 9b9a9998 9f9e9d9c  ................\n"
"    123456f0 a3a2a1a0 a7a6a5a4 abaaa9a8 afaeadac  ................\n"
"    12345700 b3b2b1b0 b7b6b5b4 bbbab9b8 bfbebdbc  ................\n"
"    12345710 c3c2c1c0 c7c6c5c4 cbcac9c8 cfcecdcc  ................\n"
"    12345720 d3d2d1d0 d7d6d5d4 dbdad9d8 dfdedddc  ................\n"
"    12345730 e3e2e1e0 e7e6e5e4 ebeae9e8 efeeedec  ................\n"
"    12345740 f3f2f1f0 f7f6f5f4 fbfaf9f8 fffefdfc  ................\n";
#endif

const char g_expected_partial_dump[] = \
"\nmemory near pc:\n"
#if defined(__LP64__)
"    00000000123455e0 0706050403020100 0f0e0d0c0b0a0908  ................\n"
"    00000000123455f0 1716151413121110 1f1e1d1c1b1a1918  ................\n"
"    0000000012345600 2726252423222120 2f2e2d2c2b2a2928   !\"#$%&'()*+,-./\n"
"    0000000012345610 3736353433323130 3f3e3d3c3b3a3938  0123456789:;<=>?\n"
"    0000000012345620 4746454443424140 4f4e4d4c4b4a4948  @ABCDEFGHIJKLMNO\n"
"    0000000012345630 5756555453525150 5f5e5d5c5b5a5958  PQRSTUVWXYZ[\\]^_\n";
#else
"    123455e0 03020100 07060504 0b0a0908 0f0e0d0c  ................\n"
"    123455f0 13121110 17161514 1b1a1918 1f1e1d1c  ................\n"
"    12345600 23222120 27262524 2b2a2928 2f2e2d2c   !\"#$%&'()*+,-./\n"
"    12345610 33323130 37363534 3b3a3938 3f3e3d3c  0123456789:;<=>?\n"
"    12345620 43424140 47464544 4b4a4948 4f4e4d4c  @ABCDEFGHIJKLMNO\n"
"    12345630 53525150 57565554 5b5a5958 5f5e5d5c  PQRSTUVWXYZ[\\]^_\n";
#endif

class MemoryMock : public unwindstack::Memory {
 public:
  virtual ~MemoryMock() = default;

  virtual size_t Read(uint64_t addr, void* buffer, size_t bytes) override {
    size_t offset = 0;
    if (last_read_addr_ > 0) {
      offset = addr - last_read_addr_;
    }
    size_t bytes_available = 0;
    if (offset < buffer_.size()) {
      bytes_available = buffer_.size() - offset;
    }

    if (partial_read_) {
      bytes = std::min(bytes, bytes_partial_read_);
      bytes_partial_read_ -= bytes;
      partial_read_ = bytes_partial_read_;
    } else if (bytes > bytes_available) {
      bytes = bytes_available;
    }

    if (bytes > 0) {
      memcpy(buffer, buffer_.data() + offset, bytes);
    }

    last_read_addr_ = addr;
    return bytes;
  }

  void SetReadData(uint8_t* buffer, size_t bytes) {
    buffer_.resize(bytes);
    memcpy(buffer_.data(), buffer, bytes);
    bytes_partial_read_ = 0;
    last_read_addr_ = 0;
  }

  void SetPartialReadAmount(size_t bytes) {
    if (bytes > buffer_.size()) {
      abort();
    }
    partial_read_ = true;
    bytes_partial_read_ = bytes;
  }

 private:
  std::vector<uint8_t> buffer_;
  bool partial_read_ = false;
  size_t bytes_partial_read_ = 0;
  uintptr_t last_read_addr_ = 0;
};

class DumpMemoryTest : public ::testing::Test {
 protected:
  virtual void SetUp() {
    memory_mock_ = std::make_unique<MemoryMock>();

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
    log_.amfd_data = nullptr;
    log_.crashed_tid = 12;
    log_.current_tid = 12;
    log_.should_retrieve_logcat = false;

    resetLogs();
  }

  virtual void TearDown() {
    if (log_.tfd >= 0) {
      close(log_.tfd);
    }
    memory_mock_.reset();
  }

  std::unique_ptr<MemoryMock> memory_mock_;

  log_t log_;
};

TEST_F(DumpMemoryTest, aligned_addr) {
  uint8_t buffer[256];
  for (size_t i = 0; i < sizeof(buffer); i++) {
    buffer[i] = i;
  }
  memory_mock_->SetReadData(buffer, sizeof(buffer));

  dump_memory(&log_, memory_mock_.get(), 0x12345678, "memory near r1");

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
  memory_mock_->SetReadData(buffer, sizeof(buffer));
  memory_mock_->SetPartialReadAmount(96);

  dump_memory(&log_, memory_mock_.get(), 0x12345679, "memory near r1");

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
  memory_mock_->SetReadData(buffer, sizeof(buffer));

  dump_memory(&log_, memory_mock_.get(), 0x12345679, "memory near r1");

  std::string tombstone_contents;
  ASSERT_TRUE(lseek(log_.tfd, 0, SEEK_SET) == 0);
  ASSERT_TRUE(android::base::ReadFdToString(log_.tfd, &tombstone_contents));
  ASSERT_STREQ(g_expected_full_dump, tombstone_contents.c_str());

  // Verify that the log buf is empty, and no error messages.
  ASSERT_STREQ("", getFakeLogBuf().c_str());
  ASSERT_STREQ("", getFakeLogPrint().c_str());
}

TEST_F(DumpMemoryTest, memory_unreadable) {
  dump_memory(&log_, memory_mock_.get(), 0xa2345678, "memory near pc");

  std::string tombstone_contents;
  ASSERT_TRUE(lseek(log_.tfd, 0, SEEK_SET) == 0);
  ASSERT_TRUE(android::base::ReadFdToString(log_.tfd, &tombstone_contents));
  ASSERT_STREQ("", tombstone_contents.c_str());

  // Verify that the log buf is empty, and no error messages.
  ASSERT_STREQ("", getFakeLogBuf().c_str());
  ASSERT_STREQ("", getFakeLogPrint().c_str());
}

TEST_F(DumpMemoryTest, memory_partially_unreadable) {
  uint8_t buffer[104];
  for (size_t i = 0; i < sizeof(buffer); i++) {
    buffer[i] = i;
  }
  memory_mock_->SetReadData(buffer, sizeof(buffer));

  dump_memory(&log_, memory_mock_.get(), 0x12345600, "memory near pc");

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
  memory_mock_->SetReadData(buffer, sizeof(buffer));
  memory_mock_->SetPartialReadAmount(102);

  dump_memory(&log_, memory_mock_.get(), 0x12345600, "memory near pc");

  std::string tombstone_contents;
  ASSERT_TRUE(lseek(log_.tfd, 0, SEEK_SET) == 0);
  ASSERT_TRUE(android::base::ReadFdToString(log_.tfd, &tombstone_contents));
  ASSERT_STREQ(g_expected_partial_dump, tombstone_contents.c_str());

#if defined(__LP64__)
  ASSERT_STREQ("6 DEBUG Bytes read 102, is not a multiple of 8\n", getFakeLogPrint().c_str());
#else
  ASSERT_STREQ("6 DEBUG Bytes read 102, is not a multiple of 4\n", getFakeLogPrint().c_str());
#endif

  // Verify that the log buf is empty, and no error messages.
  ASSERT_STREQ("", getFakeLogBuf().c_str());
}

TEST_F(DumpMemoryTest, memory_partially_unreadable_two_unaligned_reads) {
  uint8_t buffer[106];
  for (size_t i = 0; i < sizeof(buffer); i++) {
    buffer[i] = i;
  }
  memory_mock_->SetReadData(buffer, sizeof(buffer));
  memory_mock_->SetPartialReadAmount(45);

  dump_memory(&log_, memory_mock_.get(), 0x12345600, "memory near pc");

  std::string tombstone_contents;
  ASSERT_TRUE(lseek(log_.tfd, 0, SEEK_SET) == 0);
  ASSERT_TRUE(android::base::ReadFdToString(log_.tfd, &tombstone_contents));
  ASSERT_STREQ(g_expected_partial_dump, tombstone_contents.c_str());

#if defined(__LP64__)
  ASSERT_STREQ("6 DEBUG Bytes read 45, is not a multiple of 8\n"
               "6 DEBUG Bytes after second read 106, is not a multiple of 8\n",
               getFakeLogPrint().c_str());
#else
  ASSERT_STREQ("6 DEBUG Bytes read 45, is not a multiple of 4\n"
               "6 DEBUG Bytes after second read 106, is not a multiple of 4\n",
               getFakeLogPrint().c_str());
#endif

  // Verify that the log buf is empty, and no error messages.
  ASSERT_STREQ("", getFakeLogBuf().c_str());
}

TEST_F(DumpMemoryTest, address_low_fence) {
  uint8_t buffer[256];
  memset(buffer, 0, sizeof(buffer));
  memory_mock_->SetReadData(buffer, sizeof(buffer));

  dump_memory(&log_, memory_mock_.get(), 0x1000, "memory near r1");

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

TEST_F(DumpMemoryTest, memory_address_too_high) {
  uint8_t buffer[256];
  memset(buffer, 0, sizeof(buffer));
  memory_mock_->SetReadData(buffer, sizeof(buffer));

#if defined(__LP64__)
  dump_memory(&log_, memory_mock_.get(), -32, "memory near r1");
  dump_memory(&log_, memory_mock_.get(), -208, "memory near r1");
#else
  dump_memory(&log_, memory_mock_.get(), 0x100000000 - 32, "memory near r1");
  dump_memory(&log_, memory_mock_.get(), 0x100000000 - 208, "memory near r1");
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
  memory_mock_->SetReadData(buffer, sizeof(buffer));

#if defined(__LP64__)
  dump_memory(&log_, memory_mock_.get(), -224, "memory near r4");
#else
  dump_memory(&log_, memory_mock_.get(), 0x100000000 - 224, "memory near r4");
#endif

  std::string tombstone_contents;
  ASSERT_TRUE(lseek(log_.tfd, 0, SEEK_SET) == 0);
  ASSERT_TRUE(android::base::ReadFdToString(log_.tfd, &tombstone_contents));
  const char* expected_dump = \
"\nmemory near r4:\n"
#if defined(__aarch64__)
"    00ffffffffffff00 0706050403020100 0f0e0d0c0b0a0908  ................\n"
"    00ffffffffffff10 1716151413121110 1f1e1d1c1b1a1918  ................\n"
"    00ffffffffffff20 2726252423222120 2f2e2d2c2b2a2928   !\"#$%&'()*+,-./\n"
"    00ffffffffffff30 3736353433323130 3f3e3d3c3b3a3938  0123456789:;<=>?\n"
"    00ffffffffffff40 4746454443424140 4f4e4d4c4b4a4948  @ABCDEFGHIJKLMNO\n"
"    00ffffffffffff50 5756555453525150 5f5e5d5c5b5a5958  PQRSTUVWXYZ[\\]^_\n"
"    00ffffffffffff60 6766656463626160 6f6e6d6c6b6a6968  `abcdefghijklmno\n"
"    00ffffffffffff70 7776757473727170 7f7e7d7c7b7a7978  pqrstuvwxyz{|}~.\n"
"    00ffffffffffff80 8786858483828180 8f8e8d8c8b8a8988  ................\n"
"    00ffffffffffff90 9796959493929190 9f9e9d9c9b9a9998  ................\n"
"    00ffffffffffffa0 a7a6a5a4a3a2a1a0 afaeadacabaaa9a8  ................\n"
"    00ffffffffffffb0 b7b6b5b4b3b2b1b0 bfbebdbcbbbab9b8  ................\n"
"    00ffffffffffffc0 c7c6c5c4c3c2c1c0 cfcecdcccbcac9c8  ................\n"
"    00ffffffffffffd0 d7d6d5d4d3d2d1d0 dfdedddcdbdad9d8  ................\n"
"    00ffffffffffffe0 e7e6e5e4e3e2e1e0 efeeedecebeae9e8  ................\n"
"    00fffffffffffff0 f7f6f5f4f3f2f1f0 fffefdfcfbfaf9f8  ................\n";
#elif defined(__LP64__)
"    ffffffffffffff00 0706050403020100 0f0e0d0c0b0a0908  ................\n"
"    ffffffffffffff10 1716151413121110 1f1e1d1c1b1a1918  ................\n"
"    ffffffffffffff20 2726252423222120 2f2e2d2c2b2a2928   !\"#$%&'()*+,-./\n"
"    ffffffffffffff30 3736353433323130 3f3e3d3c3b3a3938  0123456789:;<=>?\n"
"    ffffffffffffff40 4746454443424140 4f4e4d4c4b4a4948  @ABCDEFGHIJKLMNO\n"
"    ffffffffffffff50 5756555453525150 5f5e5d5c5b5a5958  PQRSTUVWXYZ[\\]^_\n"
"    ffffffffffffff60 6766656463626160 6f6e6d6c6b6a6968  `abcdefghijklmno\n"
"    ffffffffffffff70 7776757473727170 7f7e7d7c7b7a7978  pqrstuvwxyz{|}~.\n"
"    ffffffffffffff80 8786858483828180 8f8e8d8c8b8a8988  ................\n"
"    ffffffffffffff90 9796959493929190 9f9e9d9c9b9a9998  ................\n"
"    ffffffffffffffa0 a7a6a5a4a3a2a1a0 afaeadacabaaa9a8  ................\n"
"    ffffffffffffffb0 b7b6b5b4b3b2b1b0 bfbebdbcbbbab9b8  ................\n"
"    ffffffffffffffc0 c7c6c5c4c3c2c1c0 cfcecdcccbcac9c8  ................\n"
"    ffffffffffffffd0 d7d6d5d4d3d2d1d0 dfdedddcdbdad9d8  ................\n"
"    ffffffffffffffe0 e7e6e5e4e3e2e1e0 efeeedecebeae9e8  ................\n"
"    fffffffffffffff0 f7f6f5f4f3f2f1f0 fffefdfcfbfaf9f8  ................\n";
#else
"    ffffff00 03020100 07060504 0b0a0908 0f0e0d0c  ................\n"
"    ffffff10 13121110 17161514 1b1a1918 1f1e1d1c  ................\n"
"    ffffff20 23222120 27262524 2b2a2928 2f2e2d2c   !\"#$%&'()*+,-./\n"
"    ffffff30 33323130 37363534 3b3a3938 3f3e3d3c  0123456789:;<=>?\n"
"    ffffff40 43424140 47464544 4b4a4948 4f4e4d4c  @ABCDEFGHIJKLMNO\n"
"    ffffff50 53525150 57565554 5b5a5958 5f5e5d5c  PQRSTUVWXYZ[\\]^_\n"
"    ffffff60 63626160 67666564 6b6a6968 6f6e6d6c  `abcdefghijklmno\n"
"    ffffff70 73727170 77767574 7b7a7978 7f7e7d7c  pqrstuvwxyz{|}~.\n"
"    ffffff80 83828180 87868584 8b8a8988 8f8e8d8c  ................\n"
"    ffffff90 93929190 97969594 9b9a9998 9f9e9d9c  ................\n"
"    ffffffa0 a3a2a1a0 a7a6a5a4 abaaa9a8 afaeadac  ................\n"
"    ffffffb0 b3b2b1b0 b7b6b5b4 bbbab9b8 bfbebdbc  ................\n"
"    ffffffc0 c3c2c1c0 c7c6c5c4 cbcac9c8 cfcecdcc  ................\n"
"    ffffffd0 d3d2d1d0 d7d6d5d4 dbdad9d8 dfdedddc  ................\n"
"    ffffffe0 e3e2e1e0 e7e6e5e4 ebeae9e8 efeeedec  ................\n"
"    fffffff0 f3f2f1f0 f7f6f5f4 fbfaf9f8 fffefdfc  ................\n";
#endif
  ASSERT_STREQ(expected_dump, tombstone_contents.c_str());

  // Verify that the log buf is empty, and no error messages.
  ASSERT_STREQ("", getFakeLogBuf().c_str());
  ASSERT_STREQ("", getFakeLogPrint().c_str());
}

TEST_F(DumpMemoryTest, first_read_empty) {
  uint8_t buffer[256];
  for (size_t i = 0; i < sizeof(buffer); i++) {
    buffer[i] = i;
  }
  memory_mock_->SetReadData(buffer, sizeof(buffer));
  memory_mock_->SetPartialReadAmount(0);

  size_t page_size = sysconf(_SC_PAGE_SIZE);
  uintptr_t addr = 0x10000020 + page_size - 120;
  dump_memory(&log_, memory_mock_.get(), addr, "memory near r4");

  std::string tombstone_contents;
  ASSERT_TRUE(lseek(log_.tfd, 0, SEEK_SET) == 0);
  ASSERT_TRUE(android::base::ReadFdToString(log_.tfd, &tombstone_contents));
  const char* expected_dump = \
"\nmemory near r4:\n"
#if defined(__LP64__)
R"(    0000000010001000 8786858483828180 8f8e8d8c8b8a8988  ................
    0000000010001010 9796959493929190 9f9e9d9c9b9a9998  ................
    0000000010001020 a7a6a5a4a3a2a1a0 afaeadacabaaa9a8  ................
    0000000010001030 b7b6b5b4b3b2b1b0 bfbebdbcbbbab9b8  ................
    0000000010001040 c7c6c5c4c3c2c1c0 cfcecdcccbcac9c8  ................
    0000000010001050 d7d6d5d4d3d2d1d0 dfdedddcdbdad9d8  ................
    0000000010001060 e7e6e5e4e3e2e1e0 efeeedecebeae9e8  ................
    0000000010001070 f7f6f5f4f3f2f1f0 fffefdfcfbfaf9f8  ................
)";
#else
R"(    10001000 83828180 87868584 8b8a8988 8f8e8d8c  ................
    10001010 93929190 97969594 9b9a9998 9f9e9d9c  ................
    10001020 a3a2a1a0 a7a6a5a4 abaaa9a8 afaeadac  ................
    10001030 b3b2b1b0 b7b6b5b4 bbbab9b8 bfbebdbc  ................
    10001040 c3c2c1c0 c7c6c5c4 cbcac9c8 cfcecdcc  ................
    10001050 d3d2d1d0 d7d6d5d4 dbdad9d8 dfdedddc  ................
    10001060 e3e2e1e0 e7e6e5e4 ebeae9e8 efeeedec  ................
    10001070 f3f2f1f0 f7f6f5f4 fbfaf9f8 fffefdfc  ................
)";
#endif
  ASSERT_STREQ(expected_dump, tombstone_contents.c_str());

  // Verify that the log buf is empty, and no error messages.
  ASSERT_STREQ("", getFakeLogBuf().c_str());
  ASSERT_STREQ("", getFakeLogPrint().c_str());
}

TEST_F(DumpMemoryTest, first_read_empty_second_read_stops) {
  uint8_t buffer[224];
  for (size_t i = 0; i < sizeof(buffer); i++) {
    buffer[i] = i;
  }
  memory_mock_->SetReadData(buffer, sizeof(buffer));
  memory_mock_->SetPartialReadAmount(0);

  size_t page_size = sysconf(_SC_PAGE_SIZE);
  uintptr_t addr = 0x10000020 + page_size - 192;
  dump_memory(&log_, memory_mock_.get(), addr, "memory near r4");

  std::string tombstone_contents;
  ASSERT_TRUE(lseek(log_.tfd, 0, SEEK_SET) == 0);
  ASSERT_TRUE(android::base::ReadFdToString(log_.tfd, &tombstone_contents));
  const char* expected_dump = \
"\nmemory near r4:\n"
#if defined(__LP64__)
"    0000000010001000 c7c6c5c4c3c2c1c0 cfcecdcccbcac9c8  ................\n"
"    0000000010001010 d7d6d5d4d3d2d1d0 dfdedddcdbdad9d8  ................\n";
#else
"    10001000 c3c2c1c0 c7c6c5c4 cbcac9c8 cfcecdcc  ................\n"
"    10001010 d3d2d1d0 d7d6d5d4 dbdad9d8 dfdedddc  ................\n";
#endif
  ASSERT_STREQ(expected_dump, tombstone_contents.c_str());

  // Verify that the log buf is empty, and no error messages.
  ASSERT_STREQ("", getFakeLogBuf().c_str());
  ASSERT_STREQ("", getFakeLogPrint().c_str());
}

TEST_F(DumpMemoryTest, first_read_empty_next_page_out_of_range) {
  uint8_t buffer[256];
  for (size_t i = 0; i < sizeof(buffer); i++) {
    buffer[i] = i;
  }
  memory_mock_->SetReadData(buffer, sizeof(buffer));
  memory_mock_->SetPartialReadAmount(0);

  uintptr_t addr = 0x10000020;
  dump_memory(&log_, memory_mock_.get(), addr, "memory near r4");

  std::string tombstone_contents;
  ASSERT_TRUE(lseek(log_.tfd, 0, SEEK_SET) == 0);
  ASSERT_TRUE(android::base::ReadFdToString(log_.tfd, &tombstone_contents));
  ASSERT_STREQ("", tombstone_contents.c_str());

  // Verify that the log buf is empty, and no error messages.
  ASSERT_STREQ("", getFakeLogBuf().c_str());
  ASSERT_STREQ("", getFakeLogPrint().c_str());
}

TEST_F(DumpMemoryTest, first_read_empty_next_page_out_of_range_fence_post) {
  uint8_t buffer[256];
  for (size_t i = 0; i < sizeof(buffer); i++) {
    buffer[i] = i;
  }
  memory_mock_->SetReadData(buffer, sizeof(buffer));
  memory_mock_->SetPartialReadAmount(0);

  size_t page_size = sysconf(_SC_PAGE_SIZE);
  uintptr_t addr = 0x10000020 + page_size - 256;

  dump_memory(&log_, memory_mock_.get(), addr, "memory near r4");

  std::string tombstone_contents;
  ASSERT_TRUE(lseek(log_.tfd, 0, SEEK_SET) == 0);
  ASSERT_TRUE(android::base::ReadFdToString(log_.tfd, &tombstone_contents));
  ASSERT_STREQ("", tombstone_contents.c_str());

  // Verify that the log buf is empty, and no error messages.
  ASSERT_STREQ("", getFakeLogBuf().c_str());
  ASSERT_STREQ("", getFakeLogPrint().c_str());
}
