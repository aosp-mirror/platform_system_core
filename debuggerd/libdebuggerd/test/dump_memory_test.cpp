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
#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <gtest/gtest.h>
#include <unwindstack/Memory.h>

#include "libdebuggerd/utility.h"

#include "log_fake.h"

std::string GetMemoryString(uintptr_t addr, const std::vector<uint64_t>& data) {
  // Must be even number of data values.
  CHECK((data.size() & 1) == 0);

  std::string str;
  for (size_t i = 0; i < data.size(); i += 2) {
    str += "    ";
    std::string ascii_str = "";
    for (size_t j = 0; j < 2; j++) {
      for (size_t k = 0; k < 8; k++) {
        uint8_t c = (data[i + j] >> (k * 8)) & 0xff;
        if (c >= 0x20 && c < 0x7f) {
          ascii_str += c;
        } else {
          ascii_str += '.';
        }
      }
    }
#if defined(__LP64__)
    str += android::base::StringPrintf("%016zx %016zx %016zx  ", addr, data[i], data[i + 1]);
#else
    str += android::base::StringPrintf(
        "%08zx %08zx %08zx %08zx %08zx  ", addr, static_cast<uintptr_t>(data[i] & 0xffffffff),
        static_cast<uintptr_t>(data[i] >> 32), static_cast<uintptr_t>(data[i + 1] & 0xffffffff),
        static_cast<uintptr_t>(data[i + 1] >> 32));
#endif
    str += ascii_str + "\n";
    addr += 0x10;
  }
  return str;
}

const std::vector<uint64_t>& GetDefaultData() {
  static std::vector<uint64_t> data(
      {0x0706050403020100UL, 0x0f0e0d0c0b0a0908UL, 0x1716151413121110UL, 0x1f1e1d1c1b1a1918UL,
       0x2726252423222120UL, 0x2f2e2d2c2b2a2928UL, 0x3736353433323130UL, 0x3f3e3d3c3b3a3938UL,
       0x4746454443424140UL, 0x4f4e4d4c4b4a4948UL, 0x5756555453525150UL, 0x5f5e5d5c5b5a5958UL,
       0x6766656463626160UL, 0x6f6e6d6c6b6a6968UL, 0x7776757473727170UL, 0x7f7e7d7c7b7a7978UL,
       0x8786858483828180UL, 0x8f8e8d8c8b8a8988UL, 0x9796959493929190UL, 0x9f9e9d9c9b9a9998UL,
       0xa7a6a5a4a3a2a1a0UL, 0xafaeadacabaaa9a8UL, 0xb7b6b5b4b3b2b1b0UL, 0xbfbebdbcbbbab9b8UL,
       0xc7c6c5c4c3c2c1c0UL, 0xcfcecdcccbcac9c8UL, 0xd7d6d5d4d3d2d1d0UL, 0xdfdedddcdbdad9d8UL,
       0xe7e6e5e4e3e2e1e0UL, 0xefeeedecebeae9e8UL, 0xf7f6f5f4f3f2f1f0UL, 0xfffefdfcfbfaf9f8UL});
  return data;
}

std::string GetFullDumpString() {
  std::string str = "\nmemory near r1:\n";
  str += GetMemoryString(0x12345650U, GetDefaultData());
  return str;
}

std::string GetPartialDumpString() {
  std::string str = "\nmemory near pc:\n";
  std::vector<uint64_t> data = GetDefaultData();
  data.resize(12);
  str += GetMemoryString(0x123455e0U, data);
  return str;
}

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
  ASSERT_EQ(GetFullDumpString(), tombstone_contents);

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
  ASSERT_EQ(GetFullDumpString(), tombstone_contents);

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
  ASSERT_EQ(GetFullDumpString(), tombstone_contents);

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
  ASSERT_EQ(GetPartialDumpString(), tombstone_contents);

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
  ASSERT_EQ(GetPartialDumpString(), tombstone_contents);

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
  ASSERT_EQ(GetPartialDumpString(), tombstone_contents);

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
  std::string expected_dump = "\nmemory near r1:\n";
  expected_dump += GetMemoryString(0x1000, std::vector<uint64_t>(32, 0UL));
  ASSERT_EQ(expected_dump, tombstone_contents);

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
  std::string expected_dump = "\nmemory near r4:\n";
  uintptr_t addr;
#if defined(__aarch64__)
  addr = 0x00ffffffffffff00UL;
#elif defined(__LP64__)
  addr = 0xffffffffffffff00UL;
#else
  addr = 0xffffff00UL;
#endif
  expected_dump += GetMemoryString(addr, GetDefaultData());
  ASSERT_EQ(expected_dump, tombstone_contents);

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
  std::string expected_dump = "\nmemory near r4:\n";
  expected_dump += GetMemoryString(
      0x10000000 + page_size,
      std::vector<uint64_t>{
          0x8786858483828180UL, 0x8f8e8d8c8b8a8988UL, 0x9796959493929190UL, 0x9f9e9d9c9b9a9998UL,
          0xa7a6a5a4a3a2a1a0UL, 0xafaeadacabaaa9a8UL, 0xb7b6b5b4b3b2b1b0UL, 0xbfbebdbcbbbab9b8UL,
          0xc7c6c5c4c3c2c1c0UL, 0xcfcecdcccbcac9c8UL, 0xd7d6d5d4d3d2d1d0UL, 0xdfdedddcdbdad9d8UL,
          0xe7e6e5e4e3e2e1e0UL, 0xefeeedecebeae9e8UL, 0xf7f6f5f4f3f2f1f0UL, 0xfffefdfcfbfaf9f8UL});
  ASSERT_EQ(expected_dump, tombstone_contents);

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
  std::string expected_dump = "\nmemory near r4:\n";
  expected_dump += GetMemoryString(
      0x10000000 + page_size, std::vector<uint64_t>{0xc7c6c5c4c3c2c1c0UL, 0xcfcecdcccbcac9c8UL,
                                                    0xd7d6d5d4d3d2d1d0UL, 0xdfdedddcdbdad9d8UL});
  ASSERT_EQ(expected_dump, tombstone_contents);

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
