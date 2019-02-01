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
#include <time.h>

#include <memory>
#include <string>

#include <android-base/file.h>
#include <android-base/properties.h>
#include <gtest/gtest.h>

#include "libdebuggerd/utility.h"

#include "UnwinderMock.h"
#include "host_signal_fixup.h"
#include "log_fake.h"

#include "tombstone.cpp"

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

TEST_F(TombstoneTest, dump_timestamp) {
  setenv("TZ", "UTC", 1);
  tzset();
  dump_timestamp(&log_, 0);
  ASSERT_STREQ("Timestamp: 1970-01-01 00:00:00+0000\n", amfd_data_.c_str());
}

class MemoryPattern : public unwindstack::Memory {
 public:
  MemoryPattern() = default;
  virtual ~MemoryPattern() = default;

  size_t Read(uint64_t, void* dst, size_t size) override {
    uint8_t* data = reinterpret_cast<uint8_t*>(dst);
    for (size_t i = 0; i < size; i++) {
      data[i] = (i % 0xff);
    }
    return size;
  }
};

TEST_F(TombstoneTest, dump_stack_single_frame) {
  std::vector<unwindstack::FrameData> frames;
  unwindstack::Maps maps;
  MemoryPattern memory;

  frames.push_back(
      unwindstack::FrameData{.num = 0, .rel_pc = 0x1000, .pc = 0x301000, .sp = 0x2000});
  dump_stack(&log_, frames, &maps, &memory);

  std::string contents;
  ASSERT_TRUE(lseek(log_.tfd, 0, SEEK_SET) == 0);
  ASSERT_TRUE(android::base::ReadFdToString(log_.tfd, &contents));

  std::string expected =
#if defined(__LP64__)
      "         0000000000001f80  0706050403020100\n"
      "         0000000000001f88  0f0e0d0c0b0a0908\n"
      "         0000000000001f90  1716151413121110\n"
      "         0000000000001f98  1f1e1d1c1b1a1918\n"
      "         0000000000001fa0  2726252423222120\n"
      "         0000000000001fa8  2f2e2d2c2b2a2928\n"
      "         0000000000001fb0  3736353433323130\n"
      "         0000000000001fb8  3f3e3d3c3b3a3938\n"
      "         0000000000001fc0  4746454443424140\n"
      "         0000000000001fc8  4f4e4d4c4b4a4948\n"
      "         0000000000001fd0  5756555453525150\n"
      "         0000000000001fd8  5f5e5d5c5b5a5958\n"
      "         0000000000001fe0  6766656463626160\n"
      "         0000000000001fe8  6f6e6d6c6b6a6968\n"
      "         0000000000001ff0  7776757473727170\n"
      "         0000000000001ff8  7f7e7d7c7b7a7978\n"
      "    #00  0000000000002000  0706050403020100\n"
      "         0000000000002008  0f0e0d0c0b0a0908\n"
      "         0000000000002010  1716151413121110\n"
      "         0000000000002018  1f1e1d1c1b1a1918\n"
      "         0000000000002020  2726252423222120\n"
      "         0000000000002028  2f2e2d2c2b2a2928\n"
      "         0000000000002030  3736353433323130\n"
      "         0000000000002038  3f3e3d3c3b3a3938\n"
      "         0000000000002040  4746454443424140\n"
      "         0000000000002048  4f4e4d4c4b4a4948\n"
      "         0000000000002050  5756555453525150\n"
      "         0000000000002058  5f5e5d5c5b5a5958\n"
      "         0000000000002060  6766656463626160\n"
      "         0000000000002068  6f6e6d6c6b6a6968\n"
      "         0000000000002070  7776757473727170\n"
      "         0000000000002078  7f7e7d7c7b7a7978\n";
#else
      "         00001fc0  03020100\n"
      "         00001fc4  07060504\n"
      "         00001fc8  0b0a0908\n"
      "         00001fcc  0f0e0d0c\n"
      "         00001fd0  13121110\n"
      "         00001fd4  17161514\n"
      "         00001fd8  1b1a1918\n"
      "         00001fdc  1f1e1d1c\n"
      "         00001fe0  23222120\n"
      "         00001fe4  27262524\n"
      "         00001fe8  2b2a2928\n"
      "         00001fec  2f2e2d2c\n"
      "         00001ff0  33323130\n"
      "         00001ff4  37363534\n"
      "         00001ff8  3b3a3938\n"
      "         00001ffc  3f3e3d3c\n"
      "    #00  00002000  03020100\n"
      "         00002004  07060504\n"
      "         00002008  0b0a0908\n"
      "         0000200c  0f0e0d0c\n"
      "         00002010  13121110\n"
      "         00002014  17161514\n"
      "         00002018  1b1a1918\n"
      "         0000201c  1f1e1d1c\n"
      "         00002020  23222120\n"
      "         00002024  27262524\n"
      "         00002028  2b2a2928\n"
      "         0000202c  2f2e2d2c\n"
      "         00002030  33323130\n"
      "         00002034  37363534\n"
      "         00002038  3b3a3938\n"
      "         0000203c  3f3e3d3c\n";
#endif
  EXPECT_EQ(expected, contents);
}

TEST_F(TombstoneTest, dump_stack_multiple_frames_same_sp) {
  std::vector<unwindstack::FrameData> frames;
  unwindstack::Maps maps;
  MemoryPattern memory;

  frames.push_back(
      unwindstack::FrameData{.num = 0, .rel_pc = 0x1000, .pc = 0x301000, .sp = 0x2000});
  frames.push_back(
      unwindstack::FrameData{.num = 0, .rel_pc = 0x1400, .pc = 0x301400, .sp = 0x2000});
  dump_stack(&log_, frames, &maps, &memory);

  std::string contents;
  ASSERT_TRUE(lseek(log_.tfd, 0, SEEK_SET) == 0);
  ASSERT_TRUE(android::base::ReadFdToString(log_.tfd, &contents));

  std::string expected =
#if defined(__LP64__)
      "         0000000000001f80  0706050403020100\n"
      "         0000000000001f88  0f0e0d0c0b0a0908\n"
      "         0000000000001f90  1716151413121110\n"
      "         0000000000001f98  1f1e1d1c1b1a1918\n"
      "         0000000000001fa0  2726252423222120\n"
      "         0000000000001fa8  2f2e2d2c2b2a2928\n"
      "         0000000000001fb0  3736353433323130\n"
      "         0000000000001fb8  3f3e3d3c3b3a3938\n"
      "         0000000000001fc0  4746454443424140\n"
      "         0000000000001fc8  4f4e4d4c4b4a4948\n"
      "         0000000000001fd0  5756555453525150\n"
      "         0000000000001fd8  5f5e5d5c5b5a5958\n"
      "         0000000000001fe0  6766656463626160\n"
      "         0000000000001fe8  6f6e6d6c6b6a6968\n"
      "         0000000000001ff0  7776757473727170\n"
      "         0000000000001ff8  7f7e7d7c7b7a7978\n"
      "    #00  0000000000002000  0706050403020100\n"
      "         ................  ................\n"
      "    #01  0000000000002000  0706050403020100\n"
      "         0000000000002008  0f0e0d0c0b0a0908\n"
      "         0000000000002010  1716151413121110\n"
      "         0000000000002018  1f1e1d1c1b1a1918\n"
      "         0000000000002020  2726252423222120\n"
      "         0000000000002028  2f2e2d2c2b2a2928\n"
      "         0000000000002030  3736353433323130\n"
      "         0000000000002038  3f3e3d3c3b3a3938\n"
      "         0000000000002040  4746454443424140\n"
      "         0000000000002048  4f4e4d4c4b4a4948\n"
      "         0000000000002050  5756555453525150\n"
      "         0000000000002058  5f5e5d5c5b5a5958\n"
      "         0000000000002060  6766656463626160\n"
      "         0000000000002068  6f6e6d6c6b6a6968\n"
      "         0000000000002070  7776757473727170\n"
      "         0000000000002078  7f7e7d7c7b7a7978\n";
#else
      "         00001fc0  03020100\n"
      "         00001fc4  07060504\n"
      "         00001fc8  0b0a0908\n"
      "         00001fcc  0f0e0d0c\n"
      "         00001fd0  13121110\n"
      "         00001fd4  17161514\n"
      "         00001fd8  1b1a1918\n"
      "         00001fdc  1f1e1d1c\n"
      "         00001fe0  23222120\n"
      "         00001fe4  27262524\n"
      "         00001fe8  2b2a2928\n"
      "         00001fec  2f2e2d2c\n"
      "         00001ff0  33323130\n"
      "         00001ff4  37363534\n"
      "         00001ff8  3b3a3938\n"
      "         00001ffc  3f3e3d3c\n"
      "    #00  00002000  03020100\n"
      "         ........  ........\n"
      "    #01  00002000  03020100\n"
      "         00002004  07060504\n"
      "         00002008  0b0a0908\n"
      "         0000200c  0f0e0d0c\n"
      "         00002010  13121110\n"
      "         00002014  17161514\n"
      "         00002018  1b1a1918\n"
      "         0000201c  1f1e1d1c\n"
      "         00002020  23222120\n"
      "         00002024  27262524\n"
      "         00002028  2b2a2928\n"
      "         0000202c  2f2e2d2c\n"
      "         00002030  33323130\n"
      "         00002034  37363534\n"
      "         00002038  3b3a3938\n"
      "         0000203c  3f3e3d3c\n";
#endif
  EXPECT_EQ(expected, contents);
}

TEST_F(TombstoneTest, dump_stack_multiple_frames) {
  std::vector<unwindstack::FrameData> frames;
  unwindstack::Maps maps;
  MemoryPattern memory;

  frames.push_back(
      unwindstack::FrameData{.num = 0, .rel_pc = 0x1000, .pc = 0x301000, .sp = 0x2000});
  frames.push_back(
      unwindstack::FrameData{.num = 0, .rel_pc = 0x1400, .pc = 0x301400, .sp = 0x2010});
  frames.push_back(
      unwindstack::FrameData{.num = 0, .rel_pc = 0x1400, .pc = 0x301400, .sp = 0x2100});
  dump_stack(&log_, frames, &maps, &memory);

  std::string contents;
  ASSERT_TRUE(lseek(log_.tfd, 0, SEEK_SET) == 0);
  ASSERT_TRUE(android::base::ReadFdToString(log_.tfd, &contents));

  std::string expected =
#if defined(__LP64__)
      "         0000000000001f80  0706050403020100\n"
      "         0000000000001f88  0f0e0d0c0b0a0908\n"
      "         0000000000001f90  1716151413121110\n"
      "         0000000000001f98  1f1e1d1c1b1a1918\n"
      "         0000000000001fa0  2726252423222120\n"
      "         0000000000001fa8  2f2e2d2c2b2a2928\n"
      "         0000000000001fb0  3736353433323130\n"
      "         0000000000001fb8  3f3e3d3c3b3a3938\n"
      "         0000000000001fc0  4746454443424140\n"
      "         0000000000001fc8  4f4e4d4c4b4a4948\n"
      "         0000000000001fd0  5756555453525150\n"
      "         0000000000001fd8  5f5e5d5c5b5a5958\n"
      "         0000000000001fe0  6766656463626160\n"
      "         0000000000001fe8  6f6e6d6c6b6a6968\n"
      "         0000000000001ff0  7776757473727170\n"
      "         0000000000001ff8  7f7e7d7c7b7a7978\n"
      "    #00  0000000000002000  0706050403020100\n"
      "         0000000000002008  0f0e0d0c0b0a0908\n"
      "    #01  0000000000002010  0706050403020100\n"
      "         0000000000002018  0f0e0d0c0b0a0908\n"
      "         0000000000002020  1716151413121110\n"
      "         0000000000002028  1f1e1d1c1b1a1918\n"
      "         0000000000002030  2726252423222120\n"
      "         0000000000002038  2f2e2d2c2b2a2928\n"
      "         0000000000002040  3736353433323130\n"
      "         0000000000002048  3f3e3d3c3b3a3938\n"
      "         0000000000002050  4746454443424140\n"
      "         0000000000002058  4f4e4d4c4b4a4948\n"
      "         0000000000002060  5756555453525150\n"
      "         0000000000002068  5f5e5d5c5b5a5958\n"
      "         0000000000002070  6766656463626160\n"
      "         0000000000002078  6f6e6d6c6b6a6968\n"
      "         0000000000002080  7776757473727170\n"
      "         0000000000002088  7f7e7d7c7b7a7978\n"
      "         ................  ................\n"
      "    #02  0000000000002100  0706050403020100\n"
      "         0000000000002108  0f0e0d0c0b0a0908\n"
      "         0000000000002110  1716151413121110\n"
      "         0000000000002118  1f1e1d1c1b1a1918\n"
      "         0000000000002120  2726252423222120\n"
      "         0000000000002128  2f2e2d2c2b2a2928\n"
      "         0000000000002130  3736353433323130\n"
      "         0000000000002138  3f3e3d3c3b3a3938\n"
      "         0000000000002140  4746454443424140\n"
      "         0000000000002148  4f4e4d4c4b4a4948\n"
      "         0000000000002150  5756555453525150\n"
      "         0000000000002158  5f5e5d5c5b5a5958\n"
      "         0000000000002160  6766656463626160\n"
      "         0000000000002168  6f6e6d6c6b6a6968\n"
      "         0000000000002170  7776757473727170\n"
      "         0000000000002178  7f7e7d7c7b7a7978\n";
#else
      "         00001fc0  03020100\n"
      "         00001fc4  07060504\n"
      "         00001fc8  0b0a0908\n"
      "         00001fcc  0f0e0d0c\n"
      "         00001fd0  13121110\n"
      "         00001fd4  17161514\n"
      "         00001fd8  1b1a1918\n"
      "         00001fdc  1f1e1d1c\n"
      "         00001fe0  23222120\n"
      "         00001fe4  27262524\n"
      "         00001fe8  2b2a2928\n"
      "         00001fec  2f2e2d2c\n"
      "         00001ff0  33323130\n"
      "         00001ff4  37363534\n"
      "         00001ff8  3b3a3938\n"
      "         00001ffc  3f3e3d3c\n"
      "    #00  00002000  03020100\n"
      "         00002004  07060504\n"
      "         00002008  0b0a0908\n"
      "         0000200c  0f0e0d0c\n"
      "    #01  00002010  03020100\n"
      "         00002014  07060504\n"
      "         00002018  0b0a0908\n"
      "         0000201c  0f0e0d0c\n"
      "         00002020  13121110\n"
      "         00002024  17161514\n"
      "         00002028  1b1a1918\n"
      "         0000202c  1f1e1d1c\n"
      "         00002030  23222120\n"
      "         00002034  27262524\n"
      "         00002038  2b2a2928\n"
      "         0000203c  2f2e2d2c\n"
      "         00002040  33323130\n"
      "         00002044  37363534\n"
      "         00002048  3b3a3938\n"
      "         0000204c  3f3e3d3c\n"
      "         ........  ........\n"
      "    #02  00002100  03020100\n"
      "         00002104  07060504\n"
      "         00002108  0b0a0908\n"
      "         0000210c  0f0e0d0c\n"
      "         00002110  13121110\n"
      "         00002114  17161514\n"
      "         00002118  1b1a1918\n"
      "         0000211c  1f1e1d1c\n"
      "         00002120  23222120\n"
      "         00002124  27262524\n"
      "         00002128  2b2a2928\n"
      "         0000212c  2f2e2d2c\n"
      "         00002130  33323130\n"
      "         00002134  37363534\n"
      "         00002138  3b3a3938\n"
      "         0000213c  3f3e3d3c\n";
#endif
  EXPECT_EQ(expected, contents);
}

TEST_F(TombstoneTest, dump_stack_multiple_frames_disjoint_frames) {
  std::vector<unwindstack::FrameData> frames;
  unwindstack::Maps maps;
  MemoryPattern memory;

  frames.push_back(
      unwindstack::FrameData{.num = 0, .rel_pc = 0x1000, .pc = 0x301000, .sp = 0x2000});
  frames.push_back(
      unwindstack::FrameData{.num = 0, .rel_pc = 0x1400, .pc = 0x301400, .sp = 0x2010});
  frames.push_back(
      unwindstack::FrameData{.num = 0, .rel_pc = 0x1400, .pc = 0x301400, .sp = 0x1000});
  frames.push_back(
      unwindstack::FrameData{.num = 0, .rel_pc = 0x1400, .pc = 0x301400, .sp = 0x1030});
  dump_stack(&log_, frames, &maps, &memory);

  std::string contents;
  ASSERT_TRUE(lseek(log_.tfd, 0, SEEK_SET) == 0);
  ASSERT_TRUE(android::base::ReadFdToString(log_.tfd, &contents));

  std::string expected =
#if defined(__LP64__)
      "         0000000000001f80  0706050403020100\n"
      "         0000000000001f88  0f0e0d0c0b0a0908\n"
      "         0000000000001f90  1716151413121110\n"
      "         0000000000001f98  1f1e1d1c1b1a1918\n"
      "         0000000000001fa0  2726252423222120\n"
      "         0000000000001fa8  2f2e2d2c2b2a2928\n"
      "         0000000000001fb0  3736353433323130\n"
      "         0000000000001fb8  3f3e3d3c3b3a3938\n"
      "         0000000000001fc0  4746454443424140\n"
      "         0000000000001fc8  4f4e4d4c4b4a4948\n"
      "         0000000000001fd0  5756555453525150\n"
      "         0000000000001fd8  5f5e5d5c5b5a5958\n"
      "         0000000000001fe0  6766656463626160\n"
      "         0000000000001fe8  6f6e6d6c6b6a6968\n"
      "         0000000000001ff0  7776757473727170\n"
      "         0000000000001ff8  7f7e7d7c7b7a7978\n"
      "    #00  0000000000002000  0706050403020100\n"
      "         0000000000002008  0f0e0d0c0b0a0908\n"
      "    #01  0000000000002010  0706050403020100\n"
      "         0000000000002018  0f0e0d0c0b0a0908\n"
      "         0000000000002020  1716151413121110\n"
      "         0000000000002028  1f1e1d1c1b1a1918\n"
      "         0000000000002030  2726252423222120\n"
      "         0000000000002038  2f2e2d2c2b2a2928\n"
      "         0000000000002040  3736353433323130\n"
      "         0000000000002048  3f3e3d3c3b3a3938\n"
      "         0000000000002050  4746454443424140\n"
      "         0000000000002058  4f4e4d4c4b4a4948\n"
      "         0000000000002060  5756555453525150\n"
      "         0000000000002068  5f5e5d5c5b5a5958\n"
      "         0000000000002070  6766656463626160\n"
      "         0000000000002078  6f6e6d6c6b6a6968\n"
      "         0000000000002080  7776757473727170\n"
      "         0000000000002088  7f7e7d7c7b7a7978\n"
      "         ................  ................\n"
      "    #02  0000000000001000  0706050403020100\n"
      "         0000000000001008  0f0e0d0c0b0a0908\n"
      "         0000000000001010  1716151413121110\n"
      "         0000000000001018  1f1e1d1c1b1a1918\n"
      "         0000000000001020  2726252423222120\n"
      "         0000000000001028  2f2e2d2c2b2a2928\n"
      "    #03  0000000000001030  0706050403020100\n"
      "         0000000000001038  0f0e0d0c0b0a0908\n"
      "         0000000000001040  1716151413121110\n"
      "         0000000000001048  1f1e1d1c1b1a1918\n"
      "         0000000000001050  2726252423222120\n"
      "         0000000000001058  2f2e2d2c2b2a2928\n"
      "         0000000000001060  3736353433323130\n"
      "         0000000000001068  3f3e3d3c3b3a3938\n"
      "         0000000000001070  4746454443424140\n"
      "         0000000000001078  4f4e4d4c4b4a4948\n"
      "         0000000000001080  5756555453525150\n"
      "         0000000000001088  5f5e5d5c5b5a5958\n"
      "         0000000000001090  6766656463626160\n"
      "         0000000000001098  6f6e6d6c6b6a6968\n"
      "         00000000000010a0  7776757473727170\n"
      "         00000000000010a8  7f7e7d7c7b7a7978\n";
#else
      "         00001fc0  03020100\n"
      "         00001fc4  07060504\n"
      "         00001fc8  0b0a0908\n"
      "         00001fcc  0f0e0d0c\n"
      "         00001fd0  13121110\n"
      "         00001fd4  17161514\n"
      "         00001fd8  1b1a1918\n"
      "         00001fdc  1f1e1d1c\n"
      "         00001fe0  23222120\n"
      "         00001fe4  27262524\n"
      "         00001fe8  2b2a2928\n"
      "         00001fec  2f2e2d2c\n"
      "         00001ff0  33323130\n"
      "         00001ff4  37363534\n"
      "         00001ff8  3b3a3938\n"
      "         00001ffc  3f3e3d3c\n"
      "    #00  00002000  03020100\n"
      "         00002004  07060504\n"
      "         00002008  0b0a0908\n"
      "         0000200c  0f0e0d0c\n"
      "    #01  00002010  03020100\n"
      "         00002014  07060504\n"
      "         00002018  0b0a0908\n"
      "         0000201c  0f0e0d0c\n"
      "         00002020  13121110\n"
      "         00002024  17161514\n"
      "         00002028  1b1a1918\n"
      "         0000202c  1f1e1d1c\n"
      "         00002030  23222120\n"
      "         00002034  27262524\n"
      "         00002038  2b2a2928\n"
      "         0000203c  2f2e2d2c\n"
      "         00002040  33323130\n"
      "         00002044  37363534\n"
      "         00002048  3b3a3938\n"
      "         0000204c  3f3e3d3c\n"
      "         ........  ........\n"
      "    #02  00001000  03020100\n"
      "         00001004  07060504\n"
      "         00001008  0b0a0908\n"
      "         0000100c  0f0e0d0c\n"
      "         00001010  13121110\n"
      "         00001014  17161514\n"
      "         00001018  1b1a1918\n"
      "         0000101c  1f1e1d1c\n"
      "         00001020  23222120\n"
      "         00001024  27262524\n"
      "         00001028  2b2a2928\n"
      "         0000102c  2f2e2d2c\n"
      "    #03  00001030  03020100\n"
      "         00001034  07060504\n"
      "         00001038  0b0a0908\n"
      "         0000103c  0f0e0d0c\n"
      "         00001040  13121110\n"
      "         00001044  17161514\n"
      "         00001048  1b1a1918\n"
      "         0000104c  1f1e1d1c\n"
      "         00001050  23222120\n"
      "         00001054  27262524\n"
      "         00001058  2b2a2928\n"
      "         0000105c  2f2e2d2c\n"
      "         00001060  33323130\n"
      "         00001064  37363534\n"
      "         00001068  3b3a3938\n"
      "         0000106c  3f3e3d3c\n";
#endif
  EXPECT_EQ(expected, contents);
}
