/*
 * Copyright (C) 2016 The Android Open Source Project
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

#include <elf.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <unistd.h>

#include <memory>
#include <vector>

#include <android-base/file.h>
#include <android-base/test_utils.h>
#include <gtest/gtest.h>

#include "Elf.h"
#include "MapInfo.h"
#include "Memory.h"

class MapInfoTest : public ::testing::Test {
 protected:
  static void SetUpTestCase() {
    std::vector<uint8_t> buffer(1024);
    memcpy(buffer.data(), ELFMAG, SELFMAG);
    for (size_t i = SELFMAG; i < buffer.size(); i++) {
      buffer[i] = i / 256 + 1;
    }
    ASSERT_TRUE(android::base::WriteFully(elf_.fd, buffer.data(), buffer.size()));

    for (size_t i = 0; i < 0x100; i++) {
      buffer[i] = i / 256 + 1;
    }
    memcpy(&buffer[0x100], ELFMAG, SELFMAG);
    for (size_t i = 0x100 + SELFMAG; i < buffer.size(); i++) {
      buffer[i] = i / 256 + 1;
    }
    ASSERT_TRUE(android::base::WriteFully(elf_at_100_.fd, buffer.data(), buffer.size()));
  }

  static TemporaryFile elf_;

  static TemporaryFile elf_at_100_;
};
TemporaryFile MapInfoTest::elf_;
TemporaryFile MapInfoTest::elf_at_100_;

TEST_F(MapInfoTest, end_le_start) {
  MapInfo info{.start = 0x100, .end = 0x100, .offset = 0, .name = elf_.path};

  std::unique_ptr<Memory> memory;
  memory.reset(info.CreateMemory(getpid()));
  ASSERT_TRUE(memory.get() == nullptr);

  info.end = 0xff;
  memory.reset(info.CreateMemory(getpid()));
  ASSERT_TRUE(memory.get() == nullptr);

  // Make sure this test is valid.
  info.end = 0x101;
  memory.reset(info.CreateMemory(getpid()));
  ASSERT_FALSE(info.CreateMemory(getpid()) == nullptr);
}

// Verify that if the offset is non-zero but there is no elf at the offset,
// that the full file is used.
TEST_F(MapInfoTest, create_memory_file_backed_non_zero_offset_full_file) {
  MapInfo info{.start = 0x100, .end = 0x200, .offset = 0x100, .name = elf_.path};

  std::unique_ptr<Memory> memory(info.CreateMemory(getpid()));
  ASSERT_TRUE(memory.get() != nullptr);
  ASSERT_EQ(0x100U, info.elf_offset);

  // Read the entire file.
  std::vector<uint8_t> buffer(1024);
  ASSERT_TRUE(memory->Read(0, buffer.data(), 1024));
  ASSERT_TRUE(memcmp(buffer.data(), ELFMAG, SELFMAG) == 0);
  for (size_t i = SELFMAG; i < buffer.size(); i++) {
    ASSERT_EQ(i / 256 + 1, buffer[i]) << "Failed at byte " << i;
  }

  ASSERT_FALSE(memory->Read(1024, buffer.data(), 1));
}

// Verify that if the offset is non-zero and there is an elf at that
// offset, that only part of the file is used.
TEST_F(MapInfoTest, create_memory_file_backed_non_zero_offset_partial_file) {
  MapInfo info{.start = 0x100, .end = 0x200, .offset = 0x100, .name = elf_at_100_.path};

  std::unique_ptr<Memory> memory(info.CreateMemory(getpid()));
  ASSERT_TRUE(memory.get() != nullptr);
  ASSERT_EQ(0U, info.elf_offset);

  // Read the valid part of the file.
  std::vector<uint8_t> buffer(0x100);
  ASSERT_TRUE(memory->Read(0, buffer.data(), 0x100));
  ASSERT_TRUE(memcmp(buffer.data(), ELFMAG, SELFMAG) == 0);
  for (size_t i = SELFMAG; i < buffer.size(); i++) {
    ASSERT_EQ(2, buffer[i]) << "Failed at byte " << i;
  }

  ASSERT_FALSE(memory->Read(0x100, buffer.data(), 1));
}

// Verify that device file names will never result in Memory object creation.
TEST_F(MapInfoTest, create_memory_check_device_maps) {
  // Set up some memory so that a valid local memory object would
  // be returned if the file mapping fails, but the device check is incorrect.
  std::vector<uint8_t> buffer(1024);
  MapInfo info;
  info.start = reinterpret_cast<uint64_t>(buffer.data());
  info.end = info.start + buffer.size();
  info.offset = 0;
  std::unique_ptr<Memory> memory;

  info.flags = 0x8000;
  info.name = "/dev/something";
  memory.reset(info.CreateMemory(getpid()));
  ASSERT_TRUE(memory.get() == nullptr);
}

TEST_F(MapInfoTest, create_memory_local_memory) {
  // Set up some memory for a valid local memory object.
  std::vector<uint8_t> buffer(1024);
  for (size_t i = 0; i < buffer.size(); i++) {
    buffer[i] = i % 256;
  }

  MapInfo info;
  info.start = reinterpret_cast<uint64_t>(buffer.data());
  info.end = info.start + buffer.size();
  info.offset = 0;

  std::unique_ptr<Memory> memory;
  memory.reset(info.CreateMemory(getpid()));
  ASSERT_TRUE(memory.get() != nullptr);

  std::vector<uint8_t> read_buffer(1024);
  ASSERT_TRUE(memory->Read(0, read_buffer.data(), read_buffer.size()));
  for (size_t i = 0; i < read_buffer.size(); i++) {
    ASSERT_EQ(i % 256, read_buffer[i]) << "Failed at byte " << i;
  }

  ASSERT_FALSE(memory->Read(read_buffer.size(), read_buffer.data(), 1));
}

TEST_F(MapInfoTest, create_memory_remote_memory) {
  std::vector<uint8_t> buffer(1024);
  memset(buffer.data(), 0xa, buffer.size());

  pid_t pid;
  if ((pid = fork()) == 0) {
    while (true)
      ;
    exit(1);
  }
  ASSERT_LT(0, pid);

  ASSERT_TRUE(ptrace(PTRACE_ATTACH, pid, 0, 0) != -1);
  uint64_t iterations = 0;
  siginfo_t si;
  while (TEMP_FAILURE_RETRY(ptrace(PTRACE_GETSIGINFO, pid, 0, &si)) < 0 && errno == ESRCH) {
    usleep(30);
    iterations++;
    ASSERT_LT(iterations, 500000000ULL);
  }

  MapInfo info;
  info.start = reinterpret_cast<uint64_t>(buffer.data());
  info.end = info.start + buffer.size();
  info.offset = 0;

  std::unique_ptr<Memory> memory;
  memory.reset(info.CreateMemory(pid));
  ASSERT_TRUE(memory.get() != nullptr);
  // Set the local memory to a different value to guarantee we are reading
  // from the remote process.
  memset(buffer.data(), 0x1, buffer.size());
  std::vector<uint8_t> read_buffer(1024);
  ASSERT_TRUE(memory->Read(0, read_buffer.data(), read_buffer.size()));
  for (size_t i = 0; i < read_buffer.size(); i++) {
    ASSERT_EQ(0xaU, read_buffer[i]) << "Failed at byte " << i;
  }

  ASSERT_TRUE(ptrace(PTRACE_DETACH, pid, 0, 0) == 0);

  kill(pid, SIGKILL);
}

TEST_F(MapInfoTest, get_elf) {
  // Create a map to use as initialization data.
  void* map = mmap(nullptr, 1024, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  ASSERT_NE(MAP_FAILED, map);

  uint64_t start = reinterpret_cast<uint64_t>(map);
  MapInfo info{.start = start, .end = start + 1024, .offset = 0, .name = ""};

  // The map contains garbage, but this should still produce an elf object.
  Elf* elf = info.GetElf(getpid(), false);
  ASSERT_TRUE(elf != nullptr);
  ASSERT_FALSE(elf->valid());

  ASSERT_EQ(0, munmap(map, 1024));
}
