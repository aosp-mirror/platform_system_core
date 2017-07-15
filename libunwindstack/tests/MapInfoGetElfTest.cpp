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

#include <unwindstack/Elf.h>
#include <unwindstack/MapInfo.h>
#include <unwindstack/Memory.h>

#include "ElfTestUtils.h"

namespace unwindstack {

class MapInfoGetElfTest : public ::testing::Test {
 protected:
  void SetUp() override {
    map_ = mmap(nullptr, kMapSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    ASSERT_NE(MAP_FAILED, map_);

    uint64_t start = reinterpret_cast<uint64_t>(map_);
    info_.reset(new MapInfo{.start = start, .end = start + 1024, .offset = 0, .name = ""});
  }

  void TearDown() override { munmap(map_, kMapSize); }

  const size_t kMapSize = 4096;

  void* map_ = nullptr;
  std::unique_ptr<MapInfo> info_;
};

TEST_F(MapInfoGetElfTest, invalid) {
  // The map is empty, but this should still create an invalid elf object.
  std::unique_ptr<Elf> elf(info_->GetElf(getpid(), false));
  ASSERT_TRUE(elf.get() != nullptr);
  ASSERT_FALSE(elf->valid());
}

TEST_F(MapInfoGetElfTest, valid32) {
  Elf32_Ehdr ehdr;
  TestInitEhdr<Elf32_Ehdr>(&ehdr, ELFCLASS32, EM_ARM);
  memcpy(map_, &ehdr, sizeof(ehdr));

  std::unique_ptr<Elf> elf(info_->GetElf(getpid(), false));
  ASSERT_TRUE(elf.get() != nullptr);
  ASSERT_TRUE(elf->valid());
  EXPECT_EQ(static_cast<uint32_t>(EM_ARM), elf->machine_type());
  EXPECT_EQ(ELFCLASS32, elf->class_type());
}

TEST_F(MapInfoGetElfTest, valid64) {
  Elf64_Ehdr ehdr;
  TestInitEhdr<Elf64_Ehdr>(&ehdr, ELFCLASS64, EM_AARCH64);
  memcpy(map_, &ehdr, sizeof(ehdr));

  std::unique_ptr<Elf> elf(info_->GetElf(getpid(), false));
  ASSERT_TRUE(elf.get() != nullptr);
  ASSERT_TRUE(elf->valid());
  EXPECT_EQ(static_cast<uint32_t>(EM_AARCH64), elf->machine_type());
  EXPECT_EQ(ELFCLASS64, elf->class_type());
}

TEST_F(MapInfoGetElfTest, gnu_debugdata_do_not_init32) {
  TestInitGnuDebugdata<Elf32_Ehdr, Elf32_Shdr>(
      ELFCLASS32, EM_ARM, false, [&](uint64_t offset, const void* ptr, size_t size) {
        memcpy(&reinterpret_cast<uint8_t*>(map_)[offset], ptr, size);
      });

  std::unique_ptr<Elf> elf(info_->GetElf(getpid(), false));
  ASSERT_TRUE(elf.get() != nullptr);
  ASSERT_TRUE(elf->valid());
  EXPECT_EQ(static_cast<uint32_t>(EM_ARM), elf->machine_type());
  EXPECT_EQ(ELFCLASS32, elf->class_type());
  EXPECT_TRUE(elf->gnu_debugdata_interface() == nullptr);
}

TEST_F(MapInfoGetElfTest, gnu_debugdata_do_not_init64) {
  TestInitGnuDebugdata<Elf64_Ehdr, Elf64_Shdr>(
      ELFCLASS64, EM_AARCH64, false, [&](uint64_t offset, const void* ptr, size_t size) {
        memcpy(&reinterpret_cast<uint8_t*>(map_)[offset], ptr, size);
      });

  std::unique_ptr<Elf> elf(info_->GetElf(getpid(), false));
  ASSERT_TRUE(elf.get() != nullptr);
  ASSERT_TRUE(elf->valid());
  EXPECT_EQ(static_cast<uint32_t>(EM_AARCH64), elf->machine_type());
  EXPECT_EQ(ELFCLASS64, elf->class_type());
  EXPECT_TRUE(elf->gnu_debugdata_interface() == nullptr);
}

TEST_F(MapInfoGetElfTest, gnu_debugdata_init32) {
  TestInitGnuDebugdata<Elf32_Ehdr, Elf32_Shdr>(
      ELFCLASS32, EM_ARM, true, [&](uint64_t offset, const void* ptr, size_t size) {
        memcpy(&reinterpret_cast<uint8_t*>(map_)[offset], ptr, size);
      });

  std::unique_ptr<Elf> elf(info_->GetElf(getpid(), true));
  ASSERT_TRUE(elf.get() != nullptr);
  ASSERT_TRUE(elf->valid());
  EXPECT_EQ(static_cast<uint32_t>(EM_ARM), elf->machine_type());
  EXPECT_EQ(ELFCLASS32, elf->class_type());
  EXPECT_TRUE(elf->gnu_debugdata_interface() != nullptr);
}

TEST_F(MapInfoGetElfTest, gnu_debugdata_init64) {
  TestInitGnuDebugdata<Elf64_Ehdr, Elf64_Shdr>(
      ELFCLASS64, EM_AARCH64, true, [&](uint64_t offset, const void* ptr, size_t size) {
        memcpy(&reinterpret_cast<uint8_t*>(map_)[offset], ptr, size);
      });

  std::unique_ptr<Elf> elf(info_->GetElf(getpid(), true));
  ASSERT_TRUE(elf.get() != nullptr);
  ASSERT_TRUE(elf->valid());
  EXPECT_EQ(static_cast<uint32_t>(EM_AARCH64), elf->machine_type());
  EXPECT_EQ(ELFCLASS64, elf->class_type());
  EXPECT_TRUE(elf->gnu_debugdata_interface() != nullptr);
}

}  // namespace unwindstack
