/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include <stdint.h>
#include <sys/mman.h>

#include <string>
#include <vector>

#include <gtest/gtest.h>

#include <android-base/file.h>
#include <unwindstack/Maps.h>

namespace unwindstack {

class TestUpdatableMaps : public LocalUpdatableMaps {
 public:
  TestUpdatableMaps() : LocalUpdatableMaps() {}
  virtual ~TestUpdatableMaps() = default;

  const std::string GetMapsFile() const override { return maps_file_; }

  void TestSetMapsFile(const std::string& maps_file) { maps_file_ = maps_file; }

  const std::vector<std::unique_ptr<MapInfo>>& TestGetSavedMaps() { return saved_maps_; }

 private:
  std::string maps_file_;
};

class LocalUpdatableMapsTest : public ::testing::Test {
 protected:
  static const std::string GetDefaultMapString() {
    return "3000-4000 r-xp 00000 00:00 0\n8000-9000 r-xp 00000 00:00 0\n";
  }

  void SetUp() override {
    TemporaryFile tf;
    ASSERT_TRUE(android::base::WriteStringToFile(GetDefaultMapString(), tf.path));

    maps_.TestSetMapsFile(tf.path);
    ASSERT_TRUE(maps_.Parse());
    ASSERT_EQ(2U, maps_.Total());

    MapInfo* map_info = maps_.Get(0);
    ASSERT_TRUE(map_info != nullptr);
    EXPECT_EQ(0x3000U, map_info->start);
    EXPECT_EQ(0x4000U, map_info->end);
    EXPECT_EQ(0U, map_info->offset);
    EXPECT_EQ(PROT_READ | PROT_EXEC, map_info->flags);
    EXPECT_TRUE(map_info->name.empty());

    map_info = maps_.Get(1);
    ASSERT_TRUE(map_info != nullptr);
    EXPECT_EQ(0x8000U, map_info->start);
    EXPECT_EQ(0x9000U, map_info->end);
    EXPECT_EQ(0U, map_info->offset);
    EXPECT_EQ(PROT_READ | PROT_EXEC, map_info->flags);
    EXPECT_TRUE(map_info->name.empty());
  }

  TestUpdatableMaps maps_;
};

TEST_F(LocalUpdatableMapsTest, same_map) {
  TemporaryFile tf;
  ASSERT_TRUE(android::base::WriteStringToFile(GetDefaultMapString(), tf.path));

  maps_.TestSetMapsFile(tf.path);
  ASSERT_TRUE(maps_.Reparse());
  ASSERT_EQ(2U, maps_.Total());
  EXPECT_EQ(0U, maps_.TestGetSavedMaps().size());

  MapInfo* map_info = maps_.Get(0);
  ASSERT_TRUE(map_info != nullptr);
  EXPECT_EQ(0x3000U, map_info->start);
  EXPECT_EQ(0x4000U, map_info->end);
  EXPECT_EQ(0U, map_info->offset);
  EXPECT_EQ(PROT_READ | PROT_EXEC, map_info->flags);
  EXPECT_TRUE(map_info->name.empty());

  map_info = maps_.Get(1);
  ASSERT_TRUE(map_info != nullptr);
  EXPECT_EQ(0x8000U, map_info->start);
  EXPECT_EQ(0x9000U, map_info->end);
  EXPECT_EQ(0U, map_info->offset);
  EXPECT_EQ(PROT_READ | PROT_EXEC, map_info->flags);
  EXPECT_TRUE(map_info->name.empty());
}

TEST_F(LocalUpdatableMapsTest, same_map_new_perms) {
  TemporaryFile tf;
  ASSERT_TRUE(
      android::base::WriteStringToFile("3000-4000 rwxp 00000 00:00 0\n"
                                       "8000-9000 r-xp 00000 00:00 0\n",
                                       tf.path));

  maps_.TestSetMapsFile(tf.path);
  ASSERT_TRUE(maps_.Reparse());
  ASSERT_EQ(2U, maps_.Total());

  MapInfo* map_info = maps_.Get(0);
  ASSERT_TRUE(map_info != nullptr);
  EXPECT_EQ(0x3000U, map_info->start);
  EXPECT_EQ(0x4000U, map_info->end);
  EXPECT_EQ(0U, map_info->offset);
  EXPECT_EQ(PROT_READ | PROT_WRITE | PROT_EXEC, map_info->flags);
  EXPECT_TRUE(map_info->name.empty());

  map_info = maps_.Get(1);
  ASSERT_TRUE(map_info != nullptr);
  EXPECT_EQ(0x8000U, map_info->start);
  EXPECT_EQ(0x9000U, map_info->end);
  EXPECT_EQ(0U, map_info->offset);
  EXPECT_EQ(PROT_READ | PROT_EXEC, map_info->flags);
  EXPECT_TRUE(map_info->name.empty());

  auto& saved_maps = maps_.TestGetSavedMaps();
  ASSERT_EQ(1U, saved_maps.size());
  map_info = saved_maps[0].get();
  ASSERT_TRUE(map_info != nullptr);
  EXPECT_EQ(0x3000U, map_info->start);
  EXPECT_EQ(0x4000U, map_info->end);
  EXPECT_EQ(0U, map_info->offset);
  EXPECT_EQ(PROT_READ | PROT_EXEC, map_info->flags);
  EXPECT_TRUE(map_info->name.empty());
}

TEST_F(LocalUpdatableMapsTest, same_map_new_name) {
  TemporaryFile tf;
  ASSERT_TRUE(
      android::base::WriteStringToFile("3000-4000 r-xp 00000 00:00 0 /fake/lib.so\n"
                                       "8000-9000 r-xp 00000 00:00 0\n",
                                       tf.path));

  maps_.TestSetMapsFile(tf.path);
  ASSERT_TRUE(maps_.Reparse());
  ASSERT_EQ(2U, maps_.Total());

  MapInfo* map_info = maps_.Get(0);
  ASSERT_TRUE(map_info != nullptr);
  EXPECT_EQ(0x3000U, map_info->start);
  EXPECT_EQ(0x4000U, map_info->end);
  EXPECT_EQ(0U, map_info->offset);
  EXPECT_EQ(PROT_READ | PROT_EXEC, map_info->flags);
  EXPECT_EQ("/fake/lib.so", map_info->name);

  map_info = maps_.Get(1);
  ASSERT_TRUE(map_info != nullptr);
  EXPECT_EQ(0x8000U, map_info->start);
  EXPECT_EQ(0x9000U, map_info->end);
  EXPECT_EQ(0U, map_info->offset);
  EXPECT_EQ(PROT_READ | PROT_EXEC, map_info->flags);
  EXPECT_TRUE(map_info->name.empty());

  auto& saved_maps = maps_.TestGetSavedMaps();
  ASSERT_EQ(1U, saved_maps.size());
  map_info = saved_maps[0].get();
  ASSERT_TRUE(map_info != nullptr);
  EXPECT_EQ(0x3000U, map_info->start);
  EXPECT_EQ(0x4000U, map_info->end);
  EXPECT_EQ(0U, map_info->offset);
  EXPECT_EQ(PROT_READ | PROT_EXEC, map_info->flags);
  EXPECT_TRUE(map_info->name.empty());
}

TEST_F(LocalUpdatableMapsTest, only_add_maps) {
  TemporaryFile tf;
  ASSERT_TRUE(
      android::base::WriteStringToFile("1000-2000 r-xp 00000 00:00 0\n"
                                       "3000-4000 r-xp 00000 00:00 0\n"
                                       "8000-9000 r-xp 00000 00:00 0\n"
                                       "a000-f000 r-xp 00000 00:00 0\n",
                                       tf.path));

  maps_.TestSetMapsFile(tf.path);
  ASSERT_TRUE(maps_.Reparse());
  ASSERT_EQ(4U, maps_.Total());
  EXPECT_EQ(0U, maps_.TestGetSavedMaps().size());

  MapInfo* map_info = maps_.Get(0);
  ASSERT_TRUE(map_info != nullptr);
  EXPECT_EQ(0x1000U, map_info->start);
  EXPECT_EQ(0x2000U, map_info->end);
  EXPECT_EQ(0U, map_info->offset);
  EXPECT_EQ(PROT_READ | PROT_EXEC, map_info->flags);
  EXPECT_TRUE(map_info->name.empty());

  map_info = maps_.Get(1);
  ASSERT_TRUE(map_info != nullptr);
  EXPECT_EQ(0x3000U, map_info->start);
  EXPECT_EQ(0x4000U, map_info->end);
  EXPECT_EQ(0U, map_info->offset);
  EXPECT_EQ(PROT_READ | PROT_EXEC, map_info->flags);
  EXPECT_TRUE(map_info->name.empty());

  map_info = maps_.Get(2);
  ASSERT_TRUE(map_info != nullptr);
  EXPECT_EQ(0x8000U, map_info->start);
  EXPECT_EQ(0x9000U, map_info->end);
  EXPECT_EQ(0U, map_info->offset);
  EXPECT_EQ(PROT_READ | PROT_EXEC, map_info->flags);
  EXPECT_TRUE(map_info->name.empty());

  map_info = maps_.Get(3);
  ASSERT_TRUE(map_info != nullptr);
  EXPECT_EQ(0xa000U, map_info->start);
  EXPECT_EQ(0xf000U, map_info->end);
  EXPECT_EQ(0U, map_info->offset);
  EXPECT_EQ(PROT_READ | PROT_EXEC, map_info->flags);
  EXPECT_TRUE(map_info->name.empty());
}

TEST_F(LocalUpdatableMapsTest, all_new_maps) {
  TemporaryFile tf;
  ASSERT_TRUE(
      android::base::WriteStringToFile("1000-2000 r-xp 00000 00:00 0\n"
                                       "a000-f000 r-xp 00000 00:00 0\n",
                                       tf.path));

  maps_.TestSetMapsFile(tf.path);
  ASSERT_TRUE(maps_.Reparse());
  ASSERT_EQ(2U, maps_.Total());

  MapInfo* map_info = maps_.Get(0);
  ASSERT_TRUE(map_info != nullptr);
  EXPECT_EQ(0x1000U, map_info->start);
  EXPECT_EQ(0x2000U, map_info->end);
  EXPECT_EQ(0U, map_info->offset);
  EXPECT_EQ(PROT_READ | PROT_EXEC, map_info->flags);
  EXPECT_TRUE(map_info->name.empty());

  map_info = maps_.Get(1);
  ASSERT_TRUE(map_info != nullptr);
  EXPECT_EQ(0xa000U, map_info->start);
  EXPECT_EQ(0xf000U, map_info->end);
  EXPECT_EQ(0U, map_info->offset);
  EXPECT_EQ(PROT_READ | PROT_EXEC, map_info->flags);
  EXPECT_TRUE(map_info->name.empty());

  auto& saved_maps = maps_.TestGetSavedMaps();
  ASSERT_EQ(2U, saved_maps.size());
  map_info = saved_maps[0].get();
  ASSERT_TRUE(map_info != nullptr);
  EXPECT_EQ(0x3000U, map_info->start);
  EXPECT_EQ(0x4000U, map_info->end);
  EXPECT_EQ(0U, map_info->offset);
  EXPECT_EQ(PROT_READ | PROT_EXEC, map_info->flags);
  EXPECT_TRUE(map_info->name.empty());

  map_info = saved_maps[1].get();
  ASSERT_TRUE(map_info != nullptr);
  EXPECT_EQ(0x8000U, map_info->start);
  EXPECT_EQ(0x9000U, map_info->end);
  EXPECT_EQ(0U, map_info->offset);
  EXPECT_EQ(PROT_READ | PROT_EXEC, map_info->flags);
  EXPECT_TRUE(map_info->name.empty());
}

}  // namespace unwindstack
