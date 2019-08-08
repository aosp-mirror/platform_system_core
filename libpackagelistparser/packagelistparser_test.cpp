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

#include <packagelistparser/packagelistparser.h>

#include <memory>

#include <android-base/file.h>

#include <gtest/gtest.h>

TEST(packagelistparser, smoke) {
  TemporaryFile tf;
  android::base::WriteStringToFile(
      // No gids.
      "com.test.a0 10014 0 /data/user/0/com.test.a0 platform:privapp:targetSdkVersion=19 none\n"
      // One gid.
      "com.test.a1 10007 1 /data/user/0/com.test.a1 platform:privapp:targetSdkVersion=21 1023\n"
      // Multiple gids.
      "com.test.a2 10011 0 /data/user/0/com.test.a2 media:privapp:targetSdkVersion=30 "
      "2001,1065,1023,3003,3007,1024\n"
      // The two new fields (profileable flag and version code).
      "com.test.a3 10022 0 /data/user/0/com.test.a3 selabel:blah none 1 123\n",
      tf.path);

  std::vector<pkg_info*> packages;
  packagelist_parse_file(
      tf.path,
      [](pkg_info* info, void* user_data) -> bool {
        reinterpret_cast<std::vector<pkg_info*>*>(user_data)->push_back(info);
        return true;
      },
      &packages);

  ASSERT_EQ(4U, packages.size());

  ASSERT_STREQ("com.test.a0", packages[0]->name);
  ASSERT_EQ(10014, packages[0]->uid);
  ASSERT_FALSE(packages[0]->debuggable);
  ASSERT_STREQ("/data/user/0/com.test.a0", packages[0]->data_dir);
  ASSERT_STREQ("platform:privapp:targetSdkVersion=19", packages[0]->seinfo);
  ASSERT_EQ(0U, packages[0]->gids.cnt);
  ASSERT_FALSE(packages[0]->profileable_from_shell);
  ASSERT_EQ(0, packages[0]->version_code);

  ASSERT_STREQ("com.test.a1", packages[1]->name);
  ASSERT_EQ(10007, packages[1]->uid);
  ASSERT_TRUE(packages[1]->debuggable);
  ASSERT_STREQ("/data/user/0/com.test.a1", packages[1]->data_dir);
  ASSERT_STREQ("platform:privapp:targetSdkVersion=21", packages[1]->seinfo);
  ASSERT_EQ(1U, packages[1]->gids.cnt);
  ASSERT_EQ(1023U, packages[1]->gids.gids[0]);
  ASSERT_FALSE(packages[0]->profileable_from_shell);
  ASSERT_EQ(0, packages[0]->version_code);

  ASSERT_STREQ("com.test.a2", packages[2]->name);
  ASSERT_EQ(10011, packages[2]->uid);
  ASSERT_FALSE(packages[2]->debuggable);
  ASSERT_STREQ("/data/user/0/com.test.a2", packages[2]->data_dir);
  ASSERT_STREQ("media:privapp:targetSdkVersion=30", packages[2]->seinfo);
  ASSERT_EQ(6U, packages[2]->gids.cnt);
  ASSERT_EQ(2001U, packages[2]->gids.gids[0]);
  ASSERT_EQ(1024U, packages[2]->gids.gids[5]);
  ASSERT_FALSE(packages[0]->profileable_from_shell);
  ASSERT_EQ(0, packages[0]->version_code);

  ASSERT_STREQ("com.test.a3", packages[3]->name);
  ASSERT_EQ(10022, packages[3]->uid);
  ASSERT_FALSE(packages[3]->debuggable);
  ASSERT_STREQ("/data/user/0/com.test.a3", packages[3]->data_dir);
  ASSERT_STREQ("selabel:blah", packages[3]->seinfo);
  ASSERT_EQ(0U, packages[3]->gids.cnt);
  ASSERT_TRUE(packages[3]->profileable_from_shell);
  ASSERT_EQ(123, packages[3]->version_code);

  for (auto& package : packages) packagelist_free(package);
}

TEST(packagelistparser, early_exit) {
  TemporaryFile tf;
  android::base::WriteStringToFile(
      "com.test.a0 1 0 / a none\n"
      "com.test.a1 1 0 / a none\n"
      "com.test.a2 1 0 / a none\n",
      tf.path);

  std::vector<pkg_info*> packages;
  packagelist_parse_file(
      tf.path,
      [](pkg_info* info, void* user_data) -> bool {
        std::vector<pkg_info*>* p = reinterpret_cast<std::vector<pkg_info*>*>(user_data);
        p->push_back(info);
        return p->size() < 2;
      },
      &packages);

  ASSERT_EQ(2U, packages.size());

  ASSERT_STREQ("com.test.a0", packages[0]->name);
  ASSERT_STREQ("com.test.a1", packages[1]->name);

  for (auto& package : packages) packagelist_free(package);
}

TEST(packagelistparser, system_package_list) {
  // Check that we can actually read the packages.list installed on the device.
  std::vector<pkg_info*> packages;
  packagelist_parse(
      [](pkg_info* info, void* user_data) -> bool {
        reinterpret_cast<std::vector<pkg_info*>*>(user_data)->push_back(info);
        return true;
      },
      &packages);
  // Not much we can say for sure about what we expect, other than that there
  // are likely to be lots of packages...
  ASSERT_GT(packages.size(), 10U);
}

TEST(packagelistparser, packagelist_free_nullptr) {
  packagelist_free(nullptr);
}
