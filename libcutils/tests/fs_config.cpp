/*
 * Copyright (C) 2017 The Android Open Source Project
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

#include <string>

#include <gtest/gtest.h>

#include <android-base/strings.h>

#include <private/android_filesystem_config.h>

extern const struct fs_path_config* __for_testing_only__android_dirs;
extern const struct fs_path_config* __for_testing_only__android_files;

static void check_one(const struct fs_path_config* paths, const std::string& prefix,
                      const std::string& alternate) {
    for (size_t idx = 0; paths[idx].prefix; ++idx) {
        std::string path(paths[idx].prefix);
        if (android::base::StartsWith(path, prefix.c_str())) {
            path = alternate + path.substr(prefix.length());
            size_t second;
            for (second = 0; paths[second].prefix; ++second) {
                if (path == paths[second].prefix) break;
            }
            if (!paths[second].prefix) {
                // guaranteed to fail expectations, trigger test failure with
                // a message that reports the violation as an inequality.
                EXPECT_STREQ((prefix + path.substr(alternate.length())).c_str(), path.c_str());
            }
        }
    }
}

static void check_two(const struct fs_path_config* paths, const std::string& prefix) {
    ASSERT_FALSE(paths == nullptr);
    std::string alternate = "system/" + prefix;
    check_one(paths, prefix, alternate);
    check_one(paths, alternate, prefix);
}

TEST(fs_config, vendor_dirs_alias) {
    check_two(__for_testing_only__android_dirs, "vendor/");
}

TEST(fs_config, vendor_files_alias) {
    check_two(__for_testing_only__android_files, "vendor/");
}

TEST(fs_config, oem_dirs_alias) {
    check_two(__for_testing_only__android_dirs, "oem/");
}

TEST(fs_config, oem_files_alias) {
    check_two(__for_testing_only__android_files, "oem/");
}

TEST(fs_config, odm_dirs_alias) {
    check_two(__for_testing_only__android_dirs, "odm/");
}

TEST(fs_config, odm_files_alias) {
    check_two(__for_testing_only__android_files, "odm/");
}
