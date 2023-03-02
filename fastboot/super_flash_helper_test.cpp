//
// Copyright (C) 2023 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

#include "super_flash_helper.h"

#include <unistd.h>

#include <android-base/file.h>
#include <android-base/unique_fd.h>
#include <gtest/gtest.h>
#include <sparse/sparse.h>

using android::base::unique_fd;

unique_fd OpenTestFile(const std::string& file, int flags) {
    std::string path = "testdata/" + file;

    unique_fd fd(open(path.c_str(), flags));
    if (fd >= 0) {
        return fd;
    }

    path = android::base::GetExecutableDirectory() + "/" + path;
    return unique_fd{open(path.c_str(), flags)};
}

class TestImageSource final : public ImageSource {
  public:
    bool ReadFile(const std::string&, std::vector<char>*) const override {
        // Not used here.
        return false;
    }
    unique_fd OpenFile(const std::string& name) const override {
        return OpenTestFile(name, O_RDONLY | O_CLOEXEC);
    }
};

TEST(SuperFlashHelper, ImageEquality) {
    auto super_empty_fd = OpenTestFile("super_empty.img", O_RDONLY);
    ASSERT_GE(super_empty_fd, 0);

    TestImageSource source;
    SuperFlashHelper helper(source);
    ASSERT_TRUE(helper.Open(super_empty_fd));
    ASSERT_TRUE(helper.AddPartition("system_a", "system.img", false));

    auto sparse_file = helper.GetSparseLayout();
    ASSERT_NE(sparse_file, nullptr);

    TemporaryFile fb_super;
    ASSERT_GE(fb_super.fd, 0);
    ASSERT_EQ(sparse_file_write(sparse_file.get(), fb_super.fd, false, false, false), 0);

    auto real_super_fd = OpenTestFile("super.img", O_RDONLY);
    ASSERT_GE(real_super_fd, 0);

    std::string expected(get_file_size(real_super_fd), '\0');
    ASSERT_FALSE(expected.empty());
    ASSERT_TRUE(android::base::ReadFully(real_super_fd, expected.data(), expected.size()));

    std::string actual(get_file_size(fb_super.fd), '\0');
    ASSERT_FALSE(actual.empty());
    ASSERT_EQ(lseek(fb_super.fd, 0, SEEK_SET), 0);
    ASSERT_TRUE(android::base::ReadFully(fb_super.fd, actual.data(), actual.size()));

    // The helper doesn't add any extra zeroes to the image, whereas lpmake does, to
    // pad to the entire super size.
    ASSERT_LE(actual.size(), expected.size());
    for (size_t i = 0; i < actual.size(); i++) {
        ASSERT_EQ(actual[i], expected[i]) << "byte mismatch at position " << i;
    }
    for (size_t i = actual.size(); i < expected.size(); i++) {
        ASSERT_EQ(expected[i], 0) << "byte mismatch at position " << i;
    }
}
