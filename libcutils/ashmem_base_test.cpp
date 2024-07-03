/*
 * Copyright (C) 2024 The Android Open Source Project
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

#include <gtest/gtest.h>

#include <unistd.h>

#include <android-base/mapped_file.h>
#include <android-base/unique_fd.h>
#include <cutils/ashmem.h>

/*
 * Tests in AshmemBaseTest are designed to run on Android as well as host
 * platforms (Linux, Mac, Windows).
 */

#if defined(_WIN32)
static inline size_t getpagesize() {
    return 4096;
}
#endif

using android::base::unique_fd;

TEST(AshmemBaseTest, BasicTest) {
    const size_t size = getpagesize();
    std::vector<uint8_t> data(size);
    std::generate(data.begin(), data.end(), [n = 0]() mutable { return n++ & 0xFF; });

    unique_fd fd = unique_fd(ashmem_create_region(nullptr, size));
    ASSERT_TRUE(fd >= 0);
    ASSERT_TRUE(ashmem_valid(fd));
    ASSERT_EQ(size, static_cast<size_t>(ashmem_get_size_region(fd)));

    std::unique_ptr<android::base::MappedFile> mapped =
            android::base::MappedFile::FromFd(fd, 0, size, PROT_READ | PROT_WRITE);
    EXPECT_TRUE(mapped.get() != nullptr);
    void* region1 = mapped->data();
    EXPECT_TRUE(region1 != nullptr);

    memcpy(region1, data.data(), size);
    ASSERT_EQ(0, memcmp(region1, data.data(), size));

    std::unique_ptr<android::base::MappedFile> mapped2 =
            android::base::MappedFile::FromFd(fd, 0, size, PROT_READ | PROT_WRITE);
    EXPECT_TRUE(mapped2.get() != nullptr);
    void* region2 = mapped2->data();
    EXPECT_TRUE(region2 != nullptr);
    ASSERT_EQ(0, memcmp(region2, data.data(), size));
}
