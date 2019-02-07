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

#include "utils/FileMap.h"

#include <gtest/gtest.h>

#include "android-base/file.h"

TEST(FileMap, zero_length_mapping) {
    // http://b/119818070 "app crashes when reading asset of zero length".
    // mmap fails with EINVAL for a zero length region.
    TemporaryFile tf;
    ASSERT_TRUE(tf.fd != -1);

    android::FileMap m;
    ASSERT_TRUE(m.create("test", tf.fd, 4096, 0, true));
    ASSERT_STREQ("test", m.getFileName());
    ASSERT_EQ(0u, m.getDataLength());
    ASSERT_EQ(4096, m.getDataOffset());
}
