/*
 * Copyright (C) 2013 The Android Open Source Project
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

#include <sys/mman.h>

#include <memory>
#include <vector>

#include <gtest/gtest.h>

#include <ion/ion.h>
#include "ion_test_fixture.h"

class InvalidValues : public IonTest {};

TEST_F(InvalidValues, ion_close) {
    EXPECT_EQ(-EBADF, ion_close(-1));
}

TEST_F(InvalidValues, ion_alloc_fd) {
    int fd;
    // no heaps
    EXPECT_EQ(-ENODEV, ion_alloc_fd(ionfd, 4096, 0, 0, 0, &fd));
    for (const auto& heap : ion_heaps) {
        // invalid ion_fd
        int ret = ion_alloc_fd(0, 4096, 0, (1 << heap.heap_id), 0, &fd);
        EXPECT_TRUE(ret == -EINVAL || ret == -ENOTTY);
        // invalid ion_fd
        EXPECT_EQ(-EBADF, ion_alloc_fd(-1, 4096, 0, (1 << heap.heap_id), 0, &fd));
        SCOPED_TRACE(::testing::Message()
                     << "heap:" << heap.name << ":" << heap.type << ":" << heap.heap_id);
        // zero size
        EXPECT_EQ(-EINVAL, ion_alloc_fd(ionfd, 0, 0, (1 << heap.heap_id), 0, &fd));
        // too large size
        EXPECT_EQ(-EINVAL, ion_alloc_fd(ionfd, -1, 0, (1 << heap.heap_id), 0, &fd));
        // bad alignment
        // TODO: Current userspace and kernel code completely ignores alignment. So this
        // test is going to fail. We need to completely remove alignment from the API.
        // All memory by default is always page aligned. OR actually pass the alignment
        // down into the kernel and make kernel respect the alignment.
        // EXPECT_EQ(-EINVAL, ion_alloc_fd(ionfd, 4096, -1, (1 << heap.heap_id), 0, &fd));

        // NULL fd
        EXPECT_EQ(-EINVAL, ion_alloc_fd(ionfd, 4096, 0, (1 << heap.heap_id), 0, nullptr));
    }
}

TEST_F(InvalidValues, ion_query_heap_cnt) {
    // NULL count
    EXPECT_EQ(-EINVAL, ion_query_heap_cnt(ionfd, nullptr));

    int heap_count;
    // bad fd
    EXPECT_EQ(-EBADF, ion_query_heap_cnt(-1, &heap_count));
}

TEST_F(InvalidValues, ion_query_get_heaps) {
    int heap_count;
    ASSERT_EQ(0, ion_query_heap_cnt(ionfd, &heap_count));
    ASSERT_GT(heap_count, 0);

    // nullptr buffers, still returns success but without
    // the ion_heap_data.
    EXPECT_EQ(0, ion_query_get_heaps(ionfd, heap_count, nullptr));

    std::unique_ptr<struct ion_heap_data[]> heaps =
            std::make_unique<struct ion_heap_data[]>(heap_count);
    // bad fd
    EXPECT_EQ(-EBADF, ion_query_get_heaps(-1, heap_count, heaps.get()));

    // invalid heap data pointer
    EXPECT_EQ(-EFAULT, ion_query_get_heaps(ionfd, heap_count, reinterpret_cast<void*>(0xdeadf00d)));
}
