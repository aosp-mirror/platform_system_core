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
#include <unistd.h>

#include <gtest/gtest.h>

#include <ion/ion.h>
#include "ion_test_fixture.h"

class Map : public IonTest {};

TEST_F(Map, MapFd) {
    static const size_t allocationSizes[] = {4 * 1024, 64 * 1024, 1024 * 1024, 2 * 1024 * 1024};
    for (const auto& heap : ion_heaps) {
        for (size_t size : allocationSizes) {
            SCOPED_TRACE(::testing::Message()
                         << "heap:" << heap.name << ":" << heap.type << ":" << heap.heap_id);
            SCOPED_TRACE(::testing::Message() << "size " << size);
            int map_fd = -1;

            ASSERT_EQ(0, ion_alloc_fd(ionfd, size, 0, (1 << heap.heap_id), 0, &map_fd));
            ASSERT_GE(map_fd, 0);

            void* ptr;
            ptr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, map_fd, 0);
            ASSERT_TRUE(ptr != NULL);
            ASSERT_EQ(0, close(map_fd));

            memset(ptr, 0xaa, size);

            ASSERT_EQ(0, munmap(ptr, size));
        }
    }
}

TEST_F(Map, MapOffset) {
    for (const auto& heap : ion_heaps) {
        SCOPED_TRACE(::testing::Message()
                     << "heap:" << heap.name << ":" << heap.type << ":" << heap.heap_id);
        int map_fd = -1;

        ASSERT_EQ(0, ion_alloc_fd(ionfd, getpagesize() * 2, 0, (1 << heap.heap_id), 0, &map_fd));
        ASSERT_GE(map_fd, 0);

        unsigned char* ptr;
        ptr = (unsigned char*)mmap(NULL, getpagesize() * 2, PROT_READ | PROT_WRITE, MAP_SHARED,
                                   map_fd, 0);
        ASSERT_TRUE(ptr != NULL);

        memset(ptr, 0, getpagesize());
        memset(ptr + getpagesize(), 0xaa, getpagesize());

        ASSERT_EQ(0, munmap(ptr, getpagesize() * 2));

        ptr = (unsigned char*)mmap(NULL, getpagesize(), PROT_READ | PROT_WRITE, MAP_SHARED, map_fd,
                                   getpagesize());
        ASSERT_TRUE(ptr != NULL);
        ASSERT_EQ(ptr[0], 0xaa);
        ASSERT_EQ(ptr[getpagesize() - 1], 0xaa);
        ASSERT_EQ(0, munmap(ptr, getpagesize()));
        ASSERT_EQ(0, close(map_fd));
    }
}

TEST_F(Map, MapCached) {
    static const size_t allocationSizes[] = {4 * 1024, 64 * 1024, 1024 * 1024, 2 * 1024 * 1024};
    for (const auto& heap : ion_heaps) {
        for (size_t size : allocationSizes) {
            SCOPED_TRACE(::testing::Message()
                         << "heap:" << heap.name << ":" << heap.type << ":" << heap.heap_id);
            SCOPED_TRACE(::testing::Message() << "size " << size);
            int map_fd = -1;
            unsigned int flags = ION_FLAG_CACHED;

            ASSERT_EQ(0, ion_alloc_fd(ionfd, size, 0, (1 << heap.heap_id), flags, &map_fd));
            ASSERT_GE(map_fd, 0);

            void* ptr;
            ptr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, map_fd, 0);
            ASSERT_TRUE(ptr != NULL);
            ASSERT_EQ(0, close(map_fd));

            memset(ptr, 0xaa, size);

            ASSERT_EQ(0, munmap(ptr, size));
        }
    }
}

TEST_F(Map, MapCachedNeedsSync) {
    static const size_t allocationSizes[] = {4 * 1024, 64 * 1024, 1024 * 1024, 2 * 1024 * 1024};
    for (const auto& heap : ion_heaps) {
        for (size_t size : allocationSizes) {
            SCOPED_TRACE(::testing::Message()
                         << "heap:" << heap.name << ":" << heap.type << ":" << heap.heap_id);
            SCOPED_TRACE(::testing::Message() << "size " << size);
            int map_fd = -1;
            unsigned int flags = ION_FLAG_CACHED | ION_FLAG_CACHED_NEEDS_SYNC;

            ASSERT_EQ(0, ion_alloc_fd(ionfd, size, 0, (1 << heap.heap_id), flags, &map_fd));
            ASSERT_GE(map_fd, 0);

            void* ptr;
            ptr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, map_fd, 0);
            ASSERT_TRUE(ptr != NULL);
            ASSERT_EQ(0, close(map_fd));

            memset(ptr, 0xaa, size);

            ASSERT_EQ(0, munmap(ptr, size));
        }
    }
}
