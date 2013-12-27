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

#include <gtest/gtest.h>

#include <ion/ion.h>

#include "ion_test_fixture.h"

class Map : public IonAllHeapsTest {
};

TEST_F(Map, MapHandle)
{
    static const size_t allocationSizes[] = {4*1024, 64*1024, 1024*1024, 2*1024*1024};
    for (unsigned int heapMask : m_allHeaps) {
        for (size_t size : allocationSizes) {
            SCOPED_TRACE(::testing::Message() << "heap " << heapMask);
            SCOPED_TRACE(::testing::Message() << "size " << size);
            ion_user_handle_t handle = 0;

            ASSERT_EQ(0, ion_alloc(m_ionFd, size, 0, heapMask, 0, &handle));
            ASSERT_TRUE(handle != 0);

            int map_fd = -1;
            unsigned char *ptr = NULL;
            ASSERT_EQ(0, ion_map(m_ionFd, handle, size, PROT_READ | PROT_WRITE, MAP_SHARED, 0, &ptr, &map_fd));
            ASSERT_TRUE(ptr != NULL);
            ASSERT_GE(map_fd, 0);

            ASSERT_EQ(0, close(map_fd));

            ASSERT_EQ(0, ion_free(m_ionFd, handle));

            memset(ptr, 0xaa, size);

            ASSERT_EQ(0, munmap(ptr, size));
        }
    }
}

TEST_F(Map, MapFd)
{
    static const size_t allocationSizes[] = {4*1024, 64*1024, 1024*1024, 2*1024*1024};
    for (unsigned int heapMask : m_allHeaps) {
        for (size_t size : allocationSizes) {
            SCOPED_TRACE(::testing::Message() << "heap " << heapMask);
            SCOPED_TRACE(::testing::Message() << "size " << size);
            int map_fd = -1;

            ASSERT_EQ(0, ion_alloc_fd(m_ionFd, size, 0, heapMask, 0, &map_fd));
            ASSERT_GE(map_fd, 0);

            void *ptr;
            ptr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, map_fd, 0);
            ASSERT_TRUE(ptr != NULL);

            ASSERT_EQ(0, close(map_fd));

            memset(ptr, 0xaa, size);

            ASSERT_EQ(0, munmap(ptr, size));
        }
    }
}

TEST_F(Map, MapOffset)
{
    for (unsigned int heapMask : m_allHeaps) {
        SCOPED_TRACE(::testing::Message() << "heap " << heapMask);
        int map_fd = -1;

        ASSERT_EQ(0, ion_alloc_fd(m_ionFd, PAGE_SIZE * 2, 0, heapMask, 0, &map_fd));
        ASSERT_GE(map_fd, 0);

        unsigned char *ptr;
        ptr = (unsigned char *)mmap(NULL, PAGE_SIZE * 2, PROT_READ | PROT_WRITE, MAP_SHARED, map_fd, 0);
        ASSERT_TRUE(ptr != NULL);

        memset(ptr, 0, PAGE_SIZE);
        memset(ptr + PAGE_SIZE, 0xaa, PAGE_SIZE);

        ASSERT_EQ(0, munmap(ptr, PAGE_SIZE * 2));

        ptr = (unsigned char *)mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, map_fd, PAGE_SIZE);
        ASSERT_TRUE(ptr != NULL);

        ASSERT_EQ(ptr[0], 0xaa);
        ASSERT_EQ(ptr[PAGE_SIZE - 1], 0xaa);

        ASSERT_EQ(0, munmap(ptr, PAGE_SIZE));

        ASSERT_EQ(0, close(map_fd));
    }
}

TEST_F(Map, MapCached)
{
    static const size_t allocationSizes[] = {4*1024, 64*1024, 1024*1024, 2*1024*1024};
    for (unsigned int heapMask : m_allHeaps) {
        for (size_t size : allocationSizes) {
            SCOPED_TRACE(::testing::Message() << "heap " << heapMask);
            SCOPED_TRACE(::testing::Message() << "size " << size);
            int map_fd = -1;
            unsigned int flags = ION_FLAG_CACHED;

            ASSERT_EQ(0, ion_alloc_fd(m_ionFd, size, 0, heapMask, flags, &map_fd));
            ASSERT_GE(map_fd, 0);

            void *ptr;
            ptr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, map_fd, 0);
            ASSERT_TRUE(ptr != NULL);

            ASSERT_EQ(0, close(map_fd));

            memset(ptr, 0xaa, size);

            ASSERT_EQ(0, munmap(ptr, size));
        }
    }
}

TEST_F(Map, MapCachedNeedsSync)
{
    static const size_t allocationSizes[] = {4*1024, 64*1024, 1024*1024, 2*1024*1024};
    for (unsigned int heapMask : m_allHeaps) {
        for (size_t size : allocationSizes) {
            SCOPED_TRACE(::testing::Message() << "heap " << heapMask);
            SCOPED_TRACE(::testing::Message() << "size " << size);
            int map_fd = -1;
            unsigned int flags = ION_FLAG_CACHED | ION_FLAG_CACHED_NEEDS_SYNC;

            ASSERT_EQ(0, ion_alloc_fd(m_ionFd, size, 0, heapMask, flags, &map_fd));
            ASSERT_GE(map_fd, 0);

            void *ptr;
            ptr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, map_fd, 0);
            ASSERT_TRUE(ptr != NULL);

            ASSERT_EQ(0, close(map_fd));

            memset(ptr, 0xaa, size);

            ASSERT_EQ(0, munmap(ptr, size));
        }
    }
}
