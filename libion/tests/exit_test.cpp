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

class Exit : public IonAllHeapsTest {
};

TEST_F(Exit, WithAlloc)
{
    static const size_t allocationSizes[] = {4*1024, 64*1024, 1024*1024, 2*1024*1024};
    for (unsigned int heapMask : m_allHeaps) {
        for (size_t size : allocationSizes) {
            SCOPED_TRACE(::testing::Message() << "heap " << heapMask);
            SCOPED_TRACE(::testing::Message() << "size " << size);
            EXPECT_EXIT({
                ion_user_handle_t handle = 0;

                ASSERT_EQ(0, ion_alloc(m_ionFd, size, 0, heapMask, 0, &handle));
                ASSERT_TRUE(handle != 0);
                exit(0);
            }, ::testing::ExitedWithCode(0), "");
        }
    }
}

TEST_F(Exit, WithAllocFd)
{
    static const size_t allocationSizes[] = {4*1024, 64*1024, 1024*1024, 2*1024*1024};
    for (unsigned int heapMask : m_allHeaps) {
        for (size_t size : allocationSizes) {
            SCOPED_TRACE(::testing::Message() << "heap " << heapMask);
            SCOPED_TRACE(::testing::Message() << "size " << size);
            EXPECT_EXIT({
                int handle_fd = -1;

                ASSERT_EQ(0, ion_alloc_fd(m_ionFd, size, 0, heapMask, 0, &handle_fd));
                ASSERT_NE(-1, handle_fd);
                exit(0);
            }, ::testing::ExitedWithCode(0), "");
        }
    }
}

TEST_F(Exit, WithRepeatedAllocFd)
{
    static const size_t allocationSizes[] = {4*1024, 64*1024, 1024*1024, 2*1024*1024};
    for (unsigned int heapMask : m_allHeaps) {
        for (size_t size : allocationSizes) {
            for (unsigned int i = 0; i < 1024; i++) {
                SCOPED_TRACE(::testing::Message() << "heap " << heapMask);
                SCOPED_TRACE(::testing::Message() << "size " << size);
                ASSERT_EXIT({
                    int handle_fd = -1;

                    ASSERT_EQ(0, ion_alloc_fd(m_ionFd, size, 0, heapMask, 0, &handle_fd));
                    ASSERT_NE(-1, handle_fd);
                    exit(0);
                }, ::testing::ExitedWithCode(0), "")
                        << "failed on heap " << heapMask
                        << " and size " << size
                        << " on iteration " << i;
            }
        }
    }
}


TEST_F(Exit, WithMapping)
{
    static const size_t allocationSizes[] = {4*1024, 64*1024, 1024*1024, 2*1024*1024};
    for (unsigned int heapMask : m_allHeaps) {
        for (size_t size : allocationSizes) {
            SCOPED_TRACE(::testing::Message() << "heap " << heapMask);
            SCOPED_TRACE(::testing::Message() << "size " << size);
            EXPECT_EXIT({
                int map_fd = -1;

                ASSERT_EQ(0, ion_alloc_fd(m_ionFd, size, 0, heapMask, 0, &map_fd));
                ASSERT_GE(map_fd, 0);

                void *ptr;
                ptr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, map_fd, 0);
                ASSERT_TRUE(ptr != NULL);
                exit(0);
            }, ::testing::ExitedWithCode(0), "");
        }
    }

}

TEST_F(Exit, WithPartialMapping)
{
    static const size_t allocationSizes[] = {64*1024, 1024*1024, 2*1024*1024};
    for (unsigned int heapMask : m_allHeaps) {
        for (size_t size : allocationSizes) {
            SCOPED_TRACE(::testing::Message() << "heap " << heapMask);
            SCOPED_TRACE(::testing::Message() << "size " << size);
            EXPECT_EXIT({
                int map_fd = -1;

                ASSERT_EQ(0, ion_alloc_fd(m_ionFd, size, 0, heapMask, 0, &map_fd));
                ASSERT_GE(map_fd, 0);

                void *ptr;
                ptr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, map_fd, 0);
                ASSERT_TRUE(ptr != NULL);

                ASSERT_EQ(0, munmap(ptr, size / 2));
                exit(0);
            }, ::testing::ExitedWithCode(0), "");
        }
    }
}

TEST_F(Exit, WithMappingCached)
{
    static const size_t allocationSizes[] = {4*1024, 64*1024, 1024*1024, 2*1024*1024};
    for (unsigned int heapMask : m_allHeaps) {
        for (size_t size : allocationSizes) {
            SCOPED_TRACE(::testing::Message() << "heap " << heapMask);
            SCOPED_TRACE(::testing::Message() << "size " << size);
            EXPECT_EXIT({
                int map_fd = -1;

                ASSERT_EQ(0, ion_alloc_fd(m_ionFd, size, 0, heapMask, ION_FLAG_CACHED, &map_fd));
                ASSERT_GE(map_fd, 0);

                void *ptr;
                ptr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, map_fd, 0);
                ASSERT_TRUE(ptr != NULL);
                exit(0);
            }, ::testing::ExitedWithCode(0), "");
        }
    }

}

TEST_F(Exit, WithPartialMappingCached)
{
    static const size_t allocationSizes[] = {64*1024, 1024*1024, 2*1024*1024};
    for (unsigned int heapMask : m_allHeaps) {
        for (size_t size : allocationSizes) {
            SCOPED_TRACE(::testing::Message() << "heap " << heapMask);
            SCOPED_TRACE(::testing::Message() << "size " << size);
            EXPECT_EXIT({
                int map_fd = -1;

                ASSERT_EQ(0, ion_alloc_fd(m_ionFd, size, 0, heapMask, ION_FLAG_CACHED, &map_fd));
                ASSERT_GE(map_fd, 0);

                void *ptr;
                ptr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, map_fd, 0);
                ASSERT_TRUE(ptr != NULL);

                ASSERT_EQ(0, munmap(ptr, size / 2));
                exit(0);
            }, ::testing::ExitedWithCode(0), "");
        }
    }
}

TEST_F(Exit, WithMappingNeedsSync)
{
    static const size_t allocationSizes[] = {4*1024, 64*1024, 1024*1024, 2*1024*1024};
    for (unsigned int heapMask : m_allHeaps) {
        for (size_t size : allocationSizes) {
            SCOPED_TRACE(::testing::Message() << "heap " << heapMask);
            SCOPED_TRACE(::testing::Message() << "size " << size);
            EXPECT_EXIT({
                int map_fd = -1;

                ASSERT_EQ(0, ion_alloc_fd(m_ionFd, size, 0, heapMask, ION_FLAG_CACHED | ION_FLAG_CACHED_NEEDS_SYNC, &map_fd));
                ASSERT_GE(map_fd, 0);

                void *ptr;
                ptr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, map_fd, 0);
                ASSERT_TRUE(ptr != NULL);
                exit(0);
            }, ::testing::ExitedWithCode(0), "");
        }
    }

}

TEST_F(Exit, WithPartialMappingNeedsSync)
{
    static const size_t allocationSizes[] = {64*1024, 1024*1024, 2*1024*1024};
    for (unsigned int heapMask : m_allHeaps) {
        for (size_t size : allocationSizes) {
            SCOPED_TRACE(::testing::Message() << "heap " << heapMask);
            SCOPED_TRACE(::testing::Message() << "size " << size);
            EXPECT_EXIT({
                int map_fd = -1;

                ASSERT_EQ(0, ion_alloc_fd(m_ionFd, size, 0, heapMask, ION_FLAG_CACHED | ION_FLAG_CACHED_NEEDS_SYNC, &map_fd));
                ASSERT_GE(map_fd, 0);

                void *ptr;
                ptr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, map_fd, 0);
                ASSERT_TRUE(ptr != NULL);

                ASSERT_EQ(0, munmap(ptr, size / 2));
                exit(0);
            }, ::testing::ExitedWithCode(0), "");
        }
    }
}
