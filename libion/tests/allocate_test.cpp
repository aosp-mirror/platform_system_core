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

#include <memory>
#include <sys/mman.h>

#include <gtest/gtest.h>

#include <ion/ion.h>
#include "ion_test_fixture.h"

class Allocate : public IonAllHeapsTest {
};

TEST_F(Allocate, Allocate)
{
    static const size_t allocationSizes[] = {4*1024, 64*1024, 1024*1024, 2*1024*1024};
    for (unsigned int heapMask : m_allHeaps) {
        for (size_t size : allocationSizes) {
            SCOPED_TRACE(::testing::Message() << "heap " << heapMask);
            SCOPED_TRACE(::testing::Message() << "size " << size);
            ion_user_handle_t handle = 0;
            ASSERT_EQ(0, ion_alloc(m_ionFd, size, 0, heapMask, 0, &handle));
            ASSERT_TRUE(handle != 0);
            ASSERT_EQ(0, ion_free(m_ionFd, handle));
        }
    }
}

TEST_F(Allocate, AllocateCached)
{
    static const size_t allocationSizes[] = {4*1024, 64*1024, 1024*1024, 2*1024*1024};
    for (unsigned int heapMask : m_allHeaps) {
        for (size_t size : allocationSizes) {
            SCOPED_TRACE(::testing::Message() << "heap " << heapMask);
            SCOPED_TRACE(::testing::Message() << "size " << size);
            ion_user_handle_t handle = 0;
            ASSERT_EQ(0, ion_alloc(m_ionFd, size, 0, heapMask, ION_FLAG_CACHED, &handle));
            ASSERT_TRUE(handle != 0);
            ASSERT_EQ(0, ion_free(m_ionFd, handle));
        }
    }
}

TEST_F(Allocate, AllocateCachedNeedsSync)
{
    static const size_t allocationSizes[] = {4*1024, 64*1024, 1024*1024, 2*1024*1024};
    for (unsigned int heapMask : m_allHeaps) {
        for (size_t size : allocationSizes) {
            SCOPED_TRACE(::testing::Message() << "heap " << heapMask);
            SCOPED_TRACE(::testing::Message() << "size " << size);
            ion_user_handle_t handle = 0;
            ASSERT_EQ(0, ion_alloc(m_ionFd, size, 0, heapMask, ION_FLAG_CACHED_NEEDS_SYNC, &handle));
            ASSERT_TRUE(handle != 0);
            ASSERT_EQ(0, ion_free(m_ionFd, handle));
        }
    }
}

TEST_F(Allocate, RepeatedAllocate)
{
    static const size_t allocationSizes[] = {4*1024, 64*1024, 1024*1024, 2*1024*1024};
    for (unsigned int heapMask : m_allHeaps) {
        for (size_t size : allocationSizes) {
            SCOPED_TRACE(::testing::Message() << "heap " << heapMask);
            SCOPED_TRACE(::testing::Message() << "size " << size);
            ion_user_handle_t handle = 0;

            for (unsigned int i = 0; i < 1024; i++) {
                SCOPED_TRACE(::testing::Message() << "iteration " << i);
                ASSERT_EQ(0, ion_alloc(m_ionFd, size, 0, heapMask, 0, &handle));
                ASSERT_TRUE(handle != 0);
                ASSERT_EQ(0, ion_free(m_ionFd, handle));
            }
        }
    }
}

TEST_F(Allocate, Zeroed)
{
    auto zeroes_ptr = std::make_unique<char[]>(4096);

    for (unsigned int heapMask : m_allHeaps) {
        SCOPED_TRACE(::testing::Message() << "heap " << heapMask);
        int fds[16];
        for (unsigned int i = 0; i < 16; i++) {
            int map_fd = -1;

            ASSERT_EQ(0, ion_alloc_fd(m_ionFd, 4096, 0, heapMask, 0, &map_fd));
            ASSERT_GE(map_fd, 0);

            void *ptr = NULL;
            ptr = mmap(NULL, 4096, PROT_WRITE, MAP_SHARED, map_fd, 0);
            ASSERT_TRUE(ptr != NULL);

            memset(ptr, 0xaa, 4096);

            ASSERT_EQ(0, munmap(ptr, 4096));
            fds[i] = map_fd;
        }

        for (unsigned int i = 0; i < 16; i++) {
            ASSERT_EQ(0, close(fds[i]));
        }

        int newIonFd = ion_open();
        int map_fd = -1;

        ASSERT_EQ(0, ion_alloc_fd(newIonFd, 4096, 0, heapMask, 0, &map_fd));
        ASSERT_GE(map_fd, 0);

        void *ptr = NULL;
        ptr = mmap(NULL, 4096, PROT_READ, MAP_SHARED, map_fd, 0);
        ASSERT_TRUE(ptr != NULL);

        ASSERT_EQ(0, memcmp(ptr, zeroes_ptr.get(), 4096));

        ASSERT_EQ(0, munmap(ptr, 4096));
        ASSERT_EQ(0, close(map_fd));
    }
}

TEST_F(Allocate, Large)
{
    for (unsigned int heapMask : m_allHeaps) {
            SCOPED_TRACE(::testing::Message() << "heap " << heapMask);
        ion_user_handle_t handle = 0;
        ASSERT_EQ(-ENOMEM, ion_alloc(m_ionFd, 3UL*1024*1024*1024, 0, heapMask, 0, &handle));
    }
}
