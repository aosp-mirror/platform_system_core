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

class InvalidValues : public IonAllHeapsTest {
 public:
    virtual void SetUp();
    virtual void TearDown();
    ion_user_handle_t m_validHandle;
    int m_validShareFd;
    ion_user_handle_t const m_badHandle = -1;
};

void InvalidValues::SetUp()
{
    IonAllHeapsTest::SetUp();
    ASSERT_EQ(0, ion_alloc(m_ionFd, 4096, 0, m_firstHeap, 0, &m_validHandle))
      << m_ionFd << " " << m_firstHeap;
    ASSERT_TRUE(m_validHandle != 0);
    ASSERT_EQ(0, ion_share(m_ionFd, m_validHandle, &m_validShareFd));
}

void InvalidValues::TearDown()
{
    ASSERT_EQ(0, ion_free(m_ionFd, m_validHandle));
    ASSERT_EQ(0, close(m_validShareFd));
    m_validHandle = 0;
    IonAllHeapsTest::TearDown();
}

TEST_F(InvalidValues, ion_close)
{
    EXPECT_EQ(-EBADF, ion_close(-1));
}

TEST_F(InvalidValues, ion_alloc)
{
    ion_user_handle_t handle;
    /* invalid ion_fd */
    int ret = ion_alloc(0, 4096, 0, m_firstHeap, 0, &handle);
    EXPECT_TRUE(ret == -EINVAL || ret == -ENOTTY);
    /* invalid ion_fd */
    EXPECT_EQ(-EBADF, ion_alloc(-1, 4096, 0, m_firstHeap, 0, &handle));
    /* no heaps */
    EXPECT_EQ(-ENODEV, ion_alloc(m_ionFd, 4096, 0, 0, 0, &handle));
    for (unsigned int heapMask : m_allHeaps) {
        SCOPED_TRACE(::testing::Message() << "heap " << heapMask);
        /* zero size */
        EXPECT_EQ(-EINVAL, ion_alloc(m_ionFd, 0, 0, heapMask, 0, &handle));
        /* too large size */
        EXPECT_EQ(-EINVAL, ion_alloc(m_ionFd, -1, 0, heapMask, 0, &handle));
        /* bad alignment */
        EXPECT_EQ(-EINVAL, ion_alloc(m_ionFd, 4096, -1, heapMask, 0, &handle));
        /* NULL handle */
        EXPECT_EQ(-EINVAL, ion_alloc(m_ionFd, 4096, 0, heapMask, 0, NULL));
    }
}

TEST_F(InvalidValues, ion_alloc_fd)
{
    int fd;
    /* invalid ion_fd */
    int ret = ion_alloc_fd(0, 4096, 0, m_firstHeap, 0, &fd);
    EXPECT_TRUE(ret == -EINVAL || ret == -ENOTTY);
    /* invalid ion_fd */
    EXPECT_EQ(-EBADF, ion_alloc_fd(-1, 4096, 0, m_firstHeap, 0, &fd));
    /* no heaps */
    EXPECT_EQ(-ENODEV, ion_alloc_fd(m_ionFd, 4096, 0, 0, 0, &fd));
    for (unsigned int heapMask : m_allHeaps) {
        SCOPED_TRACE(::testing::Message() << "heap " << heapMask);
        /* zero size */
        EXPECT_EQ(-EINVAL, ion_alloc_fd(m_ionFd, 0, 0, heapMask, 0, &fd));
        /* too large size */
        EXPECT_EQ(-EINVAL, ion_alloc_fd(m_ionFd, -1, 0, heapMask, 0, &fd));
        /* bad alignment */
        EXPECT_EQ(-EINVAL, ion_alloc_fd(m_ionFd, 4096, -1, heapMask, 0, &fd));
        /* NULL handle */
        EXPECT_EQ(-EINVAL, ion_alloc_fd(m_ionFd, 4096, 0, heapMask, 0, NULL));
    }
}

TEST_F(InvalidValues, ion_free)
{
    /* invalid ion fd */
    int ret = ion_free(0, m_validHandle);
    EXPECT_TRUE(ret == -EINVAL || ret == -ENOTTY);
    /* invalid ion fd */
    EXPECT_EQ(-EBADF, ion_free(-1, m_validHandle));
    /* zero handle */
    EXPECT_EQ(-EINVAL, ion_free(m_ionFd, 0));
    /* bad handle */
    EXPECT_EQ(-EINVAL, ion_free(m_ionFd, m_badHandle));
}

TEST_F(InvalidValues, ion_map)
{
    int map_fd;
    unsigned char *ptr;

    /* invalid ion fd */
    int ret = ion_map(0, m_validHandle, 4096, PROT_READ, 0, 0, &ptr, &map_fd);
    EXPECT_TRUE(ret == -EINVAL || ret == -ENOTTY);
    /* invalid ion fd */
    EXPECT_EQ(-EBADF, ion_map(-1, m_validHandle, 4096, PROT_READ, 0, 0, &ptr, &map_fd));
    /* zero handle */
    EXPECT_EQ(-EINVAL, ion_map(m_ionFd, 0, 4096, PROT_READ, 0, 0, &ptr, &map_fd));
    /* bad handle */
    EXPECT_EQ(-EINVAL, ion_map(m_ionFd, m_badHandle, 4096, PROT_READ, 0, 0, &ptr, &map_fd));
    /* zero length */
    EXPECT_EQ(-EINVAL, ion_map(m_ionFd, m_validHandle, 0, PROT_READ, 0, 0, &ptr, &map_fd));
    /* bad prot */
    EXPECT_EQ(-EINVAL, ion_map(m_ionFd, m_validHandle, 4096, -1, 0, 0, &ptr, &map_fd));
    /* bad offset */
    EXPECT_EQ(-EINVAL, ion_map(m_ionFd, m_validHandle, 4096, PROT_READ, 0, -1, &ptr, &map_fd));
    /* NULL ptr */
    EXPECT_EQ(-EINVAL, ion_map(m_ionFd, m_validHandle, 4096, PROT_READ, 0, 0, NULL, &map_fd));
    /* NULL map_fd */
    EXPECT_EQ(-EINVAL, ion_map(m_ionFd, m_validHandle, 4096, PROT_READ, 0, 0, &ptr, NULL));
}

TEST_F(InvalidValues, ion_share)
{
    int share_fd;

    /* invalid ion fd */
    int ret = ion_share(0, m_validHandle, &share_fd);
    EXPECT_TRUE(ret == -EINVAL || ret == -ENOTTY);
    /* invalid ion fd */
    EXPECT_EQ(-EBADF, ion_share(-1, m_validHandle, &share_fd));
    /* zero handle */
    EXPECT_EQ(-EINVAL, ion_share(m_ionFd, 0, &share_fd));
    /* bad handle */
    EXPECT_EQ(-EINVAL, ion_share(m_ionFd, m_badHandle, &share_fd));
    /* NULL share_fd */
    EXPECT_EQ(-EINVAL, ion_share(m_ionFd, m_validHandle, NULL));
}

TEST_F(InvalidValues, ion_import)
{
    ion_user_handle_t handle;

    /* invalid ion fd */
    int ret = ion_import(0, m_validShareFd, &handle);
    EXPECT_TRUE(ret == -EINVAL || ret == -ENOTTY);
    /* invalid ion fd */
    EXPECT_EQ(-EBADF, ion_import(-1, m_validShareFd, &handle));
    /* bad share_fd */
    EXPECT_EQ(-EINVAL, ion_import(m_ionFd, 0, &handle));
    /* invalid share_fd */
    EXPECT_EQ(-EBADF, ion_import(m_ionFd, -1, &handle));
    /* NULL handle */
    EXPECT_EQ(-EINVAL, ion_import(m_ionFd, m_validShareFd, NULL));
}

TEST_F(InvalidValues, ion_sync_fd)
{
    /* invalid ion fd */
    int ret = ion_sync_fd(0, m_validShareFd);
    EXPECT_TRUE(ret == -EINVAL || ret == -ENOTTY);
    /* invalid ion fd */
    EXPECT_EQ(-EBADF, ion_sync_fd(-1, m_validShareFd));
    /* bad share_fd */
    EXPECT_EQ(-EINVAL, ion_sync_fd(m_ionFd, 0));
    /* invalid share_fd */
    EXPECT_EQ(-EBADF, ion_sync_fd(m_ionFd, -1));
}
