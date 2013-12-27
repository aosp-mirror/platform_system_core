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

class FormerlyValidHandle : public IonTest {
 public:
    virtual void SetUp();
    virtual void TearDown();
    ion_user_handle_t m_handle;
};

void FormerlyValidHandle::SetUp()
{
    IonTest::SetUp();
    ASSERT_EQ(0, ion_alloc(m_ionFd, 4096, 0, 1/* ion_env->m_firstHeap */, 0, &m_handle));
    ASSERT_TRUE(m_handle != 0);
    ASSERT_EQ(0, ion_free(m_ionFd, m_handle));
}

void FormerlyValidHandle::TearDown()
{
    m_handle = 0;
}

TEST_F(FormerlyValidHandle, free)
{
	ASSERT_EQ(-EINVAL, ion_free(m_ionFd, m_handle));
}

TEST_F(FormerlyValidHandle, map)
{
    int map_fd;
    unsigned char *ptr;

    ASSERT_EQ(-EINVAL, ion_map(m_ionFd, m_handle, 4096, PROT_READ, 0, 0, &ptr, &map_fd));
}

TEST_F(FormerlyValidHandle, share)
{
    int share_fd;

    ASSERT_EQ(-EINVAL, ion_share(m_ionFd, m_handle, &share_fd));
}
