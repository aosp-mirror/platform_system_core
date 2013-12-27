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

#include <gtest/gtest.h>

#include <ion/ion.h>

#include "ion_test_fixture.h"

IonTest::IonTest() : m_ionFd(-1)
{
}

void IonTest::SetUp() {
    m_ionFd = ion_open();
    ASSERT_GE(m_ionFd, 0);
}

void IonTest::TearDown() {
    ion_close(m_ionFd);
}

IonAllHeapsTest::IonAllHeapsTest() :
        m_firstHeap(0),
        m_lastHeap(0),
        m_allHeaps()
{
}

void IonAllHeapsTest::SetUp() {
    int fd = ion_open();
    ASSERT_GE(fd, 0);

    for (int i = 1; i != 0; i <<= 1) {
        ion_user_handle_t handle = 0;
        int ret;
        ret = ion_alloc(fd, 4096, 0, i, 0, &handle);
        if (ret == 0 && handle != 0) {
            ion_free(fd, handle);
            if (!m_firstHeap) {
                m_firstHeap = i;
            }
            m_lastHeap = i;
            m_allHeaps.push_back(i);
        } else {
            ASSERT_EQ(-ENODEV, ret);
        }
    }
    ion_close(fd);

    EXPECT_NE(0U, m_firstHeap);
    EXPECT_NE(0U, m_lastHeap);

    RecordProperty("Heaps", m_allHeaps.size());
    IonTest::SetUp();
}

void IonAllHeapsTest::TearDown() {
    IonTest::TearDown();
}
