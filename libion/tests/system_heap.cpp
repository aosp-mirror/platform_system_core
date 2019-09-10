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

#include <unistd.h>

#include <gtest/gtest.h>
#include <iostream>

#include <ion/ion.h>
#include "ion_test_fixture.h"

class SystemHeap : public IonTest {};

TEST_F(SystemHeap, Presence) {
    bool system_heap_found = false;
    for (const auto& heap : ion_heaps) {
        if (heap.type == ION_HEAP_TYPE_SYSTEM) {
            system_heap_found = true;
            EXPECT_TRUE((1 << heap.heap_id) & ION_HEAP_SYSTEM_MASK);
        }
    }
    // We now expect the system heap to exist from Android
    ASSERT_TRUE(system_heap_found);
}

TEST_F(SystemHeap, Allocate) {
    int fd;
    ASSERT_EQ(0, ion_alloc_fd(ionfd, getpagesize(), 0, ION_HEAP_SYSTEM_MASK, 0, &fd));
    ASSERT_TRUE(fd != 0);
    ASSERT_EQ(close(fd), 0);  // free the buffer
}
