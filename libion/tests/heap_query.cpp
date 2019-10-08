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

#include <gtest/gtest.h>

#include <ion/ion.h>
#include "ion_test_fixture.h"

class HeapQuery : public IonTest {};

TEST_F(HeapQuery, AtleastOneHeap) {
    ASSERT_GT(ion_heaps.size(), 0);
}

// TODO: Adjust this test to account for the range of valid carveout and DMA heap ids.
TEST_F(HeapQuery, HeapIdVerify) {
    for (const auto& heap : ion_heaps) {
        SCOPED_TRACE(::testing::Message() << "Invalid id for heap:" << heap.name << ":" << heap.type
                                          << ":" << heap.heap_id);
        switch (heap.type) {
            case ION_HEAP_TYPE_SYSTEM:
                ASSERT_TRUE((1 << heap.heap_id) & ION_HEAP_SYSTEM_MASK);
                break;
            case ION_HEAP_TYPE_SYSTEM_CONTIG:
                ASSERT_TRUE((1 << heap.heap_id) & ION_HEAP_SYSTEM_CONTIG_MASK);
                break;
            case ION_HEAP_TYPE_CARVEOUT:
                ASSERT_TRUE((1 << heap.heap_id) & ION_HEAP_CARVEOUT_MASK);
                break;
            case ION_HEAP_TYPE_DMA:
                ASSERT_TRUE((1 << heap.heap_id) & ION_HEAP_TYPE_DMA_MASK);
                break;
        }
    }
}
