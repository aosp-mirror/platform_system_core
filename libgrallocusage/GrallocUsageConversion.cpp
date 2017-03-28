/*
 * Copyright 2017 The Android Open Source Project
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

#include <grallocusage/GrallocUsageConversion.h>

#include <android/hardware/graphics/allocator/2.0/types.h>
#include <hardware/gralloc.h>

using android::hardware::graphics::allocator::V2_0::ProducerUsage;
using android::hardware::graphics::allocator::V2_0::ConsumerUsage;

void android_convertGralloc0To1Usage(int32_t usage, uint64_t* producerUsage,
                                     uint64_t* consumerUsage) {
    constexpr uint64_t PRODUCER_MASK = ProducerUsage::CPU_READ |
                                       /* ProducerUsage::CPU_READ_OFTEN | */
                                       ProducerUsage::CPU_WRITE |
                                       /* ProducerUsage::CPU_WRITE_OFTEN | */
                                       ProducerUsage::GPU_RENDER_TARGET | ProducerUsage::PROTECTED |
                                       ProducerUsage::CAMERA | ProducerUsage::VIDEO_DECODER |
                                       ProducerUsage::SENSOR_DIRECT_DATA;
    constexpr uint64_t CONSUMER_MASK = ConsumerUsage::CPU_READ |
                                       /* ConsumerUsage::CPU_READ_OFTEN | */
                                       ConsumerUsage::GPU_TEXTURE | ConsumerUsage::HWCOMPOSER |
                                       ConsumerUsage::CLIENT_TARGET | ConsumerUsage::CURSOR |
                                       ConsumerUsage::VIDEO_ENCODER | ConsumerUsage::CAMERA |
                                       ConsumerUsage::RENDERSCRIPT | ConsumerUsage::GPU_DATA_BUFFER;
    *producerUsage = static_cast<uint64_t>(usage) & PRODUCER_MASK;
    *consumerUsage = static_cast<uint64_t>(usage) & CONSUMER_MASK;
    if ((static_cast<uint32_t>(usage) & GRALLOC_USAGE_SW_READ_OFTEN) == GRALLOC_USAGE_SW_READ_OFTEN) {
        *producerUsage |= ProducerUsage::CPU_READ_OFTEN;
        *consumerUsage |= ConsumerUsage::CPU_READ_OFTEN;
    }
    if ((static_cast<uint32_t>(usage) & GRALLOC_USAGE_SW_WRITE_OFTEN) ==
        GRALLOC_USAGE_SW_WRITE_OFTEN) {
        *producerUsage |= ProducerUsage::CPU_WRITE_OFTEN;
    }
}

int32_t android_convertGralloc1To0Usage(uint64_t producerUsage, uint64_t consumerUsage) {
    static_assert(uint64_t(ConsumerUsage::CPU_READ_OFTEN) == uint64_t(ProducerUsage::CPU_READ_OFTEN),
                  "expected ConsumerUsage and ProducerUsage CPU_READ_OFTEN bits to match");
    uint64_t merged = producerUsage | consumerUsage;
    if ((merged & (ConsumerUsage::CPU_READ_OFTEN)) != 0) {
        merged &= ~uint64_t(ConsumerUsage::CPU_READ_OFTEN);
        merged |= GRALLOC_USAGE_SW_READ_OFTEN;
    }
    if ((merged & (ProducerUsage::CPU_WRITE_OFTEN)) != 0) {
        merged &= ~uint64_t(ProducerUsage::CPU_WRITE_OFTEN);
        merged |= GRALLOC_USAGE_SW_WRITE_OFTEN;
    }
    return static_cast<int32_t>(merged);
}
