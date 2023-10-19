/*
 * Copyright (C) 2023 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <android-base/unique_fd.h>
#include <fcntl.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <liblp/metadata_format.h>
#include <liblp/super_layout_builder.h>
#include <linux/memfd.h>
#include <storage_literals/storage_literals.h>
#include <sys/syscall.h>

using namespace android::fs_mgr;
using namespace std;
using unique_fd = android::base::unique_fd;
using namespace android::storage_literals;

static constexpr uint64_t kSuperLayoutValidBlockDevSize = 4_MiB;
static constexpr uint64_t kMinBlockDevValue = 0;
static constexpr uint64_t kMaxBlockDevValue = 100000;
static constexpr uint64_t kMinElements = 0;
static constexpr uint64_t kMaxElements = 10;
static constexpr uint32_t kSuperLayoutValidMetadataSize = 8_KiB;
static constexpr uint32_t kMinMetadataValue = 0;
static constexpr uint32_t kMaxMetadataValue = 10000;
static constexpr uint32_t kMaxBytes = 20;
static constexpr uint32_t kMinSlot = 0;
static constexpr uint32_t kMaxSlot = 10;
static constexpr uint32_t kMinOpen = 0;
static constexpr uint32_t kMaxOpen = 2;

const uint64_t kAttributeTypes[] = {
        LP_PARTITION_ATTR_NONE,    LP_PARTITION_ATTR_READONLY, LP_PARTITION_ATTR_SLOT_SUFFIXED,
        LP_PARTITION_ATTR_UPDATED, LP_PARTITION_ATTR_DISABLED,
};

class SuperLayoutBuilderFuzzer {
  public:
    SuperLayoutBuilderFuzzer(const uint8_t* data, size_t size) : mFdp(data, size){};
    void process();

  private:
    FuzzedDataProvider mFdp;
    void invokeSuperLayoutBuilderAPIs();
    void callRandomOpen(int32_t open);
    void addMultiplePartitions(int32_t numPartitions);
    void setupSuperLayoutBuilder(string fuzzPartitionName);
    SuperLayoutBuilder mSuperLayoutBuilder;
    unique_ptr<MetadataBuilder> mSuperBuilder;
    unique_ptr<LpMetadata> mMetadata;
    bool mOpenSuccess = false;
};

void SuperLayoutBuilderFuzzer::setupSuperLayoutBuilder(string fuzzPartitionName) {
    uint64_t randomBlockDevSize =
            mFdp.ConsumeIntegralInRange<uint64_t>(kMinBlockDevValue, kMaxBlockDevValue);
    uint64_t blockDevSize = mFdp.ConsumeBool() ? kSuperLayoutValidBlockDevSize : randomBlockDevSize;
    uint32_t randomMetadataMaxSize =
            mFdp.ConsumeIntegralInRange<uint32_t>(kMinMetadataValue, kMaxMetadataValue);
    uint32_t metadataMaxSize =
            mFdp.ConsumeBool() ? kSuperLayoutValidMetadataSize : randomMetadataMaxSize;
    uint32_t metadataSlotCount = mFdp.ConsumeIntegralInRange<uint32_t>(kMinSlot, kMaxSlot);
    mSuperBuilder = MetadataBuilder::New(blockDevSize, metadataMaxSize, metadataSlotCount);

    if (mSuperBuilder.get()) {
        if (mFdp.ConsumeBool()) {
            int32_t numPartitions =
                    mFdp.ConsumeIntegralInRange<int32_t>(kMinElements, kMaxElements);
            addMultiplePartitions(numPartitions);
        }

        uint32_t randomOpen = mFdp.ConsumeIntegralInRange<uint32_t>(kMinOpen, kMaxOpen);
        callRandomOpen(randomOpen);

        if (!fuzzPartitionName.size()) {
            fuzzPartitionName = "builder_partition";
        }
    }
}

void SuperLayoutBuilderFuzzer::addMultiplePartitions(int32_t numPartitions) {
    for (int32_t idx = 0; idx < numPartitions; ++idx) {
        string partitionName = mFdp.ConsumeBool() ? mFdp.ConsumeRandomLengthString(kMaxBytes)
                                                  : "builder_partition";
        mSuperBuilder->AddPartition(partitionName, mFdp.PickValueInArray(kAttributeTypes));
    }
}

void SuperLayoutBuilderFuzzer::callRandomOpen(int32_t open) {
    mMetadata = mSuperBuilder->Export();
    switch (open) {
        case 0: {
            vector<uint8_t> imageData = mFdp.ConsumeBytes<uint8_t>(kMaxBytes);
            mOpenSuccess = mSuperLayoutBuilder.Open((void*)(imageData.data()), imageData.size());
            break;
        }
        case 1: {
            mOpenSuccess = mSuperLayoutBuilder.Open(*mMetadata.get());
            break;
        }
        case 2: {
            unique_fd fd(syscall(__NR_memfd_create, "image_file", 0));
            WriteToImageFile(fd, *mMetadata.get());
            mOpenSuccess = mSuperLayoutBuilder.Open(fd);
            break;
        }
    }
}

void SuperLayoutBuilderFuzzer::invokeSuperLayoutBuilderAPIs() {
    string imageName = mFdp.ConsumeRandomLengthString(kMaxBytes);
    string fuzzPartitionName =
            mFdp.ConsumeBool() ? "builder_partition" : mFdp.ConsumeRandomLengthString(kMaxBytes);
    setupSuperLayoutBuilder(fuzzPartitionName);
    if (mOpenSuccess) {
        while (mFdp.remaining_bytes()) {
            auto invokeSuperAPIs = mFdp.PickValueInArray<const function<void()>>({
                    [&]() { mSuperLayoutBuilder.GetImageLayout(); },
                    [&]() {
                        mSuperLayoutBuilder.AddPartition(fuzzPartitionName, imageName,
                                                         mFdp.ConsumeIntegral<uint64_t>());
                    },
            });
            invokeSuperAPIs();
        }
    }
}

void SuperLayoutBuilderFuzzer::process() {
    invokeSuperLayoutBuilderAPIs();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    SuperLayoutBuilderFuzzer superLayoutBuilderFuzzer(data, size);
    superLayoutBuilderFuzzer.process();
    return 0;
}
