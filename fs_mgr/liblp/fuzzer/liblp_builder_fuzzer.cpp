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

#include <fuzzer/FuzzedDataProvider.h>
#include <liblp/builder.h>
#include <liblp/property_fetcher.h>
#include <storage_literals/storage_literals.h>

using namespace android::fs_mgr;
using namespace std;
using namespace android::storage_literals;

static constexpr uint64_t kValidBlockSize = 4096 * 50;
static constexpr uint64_t kBlockDeviceInfoSize = 1024 * 1024;
static constexpr uint64_t kValidBlockDeviceInfoSize = 8_GiB;
static constexpr uint64_t kValidMaxGroupSize = 40960;
static constexpr uint64_t kMinBlockDevValue = 0;
static constexpr uint64_t kMaxBlockDevValue = 100000;
static constexpr uint64_t kMinSectorValue = 1;
static constexpr uint64_t kMaxSectorValue = 1000000;
static constexpr uint64_t kMinValue = 0;
static constexpr uint64_t kMaxValue = 10000;
static constexpr uint64_t kValidNumSectors = 1901568;
static constexpr uint64_t kValidPhysicalSector = 3608576;
static constexpr uint64_t kMinElements = 0;
static constexpr uint64_t kMaxElements = 10;
static constexpr uint32_t kValidAlignment = 786432;
static constexpr uint32_t kValidMetadataSize = 40960;
static constexpr uint32_t kValidAlignmentOffset = 229376;
static constexpr uint32_t kValidLogicalBlockSize = 4096;
static constexpr uint32_t kValidMaxMetadataSize = 65536;
static constexpr uint32_t kMinMetadataValue = 0;
static constexpr uint32_t kMaxMetadataValue = 10000;
static constexpr uint32_t kZeroAlignment = 0;
static constexpr uint32_t kZeroAlignmentOffset = 0;
static constexpr uint32_t kMaxBytes = 20;
static constexpr uint32_t kMinBuilder = 0;
static constexpr uint32_t kMaxBuilder = 4;

const uint64_t kAttributeTypes[] = {
        LP_PARTITION_ATTR_NONE,    LP_PARTITION_ATTR_READONLY, LP_PARTITION_ATTR_SLOT_SUFFIXED,
        LP_PARTITION_ATTR_UPDATED, LP_PARTITION_ATTR_DISABLED,
};

const string kFuzzPartitionName = "fuzz_partition_name";
const string kSuperPartitionName = "super_partition";
const string kDeviceInfoName = "super";
const string kDefaultGroupName = "default";

class BuilderFuzzer {
  public:
    BuilderFuzzer(const uint8_t* data, size_t size) : mFdp(data, size){};
    void process();

  private:
    FuzzedDataProvider mFdp;
    void invokeBuilderAPIs();
    void selectRandomBuilder(int32_t randomBuilder, string superBlockDeviceName);
    void setupBuilder(string superBlockDeviceName);
    void callChangePartitionGroup();
    void callVerifyExtentsAgainstSourceMetadata();
    vector<BlockDeviceInfo> mBlockDevices;
    unique_ptr<MetadataBuilder> mBuilder;
    string mResizePartitionName;
    string mGroupNames[4] = {
            "default",
            "group_a",
            "group_b",
            mFdp.ConsumeRandomLengthString(kMaxBytes),
    };
    string mPartitionNames[5] = {
            "system_a",
            "vendor_a",
            "system_b",
            "vendor_b",
            mFdp.ConsumeRandomLengthString(kMaxBytes),
    };
    Partition* mPartition;
    Partition* mFuzzPartition;
    Partition* mResizePartition;
    template <typename T>
    T getParamValue(T validValue) {
        T parameter = validValue;
        if (mFdp.ConsumeBool()) {
            parameter = mFdp.ConsumeIntegralInRange<T>(kMinValue, kMaxValue);
        }
        return parameter;
    }
};

void BuilderFuzzer::selectRandomBuilder(int32_t randomBuilder, string superBlockDeviceName) {
    switch (randomBuilder) {
        case 0: {
            uint32_t maxMetadataSize = getParamValue(kValidMaxMetadataSize);
            uint32_t numSlots = mFdp.ConsumeBool() ? 0 : 1;
            mBuilder = MetadataBuilder::New(mBlockDevices, superBlockDeviceName, maxMetadataSize,
                                            numSlots);
            break;
        }
        case 1: {
            uint64_t blockDevSize =
                    mFdp.ConsumeIntegralInRange<uint64_t>(kMinBlockDevValue, kMaxBlockDevValue);
            uint32_t metadataMaxSize =
                    mFdp.ConsumeIntegralInRange<uint32_t>(kMinMetadataValue, kMaxMetadataValue);
            uint32_t metadataSlotCount = mFdp.ConsumeBool() ? 0 : 1;
            mBuilder = MetadataBuilder::New(blockDevSize, metadataMaxSize, metadataSlotCount);
            break;
        }
        case 2: {
            uint64_t blockDevSize = getParamValue(kValidBlockSize);
            uint32_t metadataSize = getParamValue(kValidMetadataSize);
            uint32_t metadataSlotCount = mFdp.ConsumeBool() ? 0 : 1;
            mBuilder = MetadataBuilder::New(blockDevSize, metadataSize, metadataSlotCount);
            break;
        }
        case 3: {
            string superPartitionName = mFdp.ConsumeBool()
                                                ? kSuperPartitionName
                                                : mFdp.ConsumeRandomLengthString(kMaxBytes);
            mBuilder = MetadataBuilder::New(PartitionOpener(), superPartitionName,
                                            mFdp.ConsumeIntegralInRange(0, 1) /* slot_number */);
            break;
        }
        case 4: {
            string superPartitionName = mFdp.ConsumeBool()
                                                ? kSuperPartitionName
                                                : mFdp.ConsumeRandomLengthString(kMaxBytes);
            mBuilder = MetadataBuilder::New(
                    superPartitionName,
                    mFdp.ConsumeIntegralInRange<uint32_t>(0, 1) /* slot_number */);
            break;
        }
    }
}

void BuilderFuzzer::setupBuilder(string superBlockDeviceName) {
    uint64_t blockDeviceInfoSize =
            mFdp.ConsumeBool() ? mFdp.ConsumeIntegral<uint64_t>() : kValidBlockDeviceInfoSize;
    uint32_t alignment = mFdp.ConsumeBool() ? mFdp.ConsumeIntegral<uint32_t>() : kValidAlignment;
    uint32_t alignmentOffset =
            mFdp.ConsumeBool() ? mFdp.ConsumeIntegral<uint32_t>() : kValidAlignmentOffset;
    uint32_t logicalBlockSize =
            mFdp.ConsumeBool() ? mFdp.ConsumeIntegral<uint32_t>() : kValidLogicalBlockSize;
    BlockDeviceInfo super(superBlockDeviceName, blockDeviceInfoSize, alignment, alignmentOffset,
                          logicalBlockSize);
    mBlockDevices.push_back(super);

    mBuilder->AddGroup(kDefaultGroupName, mFdp.ConsumeIntegral<uint64_t>() /* max_size */);
    mPartition = mBuilder->AddPartition(kSuperPartitionName, LP_PARTITION_ATTR_READONLY);

    mFuzzPartition = mBuilder->AddPartition(kFuzzPartitionName, kDefaultGroupName,
                                            LP_PARTITION_ATTR_READONLY);

    string mResizePartitionName = mFdp.ConsumeRandomLengthString(kMaxBytes);
    if (!mResizePartitionName.size()) {
        mResizePartitionName = "resize_partition";
    }
    mResizePartition = mBuilder->AddPartition(mResizePartitionName, kDefaultGroupName,
                                              LP_PARTITION_ATTR_READONLY);

    string changePartitionDeviceInfoName =
            mFdp.ConsumeBool() ? kDeviceInfoName : mFdp.ConsumeRandomLengthString(kMaxBytes);
    BlockDeviceInfo changePartitionDeviceInfo(
            changePartitionDeviceInfoName,
            mFdp.ConsumeBool() ? mFdp.ConsumeIntegral<uint64_t>() : kBlockDeviceInfoSize /* size */,
            mFdp.ConsumeBool() ? mFdp.ConsumeIntegral<uint32_t>()
                               : kZeroAlignmentOffset /* alignment */,
            mFdp.ConsumeBool() ? mFdp.ConsumeIntegral<uint32_t>()
                               : kZeroAlignmentOffset /* alignment_offset */,
            mFdp.ConsumeBool() ? mFdp.ConsumeIntegral<uint32_t>()
                               : kValidLogicalBlockSize /* logical_block_size */);
    mBlockDevices.push_back(changePartitionDeviceInfo);
}

void BuilderFuzzer::callChangePartitionGroup() {
    string group1 = mFdp.ConsumeBool() ? mFdp.ConsumeRandomLengthString(kMaxBytes) : "group1";
    uint64_t group1Size = getParamValue(0);

    string group2 = mFdp.ConsumeBool() ? mFdp.ConsumeRandomLengthString(kMaxBytes) : "group2";
    uint64_t group2Size = getParamValue(0);

    bool group1Added = mBuilder->AddGroup(group1, group1Size);
    bool group2Added = mBuilder->AddGroup(group2, group2Size);

    string changeGroupPartitionName = mFdp.ConsumeRandomLengthString(kMaxBytes);
    if (changeGroupPartitionName.size() && group1Added && group2Added) {
        Partition* changeGroupPartition = mBuilder->AddPartition(changeGroupPartitionName, group1,
                                                                 LP_PARTITION_ATTR_READONLY);
        if (changeGroupPartition) {
            mBuilder->ChangePartitionGroup(changeGroupPartition, group2);
        }
    }
}

void BuilderFuzzer::callVerifyExtentsAgainstSourceMetadata() {
    uint64_t sourceBlockDevSize = getParamValue(kValidBlockSize);
    uint32_t sourceMetadataMaxSize = getParamValue(kValidMetadataSize);
    uint32_t sourceSlotCount = mFdp.ConsumeIntegralInRange<uint32_t>(0, 1);
    auto sourceBuilder =
            MetadataBuilder::New(sourceBlockDevSize, sourceMetadataMaxSize, sourceSlotCount);

    uint64_t targetBlockDevSize = getParamValue(kValidBlockSize);
    uint32_t targetMetadataMaxSize = getParamValue(kValidMetadataSize);
    uint32_t targetSlotCount = mFdp.ConsumeIntegralInRange<uint32_t>(0, 1);
    auto targetBuilder =
            MetadataBuilder::New(targetBlockDevSize, targetMetadataMaxSize, targetSlotCount);

    if (sourceBuilder && targetBuilder) {
        int64_t sourceGroups = mFdp.ConsumeIntegralInRange<int64_t>(kMinElements, kMaxElements);
        for (int64_t idx = 0; idx < sourceGroups; ++idx) {
            sourceBuilder->AddGroup(
                    mFdp.PickValueInArray(mGroupNames),
                    mFdp.ConsumeBool() ? kValidMaxGroupSize : mFdp.ConsumeIntegral<uint64_t>());
        }

        int64_t sourcePartitions = mFdp.ConsumeIntegralInRange<int64_t>(kMinElements, kMaxElements);
        for (int64_t idx = 0; idx < sourcePartitions; ++idx) {
            sourceBuilder->AddPartition(mFdp.PickValueInArray(mPartitionNames),
                                        LP_PARTITION_ATTR_READONLY);
        }

        int64_t targetGroups = mFdp.ConsumeIntegralInRange<int64_t>(kMinElements, kMaxElements);
        for (int64_t idx = 0; idx < targetGroups; ++idx) {
            targetBuilder->AddGroup(
                    mFdp.PickValueInArray(mGroupNames),
                    mFdp.ConsumeBool() ? kValidMaxGroupSize : mFdp.ConsumeIntegral<uint64_t>());
        }

        int64_t targetPartitions = mFdp.ConsumeIntegralInRange<int64_t>(kMinElements, kMaxElements);
        for (int64_t idx = 0; idx < targetPartitions; ++idx) {
            targetBuilder->AddPartition(mFdp.PickValueInArray(mPartitionNames),
                                        LP_PARTITION_ATTR_READONLY);
        }

        MetadataBuilder::VerifyExtentsAgainstSourceMetadata(
                *sourceBuilder, mFdp.ConsumeBool() ? 0 : 1 /* source_slot_number */, *targetBuilder,
                mFdp.ConsumeBool() ? 0 : 1 /* target_slot_number */,
                vector<string>{"system", "vendor", mFdp.ConsumeRandomLengthString(kMaxBytes)});
    }
}

void BuilderFuzzer::invokeBuilderAPIs() {
    string superBlockDeviceName =
            mFdp.ConsumeBool() ? mFdp.ConsumeRandomLengthString(kMaxBytes) : kDeviceInfoName;
    uint32_t randomBuilder = mFdp.ConsumeIntegralInRange<uint32_t>(kMinBuilder, kMaxBuilder);
    selectRandomBuilder(randomBuilder, superBlockDeviceName);

    if (mBuilder.get()) {
        setupBuilder(superBlockDeviceName);

        while (mFdp.remaining_bytes()) {
            auto invokeAPIs = mFdp.PickValueInArray<const function<void()>>({
                    [&]() { callChangePartitionGroup(); },
                    [&]() {
                        string addedGroupName = mFdp.PickValueInArray(mGroupNames);
                        mBuilder->AddGroup(addedGroupName,
                                           mFdp.ConsumeIntegralInRange<uint64_t>(
                                                   kMinValue, kMaxValue) /* max_size */);
                    },
                    [&]() {
                        string partitionName = mFdp.PickValueInArray(mPartitionNames);
                        Partition* addedPartition = mBuilder->AddPartition(
                                partitionName, mFdp.PickValueInArray(kAttributeTypes));
                    },
                    [&]() {
                        int64_t numSectors = mFdp.ConsumeBool()
                                                     ? mFdp.ConsumeIntegralInRange<uint64_t>(
                                                               kMinSectorValue, kMaxSectorValue)
                                                     : kValidNumSectors;
                        int64_t physicalSector = mFdp.ConsumeBool()
                                                         ? mFdp.ConsumeIntegralInRange<uint64_t>(
                                                                   kMinSectorValue, kMaxSectorValue)
                                                         : kValidPhysicalSector;

                        int64_t numExtents =
                                mFdp.ConsumeIntegralInRange<int64_t>(kMinElements, kMaxElements);
                        if (mFuzzPartition) {
                            bool extentAdded = false;
                            for (int64_t i = 0; i <= numExtents; ++i) {
                                extentAdded =
                                        mBuilder->AddLinearExtent(mFuzzPartition, kDeviceInfoName,
                                                                  numSectors, physicalSector);
                            }

                            if (extentAdded) {
                                unique_ptr<LpMetadata> metadata = mBuilder->Export();
                                uint64_t alignedSize =
                                        mFdp.ConsumeIntegralInRange<uint64_t>(kMinValue, kMaxValue);
                                mFuzzPartition->GetBeginningExtents(LP_SECTOR_SIZE * numExtents);
                            }
                        }
                    },
                    [&]() { callVerifyExtentsAgainstSourceMetadata(); },
                    [&]() { mBuilder->ListPartitionsInGroup(mFdp.PickValueInArray(mGroupNames)); },
                    [&]() {
                        int64_t maxSize = mFdp.ConsumeIntegral<uint64_t>();
                        mBuilder->ChangeGroupSize(mFdp.PickValueInArray(mGroupNames), maxSize);
                    },
                    [&]() {
                        string deviceInfoName = mFdp.ConsumeBool()
                                                        ? kDeviceInfoName
                                                        : mFdp.ConsumeRandomLengthString(kMaxBytes);
                        mBuilder->GetBlockDeviceInfo(deviceInfoName, &mBlockDevices[1]);
                    },
                    [&]() {
                        string deviceInfoName = mFdp.ConsumeBool()
                                                        ? kDeviceInfoName
                                                        : mFdp.ConsumeRandomLengthString(kMaxBytes);
                        mBuilder->UpdateBlockDeviceInfo(deviceInfoName, mBlockDevices[1]);
                    },
                    [&]() {
                        unique_ptr<LpMetadata> metadata = mBuilder->Export();
                        mBuilder->ImportPartitions(*metadata.get(),
                                                   {mFdp.PickValueInArray(mPartitionNames)});
                    },
                    [&]() { mBuilder->HasBlockDevice(mFdp.PickValueInArray(mPartitionNames)); },
                    [&]() { mBuilder->SetVirtualABDeviceFlag(); },
                    [&]() { mBuilder->SetAutoSlotSuffixing(); },
                    [&]() { mBuilder->ListGroups(); },
                    [&]() { mBuilder->UsedSpace(); },
                    [&]() { mBuilder->RequireExpandedMetadataHeader(); },
                    [&]() {
                        uint64_t resizedPartitionSize = getParamValue(0);
                        mBuilder->ResizePartition(mResizePartition, resizedPartitionSize);
                    },
                    [&]() {
                        uint32_t sourceSlot = mFdp.ConsumeBool() ? 0 : 1;
                        uint32_t targetSlot = mFdp.ConsumeBool() ? 0 : 1;
                        PartitionOpener partitionOpener;
                        string sourcePartition =
                                mFdp.ConsumeBool() ? kFuzzPartitionName : kDeviceInfoName;

                        MetadataBuilder::NewForUpdate(partitionOpener, sourcePartition, sourceSlot,
                                                      targetSlot);
                        partitionOpener.GetDeviceString(mFdp.PickValueInArray(mPartitionNames));
                    },
                    [&]() {
                        unique_ptr<LpMetadata> metadata = mBuilder->Export();
                        MetadataBuilder::New(*metadata.get());
                    },
                    [&]() { mBuilder->AllocatableSpace(); },
                    [&]() {
                        PartitionOpener pOpener;
                        string superPartitionName =
                                mFdp.ConsumeBool() ? kSuperPartitionName
                                                   : mFdp.ConsumeRandomLengthString(kMaxBytes);
                        pOpener.Open(superPartitionName, O_RDONLY);
                        pOpener.GetInfo(superPartitionName, &mBlockDevices[0]);
                    },
                    [&]() {
                        PartitionOpener pOpener;
                        string superPartitionName =
                                mFdp.ConsumeBool() ? kSuperPartitionName
                                                   : mFdp.ConsumeRandomLengthString(kMaxBytes);
                        pOpener.Open(superPartitionName, O_RDONLY);
                        pOpener.GetDeviceString(superPartitionName);
                    },
                    [&]() {
                        Interval::Intersect(
                                Interval(mFdp.ConsumeIntegral<uint64_t>() /* device _index */,
                                         mFdp.ConsumeIntegral<uint64_t>() /* start */,
                                         mFdp.ConsumeIntegral<uint64_t>()) /* end */,
                                Interval(mFdp.ConsumeIntegral<uint64_t>() /* device _index */,
                                         mFdp.ConsumeIntegral<uint64_t>() /* start */,
                                         mFdp.ConsumeIntegral<uint64_t>() /* end */));
                    },
                    [&]() {
                        vector<Interval> intervalVectorA;
                        int64_t internalVectorAElements =
                                mFdp.ConsumeIntegralInRange<int64_t>(kMinElements, kMaxElements);
                        for (int64_t idx = 0; idx < internalVectorAElements; ++idx) {
                            intervalVectorA.push_back(
                                    Interval(mFdp.ConsumeIntegral<uint64_t>() /* device _index */,
                                             mFdp.ConsumeIntegral<uint64_t>() /* start */,
                                             mFdp.ConsumeIntegral<uint64_t>() /* end */));
                        }

                        vector<Interval> intervalVectorB;
                        int64_t internalVectorBElements =
                                mFdp.ConsumeIntegralInRange<int64_t>(kMinElements, kMaxElements);
                        for (int64_t idx = 0; idx < internalVectorBElements; ++idx) {
                            intervalVectorB.push_back(
                                    Interval(mFdp.ConsumeIntegral<uint64_t>() /* device _index */,
                                             mFdp.ConsumeIntegral<uint64_t>() /* start */,
                                             mFdp.ConsumeIntegral<uint64_t>() /* end */));
                        }

                        Interval::Intersect(intervalVectorA, intervalVectorB);
                    },
                    [&]() {
                        uint64_t numSectors =
                                mFdp.ConsumeIntegralInRange<uint64_t>(kMinValue, kMaxValue);
                        uint32_t deviceIndex =
                                mFdp.ConsumeIntegralInRange<uint32_t>(kMinValue, kMaxValue);
                        uint64_t physicalSector =
                                mFdp.ConsumeIntegralInRange<uint64_t>(kMinValue, kMaxValue);
                        LinearExtent extent(numSectors, deviceIndex, physicalSector);
                        extent.AsInterval();
                    },
                    [&]() {
                        IPropertyFetcher::OverrideForTesting(std::make_unique<PropertyFetcher>());
                    },
            });
            invokeAPIs();
        }
        if (mFdp.ConsumeBool()) {
            mBuilder->RemoveGroupAndPartitions(mFdp.PickValueInArray(mGroupNames));
        } else {
            string removePartition = mFdp.PickValueInArray(mPartitionNames);
            mBuilder->RemovePartition(removePartition);
        }
    }
}

void BuilderFuzzer::process() {
    invokeBuilderAPIs();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    BuilderFuzzer builderFuzzer(data, size);
    builderFuzzer.process();
    return 0;
}
