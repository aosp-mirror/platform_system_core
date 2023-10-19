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
 */

#include <android-base/file.h>
#include <fcntl.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <liblp/builder.h>
#include <liblp/partition_opener.h>
#include <linux/memfd.h>
#include <sys/syscall.h>
#include <writer.h>
#include "images.h"
#include "test_partition_opener.h"

using namespace std;
using namespace android;
using namespace android::fs_mgr;
using unique_fd = android::base::unique_fd;

static constexpr size_t kDiskSize = 131072;
static constexpr size_t kMetadataSize = 512;
static constexpr size_t kMetadataSlots = 2;
static constexpr uint32_t kMaxBytes = 20;
static constexpr uint32_t kValidAlignment = 0;
static constexpr uint32_t kValidAlignmentOffset = 0;
static constexpr uint32_t kValidLogicalBlockSize = 4096;
static constexpr uint32_t kMinMetadataSize = 0;
static constexpr uint32_t kMaxMetadataSize = 10000;
static constexpr uint32_t kMinSlot = 0;
static constexpr uint32_t kMaxSlot = 10;
static constexpr uint32_t kMinFactor = 0;
static constexpr uint32_t kMaxFactor = 10;
static constexpr uint32_t kMetadataGeometrySize = 4096;
static constexpr uint64_t kValidNumSectors = 1901568;
static constexpr uint64_t kValidPhysicalSector = 3608576;
static constexpr uint64_t kMinSectorValue = 1;
static constexpr uint64_t kMaxSectorValue = 1000000;
static constexpr uint64_t kMaxBufferSize = 100000;

const string kImageFile = "image_file";
const string kSuperName = "super";
const string kSystemPartitionName = "system";
const string kPartitionName = "builder_partition";
const string kSuperPartitionName = "super_partition";

const string kSuffix[] = {"_a", "_b", "a", "b"};

class LiplpApisFuzzer {
  public:
    LiplpApisFuzzer(const uint8_t* data, size_t size) : mFdp(data, size){};
    void process();

  private:
    void setupBuilder();
    BlockDeviceInfo getBlockDevice();
    FuzzedDataProvider mFdp;
    unique_ptr<MetadataBuilder> mBuilder;
    string mBlockDeviceInfoName;
    string mSuperPartitionName;
    string mPartitionName;
    const string mImagePaths[10] = {
            "data/test_dtb.img",
            "data/test_bootconfig.img",
            "data/test_vendor_ramdisk_none.img",
            "data/test_vendor_ramdisk_platform.img",
            "data/test_vendor_ramdisk_replace.img",
            "data/test_vendor_boot_v4_with_frag.img",
            "data/test_vendor_boot_v4_without_frag.img",
            "data/test_vendor_boot_v3.img",
            "dev/null",
            mFdp.ConsumeRandomLengthString(kMaxBytes),
    };
};

BlockDeviceInfo LiplpApisFuzzer::getBlockDevice() {
    mBlockDeviceInfoName =
            mFdp.ConsumeBool() ? kSuperName : mFdp.ConsumeRandomLengthString(kMaxBytes);
    uint64_t blockDeviceInfoSize =
            mFdp.ConsumeBool() ? mFdp.ConsumeIntegral<uint64_t>() : kDiskSize;
    uint32_t alignment = mFdp.ConsumeBool() ? mFdp.ConsumeIntegral<uint32_t>() : kValidAlignment;
    uint32_t alignmentOffset =
            mFdp.ConsumeBool() ? mFdp.ConsumeIntegral<uint32_t>() : kValidAlignmentOffset;
    uint32_t logicalBlockSize =
            mFdp.ConsumeBool() ? mFdp.ConsumeIntegral<uint32_t>() : kValidLogicalBlockSize;

    BlockDeviceInfo superInfo{mBlockDeviceInfoName, blockDeviceInfoSize, alignment, alignmentOffset,
                              logicalBlockSize};
    return superInfo;
}

void LiplpApisFuzzer::setupBuilder() {
    uint64_t randomBlockDevSize =
            mFdp.ConsumeIntegralInRange<uint64_t>(kMinFactor, kMaxFactor) * LP_SECTOR_SIZE;
    uint64_t blockDevSize = mFdp.ConsumeBool() ? randomBlockDevSize : kDiskSize;
    uint32_t randomMetadataMaxSize =
            mFdp.ConsumeIntegralInRange<uint32_t>(kMinMetadataSize, kMaxMetadataSize);
    uint32_t metadataMaxSize = mFdp.ConsumeBool() ? kMetadataSize : randomMetadataMaxSize;
    uint32_t metadataSlotCount = mFdp.ConsumeIntegralInRange<uint32_t>(kMinSlot, kMaxSlot);
    mBuilder = MetadataBuilder::New(blockDevSize, metadataMaxSize, metadataSlotCount);

    if (mBuilder.get()) {
        mBuilder->AddPartition(kSystemPartitionName, LP_PARTITION_ATTR_READONLY);

        mPartitionName =
                mFdp.ConsumeBool() ? mFdp.ConsumeRandomLengthString(kMaxBytes) : kPartitionName;
        if (!mPartitionName.size()) {
            mPartitionName = kPartitionName;
        }
        mSuperPartitionName = mFdp.ConsumeBool() ? mFdp.ConsumeRandomLengthString(kMaxBytes)
                                                 : kSuperPartitionName;
        if (!mSuperPartitionName.size()) {
            mSuperPartitionName = kSuperPartitionName;
        }

        Partition* super = mBuilder->AddPartition(mSuperPartitionName, LP_PARTITION_ATTR_READONLY);
        mBuilder->AddPartition(mPartitionName, LP_PARTITION_ATTR_READONLY);

        int64_t numSectors = mFdp.ConsumeBool() ? mFdp.ConsumeIntegralInRange<uint64_t>(
                                                          kMinSectorValue, kMaxSectorValue)
                                                : kValidNumSectors;
        int64_t physicalSector = mFdp.ConsumeBool() ? mFdp.ConsumeIntegralInRange<uint64_t>(
                                                              kMinSectorValue, kMaxSectorValue)
                                                    : kValidPhysicalSector;

        mBuilder->AddLinearExtent(super, mBlockDeviceInfoName, numSectors, physicalSector);
    }
}

void LiplpApisFuzzer::process() {
    BlockDeviceInfo superInfo = getBlockDevice();
    unique_fd fd(syscall(__NR_memfd_create, "image_file", MFD_ALLOW_SEALING));
    setupBuilder();

    TestPartitionOpener opener(
            {{mFdp.ConsumeBool() ? mFdp.ConsumeRandomLengthString(kMaxBytes) : kSuperName, fd}},
            {{mFdp.ConsumeBool() ? mFdp.ConsumeRandomLengthString(kMaxBytes) : kSuperName,
              superInfo}});

    if (mBuilder.get()) {
        unique_ptr<LpMetadata> metadata = mBuilder->Export();
        const LpMetadata& metadataValue = *metadata.get();

        map<string, string> images = {};
        if (mFdp.ConsumeBool()) {
            images[mSuperPartitionName] = mFdp.PickValueInArray(mImagePaths);
        }

        while (mFdp.remaining_bytes()) {
            auto invokeAPIs = mFdp.PickValueInArray<const function<void()>>({
                    [&]() { WriteToImageFile(fd, metadataValue); },
                    [&]() { WriteToImageFile(kImageFile.c_str(), metadataValue); },
                    [&]() { FlashPartitionTable(opener, kSuperName, metadataValue); },
                    [&]() {
                        UpdatePartitionTable(opener, mPartitionName, metadataValue,
                                             mFdp.ConsumeBool() ? 0 : 1 /* slot_number */);
                    },
                    [&]() {
                        ReadMetadata(mPartitionName, mFdp.ConsumeBool() ? 0 : 1 /* slot_number */);
                    },
                    [&]() { FlashPartitionTable(mPartitionName, metadataValue); },
                    [&]() {
                        UpdatePartitionTable(mPartitionName, metadataValue,
                                             mFdp.ConsumeBool() ? 0 : 1 /* slot_number */);
                    },
                    [&]() {
                        WriteToImageFile(kImageFile.c_str(), metadataValue,
                                         metadata->geometry.logical_block_size, images,
                                         mFdp.ConsumeBool() ? true : false /* sparsify */);
                    },

                    [&]() {
                        WriteSplitImageFiles(kImageFile.c_str(), metadataValue,
                                             metadata->geometry.logical_block_size, images,
                                             mFdp.ConsumeBool() ? true : false /* sparsify */);
                    },
                    [&]() { ReadFromImageFile(kImageFile.c_str()); },
                    [&]() { IsEmptySuperImage(kImageFile.c_str()); },
                    [&]() {
                        uint64_t bufferSize = mFdp.ConsumeIntegralInRange<uint64_t>(
                                2 * kMetadataGeometrySize, kMaxBufferSize);
                        vector<uint8_t> buffer = mFdp.ConsumeBytes<uint8_t>(kMaxBytes);
                        buffer.resize(bufferSize);
                        ReadFromImageBlob(buffer.data(), buffer.size());
                    },
                    [&]() {
                        uint32_t groupVectorSize = metadata->groups.size();
                        uint32_t randomGroupIndex =
                                mFdp.ConsumeIntegralInRange<uint32_t>(0, groupVectorSize);
                        GetPartitionGroupName(metadata->groups[randomGroupIndex]);
                    },
                    [&]() {
                        uint32_t blockDeviceVectorSize = metadata->block_devices.size();
                        uint32_t randomBlockDeviceIndex =
                                mFdp.ConsumeIntegralInRange<uint32_t>(0, blockDeviceVectorSize);
                        GetBlockDevicePartitionName(
                                metadata->block_devices[randomBlockDeviceIndex]);
                    },
                    [&]() { GetMetadataSuperBlockDevice(metadataValue); },
                    [&]() {
                        string suffix = mFdp.ConsumeBool()
                                                ? mFdp.PickValueInArray<string>(kSuffix)
                                                : mFdp.ConsumeRandomLengthString(kMaxBytes);
                        SlotNumberForSlotSuffix(suffix);
                    },
                    [&]() {
                        auto entry = FindPartition(metadataValue, kSystemPartitionName);
                        GetPartitionSize(metadataValue, *entry);
                    },
                    [&]() { GetPartitionSlotSuffix(mPartitionName); },
                    [&]() { FindPartition(metadataValue, mPartitionName); },
                    [&]() {
                        uint32_t partitionVectorSize = metadata->partitions.size();
                        uint32_t randomPartitionIndex =
                                mFdp.ConsumeIntegralInRange<uint32_t>(0, partitionVectorSize);
                        GetPartitionName(metadata->partitions[randomPartitionIndex]);
                    },
                    [&]() { GetTotalSuperPartitionSize(metadataValue); },
                    [&]() { GetBlockDevicePartitionNames(metadataValue); },
            });
            invokeAPIs();
        }
        remove(kImageFile.c_str());
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    LiplpApisFuzzer liplpApisFuzzer(data, size);
    liplpApisFuzzer.process();
    return 0;
}
