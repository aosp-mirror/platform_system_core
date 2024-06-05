//
// Copyright (C) 2021 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

#include <gmock/gmock.h>
#include <libsnapshot/cow_writer.h>

namespace android::snapshot {

class MockCowWriter : public ICowWriter {
  public:
    using FileDescriptor = chromeos_update_engine::FileDescriptor;

    MOCK_METHOD(bool, Finalize, (), (override));
    MOCK_METHOD(CowSizeInfo, GetCowSizeInfo, (), (const, override));

    MOCK_METHOD(bool, AddCopy, (uint64_t, uint64_t, uint64_t), (override));
    MOCK_METHOD(bool, AddRawBlocks, (uint64_t, const void*, size_t), (override));
    MOCK_METHOD(bool, AddXorBlocks, (uint32_t, const void*, size_t, uint32_t, uint16_t),
                (override));
    MOCK_METHOD(bool, AddZeroBlocks, (uint64_t, uint64_t), (override));
    MOCK_METHOD(bool, AddLabel, (uint64_t), (override));
    MOCK_METHOD(bool, AddSequenceData, (size_t, const uint32_t*), (override));
    MOCK_METHOD(uint32_t, GetBlockSize, (), (override, const));
    MOCK_METHOD(std::optional<uint32_t>, GetMaxBlocks, (), (override, const));

    MOCK_METHOD(std::unique_ptr<ICowReader>, OpenReader, (), (override));
    MOCK_METHOD(std::unique_ptr<FileDescriptor>, OpenFileDescriptor,
                (const std::optional<std::string>&), (override));
};

}  // namespace android::snapshot
