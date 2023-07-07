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
#include <libsnapshot/snapshot_writer.h>

namespace android::snapshot {

class MockSnapshotWriter : public ISnapshotWriter {
  public:
    using FileDescriptor = ISnapshotWriter::FileDescriptor;

    explicit MockSnapshotWriter(const CowOptions& options) : ISnapshotWriter(options) {}
    MockSnapshotWriter() : ISnapshotWriter({}) {}

    MOCK_METHOD(bool, Finalize, (), (override));

    // Return number of bytes the cow image occupies on disk.
    MOCK_METHOD(uint64_t, GetCowSize, (), (override));

    // Returns true if AddCopy() operations are supported.
    MOCK_METHOD(bool, SupportsCopyOperation, (), (const override));

    MOCK_METHOD(bool, EmitCopy, (uint64_t, uint64_t, uint64_t), (override));
    MOCK_METHOD(bool, EmitRawBlocks, (uint64_t, const void*, size_t), (override));
    MOCK_METHOD(bool, EmitXorBlocks, (uint32_t, const void*, size_t, uint32_t, uint16_t),
                (override));
    MOCK_METHOD(bool, EmitZeroBlocks, (uint64_t, uint64_t), (override));
    MOCK_METHOD(bool, EmitLabel, (uint64_t), (override));
    MOCK_METHOD(bool, EmitSequenceData, (size_t, const uint32_t*), (override));

    // Open the writer in write mode (no append).
    MOCK_METHOD(bool, Initialize, (), (override));
    MOCK_METHOD(bool, VerifyMergeOps, (), (override, const, noexcept));

    // Open the writer in append mode, with the last label to resume
    // from. See CowWriter::InitializeAppend.
    MOCK_METHOD(bool, InitializeAppend, (uint64_t label), (override));

    MOCK_METHOD(std::unique_ptr<FileDescriptor>, OpenReader, (), (override));
};
}  // namespace android::snapshot
