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

#include <libsnapshot/snapshot.h>

#include <unordered_set>

#include <android-base/file.h>
#include <gtest/gtest.h>
#include <libsnapshot/snapshot_writer.h>
#include <payload_consumer/file_descriptor.h>

namespace android::snapshot {
class CompressedSnapshotWriterTest : public ::testing::Test {
  public:
    static constexpr size_t BLOCK_SIZE = 4096;
};

TEST_F(CompressedSnapshotWriterTest, ReadAfterWrite) {
    TemporaryFile cow_device_file{};
    android::snapshot::CowOptions options{.block_size = BLOCK_SIZE};
    android::snapshot::CompressedSnapshotWriter snapshot_writer{options};
    snapshot_writer.SetCowDevice(android::base::unique_fd{cow_device_file.fd});
    snapshot_writer.Initialize();
    std::vector<unsigned char> buffer;
    buffer.resize(BLOCK_SIZE);
    std::fill(buffer.begin(), buffer.end(), 123);

    ASSERT_TRUE(snapshot_writer.AddRawBlocks(0, buffer.data(), buffer.size()));
    ASSERT_TRUE(snapshot_writer.Finalize());
    auto cow_reader = snapshot_writer.OpenReader();
    ASSERT_NE(cow_reader, nullptr);
    ASSERT_TRUE(snapshot_writer.AddRawBlocks(1, buffer.data(), buffer.size()));
    ASSERT_TRUE(snapshot_writer.AddRawBlocks(2, buffer.data(), buffer.size()));
    ASSERT_TRUE(snapshot_writer.Finalize());
    // After wrigin some data, if we call OpenReader() again, writes should
    // be visible to the newly opened reader. update_engine relies on this
    // behavior for verity writes.
    cow_reader = snapshot_writer.OpenReader();
    ASSERT_NE(cow_reader, nullptr);
    std::vector<unsigned char> read_back;
    read_back.resize(buffer.size());
    cow_reader->Seek(BLOCK_SIZE, SEEK_SET);
    const auto bytes_read = cow_reader->Read(read_back.data(), read_back.size());
    ASSERT_EQ((size_t)(bytes_read), BLOCK_SIZE);
    ASSERT_EQ(read_back, buffer);
}

}  // namespace android::snapshot
