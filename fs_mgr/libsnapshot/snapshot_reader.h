//
// Copyright (C) 2020 The Android Open Source Project
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

#pragma once

#include <optional>
#include <vector>

#include <android-base/file.h>
#include <libsnapshot/cow_reader.h>
#include <payload_consumer/file_descriptor.h>

namespace android {
namespace snapshot {

class ReadOnlyFileDescriptor : public chromeos_update_engine::FileDescriptor {
  public:
    bool Open(const char* path, int flags, mode_t mode) override;
    bool Open(const char* path, int flags) override;
    ssize_t Write(const void* buf, size_t count) override;
    bool BlkIoctl(int request, uint64_t start, uint64_t length, int* result) override;
};

class ReadFdFileDescriptor : public ReadOnlyFileDescriptor {
  public:
    explicit ReadFdFileDescriptor(android::base::unique_fd&& fd);

    ssize_t Read(void* buf, size_t count) override;
    off64_t Seek(off64_t offset, int whence) override;
    uint64_t BlockDevSize() override;
    bool Close() override;
    bool IsSettingErrno() override;
    bool IsOpen() override;
    bool Flush() override;

  private:
    android::base::unique_fd fd_;
};

class CompressedSnapshotReader : public ReadOnlyFileDescriptor {
  public:
    bool SetCow(std::unique_ptr<CowReader>&& cow);
    void SetSourceDevice(const std::string& source_device);
    void SetBlockDeviceSize(uint64_t block_device_size);

    ssize_t Read(void* buf, size_t count) override;
    off64_t Seek(off64_t offset, int whence) override;
    uint64_t BlockDevSize() override;
    bool Close() override;
    bool IsSettingErrno() override;
    bool IsOpen() override;
    bool Flush() override;

  private:
    ssize_t ReadBlock(uint64_t chunk, IByteSink* sink, size_t start_offset,
                      const std::optional<uint64_t>& max_bytes = {});
    android::base::borrowed_fd GetSourceFd();

    std::unique_ptr<CowReader> cow_;
    std::unique_ptr<ICowOpIter> op_iter_;
    uint32_t block_size_ = 0;

    std::optional<std::string> source_device_;
    android::base::unique_fd source_fd_;
    uint64_t block_device_size_ = 0;
    off64_t offset_ = 0;

    std::vector<const CowOperation*> ops_;
};

}  // namespace snapshot
}  // namespace android
