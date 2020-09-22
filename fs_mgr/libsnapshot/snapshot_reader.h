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

#include <android-base/file.h>
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

}  // namespace snapshot
}  // namespace android
