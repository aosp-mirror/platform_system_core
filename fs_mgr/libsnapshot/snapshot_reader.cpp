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

#include <ext4_utils/ext4_utils.h>

#include "snapshot_reader.h"

namespace android {
namespace snapshot {

// Not supported.
bool ReadOnlyFileDescriptor::Open(const char*, int, mode_t) {
    errno = EINVAL;
    return false;
}

bool ReadOnlyFileDescriptor::Open(const char*, int) {
    errno = EINVAL;
    return false;
}

ssize_t ReadOnlyFileDescriptor::Write(const void*, size_t) {
    errno = EINVAL;
    return false;
}

bool ReadOnlyFileDescriptor::BlkIoctl(int, uint64_t, uint64_t, int*) {
    errno = EINVAL;
    return false;
}

ReadFdFileDescriptor::ReadFdFileDescriptor(android::base::unique_fd&& fd) : fd_(std::move(fd)) {}

ssize_t ReadFdFileDescriptor::Read(void* buf, size_t count) {
    return read(fd_.get(), buf, count);
}

off64_t ReadFdFileDescriptor::Seek(off64_t offset, int whence) {
    return lseek(fd_.get(), offset, whence);
}

uint64_t ReadFdFileDescriptor::BlockDevSize() {
    return get_block_device_size(fd_.get());
}

bool ReadFdFileDescriptor::Close() {
    fd_ = {};
    return true;
}

bool ReadFdFileDescriptor::IsSettingErrno() {
    return true;
}

bool ReadFdFileDescriptor::IsOpen() {
    return fd_ >= 0;
}

bool ReadFdFileDescriptor::Flush() {
    return true;
}

}  // namespace snapshot
}  // namespace android
