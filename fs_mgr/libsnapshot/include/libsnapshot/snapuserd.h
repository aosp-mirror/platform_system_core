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

#pragma once

#include <linux/types.h>
#include <stdint.h>
#include <stdlib.h>

#include <csignal>
#include <cstring>
#include <iostream>
#include <limits>
#include <string>
#include <thread>
#include <vector>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <android-base/unique_fd.h>
#include <libdm/dm.h>
#include <libsnapshot/cow_reader.h>
#include <libsnapshot/cow_writer.h>
#include <libsnapshot/snapuserd_kernel.h>

namespace android {
namespace snapshot {

using android::base::unique_fd;

class BufferSink : public IByteSink {
  public:
    void Initialize(size_t size);
    void* GetBufPtr() { return buffer_.get(); }
    void Clear() { memset(GetBufPtr(), 0, buffer_size_); }
    void* GetPayloadBuffer(size_t size);
    void* GetBuffer(size_t requested, size_t* actual) override;
    void UpdateBufferOffset(size_t size) { buffer_offset_ += size; }
    struct dm_user_header* GetHeaderPtr();
    bool ReturnData(void*, size_t) override { return true; }
    void ResetBufferOffset() { buffer_offset_ = 0; }

  private:
    std::unique_ptr<uint8_t[]> buffer_;
    loff_t buffer_offset_;
    size_t buffer_size_;
};

class Snapuserd final {
  public:
    Snapuserd(const std::string& in_cow_device, const std::string& in_backing_store_device,
              const std::string& in_control_device)
        : cow_device_(in_cow_device),
          backing_store_device_(in_backing_store_device),
          control_device_(in_control_device),
          metadata_read_done_(false) {}

    bool Init();
    int Run();
    int ReadDmUserHeader();
    int WriteDmUserPayload(size_t size);
    int ConstructKernelCowHeader();
    int ReadMetadata();
    int ZerofillDiskExceptions(size_t read_size);
    int ReadDiskExceptions(chunk_t chunk, size_t size);
    int ReadData(chunk_t chunk, size_t size);

    std::string GetControlDevicePath() { return control_device_; }

  private:
    int ProcessReplaceOp(const CowOperation* cow_op);
    int ProcessCopyOp(const CowOperation* cow_op);
    int ProcessZeroOp();

    std::string cow_device_;
    std::string backing_store_device_;
    std::string control_device_;

    unique_fd cow_fd_;
    unique_fd backing_store_fd_;
    unique_fd ctrl_fd_;

    uint32_t exceptions_per_area_;

    std::unique_ptr<ICowOpIter> cowop_iter_;
    std::unique_ptr<CowReader> reader_;

    // Vector of disk exception which is a
    // mapping of old-chunk to new-chunk
    std::vector<std::unique_ptr<uint8_t[]>> vec_;

    // Index - Chunk ID
    // Value - cow operation
    std::vector<const CowOperation*> chunk_vec_;

    bool metadata_read_done_;
    BufferSink bufsink_;
};

}  // namespace snapshot
}  // namespace android
