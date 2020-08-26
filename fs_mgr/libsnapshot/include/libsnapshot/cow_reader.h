// Copyright (C) 2019 The Android Open Source Project
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

#include <stdint.h>

#include <functional>
#include <memory>

#include <android-base/unique_fd.h>
#include <libsnapshot/cow_format.h>

namespace android {
namespace snapshot {

class ICowOpIter;

// A ByteSink object handles requests for a buffer of a specific size. It
// always owns the underlying buffer. It's designed to minimize potential
// copying as we parse or decompress the COW.
class IByteSink {
  public:
    virtual ~IByteSink() {}

    // Called when the reader has data. The size of the request is given. The
    // sink must return a valid pointer (or null on failure), and return the
    // maximum number of bytes that can be written to the returned buffer.
    //
    // The returned buffer is owned by IByteSink, but must remain valid until
    // the ready operation has completed (or the entire buffer has been
    // covered by calls to ReturnData).
    //
    // After calling GetBuffer(), all previous buffers returned are no longer
    // valid.
    virtual void* GetBuffer(size_t requested, size_t* actual) = 0;

    // Called when a section returned by |GetBuffer| has been filled with data.
    virtual bool ReturnData(void* buffer, size_t length) = 0;
};

// Interface for reading from a snapuserd COW.
class ICowReader {
  public:
    virtual ~ICowReader() {}

    // Return the file header.
    virtual bool GetHeader(CowHeader* header) = 0;

    // Return an iterator for retrieving CowOperation entries.
    virtual std::unique_ptr<ICowOpIter> GetOpIter() = 0;

    // Get raw bytes from the data section.
    virtual bool GetRawBytes(uint64_t offset, void* buffer, size_t len) = 0;

    // Get decoded bytes from the data section, handling any decompression.
    // All retrieved data is passed to the sink.
    virtual bool ReadData(const CowOperation& op, IByteSink* sink) = 0;
};

// Iterate over a sequence of COW operations.
class ICowOpIter {
  public:
    virtual ~ICowOpIter() {}

    // True if there are more items to read, false otherwise.
    virtual bool Done() = 0;

    // Read the current operation.
    virtual const CowOperation& Get() = 0;

    // Advance to the next item.
    virtual void Next() = 0;
};

class CowReader : public ICowReader {
  public:
    CowReader();

    bool Parse(android::base::unique_fd&& fd);
    bool Parse(android::base::borrowed_fd fd);

    bool GetHeader(CowHeader* header) override;

    // Create a CowOpIter object which contains header_.num_ops
    // CowOperation objects. Get() returns a unique CowOperation object
    // whose lifeteime depends on the CowOpIter object
    std::unique_ptr<ICowOpIter> GetOpIter() override;
    bool GetRawBytes(uint64_t offset, void* buffer, size_t len) override;
    bool ReadData(const CowOperation& op, IByteSink* sink) override;

  private:
    android::base::unique_fd owned_fd_;
    android::base::borrowed_fd fd_;
    CowHeader header_;
    uint64_t fd_size_;
};

}  // namespace snapshot
}  // namespace android
