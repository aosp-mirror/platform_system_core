// Copyright (C) 2023 The Android Open Source Project
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

#include <stddef.h>
#include <stdint.h>

#include <memory>

namespace android {
namespace snapshot {

// These interfaces model the block device driver component of snapuserd (eg,
// dm-user).

// An open connection to a userspace block device control
class IBlockServer {
  public:
    class Delegate {
      public:
        virtual ~Delegate() {}

        // Respond to a request for reading a contiguous run of sectors. This
        // call should be followed by calls to GetResponseBuffer/CommitBuffer
        // until the |size| is fulfilled.
        //
        // If false is returned, an error will be automatically reported unless
        // SendError was called.
        virtual bool RequestSectors(uint64_t sector, uint64_t size) = 0;
    };

    virtual ~IBlockServer() {}

    // Process I/O requests. This can block the worker thread until either a
    // request is available or the underlying connection has been destroyed.
    //
    // True indicates that one or more requests was processed. False indicates
    // an unrecoverable condition and processing should stop.
    virtual bool ProcessRequests() = 0;

    // Return a buffer for fulfilling a RequestSectors request. This buffer
    // is valid until calling SendBufferedIo. This cannot be called outside
    // of RequestSectors().
    //
    // "to_write" must be <= "size". If it is < size, the excess bytes are
    // available for writing, but will not be send via SendBufferedIo, and
    // may be reallocated in the next call to GetResponseBuffer.
    //
    // All buffers returned are invalidated after SendBufferedIo or returning
    // control from RequestSectors.
    virtual void* GetResponseBuffer(size_t size, size_t to_write) = 0;

    // Send all outstanding buffers to the driver, in order. This should
    // be called at least once in response to RequestSectors. This returns
    // ownership of any buffers returned by GetResponseBuffer.
    //
    // If false is returned, an error is automatically reported to the driver.
    virtual bool SendBufferedIo() = 0;

    void* GetResponseBuffer(size_t size) { return GetResponseBuffer(size, size); }
};

class IBlockServerOpener {
  public:
    virtual ~IBlockServerOpener() = default;

    // Open a connection to the service. This is called on the daemon thread.
    //
    // buffer_size is the maximum amount of buffered I/O to use.
    virtual std::unique_ptr<IBlockServer> Open(IBlockServer::Delegate* delegate,
                                               size_t buffer_size) = 0;
};

class IBlockServerFactory {
  public:
    virtual ~IBlockServerFactory() {}

    // Return a new IBlockServerOpener given a unique device name.
    virtual std::shared_ptr<IBlockServerOpener> CreateOpener(const std::string& misc_name) = 0;
};

}  // namespace snapshot
}  // namespace android
