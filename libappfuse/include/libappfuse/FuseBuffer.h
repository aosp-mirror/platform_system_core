/*
 * Copyright (C) 2016 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specic language governing permissions and
 * limitations under the License.
 */

#ifndef ANDROID_LIBAPPFUSE_FUSEBUFFER_H_
#define ANDROID_LIBAPPFUSE_FUSEBUFFER_H_

#include <android-base/unique_fd.h>
#include <linux/fuse.h>

namespace android {
namespace fuse {

// The numbers came from sdcard.c.
// Maximum number of bytes to write/read in one request/one reply.
constexpr size_t kFuseMaxWrite = 128 * 1024;
constexpr size_t kFuseMaxRead = 128 * 1024;
constexpr int32_t kFuseSuccess = 0;

// Setup sockets to transfer FuseMessage.
bool SetupMessageSockets(base::unique_fd (*sockets)[2]);

enum class ResultOrAgain {
    kSuccess,
    kFailure,
    kAgain,
};

template<typename T>
class FuseMessage {
 public:
  bool Read(int fd);
  bool Write(int fd) const;
  bool WriteWithBody(int fd, size_t max_size, const void* data) const;
  ResultOrAgain ReadOrAgain(int fd);
  ResultOrAgain WriteOrAgain(int fd) const;
};

// FuseRequest represents file operation requests from /dev/fuse. It starts
// from fuse_in_header. The body layout depends on the operation code.
struct FuseRequest : public FuseMessage<FuseRequest> {
  fuse_in_header header;
  union {
    // for FUSE_WRITE
    struct {
      fuse_write_in write_in;
      char write_data[kFuseMaxWrite];
    };
    // for FUSE_OPEN
    fuse_open_in open_in;
    // for FUSE_INIT
    fuse_init_in init_in;
    // for FUSE_READ
    fuse_read_in read_in;
    // for FUSE_LOOKUP
    char lookup_name[kFuseMaxWrite];
  };
  void Reset(uint32_t data_length, uint32_t opcode, uint64_t unique);
};

// FuseResponse represents file operation responses to /dev/fuse. It starts
// from fuse_out_header. The body layout depends on the operation code.
template <size_t N>
struct FuseResponseBase : public FuseMessage<FuseResponseBase<N>> {
    fuse_out_header header;
    union {
        // for FUSE_INIT
        fuse_init_out init_out;
        // for FUSE_LOOKUP
        fuse_entry_out entry_out;
        // for FUSE_GETATTR
        fuse_attr_out attr_out;
        // for FUSE_OPEN
        fuse_open_out open_out;
        // for FUSE_READ
        char read_data[N];
        // for FUSE_WRITE
        fuse_write_out write_out;
    };
    void Reset(uint32_t data_length, int32_t error, uint64_t unique);
    void ResetHeader(uint32_t data_length, int32_t error, uint64_t unique);
};

using FuseResponse = FuseResponseBase<kFuseMaxRead>;
using FuseSimpleResponse = FuseResponseBase<0u>;

// To reduce memory usage, FuseBuffer shares the memory region for request and
// response.
union FuseBuffer final {
  FuseRequest request;
  FuseResponse response;

  void HandleInit();
  void HandleNotImpl();
};

}  // namespace fuse
}  // namespace android

#endif  // ANDROID_LIBAPPFUSE_FUSEBUFFER_H_
