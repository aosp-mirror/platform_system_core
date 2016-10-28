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

#ifndef ANDROID_LIBAPPFUSE_APPFUSE_H_
#define ANDROID_LIBAPPFUSE_APPFUSE_H_

#include <linux/fuse.h>

namespace android {

// The numbers came from sdcard.c.
// Maximum number of bytes to write/read in one request/one reply.
constexpr size_t kFuseMaxWrite = 256 * 1024;
constexpr size_t kFuseMaxRead = 128 * 1024;
constexpr int32_t kFuseSuccess = 0;

template<typename T, typename Header>
struct FuseMessage {
  Header header;
  bool Read(int fd);
  bool Write(int fd) const;
 private:
  bool CheckHeaderLength() const;
  bool CheckResult(int result, const char* operation_name) const;
};

struct FuseRequest : public FuseMessage<FuseRequest, fuse_in_header> {
  union {
    struct {
      fuse_write_in write_in;
      char write_data[kFuseMaxWrite];
    };
    fuse_open_in open_in;
    fuse_init_in init_in;
    fuse_read_in read_in;
    char lookup_name[];
  };
};

struct FuseResponse : public FuseMessage<FuseResponse, fuse_out_header> {
  union {
    fuse_init_out init_out;
    fuse_entry_out entry_out;
    fuse_attr_out attr_out;
    fuse_open_out open_out;
    char read_data[kFuseMaxRead];
    fuse_write_out write_out;
  };
  void Reset(uint32_t data_length, int32_t error, uint64_t unique);
  void ResetHeader(uint32_t data_length, int32_t error, uint64_t unique);
};

union FuseBuffer {
  FuseRequest request;
  FuseResponse response;

  void HandleInit();
  void HandleNotImpl();
};

}  // namespace android

#endif  // ANDROID_LIBAPPFUSE_APPFUSE_H_
