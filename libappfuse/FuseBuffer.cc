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

#include "libappfuse/FuseBuffer.h"

#include <inttypes.h>
#include <string.h>
#include <unistd.h>

#include <algorithm>
#include <type_traits>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/macros.h>

namespace android {
namespace fuse {

static_assert(
    std::is_standard_layout<FuseBuffer>::value,
    "FuseBuffer must be standard layout union.");

template <typename T>
bool FuseMessage<T>::CheckHeaderLength(const char* name) const {
  const auto& header = static_cast<const T*>(this)->header;
  if (header.len >= sizeof(header) && header.len <= sizeof(T)) {
    return true;
  } else {
    LOG(ERROR) << "Invalid header length is found in " << name << ": " <<
        header.len;
    return false;
  }
}

template <typename T>
bool FuseMessage<T>::Read(int fd) {
  char* const buf = reinterpret_cast<char*>(this);
  const ssize_t result = TEMP_FAILURE_RETRY(::read(fd, buf, sizeof(T)));
  if (result < 0) {
    PLOG(ERROR) << "Failed to read a FUSE message";
    return false;
  }

  const auto& header = static_cast<const T*>(this)->header;
  if (result < static_cast<ssize_t>(sizeof(header))) {
    LOG(ERROR) << "Read bytes " << result << " are shorter than header size " <<
        sizeof(header);
    return false;
  }

  if (!CheckHeaderLength("Read")) {
    return false;
  }

  if (static_cast<uint32_t>(result) > header.len) {
    LOG(ERROR) << "Read bytes " << result << " are longer than header.len " <<
        header.len;
    return false;
  }

  if (!base::ReadFully(fd, buf + result, header.len - result)) {
    PLOG(ERROR) << "ReadFully failed";
    return false;
  }

  return true;
}

template <typename T>
bool FuseMessage<T>::Write(int fd) const {
  if (!CheckHeaderLength("Write")) {
    return false;
  }

  const char* const buf = reinterpret_cast<const char*>(this);
  const auto& header = static_cast<const T*>(this)->header;
  if (!base::WriteFully(fd, buf, header.len)) {
    PLOG(ERROR) << "WriteFully failed";
    return false;
  }

  return true;
}

template class FuseMessage<FuseRequest>;
template class FuseMessage<FuseResponse>;

void FuseRequest::Reset(
    uint32_t data_length, uint32_t opcode, uint64_t unique) {
  memset(this, 0, sizeof(fuse_in_header) + data_length);
  header.len = sizeof(fuse_in_header) + data_length;
  header.opcode = opcode;
  header.unique = unique;
}

void FuseResponse::ResetHeader(
    uint32_t data_length, int32_t error, uint64_t unique) {
  CHECK_LE(error, 0) << "error should be zero or negative.";
  header.len = sizeof(fuse_out_header) + data_length;
  header.error = error;
  header.unique = unique;
}

void FuseResponse::Reset(uint32_t data_length, int32_t error, uint64_t unique) {
  memset(this, 0, sizeof(fuse_out_header) + data_length);
  ResetHeader(data_length, error, unique);
}

void FuseBuffer::HandleInit() {
  const fuse_init_in* const in = &request.init_in;

  // Before writing |out|, we need to copy data from |in|.
  const uint64_t unique = request.header.unique;
  const uint32_t minor = in->minor;
  const uint32_t max_readahead = in->max_readahead;

  // Kernel 2.6.16 is the first stable kernel with struct fuse_init_out
  // defined (fuse version 7.6). The structure is the same from 7.6 through
  // 7.22. Beginning with 7.23, the structure increased in size and added
  // new parameters.
  if (in->major != FUSE_KERNEL_VERSION || in->minor < 6) {
    LOG(ERROR) << "Fuse kernel version mismatch: Kernel version " << in->major
        << "." << in->minor << " Expected at least " << FUSE_KERNEL_VERSION
        << ".6";
    response.Reset(0, -EPERM, unique);
    return;
  }

  // We limit ourselves to minor=15 because we don't handle BATCH_FORGET yet.
  // Thus we need to use FUSE_COMPAT_22_INIT_OUT_SIZE.
#if defined(FUSE_COMPAT_22_INIT_OUT_SIZE)
  // FUSE_KERNEL_VERSION >= 23.
  const size_t response_size = FUSE_COMPAT_22_INIT_OUT_SIZE;
#else
  const size_t response_size = sizeof(fuse_init_out);
#endif

  response.Reset(response_size, kFuseSuccess, unique);
  fuse_init_out* const out = &response.init_out;
  out->major = FUSE_KERNEL_VERSION;
  out->minor = std::min(minor, 15u);
  out->max_readahead = max_readahead;
  out->flags = FUSE_ATOMIC_O_TRUNC | FUSE_BIG_WRITES;
  out->max_background = 32;
  out->congestion_threshold = 32;
  out->max_write = kFuseMaxWrite;
}

void FuseBuffer::HandleNotImpl() {
  LOG(VERBOSE) << "NOTIMPL op=" << request.header.opcode << " uniq="
      << request.header.unique << " nid=" << request.header.nodeid;
  const uint64_t unique = request.header.unique;
  response.Reset(0, -ENOSYS, unique);
}

}  // namespace fuse
}  // namespace android
