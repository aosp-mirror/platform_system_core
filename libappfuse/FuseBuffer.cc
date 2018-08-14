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

#include <sys/socket.h>
#include <sys/uio.h>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/macros.h>

namespace android {
namespace fuse {
namespace {

constexpr useconds_t kRetrySleepForWriting = 1000;  // 1 ms

template <typename T>
bool CheckHeaderLength(const FuseMessage<T>* self, const char* name, size_t max_size) {
    const auto& header = static_cast<const T*>(self)->header;
    if (header.len >= sizeof(header) && header.len <= max_size) {
        return true;
    } else {
        LOG(ERROR) << "Invalid header length is found in " << name << ": " << header.len;
        return false;
    }
}

template <typename T>
ResultOrAgain ReadInternal(FuseMessage<T>* self, int fd, int sockflag) {
    char* const buf = reinterpret_cast<char*>(self);
    const ssize_t result = sockflag ? TEMP_FAILURE_RETRY(recv(fd, buf, sizeof(T), sockflag))
                                    : TEMP_FAILURE_RETRY(read(fd, buf, sizeof(T)));

    switch (result) {
        case 0:
            // Expected EOF.
            return ResultOrAgain::kFailure;
        case -1:
            if (errno == EAGAIN) {
                return ResultOrAgain::kAgain;
            }
            PLOG(ERROR) << "Failed to read a FUSE message";
            return ResultOrAgain::kFailure;
    }

    const auto& header = static_cast<const T*>(self)->header;
    if (result < static_cast<ssize_t>(sizeof(header))) {
        LOG(ERROR) << "Read bytes " << result << " are shorter than header size " << sizeof(header);
        return ResultOrAgain::kFailure;
    }

    if (!CheckHeaderLength<T>(self, "Read", sizeof(T))) {
        return ResultOrAgain::kFailure;
    }

    if (static_cast<uint32_t>(result) != header.len) {
        LOG(ERROR) << "Read bytes " << result << " are different from header.len " << header.len;
        return ResultOrAgain::kFailure;
    }

    return ResultOrAgain::kSuccess;
}

template <typename T>
ResultOrAgain WriteInternal(const FuseMessage<T>* self, int fd, int sockflag, const void* data,
                            size_t max_size) {
    if (!CheckHeaderLength<T>(self, "Write", max_size)) {
        return ResultOrAgain::kFailure;
    }

    const char* const buf = reinterpret_cast<const char*>(self);
    const auto& header = static_cast<const T*>(self)->header;

    while (true) {
        int result;
        if (sockflag) {
            CHECK(data == nullptr);
            result = TEMP_FAILURE_RETRY(send(fd, buf, header.len, sockflag));
        } else if (data) {
            const struct iovec vec[] = {{const_cast<char*>(buf), sizeof(header)},
                                        {const_cast<void*>(data), header.len - sizeof(header)}};
            result = TEMP_FAILURE_RETRY(writev(fd, vec, arraysize(vec)));
        } else {
            result = TEMP_FAILURE_RETRY(write(fd, buf, header.len));
        }
        if (result == -1) {
            switch (errno) {
                case ENOBUFS:
                    // When returning ENOBUFS, epoll still reports the FD is writable. Just usleep
                    // and retry again.
                    usleep(kRetrySleepForWriting);
                    continue;
                case EAGAIN:
                    return ResultOrAgain::kAgain;
                default:
                    PLOG(ERROR) << "Failed to write a FUSE message: "
                                << "fd=" << fd << " "
                                << "sockflag=" << sockflag << " "
                                << "data=" << data;
                    return ResultOrAgain::kFailure;
            }
        }

        if (static_cast<unsigned int>(result) != header.len) {
            LOG(ERROR) << "Written bytes " << result << " is different from length in header "
                       << header.len;
            return ResultOrAgain::kFailure;
        }
        return ResultOrAgain::kSuccess;
    }
}
}

static_assert(std::is_standard_layout<FuseBuffer>::value,
              "FuseBuffer must be standard layout union.");

bool SetupMessageSockets(base::unique_fd (*result)[2]) {
    base::unique_fd fds[2];
    {
        int raw_fds[2];
        if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, raw_fds) == -1) {
            PLOG(ERROR) << "Failed to create sockets for proxy";
            return false;
        }
        fds[0].reset(raw_fds[0]);
        fds[1].reset(raw_fds[1]);
    }

    constexpr int kMaxMessageSize = sizeof(FuseBuffer);
    if (setsockopt(fds[0], SOL_SOCKET, SO_SNDBUF, &kMaxMessageSize, sizeof(int)) != 0 ||
        setsockopt(fds[1], SOL_SOCKET, SO_SNDBUF, &kMaxMessageSize, sizeof(int)) != 0) {
        PLOG(ERROR) << "Failed to update buffer size for socket";
        return false;
    }

    (*result)[0] = std::move(fds[0]);
    (*result)[1] = std::move(fds[1]);
    return true;
}

template <typename T>
bool FuseMessage<T>::Read(int fd) {
    return ReadInternal(this, fd, 0) == ResultOrAgain::kSuccess;
}

template <typename T>
ResultOrAgain FuseMessage<T>::ReadOrAgain(int fd) {
    return ReadInternal(this, fd, MSG_DONTWAIT);
}

template <typename T>
bool FuseMessage<T>::Write(int fd) const {
    return WriteInternal(this, fd, 0, nullptr, sizeof(T)) == ResultOrAgain::kSuccess;
}

template <typename T>
bool FuseMessage<T>::WriteWithBody(int fd, size_t max_size, const void* data) const {
    CHECK(data != nullptr);
    return WriteInternal(this, fd, 0, data, max_size) == ResultOrAgain::kSuccess;
}

template <typename T>
ResultOrAgain FuseMessage<T>::WriteOrAgain(int fd) const {
    return WriteInternal(this, fd, MSG_DONTWAIT, nullptr, sizeof(T));
}

void FuseRequest::Reset(
    uint32_t data_length, uint32_t opcode, uint64_t unique) {
  memset(this, 0, sizeof(fuse_in_header) + data_length);
  header.len = sizeof(fuse_in_header) + data_length;
  header.opcode = opcode;
  header.unique = unique;
}

template <size_t N>
void FuseResponseBase<N>::ResetHeader(uint32_t data_length, int32_t error, uint64_t unique) {
    CHECK_LE(error, 0) << "error should be zero or negative.";
    header.len = sizeof(fuse_out_header) + data_length;
    header.error = error;
    header.unique = unique;
}

template <size_t N>
void FuseResponseBase<N>::Reset(uint32_t data_length, int32_t error, uint64_t unique) {
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
  // Add volatile as a workaround for compiler issue which removes the temporary
  // variable.
  const volatile uint64_t unique = request.header.unique;
  response.Reset(0, -ENOSYS, unique);
}

template class FuseMessage<FuseRequest>;
template class FuseMessage<FuseResponse>;
template class FuseMessage<FuseSimpleResponse>;
template struct FuseResponseBase<0u>;
template struct FuseResponseBase<kFuseMaxRead>;

}  // namespace fuse
}  // namespace android
