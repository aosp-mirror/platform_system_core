/*
 * Copyright (C) 2019 The Android Open Source Project
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
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <android-base/cmsg.h>

#include <alloca.h>
#include <errno.h>
#include <malloc.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/user.h>

#include <memory>

#include <android-base/logging.h>

namespace android {
namespace base {

ssize_t SendFileDescriptorVector(int sockfd, const void* data, size_t len,
                                 const std::vector<int>& fds) {
  size_t cmsg_space = CMSG_SPACE(sizeof(int) * fds.size());
  size_t cmsg_len = CMSG_LEN(sizeof(int) * fds.size());
  if (cmsg_space >= PAGE_SIZE) {
    errno = ENOMEM;
    return -1;
  }

  alignas(struct cmsghdr) char cmsg_buf[cmsg_space];
  iovec iov = {.iov_base = const_cast<void*>(data), .iov_len = len};
  msghdr msg = {
      .msg_name = nullptr,
      .msg_namelen = 0,
      .msg_iov = &iov,
      .msg_iovlen = 1,
      .msg_control = cmsg_buf,
      .msg_controllen = cmsg_space,
      .msg_flags = 0,
  };

  struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;
  cmsg->cmsg_len = cmsg_len;

  int* cmsg_fds = reinterpret_cast<int*>(CMSG_DATA(cmsg));
  for (size_t i = 0; i < fds.size(); ++i) {
    cmsg_fds[i] = fds[i];
  }

  return TEMP_FAILURE_RETRY(sendmsg(sockfd, &msg, MSG_NOSIGNAL));
}

ssize_t ReceiveFileDescriptorVector(int sockfd, void* data, size_t len, size_t max_fds,
                                    std::vector<unique_fd>* fds) {
  fds->clear();

  size_t cmsg_space = CMSG_SPACE(sizeof(int) * max_fds);
  if (cmsg_space >= PAGE_SIZE) {
    errno = ENOMEM;
    return -1;
  }

  alignas(struct cmsghdr) char cmsg_buf[cmsg_space];
  iovec iov = {.iov_base = const_cast<void*>(data), .iov_len = len};
  msghdr msg = {
      .msg_name = nullptr,
      .msg_namelen = 0,
      .msg_iov = &iov,
      .msg_iovlen = 1,
      .msg_control = cmsg_buf,
      .msg_controllen = cmsg_space,
      .msg_flags = 0,
  };

  ssize_t rc = TEMP_FAILURE_RETRY(
      recvmsg(sockfd, &msg, MSG_TRUNC | MSG_CTRUNC | MSG_CMSG_CLOEXEC | MSG_NOSIGNAL));
  if (rc == -1) {
    return -1;
  }

  int error = 0;
  if ((msg.msg_flags & MSG_TRUNC)) {
    LOG(ERROR) << "message was truncated when receiving file descriptors";
    error = EMSGSIZE;
  } else if ((msg.msg_flags & MSG_CTRUNC)) {
    LOG(ERROR) << "control message was truncated when receiving file descriptors";
    error = EMSGSIZE;
  }

  std::vector<unique_fd> received_fds;
  struct cmsghdr* cmsg;
  for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != nullptr; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
    if (cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS) {
      LOG(ERROR) << "received unexpected cmsg: [" << cmsg->cmsg_level << ", " << cmsg->cmsg_type
                 << "]";
      error = EBADMSG;
      continue;
    }

    // There isn't a macro that does the inverse of CMSG_LEN, so hack around it ourselves, with
    // some static asserts to ensure that CMSG_LEN behaves as we expect.
    static_assert(CMSG_LEN(0) + 1 * sizeof(int) == CMSG_LEN(1 * sizeof(int)));
    static_assert(CMSG_LEN(0) + 2 * sizeof(int) == CMSG_LEN(2 * sizeof(int)));
    static_assert(CMSG_LEN(0) + 3 * sizeof(int) == CMSG_LEN(3 * sizeof(int)));
    static_assert(CMSG_LEN(0) + 4 * sizeof(int) == CMSG_LEN(4 * sizeof(int)));

    if (cmsg->cmsg_len % sizeof(int) != 0) {
      LOG(FATAL) << "cmsg_len(" << cmsg->cmsg_len << ") not aligned to sizeof(int)";
    } else if (cmsg->cmsg_len <= CMSG_LEN(0)) {
      LOG(FATAL) << "cmsg_len(" << cmsg->cmsg_len << ") not long enough to hold any data";
    }

    int* cmsg_fds = reinterpret_cast<int*>(CMSG_DATA(cmsg));
    size_t cmsg_fdcount = static_cast<size_t>(cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int);
    for (size_t i = 0; i < cmsg_fdcount; ++i) {
      received_fds.emplace_back(cmsg_fds[i]);
    }
  }

  if (error != 0) {
    errno = error;
    return -1;
  }

  if (received_fds.size() > max_fds) {
    LOG(ERROR) << "received too many file descriptors, expected " << fds->size() << ", received "
               << received_fds.size();
    errno = EMSGSIZE;
    return -1;
  }

  *fds = std::move(received_fds);
  return rc;
}

}  // namespace base
}  // namespace android
