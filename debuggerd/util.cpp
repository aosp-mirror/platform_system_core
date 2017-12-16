/*
 * Copyright 2016, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "util.h"

#include <sys/socket.h>

#include <string>
#include <utility>

#include <android-base/file.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <cutils/sockets.h>
#include "protocol.h"

using android::base::unique_fd;

ssize_t send_fd(int sockfd, const void* data, size_t len, unique_fd fd) {
  char cmsg_buf[CMSG_SPACE(sizeof(int))];

  iovec iov = { .iov_base = const_cast<void*>(data), .iov_len = len };
  msghdr msg = {
    .msg_iov = &iov, .msg_iovlen = 1, .msg_control = cmsg_buf, .msg_controllen = sizeof(cmsg_buf),
  };
  auto cmsg = CMSG_FIRSTHDR(&msg);
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;
  cmsg->cmsg_len = CMSG_LEN(sizeof(int));
  *reinterpret_cast<int*>(CMSG_DATA(cmsg)) = fd.get();

  return TEMP_FAILURE_RETRY(sendmsg(sockfd, &msg, 0));
}

ssize_t recv_fd(int sockfd, void* _Nonnull data, size_t len, unique_fd* _Nullable out_fd) {
  char cmsg_buf[CMSG_SPACE(sizeof(int))];

  iovec iov = { .iov_base = const_cast<void*>(data), .iov_len = len };
  msghdr msg = {
    .msg_iov = &iov,
    .msg_iovlen = 1,
    .msg_control = cmsg_buf,
    .msg_controllen = sizeof(cmsg_buf),
    .msg_flags = 0,
  };
  auto cmsg = CMSG_FIRSTHDR(&msg);
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;
  cmsg->cmsg_len = CMSG_LEN(sizeof(int));

  ssize_t result = TEMP_FAILURE_RETRY(recvmsg(sockfd, &msg, 0));
  if (result == -1) {
    return -1;
  }

  unique_fd fd;
  bool received_fd = msg.msg_controllen == sizeof(cmsg_buf);
  if (received_fd) {
    fd.reset(*reinterpret_cast<int*>(CMSG_DATA(cmsg)));
  }

  if ((msg.msg_flags & MSG_TRUNC) != 0) {
    errno = EFBIG;
    return -1;
  } else if ((msg.msg_flags & MSG_CTRUNC) != 0) {
    errno = ERANGE;
    return -1;
  }

  if (out_fd) {
    *out_fd = std::move(fd);
  } else if (received_fd) {
    errno = ERANGE;
    return -1;
  }

  return result;
}

std::string get_process_name(pid_t pid) {
  std::string result = "<unknown>";
  android::base::ReadFileToString(android::base::StringPrintf("/proc/%d/cmdline", pid), &result);
  return result;
}

std::string get_thread_name(pid_t tid) {
  std::string result = "<unknown>";
  android::base::ReadFileToString(android::base::StringPrintf("/proc/%d/comm", tid), &result);
  return android::base::Trim(result);
}
