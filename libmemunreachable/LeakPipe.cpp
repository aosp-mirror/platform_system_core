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
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <errno.h>
#include <string.h>

#include "LeakPipe.h"

#include "log.h"

namespace android {

bool LeakPipe::SendFd(int sock, int fd) {
  struct msghdr hdr {};
  struct iovec iov {};
  unsigned int data = 0xfdfdfdfd;
  alignas(struct cmsghdr) char cmsgbuf[CMSG_SPACE(sizeof(int))];

  hdr.msg_iov = &iov;
  hdr.msg_iovlen = 1;
  iov.iov_base = &data;
  iov.iov_len = sizeof(data);

  hdr.msg_control = cmsgbuf;
  hdr.msg_controllen = CMSG_LEN(sizeof(int));

  struct cmsghdr* cmsg = CMSG_FIRSTHDR(&hdr);
  cmsg->cmsg_len = CMSG_LEN(sizeof(int));
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;

  *(int*)CMSG_DATA(cmsg) = fd;

  int ret = sendmsg(sock, &hdr, 0);
  if (ret < 0) {
    MEM_ALOGE("failed to send fd: %s", strerror(errno));
    return false;
  }
  if (ret == 0) {
    MEM_ALOGE("eof when sending fd");
    return false;
  }

  return true;
}

int LeakPipe::ReceiveFd(int sock) {
  struct msghdr hdr {};
  struct iovec iov {};
  unsigned int data;
  alignas(struct cmsghdr) char cmsgbuf[CMSG_SPACE(sizeof(int))];

  hdr.msg_iov = &iov;
  hdr.msg_iovlen = 1;
  iov.iov_base = &data;
  iov.iov_len = sizeof(data);

  hdr.msg_control = cmsgbuf;
  hdr.msg_controllen = CMSG_LEN(sizeof(int));

  int ret = recvmsg(sock, &hdr, 0);
  if (ret < 0) {
    MEM_ALOGE("failed to receive fd: %s", strerror(errno));
    return -1;
  }
  if (ret == 0) {
    MEM_ALOGE("eof when receiving fd");
    return -1;
  }

  struct cmsghdr* cmsg = CMSG_FIRSTHDR(&hdr);
  if (cmsg == NULL || cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS) {
    MEM_ALOGE("missing fd while receiving fd");
    return -1;
  }

  return *(int*)CMSG_DATA(cmsg);
}

}  // namespace android
