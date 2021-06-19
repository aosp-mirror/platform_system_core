/*
 * Copyright 2017, The Android Open Source Project
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

#include "tombstoned/tombstoned.h"

#include <fcntl.h>
#include <unistd.h>

#include <utility>

#include <android-base/cmsg.h>
#include <android-base/unique_fd.h>
#include <async_safe/log.h>
#include <cutils/sockets.h>

#include "protocol.h"
#include "util.h"

using android::base::ReceiveFileDescriptors;
using android::base::unique_fd;

bool tombstoned_connect(pid_t pid, unique_fd* tombstoned_socket, unique_fd* text_output_fd,
                        DebuggerdDumpType dump_type) {
  return tombstoned_connect(pid, tombstoned_socket, text_output_fd, nullptr, dump_type);
}

bool tombstoned_connect(pid_t pid, unique_fd* tombstoned_socket, unique_fd* text_output_fd,
                        unique_fd* proto_output_fd, DebuggerdDumpType dump_type) {
  unique_fd sockfd(
      socket_local_client((dump_type != kDebuggerdJavaBacktrace ? kTombstonedCrashSocketName
                                                                : kTombstonedJavaTraceSocketName),
                          ANDROID_SOCKET_NAMESPACE_RESERVED, SOCK_SEQPACKET));
  if (sockfd == -1) {
    async_safe_format_log(ANDROID_LOG_ERROR, "libc", "failed to connect to tombstoned: %s",
                          strerror(errno));
    return false;
  }

  TombstonedCrashPacket packet = {};
  packet.packet_type = CrashPacketType::kDumpRequest;
  packet.packet.dump_request.pid = pid;
  packet.packet.dump_request.dump_type = dump_type;
  if (TEMP_FAILURE_RETRY(write(sockfd, &packet, sizeof(packet))) != sizeof(packet)) {
    async_safe_format_log(ANDROID_LOG_ERROR, "libc", "failed to write DumpRequest packet: %s",
                          strerror(errno));
    return false;
  }

  unique_fd tmp_output_fd, tmp_proto_fd;
  ssize_t rc = -1;

  if (dump_type == kDebuggerdTombstoneProto) {
    rc = ReceiveFileDescriptors(sockfd, &packet, sizeof(packet), &tmp_output_fd, &tmp_proto_fd);
  } else {
    rc = ReceiveFileDescriptors(sockfd, &packet, sizeof(packet), &tmp_output_fd);
  }

  if (rc == -1) {
    async_safe_format_log(ANDROID_LOG_ERROR, "libc",
                          "failed to read response to DumpRequest packet: %s", strerror(errno));
    return false;
  } else if (rc != sizeof(packet)) {
    async_safe_format_log(
        ANDROID_LOG_ERROR, "libc",
        "received DumpRequest response packet of incorrect length (expected %zu, got %zd)",
        sizeof(packet), rc);
    return false;
  }

  // Make the fd O_APPEND so that our output is guaranteed to be at the end of a file.
  // (This also makes selinux rules consistent, because selinux distinguishes between writing to
  // a regular fd, and writing to an fd with O_APPEND).
  int flags = fcntl(tmp_output_fd.get(), F_GETFL);
  if (fcntl(tmp_output_fd.get(), F_SETFL, flags | O_APPEND) != 0) {
    async_safe_format_log(ANDROID_LOG_WARN, "libc", "failed to set output fd flags: %s",
                          strerror(errno));
  }

  *tombstoned_socket = std::move(sockfd);
  *text_output_fd = std::move(tmp_output_fd);
  if (proto_output_fd) {
    *proto_output_fd = std::move(tmp_proto_fd);
  }
  return true;
}

bool tombstoned_notify_completion(int tombstoned_socket) {
  TombstonedCrashPacket packet = {};
  packet.packet_type = CrashPacketType::kCompletedDump;
  if (TEMP_FAILURE_RETRY(write(tombstoned_socket, &packet, sizeof(packet))) != sizeof(packet)) {
    return false;
  }
  return true;
}
