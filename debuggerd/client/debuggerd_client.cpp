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

#include <debuggerd/client.h>

#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <chrono>

#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <android-base/unique_fd.h>
#include <cutils/sockets.h>
#include <debuggerd/handler.h>
#include <debuggerd/protocol.h>
#include <debuggerd/util.h>

using android::base::unique_fd;

static bool send_signal(pid_t pid, bool backtrace) {
  sigval val;
  val.sival_int = backtrace;
  if (sigqueue(pid, DEBUGGER_SIGNAL, val) != 0) {
    PLOG(ERROR) << "libdebuggerd_client: failed to send signal to pid " << pid;
    return false;
  }
  return true;
}

bool debuggerd_trigger_dump(pid_t pid, unique_fd output_fd, DebuggerdDumpType dump_type,
                            int timeout_ms) {
  LOG(INFO) << "libdebuggerd_client: started dumping process " << pid;
  unique_fd sockfd;
  const auto end = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
  auto set_timeout = [timeout_ms, &sockfd, &end]() {
    if (timeout_ms <= 0) {
      return true;
    }

    auto now = std::chrono::steady_clock::now();
    if (now > end) {
      return false;
    }

    auto time_left = std::chrono::duration_cast<std::chrono::microseconds>(end - now);
    auto seconds = std::chrono::duration_cast<std::chrono::seconds>(time_left);
    auto microseconds = std::chrono::duration_cast<std::chrono::microseconds>(time_left - seconds);
    struct timeval timeout = {
      .tv_sec = static_cast<long>(seconds.count()),
      .tv_usec = static_cast<long>(microseconds.count()),
    };

    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0) {
      return false;
    }
    if (setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) != 0) {
      return false;
    }

    return true;
  };

  sockfd.reset(socket(AF_LOCAL, SOCK_SEQPACKET, 0));
  if (sockfd == -1) {
    PLOG(ERROR) << "libdebugger_client: failed to create socket";
    return false;
  }

  if (!set_timeout()) {
    PLOG(ERROR) << "libdebugger_client: failed to set timeout";
    return false;
  }

  if (socket_local_client_connect(sockfd.get(), kTombstonedInterceptSocketName,
                                  ANDROID_SOCKET_NAMESPACE_RESERVED, SOCK_SEQPACKET) == -1) {
    PLOG(ERROR) << "libdebuggerd_client: failed to connect to tombstoned";
    return false;
  }

  InterceptRequest req = {.pid = pid };
  if (!set_timeout()) {
    PLOG(ERROR) << "libdebugger_client: failed to set timeout";
  }

  if (send_fd(sockfd.get(), &req, sizeof(req), std::move(output_fd)) != sizeof(req)) {
    PLOG(ERROR) << "libdebuggerd_client: failed to send output fd to tombstoned";
    return false;
  }

  bool backtrace = dump_type == kDebuggerdBacktrace;
  send_signal(pid, backtrace);

  if (!set_timeout()) {
    PLOG(ERROR) << "libdebugger_client: failed to set timeout";
  }

  InterceptResponse response;
  ssize_t rc = TEMP_FAILURE_RETRY(recv(sockfd.get(), &response, sizeof(response), MSG_TRUNC));
  if (rc == 0) {
    LOG(ERROR) << "libdebuggerd_client: failed to read response from tombstoned: timeout reached?";
    return false;
  } else if (rc != sizeof(response)) {
    LOG(ERROR)
      << "libdebuggerd_client: received packet of unexpected length from tombstoned: expected "
      << sizeof(response) << ", received " << rc;
    return false;
  }

  if (response.success != 1) {
    response.error_message[sizeof(response.error_message) - 1] = '\0';
    LOG(ERROR) << "libdebuggerd_client: tombstoned reported failure: " << response.error_message;
  }

  LOG(INFO) << "libdebuggerd_client: done dumping process " << pid;

  return true;
}

int dump_backtrace_to_file(pid_t tid, int fd) {
  return dump_backtrace_to_file_timeout(tid, fd, 0);
}

int dump_backtrace_to_file_timeout(pid_t tid, int fd, int timeout_secs) {
  android::base::unique_fd copy(dup(fd));
  if (copy == -1) {
    return -1;
  }
  int timeout_ms = timeout_secs > 0 ? timeout_secs * 1000 : 0;
  return debuggerd_trigger_dump(tid, std::move(copy), kDebuggerdBacktrace, timeout_ms) ? 0 : -1;
}
