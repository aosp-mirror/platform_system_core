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
#include <sys/poll.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <chrono>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/parseint.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <cutils/sockets.h>

#include "debuggerd/handler.h"
#include "protocol.h"
#include "util.h"

using namespace std::chrono_literals;

using android::base::unique_fd;

static bool send_signal(pid_t pid, const DebuggerdDumpType dump_type) {
  const int signal = (dump_type == kDebuggerdJavaBacktrace) ? SIGQUIT : DEBUGGER_SIGNAL;
  sigval val;
  val.sival_int = (dump_type == kDebuggerdNativeBacktrace) ? 1 : 0;

  if (sigqueue(pid, signal, val) != 0) {
    PLOG(ERROR) << "libdebuggerd_client: failed to send signal to pid " << pid;
    return false;
  }
  return true;
}

template <typename Duration>
static void populate_timeval(struct timeval* tv, const Duration& duration) {
  auto seconds = std::chrono::duration_cast<std::chrono::seconds>(duration);
  auto microseconds = std::chrono::duration_cast<std::chrono::microseconds>(duration - seconds);
  tv->tv_sec = static_cast<long>(seconds.count());
  tv->tv_usec = static_cast<long>(microseconds.count());
}

bool debuggerd_trigger_dump(pid_t pid, DebuggerdDumpType dump_type, unsigned int timeout_ms,
                            unique_fd output_fd) {
  LOG(INFO) << "libdebuggerd_client: started dumping process " << pid;
  unique_fd sockfd;
  const auto end = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
  auto time_left = [&end]() { return end - std::chrono::steady_clock::now(); };
  auto set_timeout = [timeout_ms, &time_left](int sockfd) {
    if (timeout_ms <= 0) {
      return sockfd;
    }

    auto remaining = time_left();
    if (remaining < decltype(remaining)::zero()) {
      LOG(ERROR) << "libdebuggerd_client: timeout expired";
      return -1;
    }

    struct timeval timeout;
    populate_timeval(&timeout, remaining);

    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0) {
      PLOG(ERROR) << "libdebuggerd_client: failed to set receive timeout";
      return -1;
    }
    if (setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) != 0) {
      PLOG(ERROR) << "libdebuggerd_client: failed to set send timeout";
      return -1;
    }

    return sockfd;
  };

  sockfd.reset(socket(AF_LOCAL, SOCK_SEQPACKET, 0));
  if (sockfd == -1) {
    PLOG(ERROR) << "libdebugger_client: failed to create socket";
    return false;
  }

  if (socket_local_client_connect(set_timeout(sockfd.get()), kTombstonedInterceptSocketName,
                                  ANDROID_SOCKET_NAMESPACE_RESERVED, SOCK_SEQPACKET) == -1) {
    PLOG(ERROR) << "libdebuggerd_client: failed to connect to tombstoned";
    return false;
  }

  InterceptRequest req = {.pid = pid, .dump_type = dump_type};
  if (!set_timeout(sockfd)) {
    PLOG(ERROR) << "libdebugger_client: failed to set timeout";
    return false;
  }

  // Create an intermediate pipe to pass to the other end.
  unique_fd pipe_read, pipe_write;
  if (!Pipe(&pipe_read, &pipe_write)) {
    PLOG(ERROR) << "libdebuggerd_client: failed to create pipe";
    return false;
  }

  std::string pipe_size_str;
  int pipe_buffer_size = 1024 * 1024;
  if (android::base::ReadFileToString("/proc/sys/fs/pipe-max-size", &pipe_size_str)) {
    pipe_size_str = android::base::Trim(pipe_size_str);

    if (!android::base::ParseInt(pipe_size_str.c_str(), &pipe_buffer_size, 0)) {
      LOG(FATAL) << "failed to parse pipe max size '" << pipe_size_str << "'";
    }
  }

  if (fcntl(pipe_read.get(), F_SETPIPE_SZ, pipe_buffer_size) != pipe_buffer_size) {
    PLOG(ERROR) << "failed to set pipe buffer size";
  }

  if (send_fd(set_timeout(sockfd), &req, sizeof(req), std::move(pipe_write)) != sizeof(req)) {
    PLOG(ERROR) << "libdebuggerd_client: failed to send output fd to tombstoned";
    return false;
  }

  // Check to make sure we've successfully registered.
  InterceptResponse response;
  ssize_t rc =
      TEMP_FAILURE_RETRY(recv(set_timeout(sockfd.get()), &response, sizeof(response), MSG_TRUNC));
  if (rc == 0) {
    LOG(ERROR) << "libdebuggerd_client: failed to read response from tombstoned: timeout reached?";
    return false;
  } else if (rc != sizeof(response)) {
    LOG(ERROR)
        << "libdebuggerd_client: received packet of unexpected length from tombstoned: expected "
        << sizeof(response) << ", received " << rc;
    return false;
  }

  if (response.status != InterceptStatus::kRegistered) {
    LOG(ERROR) << "libdebuggerd_client: unexpected registration response: "
               << static_cast<int>(response.status);
    return false;
  }

  if (!send_signal(pid, dump_type)) {
    return false;
  }

  rc = TEMP_FAILURE_RETRY(recv(set_timeout(sockfd.get()), &response, sizeof(response), MSG_TRUNC));
  if (rc == 0) {
    LOG(ERROR) << "libdebuggerd_client: failed to read response from tombstoned: timeout reached?";
    return false;
  } else if (rc != sizeof(response)) {
    LOG(ERROR)
      << "libdebuggerd_client: received packet of unexpected length from tombstoned: expected "
      << sizeof(response) << ", received " << rc;
    return false;
  }

  if (response.status != InterceptStatus::kStarted) {
    response.error_message[sizeof(response.error_message) - 1] = '\0';
    LOG(ERROR) << "libdebuggerd_client: tombstoned reported failure: " << response.error_message;
    return false;
  }

  // Forward output from the pipe to the output fd.
  while (true) {
    auto remaining_ms = std::chrono::duration_cast<std::chrono::milliseconds>(time_left()).count();
    if (timeout_ms <= 0) {
      remaining_ms = -1;
    } else if (remaining_ms < 0) {
      LOG(ERROR) << "libdebuggerd_client: timeout expired";
      return false;
    }

    struct pollfd pfd = {
        .fd = pipe_read.get(), .events = POLLIN, .revents = 0,
    };

    rc = poll(&pfd, 1, remaining_ms);
    if (rc == -1) {
      if (errno == EINTR) {
        continue;
      } else {
        PLOG(ERROR) << "libdebuggerd_client: error while polling";
        return false;
      }
    } else if (rc == 0) {
      LOG(ERROR) << "libdebuggerd_client: timeout expired";
      return false;
    }

    char buf[1024];
    rc = TEMP_FAILURE_RETRY(read(pipe_read.get(), buf, sizeof(buf)));
    if (rc == 0) {
      // Done.
      break;
    } else if (rc == -1) {
      PLOG(ERROR) << "libdebuggerd_client: error while reading";
      return false;
    }

    if (!android::base::WriteFully(output_fd.get(), buf, rc)) {
      PLOG(ERROR) << "libdebuggerd_client: error while writing";
      return false;
    }
  }

  LOG(INFO) << "libdebuggerd_client: done dumping process " << pid;

  return true;
}

int dump_backtrace_to_file(pid_t tid, DebuggerdDumpType dump_type, int fd) {
  return dump_backtrace_to_file_timeout(tid, dump_type, 0, fd);
}

int dump_backtrace_to_file_timeout(pid_t tid, DebuggerdDumpType dump_type, int timeout_secs,
                                   int fd) {
  android::base::unique_fd copy(dup(fd));
  if (copy == -1) {
    return -1;
  }
  int timeout_ms = timeout_secs > 0 ? timeout_secs * 1000 : 0;
  return debuggerd_trigger_dump(tid, dump_type, timeout_ms, std::move(copy)) ? 0 : -1;
}
