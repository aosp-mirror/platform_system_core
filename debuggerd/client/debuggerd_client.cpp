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
#include <time.h>
#include <unistd.h>

#include <chrono>
#include <iomanip>

#include <android-base/cmsg.h>
#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/parseint.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <bionic/reserved_signals.h>
#include <cutils/sockets.h>
#include <procinfo/process.h>

#include "debuggerd/handler.h"
#include "protocol.h"
#include "util.h"

using namespace std::chrono_literals;

using android::base::ReadFileToString;
using android::base::SendFileDescriptors;
using android::base::StringAppendV;
using android::base::unique_fd;
using android::base::WriteStringToFd;

#define TAG "libdebuggerd_client: "

// Log an error both to the log (via LOG(ERROR)) and to the given fd.
static void log_error(int fd, int errno_value, const char* format, ...) __printflike(3, 4) {
  std::string message(TAG);

  va_list ap;
  va_start(ap, format);
  StringAppendV(&message, format, ap);
  va_end(ap);

  if (errno_value != 0) {
    message = message + ": " + strerror(errno_value);
  }

  if (fd != -1) {
    dprintf(fd, "%s\n", message.c_str());
  }

  LOG(ERROR) << message;
}

template <typename Duration>
static void populate_timeval(struct timeval* tv, const Duration& duration) {
  auto seconds = std::chrono::duration_cast<std::chrono::seconds>(duration);
  auto microseconds = std::chrono::duration_cast<std::chrono::microseconds>(duration - seconds);
  tv->tv_sec = static_cast<long>(seconds.count());
  tv->tv_usec = static_cast<long>(microseconds.count());
}

/**
 * Returns the wchan data for each thread in the process,
 * or empty string if unable to obtain any data.
 */
static std::string get_wchan_data(int fd, pid_t pid) {
  std::vector<pid_t> tids;
  if (!android::procinfo::GetProcessTids(pid, &tids)) {
    log_error(fd, 0, "failed to get process tids");
    return "";
  }

  std::stringstream data;
  for (int tid : tids) {
    std::string path = "/proc/" + std::to_string(pid) + "/task/" + std::to_string(tid) + "/wchan";
    std::string wchan_str;
    if (!ReadFileToString(path, &wchan_str, true)) {
      log_error(fd, errno, "failed to read \"%s\"", path.c_str());
      continue;
    }
    data << "sysTid=" << std::left << std::setw(10) << tid << wchan_str << "\n";
  }

  std::stringstream buffer;
  if (std::string str = data.str(); !str.empty()) {
    buffer << "\n----- Waiting Channels: pid " << pid << " at " << get_timestamp() << " -----\n"
           << "Cmd line: " << android::base::Join(get_command_line(pid), " ") << "\n";
    buffer << "\n" << str << "\n";
    buffer << "----- end " << std::to_string(pid) << " -----\n";
    buffer << "\n";
  }
  return buffer.str();
}

bool debuggerd_trigger_dump(pid_t tid, DebuggerdDumpType dump_type, unsigned int timeout_ms,
                            unique_fd output_fd) {
  if (dump_type == kDebuggerdJavaBacktrace) {
    // Java dumps always get sent to the tgid, so we need to resolve our tid to a tgid.
    android::procinfo::ProcessInfo procinfo;
    std::string error;
    if (!android::procinfo::GetProcessInfo(tid, &procinfo, &error)) {
      log_error(output_fd, 0, "failed to get process info: %s", error.c_str());
      return false;
    }
    tid = procinfo.pid;
  }

  LOG(INFO) << TAG "started dumping process " << tid;

  // Rather than try to deal with poll() all the way through the flow, we update
  // the socket timeout between each step (and only use poll() during the final
  // copy loop).
  const auto end = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
  auto update_timeout = [timeout_ms, &output_fd](int sockfd, auto end) {
    if (timeout_ms <= 0) return true;

    auto remaining = end - std::chrono::steady_clock::now();
    if (remaining < decltype(remaining)::zero()) {
      log_error(output_fd, 0, "timeout expired (update_timeout)");
      return false;
    }

    struct timeval timeout;
    populate_timeval(&timeout, remaining);
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0) {
      log_error(output_fd, errno, "failed to set receive timeout");
      return false;
    }
    if (setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) != 0) {
      log_error(output_fd, errno, "failed to set send timeout");
      return false;
    }
    return true;
  };

  unique_fd sockfd(socket(AF_LOCAL, SOCK_SEQPACKET, 0));
  if (sockfd == -1) {
    log_error(output_fd, errno, "failed to create socket");
    return false;
  }

  if (!update_timeout(sockfd, end)) return false;

  if (socket_local_client_connect(sockfd.get(), kTombstonedInterceptSocketName,
                                  ANDROID_SOCKET_NAMESPACE_RESERVED, SOCK_SEQPACKET) == -1) {
    log_error(output_fd, errno, "failed to connect to tombstoned");
    return false;
  }

  InterceptRequest req = {
      .dump_type = dump_type,
      .pid = tid,
  };

  // Create an intermediate pipe to pass to the other end.
  unique_fd pipe_read, pipe_write;
  if (!Pipe(&pipe_read, &pipe_write)) {
    log_error(output_fd, errno, "failed to create pipe");
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
    log_error(output_fd, errno, "failed to set pipe buffer size");
  }

  if (!update_timeout(sockfd, end)) return false;
  ssize_t rc = SendFileDescriptors(sockfd, &req, sizeof(req), pipe_write.get());
  pipe_write.reset();
  if (rc != sizeof(req)) {
    log_error(output_fd, errno, "failed to send output fd to tombstoned");
    return false;
  }

  auto get_response = [&output_fd](const char* kind, int sockfd, InterceptResponse* response) {
    ssize_t rc = TEMP_FAILURE_RETRY(recv(sockfd, response, sizeof(*response), MSG_TRUNC));
    if (rc == 0) {
      log_error(output_fd, 0, "failed to read %s response from tombstoned: timeout reached?", kind);
      return false;
    } else if (rc == -1) {
      log_error(output_fd, errno, "failed to read %s response from tombstoned", kind);
      return false;
    } else if (rc != sizeof(*response)) {
      log_error(output_fd, 0,
                "received packet of unexpected length from tombstoned while reading %s response: "
                "expected %zd, received %zd",
                kind, sizeof(*response), rc);
      return false;
    }
    return true;
  };

  // Check to make sure we've successfully registered.
  InterceptResponse response;
  if (!update_timeout(sockfd, end)) return false;
  if (!get_response("initial", sockfd, &response)) return false;
  if (response.status != InterceptStatus::kRegistered) {
    log_error(output_fd, 0, "unexpected registration response: %d",
              static_cast<int>(response.status));
    return false;
  }

  // Send the signal.
  const int signal = (dump_type == kDebuggerdJavaBacktrace) ? SIGQUIT : BIONIC_SIGNAL_DEBUGGER;
  sigval val = {.sival_int = (dump_type == kDebuggerdNativeBacktrace) ? 1 : 0};
  if (sigqueue(tid, signal, val) != 0) {
    log_error(output_fd, errno, "failed to send signal to pid %d", tid);
    return false;
  }

  if (!update_timeout(sockfd, end)) return false;
  if (!get_response("status", sockfd, &response)) return false;
  if (response.status != InterceptStatus::kStarted) {
    response.error_message[sizeof(response.error_message) - 1] = '\0';
    log_error(output_fd, 0, "tombstoned reported failure: %s", response.error_message);
    return false;
  }

  // Forward output from the pipe to the output fd.
  while (true) {
    auto remaining = end - std::chrono::steady_clock::now();
    auto remaining_ms = std::chrono::duration_cast<std::chrono::milliseconds>(remaining).count();
    if (timeout_ms <= 0) {
      remaining_ms = -1;
    } else if (remaining_ms < 0) {
      log_error(output_fd, 0, "timeout expired before poll");
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
        log_error(output_fd, errno, "error while polling");
        return false;
      }
    } else if (rc == 0) {
      log_error(output_fd, 0, "poll timeout expired");
      return false;
    }

    // WARNING: It's not possible to replace the below with a splice call.
    // Due to the way debuggerd does many small writes across the pipe,
    // this would cause splice to copy a page for each write. The second
    // pipe fills up based on the number of pages being copied, even
    // though there is not much data being transferred per page. When
    // the second pipe is full, everything stops since there is nothing
    // reading the second pipe to clear it.
    char buf[1024];
    rc = TEMP_FAILURE_RETRY(read(pipe_read.get(), buf, sizeof(buf)));
    if (rc == 0) {
      // Done.
      break;
    } else if (rc == -1) {
      log_error(output_fd, errno, "error while reading");
      return false;
    }

    if (!android::base::WriteFully(output_fd.get(), buf, rc)) {
      log_error(output_fd, errno, "error while writing");
      return false;
    }
  }

  LOG(INFO) << TAG "done dumping process " << tid;

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

  // debuggerd_trigger_dump results in every thread in the process being interrupted
  // by a signal, so we need to fetch the wchan data before calling that.
  std::string wchan_data = get_wchan_data(fd, tid);

  int timeout_ms = timeout_secs > 0 ? timeout_secs * 1000 : 0;
  int ret = debuggerd_trigger_dump(tid, dump_type, timeout_ms, std::move(copy)) ? 0 : -1;

  // Dump wchan data, since only privileged processes (CAP_SYS_ADMIN) can read
  // kernel stack traces (/proc/*/stack).
  if (!WriteStringToFd(wchan_data, fd)) {
    LOG(WARNING) << TAG "Failed to dump wchan data for pid: " << tid;
  }

  return ret;
}
