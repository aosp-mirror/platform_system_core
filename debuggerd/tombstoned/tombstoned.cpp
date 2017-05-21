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

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <array>
#include <deque>
#include <unordered_map>

#include <event2/event.h>
#include <event2/listener.h>
#include <event2/thread.h>

#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <android-base/unique_fd.h>
#include <cutils/sockets.h>

#include "debuggerd/handler.h"
#include "debuggerd/protocol.h"
#include "debuggerd/util.h"

#include "intercept_manager.h"

using android::base::StringPrintf;
using android::base::unique_fd;

static InterceptManager* intercept_manager;

enum CrashStatus {
  kCrashStatusRunning,
  kCrashStatusQueued,
};

struct Crash;

class CrashType {
 public:
  CrashType(const std::string& dir_path, const std::string& file_name_prefix, size_t max_artifacts,
            size_t max_concurrent_dumps)
      : file_name_prefix_(file_name_prefix),
        dir_path_(dir_path),
        dir_fd_(open(dir_path.c_str(), O_DIRECTORY | O_RDONLY | O_CLOEXEC)),
        max_artifacts_(max_artifacts),
        next_artifact_(0),
        max_concurrent_dumps_(max_concurrent_dumps),
        num_concurrent_dumps_(0) {
    if (dir_fd_ == -1) {
      PLOG(FATAL) << "failed to open directory: " << dir_path;
    }

    // NOTE: If max_artifacts_ <= max_concurrent_dumps_, then theoretically the
    // same filename could be handed out to multiple processes.
    CHECK(max_artifacts_ > max_concurrent_dumps_);

    find_oldest_artifact();
  }

  unique_fd get_output_fd() {
    unique_fd result;
    char buf[PATH_MAX];
    snprintf(buf, sizeof(buf), "%s%02d", file_name_prefix_.c_str(), next_artifact_);
    // Unlink and create the file, instead of using O_TRUNC, to avoid two processes
    // interleaving their output in case we ever get into that situation.
    if (unlinkat(dir_fd_, buf, 0) != 0 && errno != ENOENT) {
      PLOG(FATAL) << "failed to unlink tombstone at " << dir_path_ << buf;
    }

    result.reset(openat(dir_fd_, buf, O_CREAT | O_EXCL | O_WRONLY | O_APPEND | O_CLOEXEC, 0640));
    if (result == -1) {
      PLOG(FATAL) << "failed to create tombstone at " << dir_path_ << buf;
    }

    next_artifact_ = (next_artifact_ + 1) % max_artifacts_;
    return result;
  }

  bool maybe_enqueue_crash(Crash* crash) {
    if (num_concurrent_dumps_ == max_concurrent_dumps_) {
      queued_requests_.push_back(crash);
      return true;
    }

    return false;
  }

  void maybe_dequeue_crashes(void (*handler)(Crash* crash)) {
    while (!queued_requests_.empty() && num_concurrent_dumps_ < max_concurrent_dumps_) {
      Crash* next_crash = queued_requests_.front();
      queued_requests_.pop_front();
      handler(next_crash);
    }
  }

  void on_crash_started() { ++num_concurrent_dumps_; }

  void on_crash_completed() { --num_concurrent_dumps_; }

  static CrashType* const tombstone;
  static CrashType* const java_trace;

 private:
  void find_oldest_artifact() {
    size_t oldest_tombstone = 0;
    time_t oldest_time = std::numeric_limits<time_t>::max();

    for (size_t i = 0; i < max_artifacts_; ++i) {
      std::string path = android::base::StringPrintf("%s/%s%02zu", dir_path_.c_str(),
                                                     file_name_prefix_.c_str(), i);
      struct stat st;
      if (stat(path.c_str(), &st) != 0) {
        if (errno == ENOENT) {
          oldest_tombstone = i;
          break;
        } else {
          PLOG(ERROR) << "failed to stat " << path;
          continue;
        }
      }

      if (st.st_mtime < oldest_time) {
        oldest_tombstone = i;
        oldest_time = st.st_mtime;
      }
    }

    next_artifact_ = oldest_tombstone;
  }

  const std::string file_name_prefix_;

  const std::string dir_path_;
  const int dir_fd_;

  const size_t max_artifacts_;
  int next_artifact_;

  const size_t max_concurrent_dumps_;
  size_t num_concurrent_dumps_;

  std::deque<Crash*> queued_requests_;

  DISALLOW_COPY_AND_ASSIGN(CrashType);
};

// Whether java trace dumps are produced via tombstoned.
static constexpr bool kJavaTraceDumpsEnabled = false;

/* static */ CrashType* const CrashType::tombstone =
    new CrashType("/data/tombstones", "tombstone_" /* file_name_prefix */, 10 /* max_artifacts */,
                  1 /* max_concurrent_dumps */);

/* static */ CrashType* const CrashType::java_trace =
    (kJavaTraceDumpsEnabled ? new CrashType("/data/anr", "anr_" /* file_name_prefix */,
                                            64 /* max_artifacts */, 4 /* max_concurrent_dumps */)
                            : nullptr);

// Ownership of Crash is a bit messy.
// It's either owned by an active event that must have a timeout, or owned by
// queued_requests, in the case that multiple crashes come in at the same time.
struct Crash {
  ~Crash() { event_free(crash_event); }

  unique_fd crash_fd;
  pid_t crash_pid;
  event* crash_event = nullptr;

  // Not owned by |Crash|.
  CrashType* crash_type = nullptr;
};

// Forward declare the callbacks so they can be placed in a sensible order.
static void crash_accept_cb(evconnlistener* listener, evutil_socket_t sockfd, sockaddr*, int, void*);
static void crash_request_cb(evutil_socket_t sockfd, short ev, void* arg);
static void crash_completed_cb(evutil_socket_t sockfd, short ev, void* arg);

static void perform_request(Crash* crash) {
  unique_fd output_fd;
  // Note that java traces are not interceptible.
  if ((crash->crash_type == CrashType::java_trace) ||
      !intercept_manager->GetIntercept(crash->crash_pid, &output_fd)) {
    output_fd = crash->crash_type->get_output_fd();
  }

  TombstonedCrashPacket response = {
    .packet_type = CrashPacketType::kPerformDump
  };
  ssize_t rc = send_fd(crash->crash_fd, &response, sizeof(response), std::move(output_fd));
  if (rc == -1) {
    PLOG(WARNING) << "failed to send response to CrashRequest";
    goto fail;
  } else if (rc != sizeof(response)) {
    PLOG(WARNING) << "crash socket write returned short";
    goto fail;
  } else {
    // TODO: Make this configurable by the interceptor?
    struct timeval timeout = { 10, 0 };

    event_base* base = event_get_base(crash->crash_event);
    event_assign(crash->crash_event, base, crash->crash_fd, EV_TIMEOUT | EV_READ,
                 crash_completed_cb, crash);
    event_add(crash->crash_event, &timeout);
  }

  crash->crash_type->on_crash_started();
  return;

fail:
  delete crash;
}

static void crash_accept_cb(evconnlistener* listener, evutil_socket_t sockfd, sockaddr*, int,
                            void* crash_type) {
  event_base* base = evconnlistener_get_base(listener);
  Crash* crash = new Crash();

  struct timeval timeout = { 1, 0 };
  event* crash_event = event_new(base, sockfd, EV_TIMEOUT | EV_READ, crash_request_cb, crash);
  crash->crash_fd.reset(sockfd);
  crash->crash_event = crash_event;
  crash->crash_type = static_cast<CrashType*>(crash_type);
  event_add(crash_event, &timeout);
}

static void crash_request_cb(evutil_socket_t sockfd, short ev, void* arg) {
  ssize_t rc;
  Crash* crash = static_cast<Crash*>(arg);
  CrashType* type = crash->crash_type;

  TombstonedCrashPacket request = {};

  if ((ev & EV_TIMEOUT) != 0) {
    LOG(WARNING) << "crash request timed out";
    goto fail;
  } else if ((ev & EV_READ) == 0) {
    LOG(WARNING) << "tombstoned received unexpected event from crash socket";
    goto fail;
  }

  rc = TEMP_FAILURE_RETRY(read(sockfd, &request, sizeof(request)));
  if (rc == -1) {
    PLOG(WARNING) << "failed to read from crash socket";
    goto fail;
  } else if (rc != sizeof(request)) {
    LOG(WARNING) << "crash socket received short read of length " << rc << " (expected "
                 << sizeof(request) << ")";
    goto fail;
  }

  if (request.packet_type != CrashPacketType::kDumpRequest) {
    LOG(WARNING) << "unexpected crash packet type, expected kDumpRequest, received  "
                 << StringPrintf("%#2hhX", request.packet_type);
    goto fail;
  }

  if (type == CrashType::tombstone) {
    crash->crash_pid = request.packet.dump_request.pid;
  } else {
    // Requests for java traces are sent from untrusted processes, so we
    // must not trust the PID sent down with the request. Instead, we ask the
    // kernel.
    ucred cr = {};
    socklen_t len = sizeof(cr);
    int ret = getsockopt(sockfd, SOL_SOCKET, SO_PEERCRED, &cr, &len);
    if (ret != 0) {
      PLOG(ERROR) << "Failed to getsockopt(..SO_PEERCRED)";
      goto fail;
    }

    crash->crash_pid = cr.pid;
  }

  LOG(INFO) << "received crash request for pid " << crash->crash_pid;

  if (type->maybe_enqueue_crash(crash)) {
    LOG(INFO) << "enqueueing crash request for pid " << crash->crash_pid;
  } else {
    perform_request(crash);
  }

  return;

fail:
  delete crash;
}

static void crash_completed_cb(evutil_socket_t sockfd, short ev, void* arg) {
  ssize_t rc;
  Crash* crash = static_cast<Crash*>(arg);
  TombstonedCrashPacket request = {};

  crash->crash_type->on_crash_completed();

  if ((ev & EV_READ) == 0) {
    goto fail;
  }

  rc = TEMP_FAILURE_RETRY(read(sockfd, &request, sizeof(request)));
  if (rc == -1) {
    PLOG(WARNING) << "failed to read from crash socket";
    goto fail;
  } else if (rc != sizeof(request)) {
    LOG(WARNING) << "crash socket received short read of length " << rc << " (expected "
                 << sizeof(request) << ")";
    goto fail;
  }

  if (request.packet_type != CrashPacketType::kCompletedDump) {
    LOG(WARNING) << "unexpected crash packet type, expected kCompletedDump, received "
                 << uint32_t(request.packet_type);
    goto fail;
  }

fail:
  CrashType* type = crash->crash_type;
  delete crash;

  // If there's something queued up, let them proceed.
  type->maybe_dequeue_crashes(perform_request);
}

int main(int, char* []) {
  umask(0137);

  // Don't try to connect to ourselves if we crash.
  struct sigaction action = {};
  action.sa_handler = [](int signal) {
    LOG(ERROR) << "received fatal signal " << signal;
    _exit(1);
  };
  debuggerd_register_handlers(&action);

  int intercept_socket = android_get_control_socket(kTombstonedInterceptSocketName);
  int crash_socket = android_get_control_socket(kTombstonedCrashSocketName);

  if (intercept_socket == -1 || crash_socket == -1) {
    PLOG(FATAL) << "failed to get socket from init";
  }

  evutil_make_socket_nonblocking(intercept_socket);
  evutil_make_socket_nonblocking(crash_socket);

  event_base* base = event_base_new();
  if (!base) {
    LOG(FATAL) << "failed to create event_base";
  }

  intercept_manager = new InterceptManager(base, intercept_socket);

  evconnlistener* tombstone_listener = evconnlistener_new(
      base, crash_accept_cb, CrashType::tombstone, -1, LEV_OPT_CLOSE_ON_FREE, crash_socket);
  if (!tombstone_listener) {
    LOG(FATAL) << "failed to create evconnlistener for tombstones.";
  }

  if (kJavaTraceDumpsEnabled) {
    const int java_trace_socket = android_get_control_socket(kTombstonedJavaTraceSocketName);
    if (java_trace_socket == -1) {
      PLOG(FATAL) << "failed to get socket from init";
    }

    evutil_make_socket_nonblocking(java_trace_socket);
    evconnlistener* java_trace_listener = evconnlistener_new(
        base, crash_accept_cb, CrashType::java_trace, -1, LEV_OPT_CLOSE_ON_FREE, java_trace_socket);
    if (!java_trace_listener) {
      LOG(FATAL) << "failed to create evconnlistener for java traces.";
    }
  }

  LOG(INFO) << "tombstoned successfully initialized";
  event_base_dispatch(base);
}
