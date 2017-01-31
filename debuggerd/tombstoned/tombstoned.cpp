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

// Ownership of Crash is a bit messy.
// It's either owned by an active event that must have a timeout, or owned by
// queued_requests, in the case that multiple crashes come in at the same time.
struct Crash {
  ~Crash() {
    event_free(crash_event);
  }

  unique_fd crash_fd;
  pid_t crash_pid;
  event* crash_event = nullptr;
};

static constexpr char kTombstoneDirectory[] = "/data/tombstones/";
static constexpr size_t kTombstoneCount = 10;
static int tombstone_directory_fd = -1;
static int next_tombstone = 0;

static constexpr size_t kMaxConcurrentDumps = 1;
static size_t num_concurrent_dumps = 0;

static std::deque<Crash*> queued_requests;

// Forward declare the callbacks so they can be placed in a sensible order.
static void crash_accept_cb(evconnlistener* listener, evutil_socket_t sockfd, sockaddr*, int, void*);
static void crash_request_cb(evutil_socket_t sockfd, short ev, void* arg);
static void crash_completed_cb(evutil_socket_t sockfd, short ev, void* arg);

static void find_oldest_tombstone() {
  size_t oldest_tombstone = 0;
  time_t oldest_time = std::numeric_limits<time_t>::max();

  for (size_t i = 0; i < kTombstoneCount; ++i) {
    std::string path = android::base::StringPrintf("%stombstone_%02zu", kTombstoneDirectory, i);
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

  next_tombstone = oldest_tombstone;
}

static unique_fd get_tombstone_fd() {
  // If kMaxConcurrentDumps is greater than 1, then theoretically the same
  // filename could be handed out to multiple processes. Unlink and create the
  // file, instead of using O_TRUNC, to avoid two processes interleaving their
  // output.
  unique_fd result;
  char buf[PATH_MAX];
  snprintf(buf, sizeof(buf), "tombstone_%02d", next_tombstone);
  if (unlinkat(tombstone_directory_fd, buf, 0) != 0 && errno != ENOENT) {
    PLOG(FATAL) << "failed to unlink tombstone at " << kTombstoneDirectory << buf;
  }

  result.reset(
    openat(tombstone_directory_fd, buf, O_CREAT | O_EXCL | O_WRONLY | O_APPEND | O_CLOEXEC, 0700));
  if (result == -1) {
    PLOG(FATAL) << "failed to create tombstone at " << kTombstoneDirectory << buf;
  }

  next_tombstone = (next_tombstone + 1) % kTombstoneCount;
  return result;
}

static void dequeue_request(Crash* crash) {
  ++num_concurrent_dumps;

  unique_fd output_fd;
  if (!intercept_manager->GetIntercept(crash->crash_pid, &output_fd)) {
    output_fd = get_tombstone_fd();
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
  return;

fail:
  delete crash;
}

static void crash_accept_cb(evconnlistener* listener, evutil_socket_t sockfd, sockaddr*, int,
                            void*) {
  event_base* base = evconnlistener_get_base(listener);
  Crash* crash = new Crash();

  struct timeval timeout = { 1, 0 };
  event* crash_event = event_new(base, sockfd, EV_TIMEOUT | EV_READ, crash_request_cb, crash);
  crash->crash_fd.reset(sockfd);
  crash->crash_event = crash_event;
  event_add(crash_event, &timeout);
}

static void crash_request_cb(evutil_socket_t sockfd, short ev, void* arg) {
  ssize_t rc;
  Crash* crash = static_cast<Crash*>(arg);
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

  crash->crash_pid = request.packet.dump_request.pid;
  LOG(INFO) << "received crash request for pid " << crash->crash_pid;

  if (num_concurrent_dumps == kMaxConcurrentDumps) {
    LOG(INFO) << "enqueueing crash request for pid " << crash->crash_pid;
    queued_requests.push_back(crash);
  } else {
    dequeue_request(crash);
  }

  return;

fail:
  delete crash;
}

static void crash_completed_cb(evutil_socket_t sockfd, short ev, void* arg) {
  ssize_t rc;
  Crash* crash = static_cast<Crash*>(arg);
  TombstonedCrashPacket request = {};

  --num_concurrent_dumps;

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
  delete crash;

  // If there's something queued up, let them proceed.
  if (!queued_requests.empty()) {
    Crash* next_crash = queued_requests.front();
    queued_requests.pop_front();
    dequeue_request(next_crash);
  }
}

int main(int, char* []) {
  tombstone_directory_fd = open(kTombstoneDirectory, O_DIRECTORY | O_RDONLY | O_CLOEXEC);
  if (tombstone_directory_fd == -1) {
    PLOG(FATAL) << "failed to open tombstone directory";
  }

  find_oldest_tombstone();

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

  evconnlistener* listener =
    evconnlistener_new(base, crash_accept_cb, nullptr, -1, LEV_OPT_CLOSE_ON_FREE, crash_socket);
  if (!listener) {
    LOG(FATAL) << "failed to create evconnlistener";
  }

  LOG(INFO) << "tombstoned successfully initialized";
  event_base_dispatch(base);
}
