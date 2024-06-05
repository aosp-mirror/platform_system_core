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
#include <string>
#include <unordered_map>
#include <utility>

#include <event2/event.h>
#include <event2/listener.h>
#include <event2/thread.h>

#include <android-base/cmsg.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <android-base/unique_fd.h>
#include <cutils/sockets.h>

#include "debuggerd/handler.h"
#include "dump_type.h"
#include "protocol.h"
#include "util.h"

#include "intercept_manager.h"

using android::base::GetIntProperty;
using android::base::SendFileDescriptors;
using android::base::StringPrintf;

using android::base::borrowed_fd;
using android::base::unique_fd;

static InterceptManager* intercept_manager;

enum CrashStatus {
  kCrashStatusRunning,
  kCrashStatusQueued,
};

struct CrashArtifact {
  unique_fd fd;

  static CrashArtifact devnull() {
    CrashArtifact result;
    result.fd.reset(open("/dev/null", O_WRONLY | O_CLOEXEC));
    return result;
  }
};

struct CrashArtifactPaths {
  std::string text;
  std::optional<std::string> proto;
};

struct CrashOutput {
  CrashArtifact text;
  std::optional<CrashArtifact> proto;
};

// Ownership of Crash is a bit messy.
// It's either owned by an active event that must have a timeout, or owned by
// queued_requests, in the case that multiple crashes come in at the same time.
struct Crash {
  ~Crash() { event_free(crash_event); }

  CrashOutput output;
  unique_fd crash_socket_fd;
  pid_t crash_pid;
  event* crash_event = nullptr;

  DebuggerdDumpType crash_type;
};

class CrashQueue {
 public:
  CrashQueue(const std::string& dir_path, const std::string& file_name_prefix, size_t max_artifacts,
             size_t max_concurrent_dumps, bool supports_proto, bool world_readable)
      : file_name_prefix_(file_name_prefix),
        dir_path_(dir_path),
        dir_fd_(open(dir_path.c_str(), O_DIRECTORY | O_RDONLY | O_CLOEXEC)),
        max_artifacts_(max_artifacts),
        next_artifact_(0),
        max_concurrent_dumps_(max_concurrent_dumps),
        num_concurrent_dumps_(0),
        supports_proto_(supports_proto),
        world_readable_(world_readable) {
    if (dir_fd_ == -1) {
      PLOG(FATAL) << "failed to open directory: " << dir_path;
    }

    // NOTE: If max_artifacts_ <= max_concurrent_dumps_, then theoretically the
    // same filename could be handed out to multiple processes.
    CHECK(max_artifacts_ > max_concurrent_dumps_);

    find_oldest_artifact();
  }

  static CrashQueue* for_crash(const Crash* crash) {
    return (crash->crash_type == kDebuggerdJavaBacktrace) ? for_anrs() : for_tombstones();
  }

  static CrashQueue* for_crash(const std::unique_ptr<Crash>& crash) {
    return for_crash(crash.get());
  }

  static CrashQueue* for_tombstones() {
    static CrashQueue queue("/data/tombstones", "tombstone_" /* file_name_prefix */,
                            GetIntProperty("tombstoned.max_tombstone_count", 32),
                            1 /* max_concurrent_dumps */, true /* supports_proto */,
                            true /* world_readable */);
    return &queue;
  }

  static CrashQueue* for_anrs() {
    static CrashQueue queue("/data/anr", "trace_" /* file_name_prefix */,
                            GetIntProperty("tombstoned.max_anr_count", 64),
                            4 /* max_concurrent_dumps */, false /* supports_proto */,
                            false /* world_readable */);
    return &queue;
  }

  CrashArtifact create_temporary_file() const {
    CrashArtifact result;

    std::optional<std::string> path;
    result.fd.reset(openat(dir_fd_, ".", O_WRONLY | O_APPEND | O_TMPFILE | O_CLOEXEC, 0660));
    if (result.fd == -1) {
      PLOG(FATAL) << "failed to create temporary tombstone in " << dir_path_;
    }

    if (world_readable_) {
      // We need to fchmodat after creating to avoid getting the umask applied.
      std::string fd_path = StringPrintf("/proc/self/fd/%d", result.fd.get());
      if (fchmodat(dir_fd_, fd_path.c_str(), 0664, 0) != 0) {
        PLOG(ERROR) << "Failed to make tombstone world-readable";
      }
    }

    return std::move(result);
  }

  std::optional<CrashOutput> get_output(DebuggerdDumpType dump_type) {
    CrashOutput result;

    switch (dump_type) {
      case kDebuggerdNativeBacktrace:
        // Don't generate tombstones for native backtrace requests.
        return {};

      case kDebuggerdTombstoneProto:
        if (!supports_proto_) {
          LOG(ERROR) << "received kDebuggerdTombstoneProto on a queue that doesn't support proto";
          return {};
        }
        result.proto = create_temporary_file();
        result.text = create_temporary_file();
        break;

      case kDebuggerdJavaBacktrace:
      case kDebuggerdTombstone:
        result.text = create_temporary_file();
        break;

      default:
        LOG(ERROR) << "unexpected dump type: " << dump_type;
        return {};
    }

    return result;
  }

  borrowed_fd dir_fd() { return dir_fd_; }

  CrashArtifactPaths get_next_artifact_paths() {
    CrashArtifactPaths result;
    result.text = StringPrintf("%s%02d", file_name_prefix_.c_str(), next_artifact_);

    if (supports_proto_) {
      result.proto = StringPrintf("%s%02d.pb", file_name_prefix_.c_str(), next_artifact_);
    }

    next_artifact_ = (next_artifact_ + 1) % max_artifacts_;
    return result;
  }

  // Consumes crash if it returns true, otherwise leaves it untouched.
  bool maybe_enqueue_crash(std::unique_ptr<Crash>&& crash) {
    if (num_concurrent_dumps_ == max_concurrent_dumps_) {
      queued_requests_.emplace_back(std::move(crash));
      return true;
    }

    return false;
  }

  void maybe_dequeue_crashes(void (*handler)(std::unique_ptr<Crash> crash)) {
    while (!queued_requests_.empty() && num_concurrent_dumps_ < max_concurrent_dumps_) {
      std::unique_ptr<Crash> next_crash = std::move(queued_requests_.front());
      queued_requests_.pop_front();
      handler(std::move(next_crash));
    }
  }

  void on_crash_started() { ++num_concurrent_dumps_; }

  void on_crash_completed() { --num_concurrent_dumps_; }

 private:
  void find_oldest_artifact() {
    size_t oldest_tombstone = 0;
    time_t oldest_time = std::numeric_limits<time_t>::max();

    for (size_t i = 0; i < max_artifacts_; ++i) {
      std::string path =
          StringPrintf("%s/%s%02zu", dir_path_.c_str(), file_name_prefix_.c_str(), i);
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

  bool supports_proto_;
  bool world_readable_;

  std::deque<std::unique_ptr<Crash>> queued_requests_;

  DISALLOW_COPY_AND_ASSIGN(CrashQueue);
};

// Whether java trace dumps are produced via tombstoned.
static constexpr bool kJavaTraceDumpsEnabled = true;

// Forward declare the callbacks so they can be placed in a sensible order.
static void crash_accept_cb(evconnlistener* listener, evutil_socket_t sockfd, sockaddr*, int,
                            void*);
static void crash_request_cb(evutil_socket_t sockfd, short ev, void* arg);
static void crash_completed_cb(evutil_socket_t sockfd, short ev, void* arg);

static void perform_request(std::unique_ptr<Crash> crash) {
  unique_fd output_fd;
  if (intercept_manager->FindIntercept(crash->crash_pid, crash->crash_type, &output_fd)) {
    if (crash->crash_type == kDebuggerdTombstoneProto) {
      crash->output.proto = CrashArtifact::devnull();
    }
  } else {
    if (auto o = CrashQueue::for_crash(crash.get())->get_output(crash->crash_type); o) {
      crash->output = std::move(*o);
      output_fd.reset(dup(crash->output.text.fd));
    } else {
      LOG(ERROR) << "failed to get crash output for type " << crash->crash_type;
      return;
    }
  }

  TombstonedCrashPacket response = {.packet_type = CrashPacketType::kPerformDump};

  ssize_t rc = -1;
  if (crash->output.proto) {
    rc = SendFileDescriptors(crash->crash_socket_fd, &response, sizeof(response), output_fd.get(),
                             crash->output.proto->fd.get());
  } else {
    rc = SendFileDescriptors(crash->crash_socket_fd, &response, sizeof(response), output_fd.get());
  }

  output_fd.reset();

  if (rc == -1) {
    PLOG(WARNING) << "failed to send response to CrashRequest";
    return;
  } else if (rc != sizeof(response)) {
    PLOG(WARNING) << "crash socket write returned short";
    return;
  }

  // TODO: Make this configurable by the interceptor?
  struct timeval timeout = {10 * android::base::HwTimeoutMultiplier(), 0};

  event_base* base = event_get_base(crash->crash_event);

  event_assign(crash->crash_event, base, crash->crash_socket_fd, EV_TIMEOUT | EV_READ,
               crash_completed_cb, crash.get());
  event_add(crash->crash_event, &timeout);
  CrashQueue::for_crash(crash)->on_crash_started();

  // The crash is now owned by the event loop.
  crash.release();
}

static void crash_accept_cb(evconnlistener* listener, evutil_socket_t sockfd, sockaddr*, int,
                            void*) {
  event_base* base = evconnlistener_get_base(listener);
  Crash* crash = new Crash();

  // TODO: Make sure that only java crashes come in on the java socket
  // and only native crashes on the native socket.
  struct timeval timeout = {1 * android::base::HwTimeoutMultiplier(), 0};
  event* crash_event = event_new(base, sockfd, EV_TIMEOUT | EV_READ, crash_request_cb, crash);
  crash->crash_socket_fd.reset(sockfd);
  crash->crash_event = crash_event;
  event_add(crash_event, &timeout);
}

static void crash_request_cb(evutil_socket_t sockfd, short ev, void* arg) {
  std::unique_ptr<Crash> crash(static_cast<Crash*>(arg));
  TombstonedCrashPacket request = {};

  if ((ev & EV_TIMEOUT) != 0) {
    LOG(WARNING) << "crash request timed out";
    return;
  } else if ((ev & EV_READ) == 0) {
    LOG(WARNING) << "tombstoned received unexpected event from crash socket";
    return;
  }

  ssize_t rc = TEMP_FAILURE_RETRY(read(sockfd, &request, sizeof(request)));
  if (rc == -1) {
    PLOG(WARNING) << "failed to read from crash socket";
    return;
  } else if (rc != sizeof(request)) {
    LOG(WARNING) << "crash socket received short read of length " << rc << " (expected "
                 << sizeof(request) << ")";
    return;
  }

  if (request.packet_type != CrashPacketType::kDumpRequest) {
    LOG(WARNING) << "unexpected crash packet type, expected kDumpRequest, received  "
                 << StringPrintf("%#2hhX", request.packet_type);
    return;
  }

  crash->crash_type = request.packet.dump_request.dump_type;
  if (crash->crash_type < 0 || crash->crash_type > kDebuggerdTombstoneProto) {
    LOG(WARNING) << "unexpected crash dump type: " << crash->crash_type;
    return;
  }

  if (crash->crash_type != kDebuggerdJavaBacktrace) {
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
      return;
    }

    crash->crash_pid = cr.pid;
  }

  pid_t crash_pid = crash->crash_pid;
  LOG(INFO) << "received crash request for pid " << crash_pid;

  if (CrashQueue::for_crash(crash)->maybe_enqueue_crash(std::move(crash))) {
    LOG(INFO) << "enqueueing crash request for pid " << crash_pid;
  } else {
    perform_request(std::move(crash));
  }
}

static bool rename_tombstone_fd(borrowed_fd fd, borrowed_fd dirfd, const std::string& path) {
  // Always try to unlink the tombstone file.
  // linkat doesn't let us replace a file, so we need to unlink before linking
  // our results onto disk, and if we fail for some reason, we should delete
  // stale tombstones to avoid confusing inconsistency.
  int rc = unlinkat(dirfd.get(), path.c_str(), 0);
  if (rc != 0 && errno != ENOENT) {
    PLOG(ERROR) << "failed to unlink tombstone at " << path;
    return false;
  }

  // This fd is created inside of dirfd in CrashQueue::create_temporary_file.
  std::string fd_path = StringPrintf("/proc/self/fd/%d", fd.get());
  rc = linkat(AT_FDCWD, fd_path.c_str(), dirfd.get(), path.c_str(), AT_SYMLINK_FOLLOW);
  if (rc != 0) {
    PLOG(ERROR) << "failed to link tombstone at " << path;
    return false;
  }
  return true;
}

static void crash_completed(borrowed_fd sockfd, std::unique_ptr<Crash> crash) {
  TombstonedCrashPacket request = {};
  CrashQueue* queue = CrashQueue::for_crash(crash);

  ssize_t rc = TEMP_FAILURE_RETRY(read(sockfd.get(), &request, sizeof(request)));
  if (rc == -1) {
    PLOG(WARNING) << "failed to read from crash socket";
    return;
  } else if (rc != sizeof(request)) {
    LOG(WARNING) << "crash socket received short read of length " << rc << " (expected "
                 << sizeof(request) << ")";
    return;
  }

  if (request.packet_type != CrashPacketType::kCompletedDump) {
    LOG(WARNING) << "unexpected crash packet type, expected kCompletedDump, received "
                 << uint32_t(request.packet_type);
    return;
  }

  if (crash->output.text.fd == -1) {
    LOG(WARNING) << "skipping tombstone file creation due to intercept";
    return;
  }

  CrashArtifactPaths paths = queue->get_next_artifact_paths();

  if (crash->output.proto && crash->output.proto->fd != -1) {
    if (!paths.proto) {
      LOG(ERROR) << "missing path for proto tombstone";
    } else {
      rename_tombstone_fd(crash->output.proto->fd, queue->dir_fd(), *paths.proto);
    }
  }

  if (rename_tombstone_fd(crash->output.text.fd, queue->dir_fd(), paths.text)) {
    if (crash->crash_type == kDebuggerdJavaBacktrace) {
      LOG(ERROR) << "Traces for pid " << crash->crash_pid << " written to: " << paths.text;
    } else {
      // NOTE: Several tools parse this log message to figure out where the
      // tombstone associated with a given native crash was written. Any changes
      // to this message must be carefully considered.
      LOG(ERROR) << "Tombstone written to: " << paths.text;
    }
  }
}

static void crash_completed_cb(evutil_socket_t sockfd, short ev, void* arg) {
  std::unique_ptr<Crash> crash(static_cast<Crash*>(arg));
  CrashQueue* queue = CrashQueue::for_crash(crash);

  queue->on_crash_completed();

  if ((ev & EV_READ) == EV_READ) {
    crash_completed(sockfd, std::move(crash));
  }

  // If there's something queued up, let them proceed.
  queue->maybe_dequeue_crashes(perform_request);
}

int main(int, char* []) {
  umask(0117);

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

  evconnlistener* tombstone_listener =
      evconnlistener_new(base, crash_accept_cb, CrashQueue::for_tombstones(), LEV_OPT_CLOSE_ON_FREE,
                         -1 /* backlog */, crash_socket);
  if (!tombstone_listener) {
    LOG(FATAL) << "failed to create evconnlistener for tombstones.";
  }

  if (kJavaTraceDumpsEnabled) {
    const int java_trace_socket = android_get_control_socket(kTombstonedJavaTraceSocketName);
    if (java_trace_socket == -1) {
      PLOG(FATAL) << "failed to get socket from init";
    }

    evutil_make_socket_nonblocking(java_trace_socket);
    evconnlistener* java_trace_listener =
        evconnlistener_new(base, crash_accept_cb, CrashQueue::for_anrs(), LEV_OPT_CLOSE_ON_FREE,
                           -1 /* backlog */, java_trace_socket);
    if (!java_trace_listener) {
      LOG(FATAL) << "failed to create evconnlistener for java traces.";
    }
  }

  LOG(INFO) << "tombstoned successfully initialized";
  event_base_dispatch(base);
}
