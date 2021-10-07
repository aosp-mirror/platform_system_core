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

#include "intercept_manager.h"

#include <inttypes.h>
#include <sys/types.h>

#include <unordered_map>

#include <event2/event.h>
#include <event2/listener.h>

#include <android-base/cmsg.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/unique_fd.h>

#include "protocol.h"
#include "util.h"

using android::base::ReceiveFileDescriptors;
using android::base::unique_fd;

static void intercept_close_cb(evutil_socket_t sockfd, short event, void* arg) {
  auto intercept = reinterpret_cast<Intercept*>(arg);
  InterceptManager* intercept_manager = intercept->intercept_manager;

  CHECK_EQ(sockfd, intercept->sockfd.get());

  // If we can read, either we received unexpected data from the other side, or the other side
  // closed their end of the socket. Either way, kill the intercept.

  // Ownership of intercept differs based on whether we've registered it with InterceptManager.
  if (!intercept->registered) {
    delete intercept;
  } else {
    auto it = intercept_manager->intercepts.find(intercept->intercept_pid);
    if (it == intercept_manager->intercepts.end()) {
      LOG(FATAL) << "intercept close callback called after intercept was already removed?";
    }
    if (it->second.get() != intercept) {
      LOG(FATAL) << "intercept close callback has different Intercept from InterceptManager?";
    }

    const char* reason;
    if ((event & EV_TIMEOUT) != 0) {
      reason = "due to timeout";
    } else {
      reason = "due to input";
    }

    LOG(INFO) << "intercept for pid " << intercept->intercept_pid << " and type "
              << intercept->dump_type << " terminated: " << reason;
    intercept_manager->intercepts.erase(it);
  }
}

static bool is_intercept_request_valid(const InterceptRequest& request) {
  if (request.pid <= 0 || request.pid > std::numeric_limits<pid_t>::max()) {
    return false;
  }

  if (request.dump_type < 0 || request.dump_type > kDebuggerdJavaBacktrace) {
    return false;
  }

  return true;
}

static void intercept_request_cb(evutil_socket_t sockfd, short ev, void* arg) {
  auto intercept = reinterpret_cast<Intercept*>(arg);
  InterceptManager* intercept_manager = intercept->intercept_manager;

  CHECK_EQ(sockfd, intercept->sockfd.get());

  if ((ev & EV_TIMEOUT) != 0) {
    LOG(WARNING) << "tombstoned didn't receive InterceptRequest before timeout";
    goto fail;
  } else if ((ev & EV_READ) == 0) {
    LOG(WARNING) << "tombstoned received unexpected event on intercept socket";
    goto fail;
  }

  {
    unique_fd rcv_fd;
    InterceptRequest intercept_request;
    ssize_t result =
        ReceiveFileDescriptors(sockfd, &intercept_request, sizeof(intercept_request), &rcv_fd);

    if (result == -1) {
      PLOG(WARNING) << "failed to read from intercept socket";
      goto fail;
    } else if (result != sizeof(intercept_request)) {
      LOG(WARNING) << "intercept socket received short read of length " << result << " (expected "
                   << sizeof(intercept_request) << ")";
      goto fail;
    }

    // Move the received FD to the upper half, in order to more easily notice FD leaks.
    int moved_fd = fcntl(rcv_fd.get(), F_DUPFD, 512);
    if (moved_fd == -1) {
      LOG(WARNING) << "failed to move received fd (" << rcv_fd.get() << ")";
      goto fail;
    }
    rcv_fd.reset(moved_fd);

    // We trust the other side, so only do minimal validity checking.
    if (!is_intercept_request_valid(intercept_request)) {
      InterceptResponse response = {};
      response.status = InterceptStatus::kFailed;
      snprintf(response.error_message, sizeof(response.error_message), "invalid intercept request");
      TEMP_FAILURE_RETRY(write(sockfd, &response, sizeof(response)));
      goto fail;
    }

    intercept->intercept_pid = intercept_request.pid;
    intercept->dump_type = intercept_request.dump_type;

    // Check if it's already registered.
    if (intercept_manager->intercepts.count(intercept_request.pid) > 0) {
      InterceptResponse response = {};
      response.status = InterceptStatus::kFailedAlreadyRegistered;
      snprintf(response.error_message, sizeof(response.error_message),
               "pid %" PRId32 " already intercepted, type %d", intercept_request.pid,
               intercept_request.dump_type);
      TEMP_FAILURE_RETRY(write(sockfd, &response, sizeof(response)));
      LOG(WARNING) << response.error_message;
      goto fail;
    }

    // Let the other side know that the intercept has been registered, now that we know we can't
    // fail. tombstoned is single threaded, so this isn't racy.
    InterceptResponse response = {};
    response.status = InterceptStatus::kRegistered;
    if (TEMP_FAILURE_RETRY(write(sockfd, &response, sizeof(response))) == -1) {
      PLOG(WARNING) << "failed to notify interceptor of registration";
      goto fail;
    }

    intercept->output_fd = std::move(rcv_fd);
    intercept_manager->intercepts[intercept_request.pid] = std::unique_ptr<Intercept>(intercept);
    intercept->registered = true;

    LOG(INFO) << "registered intercept for pid " << intercept_request.pid << " and type "
              << intercept_request.dump_type;

    // Register a different read event on the socket so that we can remove intercepts if the socket
    // closes (e.g. if a user CTRL-C's the process that requested the intercept).
    event_assign(intercept->intercept_event, intercept_manager->base, sockfd, EV_READ | EV_TIMEOUT,
                 intercept_close_cb, arg);

    struct timeval timeout = {.tv_sec = 10 * android::base::HwTimeoutMultiplier(), .tv_usec = 0};
    event_add(intercept->intercept_event, &timeout);
  }

  return;

fail:
  delete intercept;
}

static void intercept_accept_cb(evconnlistener* listener, evutil_socket_t sockfd, sockaddr*, int,
                                void* arg) {
  Intercept* intercept = new Intercept();
  intercept->intercept_manager = static_cast<InterceptManager*>(arg);
  intercept->sockfd.reset(sockfd);

  struct timeval timeout = {1 * android::base::HwTimeoutMultiplier(), 0};
  event_base* base = evconnlistener_get_base(listener);
  event* intercept_event =
    event_new(base, sockfd, EV_TIMEOUT | EV_READ, intercept_request_cb, intercept);
  intercept->intercept_event = intercept_event;
  event_add(intercept_event, &timeout);
}

InterceptManager::InterceptManager(event_base* base, int intercept_socket) : base(base) {
  this->listener = evconnlistener_new(base, intercept_accept_cb, this, LEV_OPT_CLOSE_ON_FREE,
                                      /* backlog */ -1, intercept_socket);
}

bool dump_types_compatible(DebuggerdDumpType interceptor, DebuggerdDumpType dump) {
  if (interceptor == dump) {
    return true;
  }

  if (interceptor == kDebuggerdTombstone && dump == kDebuggerdTombstoneProto) {
    return true;
  }

  return false;
}

bool InterceptManager::GetIntercept(pid_t pid, DebuggerdDumpType dump_type,
                                    android::base::unique_fd* out_fd) {
  auto it = this->intercepts.find(pid);
  if (it == this->intercepts.end()) {
    return false;
  }

  if (dump_type == kDebuggerdAnyIntercept) {
    LOG(INFO) << "found registered intercept of type " << it->second->dump_type
              << " for requested type kDebuggerdAnyIntercept";
  } else if (!dump_types_compatible(it->second->dump_type, dump_type)) {
    LOG(WARNING) << "found non-matching intercept of type " << it->second->dump_type
                 << " for requested type: " << dump_type;
    return false;
  }

  auto intercept = std::move(it->second);
  this->intercepts.erase(it);

  LOG(INFO) << "found intercept fd " << intercept->output_fd.get() << " for pid " << pid
            << " and type " << intercept->dump_type;
  InterceptResponse response = {};
  response.status = InterceptStatus::kStarted;
  TEMP_FAILURE_RETRY(write(intercept->sockfd, &response, sizeof(response)));
  *out_fd = std::move(intercept->output_fd);

  return true;
}
