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

#include <limits>
#include <memory>
#include <unordered_map>
#include <utility>

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
  std::unique_ptr<Intercept> intercept(reinterpret_cast<Intercept*>(arg));

  CHECK_EQ(sockfd, intercept->sockfd.get());

  // If we can read, either we received unexpected data from the other side, or the other side
  // closed their end of the socket. Either way, kill the intercept.

  // Ownership of intercept differs based on whether we've registered it with InterceptManager.
  if (!intercept->registered) {
    LOG(WARNING) << "intercept for pid " << intercept->pid << " and type " << intercept->dump_type
                 << " closed before being registered.";
    return;
  }

  const char* reason = (event & EV_TIMEOUT) ? "due to timeout" : "due to input";
  LOG(INFO) << "intercept for pid " << intercept->pid << " and type " << intercept->dump_type
            << " terminated: " << reason;
}

void InterceptManager::Unregister(Intercept* intercept) {
  CHECK(intercept->registered);
  auto pid_entry = intercepts.find(intercept->pid);
  if (pid_entry == intercepts.end()) {
    LOG(FATAL) << "No intercepts found for pid " << intercept->pid;
  }
  auto& dump_type_hash = pid_entry->second;
  auto dump_type_entry = dump_type_hash.find(intercept->dump_type);
  if (dump_type_entry == dump_type_hash.end()) {
    LOG(FATAL) << "Unknown intercept " << intercept->pid << " " << intercept->dump_type;
  }
  if (intercept != dump_type_entry->second) {
    LOG(FATAL) << "Mismatch pointer trying to unregister intercept " << intercept->pid << " "
               << intercept->dump_type;
  }

  dump_type_hash.erase(dump_type_entry);
  if (dump_type_hash.empty()) {
    intercepts.erase(pid_entry);
  }
}

static void intercept_request_cb(evutil_socket_t sockfd, short ev, void* arg) {
  std::unique_ptr<Intercept> intercept(reinterpret_cast<Intercept*>(arg));
  InterceptManager* intercept_manager = intercept->intercept_manager;

  CHECK_EQ(sockfd, intercept->sockfd.get());

  if ((ev & EV_TIMEOUT) != 0) {
    LOG(WARNING) << "tombstoned didn't receive InterceptRequest before timeout";
    return;
  } else if ((ev & EV_READ) == 0) {
    LOG(WARNING) << "tombstoned received unexpected event on intercept socket";
    return;
  }

  unique_fd rcv_fd;
  InterceptRequest intercept_request;
  ssize_t result =
      ReceiveFileDescriptors(sockfd, &intercept_request, sizeof(intercept_request), &rcv_fd);

  if (result == -1) {
    PLOG(WARNING) << "failed to read from intercept socket";
    return;
  }
  if (result != sizeof(intercept_request)) {
    LOG(WARNING) << "intercept socket received short read of length " << result << " (expected "
                 << sizeof(intercept_request) << ")";
    return;
  }

  // Move the received FD to the upper half, in order to more easily notice FD leaks.
  int moved_fd = fcntl(rcv_fd.get(), F_DUPFD, 512);
  if (moved_fd == -1) {
    LOG(WARNING) << "failed to move received fd (" << rcv_fd.get() << ")";
    return;
  }
  rcv_fd.reset(moved_fd);

  // See if we can properly register the intercept.
  InterceptResponse response = {};
  if (!intercept_manager->CanRegister(intercept_request, response)) {
    TEMP_FAILURE_RETRY(write(sockfd, &response, sizeof(response)));
    LOG(WARNING) << response.error_message;
    return;
  }

  // Let the other side know that the intercept has been registered, now that we know we can't
  // fail. tombstoned is single threaded, so this isn't racy.
  response.status = InterceptStatus::kRegistered;
  if (TEMP_FAILURE_RETRY(write(sockfd, &response, sizeof(response))) == -1) {
    PLOG(WARNING) << "failed to notify interceptor of registration";
    return;
  }

  intercept->pid = intercept_request.pid;
  intercept->dump_type = intercept_request.dump_type;
  intercept->output_fd = std::move(rcv_fd);
  intercept_manager->Register(intercept.get());

  LOG(INFO) << "registered intercept for pid " << intercept_request.pid << " and type "
            << intercept_request.dump_type;

  // Register a different read event on the socket so that we can remove intercepts if the socket
  // closes (e.g. if a user CTRL-C's the process that requested the intercept).
  event_assign(intercept->intercept_event, intercept_manager->base, sockfd, EV_READ | EV_TIMEOUT,
               intercept_close_cb, arg);

  // If no request comes in, then this will close the intercept and free the pointer.
  struct timeval timeout = {.tv_sec = 10 * android::base::HwTimeoutMultiplier(), .tv_usec = 0};
  event_add(intercept->intercept_event, &timeout);
  intercept.release();
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

Intercept::~Intercept() {
  event_free(intercept_event);
  if (registered) {
    CHECK(intercept_manager != nullptr);
    intercept_manager->Unregister(this);
  }
}

InterceptManager::InterceptManager(event_base* base, int intercept_socket) : base(base) {
  this->listener = evconnlistener_new(base, intercept_accept_cb, this, LEV_OPT_CLOSE_ON_FREE,
                                      /* backlog */ -1, intercept_socket);
}

static DebuggerdDumpType canonical_dump_type(const DebuggerdDumpType dump_type) {
  // kDebuggerdTombstone and kDebuggerdTombstoneProto should be treated as
  // a single dump_type for intercepts (kDebuggerdTombstone).
  if (dump_type == kDebuggerdTombstoneProto) {
    return kDebuggerdTombstone;
  }
  return dump_type;
}

Intercept* InterceptManager::Get(const pid_t pid, const DebuggerdDumpType dump_type) {
  auto pid_entry = intercepts.find(pid);
  if (pid_entry == intercepts.end()) {
    return nullptr;
  }

  const auto& dump_type_hash = pid_entry->second;
  auto dump_type_entry = dump_type_hash.find(canonical_dump_type(dump_type));
  if (dump_type_entry == dump_type_hash.end()) {
    if (dump_type != kDebuggerdAnyIntercept) {
      return nullptr;
    }
    // If doing a dump with an any intercept, only allow an any to match
    // a single intercept. If there are multiple dump types with intercepts
    // then there would be no way to figure out which to use.
    if (dump_type_hash.size() != 1) {
      LOG(WARNING) << "Cannot intercept using kDebuggerdAnyIntercept: there is more than one "
                      "intercept registered for pid "
                   << pid;
      return nullptr;
    }
    dump_type_entry = dump_type_hash.begin();
  }
  return dump_type_entry->second;
}

bool InterceptManager::CanRegister(const InterceptRequest& request, InterceptResponse& response) {
  if (request.pid <= 0 || request.pid > std::numeric_limits<pid_t>::max()) {
    response.status = InterceptStatus::kFailed;
    snprintf(response.error_message, sizeof(response.error_message),
             "invalid intercept request: bad pid %" PRId32, request.pid);
    return false;
  }
  if (request.dump_type < 0 || request.dump_type > kDebuggerdJavaBacktrace) {
    response.status = InterceptStatus::kFailed;
    snprintf(response.error_message, sizeof(response.error_message),
             "invalid intercept request: bad dump type %s", get_dump_type_name(request.dump_type));
    return false;
  }

  if (Get(request.pid, request.dump_type) != nullptr) {
    response.status = InterceptStatus::kFailedAlreadyRegistered;
    snprintf(response.error_message, sizeof(response.error_message),
             "pid %" PRId32 " already registered, type %s", request.pid,
             get_dump_type_name(request.dump_type));
    return false;
  }

  return true;
}

void InterceptManager::Register(Intercept* intercept) {
  CHECK(!intercept->registered);
  auto& dump_type_hash = intercepts[intercept->pid];
  dump_type_hash[canonical_dump_type(intercept->dump_type)] = intercept;
  intercept->registered = true;
}

bool InterceptManager::FindIntercept(pid_t pid, DebuggerdDumpType dump_type,
                                     android::base::unique_fd* out_fd) {
  Intercept* intercept = Get(pid, dump_type);
  if (intercept == nullptr) {
    return false;
  }

  if (dump_type != intercept->dump_type) {
    LOG(INFO) << "found registered intercept of type " << intercept->dump_type
              << " for requested type " << dump_type;
  }

  LOG(INFO) << "found intercept fd " << intercept->output_fd.get() << " for pid " << pid
            << " and type " << intercept->dump_type;
  InterceptResponse response = {};
  response.status = InterceptStatus::kStarted;
  TEMP_FAILURE_RETRY(write(intercept->sockfd, &response, sizeof(response)));
  *out_fd = std::move(intercept->output_fd);

  // Delete the intercept data, which will unregister the intercept and remove the timeout event.
  delete intercept;

  return true;
}
