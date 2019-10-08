#pragma once

/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include "sysdeps.h"

#include <deque>
#include <list>
#include <mutex>
#include <unordered_map>

#include <android-base/thread_annotations.h>

#include "adb_unique_fd.h"
#include "fdevent.h"

struct PollNode {
  fdevent* fde;
  adb_pollfd pollfd;

  explicit PollNode(fdevent* fde) : fde(fde) {
      memset(&pollfd, 0, sizeof(pollfd));
      pollfd.fd = fde->fd.get();

#if defined(__linux__)
      // Always enable POLLRDHUP, so the host server can take action when some clients disconnect.
      // Then we can avoid leaving many sockets in CLOSE_WAIT state. See http://b/23314034.
      pollfd.events = POLLRDHUP;
#endif
  }
};

struct fdevent_context_poll final : public fdevent_context {
    fdevent_context_poll();
    virtual ~fdevent_context_poll();

    virtual void Set(fdevent* fde, unsigned events) final;

    virtual void Loop() final;

    virtual size_t InstalledCount() final;

  protected:
    virtual void Interrupt() final;

  public:
    unique_fd interrupt_fd_;
    fdevent* interrupt_fde_ = nullptr;
};
