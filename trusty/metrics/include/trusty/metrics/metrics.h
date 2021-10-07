/*
 * Copyright (C) 2021 The Android Open Source Project
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

#pragma once

#include <functional>
#include <memory>
#include <string>

#include <android-base/result.h>
#include <android-base/unique_fd.h>

namespace android {
namespace trusty {
namespace metrics {

using android::base::Result;
using android::base::unique_fd;

class TrustyMetrics {
  public:
    /* Wait for next event with a given timeout. Negative timeout means infinite timeout. */
    Result<void> WaitForEvent(int timeout_ms = -1);
    /* Attempt to handle an event from Metrics TA in a non-blocking manner. */
    Result<void> HandleEvent();
    /* Expose TIPC channel so that client can integrate it into an event loop with other fds. */
    int GetRawFd() { return metrics_fd_; };

  protected:
    TrustyMetrics(std::string tipc_dev) : tipc_dev_(std::move(tipc_dev)), metrics_fd_(-1) {}
    virtual ~TrustyMetrics(){};

    Result<void> Open();
    virtual void HandleCrash(const std::string& app_id) = 0;
    virtual void HandleEventDrop() = 0;

  private:
    std::string tipc_dev_;
    unique_fd metrics_fd_;
};

}  // namespace metrics
}  // namespace trusty
}  // namespace android
