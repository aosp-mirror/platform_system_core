/*
 * Copyright (C) 2016 The Android Open Source Project
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
 * See the License for the specic language governing permissions and
 * limitations under the License.
 */

#ifndef ANDROID_LIBAPPFUSE_FUSEBRIDGELOOP_H_
#define ANDROID_LIBAPPFUSE_FUSEBRIDGELOOP_H_

#include <map>
#include <mutex>
#include <queue>
#include <unordered_set>

#include <android-base/macros.h>

#include "libappfuse/FuseBuffer.h"

namespace android {
namespace fuse {

class FuseBridgeLoopCallback {
 public:
   virtual void OnMount(int mount_id) = 0;
   virtual void OnClosed(int mount_id) = 0;
   virtual ~FuseBridgeLoopCallback() = default;
};

class FuseBridgeEntry;
class BridgeEpollController;

class FuseBridgeLoop final {
  public:
    FuseBridgeLoop();
    ~FuseBridgeLoop();

    void Start(FuseBridgeLoopCallback* callback);

    // Add bridge to the loop. It's OK to invoke the method from a different
    // thread from one which invokes |Start|.
    bool AddBridge(int mount_id, base::unique_fd dev_fd, base::unique_fd proxy_fd);

  private:
    bool ProcessEventLocked(const std::unordered_set<FuseBridgeEntry*>& entries,
                            FuseBridgeLoopCallback* callback);

    std::unique_ptr<BridgeEpollController> epoll_controller_;

    // Map between |mount_id| and bridge entry.
    std::map<int, std::unique_ptr<FuseBridgeEntry>> bridges_;

    // Lock for multi-threading.
    std::mutex mutex_;

    bool opened_;

    DISALLOW_COPY_AND_ASSIGN(FuseBridgeLoop);
};

}  // namespace fuse
}  // namespace android

#endif  // ANDROID_LIBAPPFUSE_FUSEBRIDGELOOP_H_
