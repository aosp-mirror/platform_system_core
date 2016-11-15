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

#include "libappfuse/FuseBuffer.h"

namespace android {
namespace fuse {

class FuseBridgeLoopCallback {
 public:
  virtual void OnMount() = 0;
  virtual ~FuseBridgeLoopCallback() = default;
};

bool StartFuseBridgeLoop(
    int dev_fd, int proxy_fd, FuseBridgeLoopCallback* callback);

}  // namespace fuse
}  // namespace android

#endif  // ANDROID_LIBAPPFUSE_FUSEBRIDGELOOP_H_
