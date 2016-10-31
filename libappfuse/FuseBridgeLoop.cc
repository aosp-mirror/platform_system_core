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

#include "libappfuse/FuseBridgeLoop.h"

#include <android-base/logging.h>
#include <android-base/unique_fd.h>

namespace android {

bool FuseBridgeLoop::Start(
    int raw_dev_fd, int raw_proxy_fd, FuseBridgeLoop::Callback* callback) {
  base::unique_fd dev_fd(raw_dev_fd);
  base::unique_fd proxy_fd(raw_proxy_fd);

  LOG(DEBUG) << "Start fuse loop.";
  while (true) {
    if (!buffer_.request.Read(dev_fd)) {
      return false;
    }

    const uint32_t opcode = buffer_.request.header.opcode;
    LOG(VERBOSE) << "Read a fuse packet, opcode=" << opcode;
    switch (opcode) {
      case FUSE_FORGET:
        // Do not reply to FUSE_FORGET.
        continue;

      case FUSE_LOOKUP:
      case FUSE_GETATTR:
      case FUSE_OPEN:
      case FUSE_READ:
      case FUSE_WRITE:
      case FUSE_RELEASE:
      case FUSE_FLUSH:
        if (!buffer_.request.Write(proxy_fd)) {
          LOG(ERROR) << "Failed to write a request to the proxy.";
          return false;
        }
        if (!buffer_.response.Read(proxy_fd)) {
          LOG(ERROR) << "Failed to read a response from the proxy.";
          return false;
        }
        break;

      case FUSE_INIT:
        buffer_.HandleInit();
        break;

      default:
        buffer_.HandleNotImpl();
        break;
    }

    if (!buffer_.response.Write(dev_fd)) {
      LOG(ERROR) << "Failed to write a response to the device.";
      return false;
    }

    if (opcode == FUSE_INIT) {
      callback->OnMount();
    }
  }
}

}  // namespace android
