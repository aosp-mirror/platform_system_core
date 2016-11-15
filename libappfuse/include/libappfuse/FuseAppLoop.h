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

#ifndef ANDROID_LIBAPPFUSE_FUSEAPPLOOP_H_
#define ANDROID_LIBAPPFUSE_FUSEAPPLOOP_H_

#include "libappfuse/FuseBuffer.h"

namespace android {
namespace fuse {

class FuseAppLoopCallback {
 public:
  virtual bool IsActive() = 0;
  virtual int64_t OnGetSize(uint64_t inode) = 0;
  virtual int32_t OnFsync(uint64_t inode) = 0;
  virtual int32_t OnWrite(
      uint64_t inode, uint64_t offset, uint32_t size, const void* data) = 0;
  virtual int32_t OnRead(
      uint64_t inode, uint64_t offset, uint32_t size, void* data) = 0;
  virtual int32_t OnOpen(uint64_t inode) = 0;
  virtual int32_t OnRelease(uint64_t inode) = 0;
  virtual ~FuseAppLoopCallback() = default;
};

bool StartFuseAppLoop(int fd, FuseAppLoopCallback* callback);

}  // namespace fuse
}  // namespace android

#endif  // ANDROID_LIBAPPFUSE_FUSEAPPLOOP_H_
