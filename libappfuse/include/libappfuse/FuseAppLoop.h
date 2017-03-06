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

#include <memory>
#include <mutex>

#include <android-base/unique_fd.h>

#include "libappfuse/FuseBuffer.h"

namespace android {
namespace fuse {

class EpollController;

class FuseAppLoopCallback {
 public:
   virtual void OnLookup(uint64_t unique, uint64_t inode) = 0;
   virtual void OnGetAttr(uint64_t unique, uint64_t inode) = 0;
   virtual void OnFsync(uint64_t unique, uint64_t inode) = 0;
   virtual void OnWrite(uint64_t unique, uint64_t inode, uint64_t offset, uint32_t size,
                        const void* data) = 0;
   virtual void OnRead(uint64_t unique, uint64_t inode, uint64_t offset, uint32_t size) = 0;
   virtual void OnOpen(uint64_t unique, uint64_t inode) = 0;
   virtual void OnRelease(uint64_t unique, uint64_t inode) = 0;
   virtual ~FuseAppLoopCallback();
};

class FuseAppLoop final {
  public:
    FuseAppLoop(base::unique_fd&& fd);

    void Start(FuseAppLoopCallback* callback);
    void Break();

    bool ReplySimple(uint64_t unique, int32_t result);
    bool ReplyLookup(uint64_t unique, uint64_t inode, int64_t size);
    bool ReplyGetAttr(uint64_t unique, uint64_t inode, int64_t size, int mode);
    bool ReplyOpen(uint64_t unique, uint64_t fh);
    bool ReplyWrite(uint64_t unique, uint32_t size);
    bool ReplyRead(uint64_t unique, uint32_t size, const void* data);

  private:
    base::unique_fd fd_;
    base::unique_fd break_fd_;

    // Lock for multi-threading.
    std::mutex mutex_;
};

bool StartFuseAppLoop(int fd, FuseAppLoopCallback* callback);

}  // namespace fuse
}  // namespace android

#endif  // ANDROID_LIBAPPFUSE_FUSEAPPLOOP_H_
