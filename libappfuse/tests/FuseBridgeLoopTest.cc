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

#include <sys/socket.h>

#include <sstream>
#include <thread>

#include <android-base/logging.h>
#include <android-base/unique_fd.h>
#include <gtest/gtest.h>

namespace android {
namespace fuse {
namespace {

class Callback : public FuseBridgeLoopCallback {
 public:
  bool mounted;
  bool closed;
  Callback() : mounted(false), closed(false) {}

  void OnMount(int /*mount_id*/) override { mounted = true; }

  void OnClosed(int /* mount_id */) override { closed = true; }
};

class FuseBridgeLoopTest : public ::testing::Test {
 protected:
  base::unique_fd dev_sockets_[2];
  base::unique_fd proxy_sockets_[2];
  Callback callback_;
  std::thread thread_;

  FuseRequest request_;
  FuseResponse response_;

  void SetUp() override {
    base::SetMinimumLogSeverity(base::VERBOSE);
    ASSERT_TRUE(SetupMessageSockets(&dev_sockets_));
    ASSERT_TRUE(SetupMessageSockets(&proxy_sockets_));
    thread_ = std::thread([this] {
        FuseBridgeLoop loop;
        loop.AddBridge(1, std::move(dev_sockets_[1]), std::move(proxy_sockets_[0]));
        loop.Start(&callback_);
    });
  }

  void CheckNotImpl(uint32_t opcode) {
    SCOPED_TRACE((std::ostringstream() << "opcode: " << opcode).str());

    memset(&request_, 0, sizeof(FuseRequest));
    request_.header.opcode = opcode;
    request_.header.len = sizeof(fuse_in_header);
    request_.header.unique = 1;
    ASSERT_TRUE(request_.Write(dev_sockets_[0]));

    memset(&response_, 0, sizeof(FuseResponse));
    ASSERT_TRUE(response_.Read(dev_sockets_[0]));
    EXPECT_EQ(-ENOSYS, response_.header.error);
  }

  void CheckProxy(uint32_t opcode) {
    SCOPED_TRACE((std::ostringstream() << "opcode: " << opcode).str());

    memset(&request_, 0, sizeof(FuseRequest));
    request_.header.opcode = opcode;
    request_.header.unique = opcode; // Use opcode as unique.
    request_.header.len = sizeof(fuse_in_header);
    ASSERT_TRUE(request_.Write(dev_sockets_[0]));

    memset(&request_, 0, sizeof(FuseRequest));
    ASSERT_TRUE(request_.Read(proxy_sockets_[1]));
    EXPECT_EQ(opcode, request_.header.opcode);
    EXPECT_EQ(opcode, request_.header.unique);

    memset(&response_, 0, sizeof(FuseResponse));
    response_.header.len = sizeof(fuse_out_header);
    response_.header.unique = opcode;  // Use opcode as unique.
    response_.header.error = kFuseSuccess;
    ASSERT_TRUE(response_.Write(proxy_sockets_[1]));

    memset(&response_, 0, sizeof(FuseResponse));
    ASSERT_TRUE(response_.Read(dev_sockets_[0]));
    EXPECT_EQ(opcode, response_.header.unique);
    EXPECT_EQ(kFuseSuccess, response_.header.error);
  }

  void SendInitRequest(uint64_t unique) {
    memset(&request_, 0, sizeof(FuseRequest));
    request_.header.opcode = FUSE_INIT;
    request_.header.unique = unique;
    request_.header.len = sizeof(fuse_in_header) + sizeof(fuse_init_in);
    request_.init_in.major = FUSE_KERNEL_VERSION;
    request_.init_in.minor = FUSE_KERNEL_MINOR_VERSION;
    ASSERT_TRUE(request_.Write(dev_sockets_[0]));
  }

  void Close() {
    dev_sockets_[0].reset();
    dev_sockets_[1].reset();
    proxy_sockets_[0].reset();
    proxy_sockets_[1].reset();
    if (thread_.joinable()) {
      thread_.join();
    }
    ASSERT_TRUE(callback_.closed);
  }

  void TearDown() override {
    Close();
  }
};

} //  namespace

TEST_F(FuseBridgeLoopTest, FuseInit) {
  SendInitRequest(1u);

  memset(&response_, 0, sizeof(FuseResponse));
  ASSERT_TRUE(response_.Read(dev_sockets_[0]));
  EXPECT_EQ(kFuseSuccess, response_.header.error);
  EXPECT_EQ(1u, response_.header.unique);

  // Unmount.
  Close();
  EXPECT_TRUE(callback_.mounted);
}

TEST_F(FuseBridgeLoopTest, FuseForget) {
  memset(&request_, 0, sizeof(FuseRequest));
  request_.header.opcode = FUSE_FORGET;
  request_.header.unique = 1u;
  request_.header.len = sizeof(fuse_in_header) + sizeof(fuse_forget_in);
  ASSERT_TRUE(request_.Write(dev_sockets_[0]));

  SendInitRequest(2u);

  memset(&response_, 0, sizeof(FuseResponse));
  ASSERT_TRUE(response_.Read(dev_sockets_[0]));
  EXPECT_EQ(2u, response_.header.unique) <<
      "The loop must not respond to FUSE_FORGET";
}

TEST_F(FuseBridgeLoopTest, FuseNotImpl) {
  CheckNotImpl(FUSE_SETATTR);
  CheckNotImpl(FUSE_READLINK);
  CheckNotImpl(FUSE_SYMLINK);
  CheckNotImpl(FUSE_MKNOD);
  CheckNotImpl(FUSE_MKDIR);
  CheckNotImpl(FUSE_UNLINK);
  CheckNotImpl(FUSE_RMDIR);
  CheckNotImpl(FUSE_RENAME);
  CheckNotImpl(FUSE_LINK);
  CheckNotImpl(FUSE_STATFS);
  CheckNotImpl(FUSE_SETXATTR);
  CheckNotImpl(FUSE_GETXATTR);
  CheckNotImpl(FUSE_LISTXATTR);
  CheckNotImpl(FUSE_REMOVEXATTR);
  CheckNotImpl(FUSE_FLUSH);
  CheckNotImpl(FUSE_OPENDIR);
  CheckNotImpl(FUSE_READDIR);
  CheckNotImpl(FUSE_RELEASEDIR);
  CheckNotImpl(FUSE_FSYNCDIR);
  CheckNotImpl(FUSE_GETLK);
  CheckNotImpl(FUSE_SETLK);
  CheckNotImpl(FUSE_SETLKW);
  CheckNotImpl(FUSE_ACCESS);
  CheckNotImpl(FUSE_CREATE);
  CheckNotImpl(FUSE_INTERRUPT);
  CheckNotImpl(FUSE_BMAP);
  CheckNotImpl(FUSE_DESTROY);
  CheckNotImpl(FUSE_IOCTL);
  CheckNotImpl(FUSE_POLL);
  CheckNotImpl(FUSE_NOTIFY_REPLY);
  CheckNotImpl(FUSE_BATCH_FORGET);
  CheckNotImpl(FUSE_FALLOCATE);
  CheckNotImpl(FUSE_READDIRPLUS);
  CheckNotImpl(FUSE_RENAME2);
  CheckNotImpl(FUSE_LSEEK);
}

TEST_F(FuseBridgeLoopTest, Proxy) {
  CheckProxy(FUSE_LOOKUP);
  CheckProxy(FUSE_GETATTR);
  CheckProxy(FUSE_READ);
  CheckProxy(FUSE_WRITE);
  CheckProxy(FUSE_FSYNC);

  // Invoke FUSE_OPEN and FUSE_RELEASE at last as the loop will exit when all files are closed.
  CheckProxy(FUSE_OPEN);
  CheckProxy(FUSE_RELEASE);

  // Ensure the loop exits.
  Close();
}

}  // namespace fuse
}  // namespace android
