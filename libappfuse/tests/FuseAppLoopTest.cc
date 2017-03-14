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

#include "libappfuse/FuseAppLoop.h"

#include <sys/socket.h>

#include <android-base/logging.h>
#include <android-base/unique_fd.h>
#include <gtest/gtest.h>
#include <thread>

namespace android {
namespace fuse {
namespace {

constexpr unsigned int kTestFileSize = 1024;

struct CallbackRequest {
  uint32_t code;
  uint64_t inode;
};

class Callback : public FuseAppLoopCallback {
 public:
  std::vector<CallbackRequest> requests;

  bool IsActive() override {
    return true;
  }

  int64_t OnGetSize(uint64_t inode) override {
    if (inode == FUSE_ROOT_ID) {
      return 0;
    } else {
      return kTestFileSize;
    }
  }

  int32_t OnFsync(uint64_t inode) override {
    requests.push_back({
      .code = FUSE_FSYNC,
      .inode = inode
    });
    return 0;
  }

  int32_t OnWrite(uint64_t inode,
                  uint64_t offset ATTRIBUTE_UNUSED,
                  uint32_t size ATTRIBUTE_UNUSED,
                  const void* data ATTRIBUTE_UNUSED) override {
    requests.push_back({
      .code = FUSE_WRITE,
      .inode = inode
    });
    return 0;
  }

  int32_t OnRead(uint64_t inode,
                 uint64_t offset ATTRIBUTE_UNUSED,
                 uint32_t size ATTRIBUTE_UNUSED,
                 void* data ATTRIBUTE_UNUSED) override {
    requests.push_back({
      .code = FUSE_READ,
      .inode = inode
    });
    return 0;
  }

  int32_t OnOpen(uint64_t inode) override {
    requests.push_back({
      .code = FUSE_OPEN,
      .inode = inode
    });
    return 0;
  }

  int32_t OnRelease(uint64_t inode) override {
    requests.push_back({
      .code = FUSE_RELEASE,
      .inode = inode
    });
    return 0;
  }
};

class FuseAppLoopTest : public ::testing::Test {
 private:
  std::thread thread_;

 protected:
  base::unique_fd sockets_[2];
  Callback callback_;
  FuseRequest request_;
  FuseResponse response_;

  void SetUp() override {
    base::SetMinimumLogSeverity(base::VERBOSE);
    ASSERT_TRUE(SetupMessageSockets(&sockets_));
    thread_ = std::thread([this] {
      StartFuseAppLoop(sockets_[1].release(), &callback_);
    });
  }

  void CheckCallback(
      size_t data_size, uint32_t code, size_t expected_out_size) {
    request_.Reset(data_size, code, 1);
    request_.header.nodeid = 10;

    ASSERT_TRUE(request_.Write(sockets_[0]));
    ASSERT_TRUE(response_.Read(sockets_[0]));

    Close();

    EXPECT_EQ(kFuseSuccess, response_.header.error);
    EXPECT_EQ(sizeof(fuse_out_header) + expected_out_size,
              response_.header.len);
    EXPECT_EQ(1u, response_.header.unique);

    ASSERT_EQ(1u, callback_.requests.size());
    EXPECT_EQ(code, callback_.requests[0].code);
    EXPECT_EQ(10u, callback_.requests[0].inode);
  }

  void Close() {
    sockets_[0].reset();
    sockets_[1].reset();
    if (thread_.joinable()) {
      thread_.join();
    }
  }

  void TearDown() override {
    Close();
  }
};

}  // namespace

TEST_F(FuseAppLoopTest, LookUp) {
  request_.Reset(3u, FUSE_LOOKUP, 1);
  request_.header.nodeid = FUSE_ROOT_ID;
  strcpy(request_.lookup_name, "10");

  ASSERT_TRUE(request_.Write(sockets_[0].get()));
  ASSERT_TRUE(response_.Read(sockets_[0].get()));

  EXPECT_EQ(kFuseSuccess, response_.header.error);
  EXPECT_EQ(sizeof(fuse_out_header) + sizeof(fuse_entry_out),
            response_.header.len);
  EXPECT_EQ(1u, response_.header.unique);

  EXPECT_EQ(10u, response_.entry_out.nodeid);
  EXPECT_EQ(0u, response_.entry_out.generation);
  EXPECT_EQ(10u, response_.entry_out.entry_valid);
  EXPECT_EQ(10u, response_.entry_out.attr_valid);
  EXPECT_EQ(0u, response_.entry_out.entry_valid_nsec);
  EXPECT_EQ(0u, response_.entry_out.attr_valid_nsec);

  EXPECT_EQ(10u, response_.entry_out.attr.ino);
  EXPECT_EQ(kTestFileSize, response_.entry_out.attr.size);
  EXPECT_EQ(0u, response_.entry_out.attr.blocks);
  EXPECT_EQ(0u, response_.entry_out.attr.atime);
  EXPECT_EQ(0u, response_.entry_out.attr.mtime);
  EXPECT_EQ(0u, response_.entry_out.attr.ctime);
  EXPECT_EQ(0u, response_.entry_out.attr.atimensec);
  EXPECT_EQ(0u, response_.entry_out.attr.mtimensec);
  EXPECT_EQ(0u, response_.entry_out.attr.ctimensec);
  EXPECT_EQ(S_IFREG | 0777u, response_.entry_out.attr.mode);
  EXPECT_EQ(0u, response_.entry_out.attr.nlink);
  EXPECT_EQ(0u, response_.entry_out.attr.uid);
  EXPECT_EQ(0u, response_.entry_out.attr.gid);
  EXPECT_EQ(0u, response_.entry_out.attr.rdev);
  EXPECT_EQ(0u, response_.entry_out.attr.blksize);
  EXPECT_EQ(0u, response_.entry_out.attr.padding);
}

TEST_F(FuseAppLoopTest, LookUp_InvalidName) {
  request_.Reset(3u, FUSE_LOOKUP, 1);
  request_.header.nodeid = FUSE_ROOT_ID;
  strcpy(request_.lookup_name, "aa");

  ASSERT_TRUE(request_.Write(sockets_[0].get()));
  ASSERT_TRUE(response_.Read(sockets_[0].get()));

  EXPECT_EQ(sizeof(fuse_out_header), response_.header.len);
  EXPECT_EQ(-ENOENT, response_.header.error);
  EXPECT_EQ(1u, response_.header.unique);
}

TEST_F(FuseAppLoopTest, LookUp_TooLargeName) {
  request_.Reset(21u, FUSE_LOOKUP, 1);
  request_.header.nodeid = FUSE_ROOT_ID;
  strcpy(request_.lookup_name, "18446744073709551616");

  ASSERT_TRUE(request_.Write(sockets_[0].get()));
  ASSERT_TRUE(response_.Read(sockets_[0].get()));

  EXPECT_EQ(sizeof(fuse_out_header), response_.header.len);
  EXPECT_EQ(-ENOENT, response_.header.error);
  EXPECT_EQ(1u, response_.header.unique);
}

TEST_F(FuseAppLoopTest, GetAttr) {
  request_.Reset(sizeof(fuse_getattr_in), FUSE_GETATTR, 1);
  request_.header.nodeid = 10;

  ASSERT_TRUE(request_.Write(sockets_[0].get()));
  ASSERT_TRUE(response_.Read(sockets_[0].get()));

  EXPECT_EQ(kFuseSuccess, response_.header.error);
  EXPECT_EQ(sizeof(fuse_out_header) + sizeof(fuse_attr_out),
            response_.header.len);
  EXPECT_EQ(1u, response_.header.unique);

  EXPECT_EQ(10u, response_.attr_out.attr_valid);
  EXPECT_EQ(0u, response_.attr_out.attr_valid_nsec);

  EXPECT_EQ(10u, response_.attr_out.attr.ino);
  EXPECT_EQ(kTestFileSize, response_.attr_out.attr.size);
  EXPECT_EQ(0u, response_.attr_out.attr.blocks);
  EXPECT_EQ(0u, response_.attr_out.attr.atime);
  EXPECT_EQ(0u, response_.attr_out.attr.mtime);
  EXPECT_EQ(0u, response_.attr_out.attr.ctime);
  EXPECT_EQ(0u, response_.attr_out.attr.atimensec);
  EXPECT_EQ(0u, response_.attr_out.attr.mtimensec);
  EXPECT_EQ(0u, response_.attr_out.attr.ctimensec);
  EXPECT_EQ(S_IFREG | 0777u, response_.attr_out.attr.mode);
  EXPECT_EQ(0u, response_.attr_out.attr.nlink);
  EXPECT_EQ(0u, response_.attr_out.attr.uid);
  EXPECT_EQ(0u, response_.attr_out.attr.gid);
  EXPECT_EQ(0u, response_.attr_out.attr.rdev);
  EXPECT_EQ(0u, response_.attr_out.attr.blksize);
  EXPECT_EQ(0u, response_.attr_out.attr.padding);
}

TEST_F(FuseAppLoopTest, GetAttr_Root) {
  request_.Reset(sizeof(fuse_getattr_in), FUSE_GETATTR, 1);
  request_.header.nodeid = FUSE_ROOT_ID;

  ASSERT_TRUE(request_.Write(sockets_[0].get()));
  ASSERT_TRUE(response_.Read(sockets_[0].get()));

  EXPECT_EQ(kFuseSuccess, response_.header.error);
  EXPECT_EQ(sizeof(fuse_out_header) + sizeof(fuse_attr_out),
            response_.header.len);
  EXPECT_EQ(1u, response_.header.unique);

  EXPECT_EQ(10u, response_.attr_out.attr_valid);
  EXPECT_EQ(0u, response_.attr_out.attr_valid_nsec);

  EXPECT_EQ(static_cast<unsigned>(FUSE_ROOT_ID), response_.attr_out.attr.ino);
  EXPECT_EQ(0u, response_.attr_out.attr.size);
  EXPECT_EQ(0u, response_.attr_out.attr.blocks);
  EXPECT_EQ(0u, response_.attr_out.attr.atime);
  EXPECT_EQ(0u, response_.attr_out.attr.mtime);
  EXPECT_EQ(0u, response_.attr_out.attr.ctime);
  EXPECT_EQ(0u, response_.attr_out.attr.atimensec);
  EXPECT_EQ(0u, response_.attr_out.attr.mtimensec);
  EXPECT_EQ(0u, response_.attr_out.attr.ctimensec);
  EXPECT_EQ(S_IFDIR | 0777u, response_.attr_out.attr.mode);
  EXPECT_EQ(0u, response_.attr_out.attr.nlink);
  EXPECT_EQ(0u, response_.attr_out.attr.uid);
  EXPECT_EQ(0u, response_.attr_out.attr.gid);
  EXPECT_EQ(0u, response_.attr_out.attr.rdev);
  EXPECT_EQ(0u, response_.attr_out.attr.blksize);
  EXPECT_EQ(0u, response_.attr_out.attr.padding);
}

TEST_F(FuseAppLoopTest, Open) {
  CheckCallback(sizeof(fuse_open_in), FUSE_OPEN, sizeof(fuse_open_out));
}

TEST_F(FuseAppLoopTest, Fsync) {
  CheckCallback(0u, FUSE_FSYNC, 0u);
}

TEST_F(FuseAppLoopTest, Release) {
  CheckCallback(0u, FUSE_RELEASE, 0u);
}

TEST_F(FuseAppLoopTest, Read) {
  CheckCallback(sizeof(fuse_read_in), FUSE_READ, 0u);
}

TEST_F(FuseAppLoopTest, Write) {
  CheckCallback(sizeof(fuse_write_in), FUSE_WRITE, sizeof(fuse_write_out));
}

}  // namespace fuse
}  // namespace android
