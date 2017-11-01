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

#include "libappfuse/FuseBuffer.h"

#include <fcntl.h>
#include <string.h>
#include <sys/socket.h>

#include <thread>

#include <android-base/unique_fd.h>
#include <gtest/gtest.h>

namespace android {
namespace fuse {

constexpr char kTempFile[] = "/data/local/tmp/appfuse_test_dump";

void OpenTempFile(android::base::unique_fd* fd) {
  fd->reset(open(kTempFile, O_CREAT | O_RDWR, 0600));
  ASSERT_NE(-1, *fd) << strerror(errno);
  unlink(kTempFile);
  ASSERT_NE(-1, *fd) << strerror(errno);
}

void TestReadInvalidLength(size_t headerSize, size_t write_size) {
  android::base::unique_fd fd;
  OpenTempFile(&fd);

  char buffer[std::max(headerSize, sizeof(FuseRequest))];
  FuseRequest* const packet = reinterpret_cast<FuseRequest*>(buffer);
  packet->header.len = headerSize;
  ASSERT_NE(-1, write(fd, packet, write_size)) << strerror(errno);

  lseek(fd, 0, SEEK_SET);
  EXPECT_FALSE(packet->Read(fd));
}

void TestWriteInvalidLength(size_t size) {
  android::base::unique_fd fd;
  OpenTempFile(&fd);

  char buffer[std::max(size, sizeof(FuseRequest))];
  FuseRequest* const packet = reinterpret_cast<FuseRequest*>(buffer);
  packet->header.len = size;
  EXPECT_FALSE(packet->Write(fd));
}

// Use FuseRequest as a template instance of FuseMessage.

TEST(FuseMessageTest, ReadAndWrite) {
  android::base::unique_fd fd;
  OpenTempFile(&fd);

  FuseRequest request;
  request.header.len = sizeof(FuseRequest);
  request.header.opcode = 1;
  request.header.unique = 2;
  request.header.nodeid = 3;
  request.header.uid = 4;
  request.header.gid = 5;
  request.header.pid = 6;
  strcpy(request.lookup_name, "test");

  ASSERT_TRUE(request.Write(fd));

  memset(&request, 0, sizeof(FuseRequest));
  lseek(fd, 0, SEEK_SET);

  ASSERT_TRUE(request.Read(fd));
  EXPECT_EQ(sizeof(FuseRequest), request.header.len);
  EXPECT_EQ(1u, request.header.opcode);
  EXPECT_EQ(2u, request.header.unique);
  EXPECT_EQ(3u, request.header.nodeid);
  EXPECT_EQ(4u, request.header.uid);
  EXPECT_EQ(5u, request.header.gid);
  EXPECT_EQ(6u, request.header.pid);
  EXPECT_STREQ("test", request.lookup_name);
}

TEST(FuseMessageTest, Read_InconsistentLength) {
  TestReadInvalidLength(sizeof(fuse_in_header), sizeof(fuse_in_header) + 1);
}

TEST(FuseMessageTest, Read_TooLong) {
  TestReadInvalidLength(sizeof(FuseRequest) + 1, sizeof(FuseRequest) + 1);
}

TEST(FuseMessageTest, Read_TooShort) {
  TestReadInvalidLength(sizeof(fuse_in_header) - 1, sizeof(fuse_in_header) - 1);
}

TEST(FuseMessageTest, Write_TooLong) {
  TestWriteInvalidLength(sizeof(FuseRequest) + 1);
}

TEST(FuseMessageTest, Write_TooShort) {
  TestWriteInvalidLength(sizeof(fuse_in_header) - 1);
}

TEST(FuseResponseTest, Reset) {
  FuseResponse response;
  // Write 1 to the first ten bytes.
  memset(response.read_data, 'a', 10);

  response.Reset(0, -1, 2);
  EXPECT_EQ(sizeof(fuse_out_header), response.header.len);
  EXPECT_EQ(-1, response.header.error);
  EXPECT_EQ(2u, response.header.unique);
  EXPECT_EQ('a', response.read_data[0]);
  EXPECT_EQ('a', response.read_data[9]);

  response.Reset(5, -4, 3);
  EXPECT_EQ(sizeof(fuse_out_header) + 5, response.header.len);
  EXPECT_EQ(-4, response.header.error);
  EXPECT_EQ(3u, response.header.unique);
  EXPECT_EQ(0, response.read_data[0]);
  EXPECT_EQ(0, response.read_data[1]);
  EXPECT_EQ(0, response.read_data[2]);
  EXPECT_EQ(0, response.read_data[3]);
  EXPECT_EQ(0, response.read_data[4]);
  EXPECT_EQ('a', response.read_data[5]);
}

TEST(FuseResponseTest, ResetHeader) {
  FuseResponse response;
  // Write 1 to the first ten bytes.
  memset(response.read_data, 'a', 10);

  response.ResetHeader(0, -1, 2);
  EXPECT_EQ(sizeof(fuse_out_header), response.header.len);
  EXPECT_EQ(-1, response.header.error);
  EXPECT_EQ(2u, response.header.unique);
  EXPECT_EQ('a', response.read_data[0]);
  EXPECT_EQ('a', response.read_data[9]);

  response.ResetHeader(5, -4, 3);
  EXPECT_EQ(sizeof(fuse_out_header) + 5, response.header.len);
  EXPECT_EQ(-4, response.header.error);
  EXPECT_EQ(3u, response.header.unique);
  EXPECT_EQ('a', response.read_data[0]);
  EXPECT_EQ('a', response.read_data[9]);
}

TEST(FuseBufferTest, HandleInit) {
  FuseBuffer buffer;
  memset(&buffer, 0, sizeof(FuseBuffer));

  buffer.request.header.opcode = FUSE_INIT;
  buffer.request.init_in.major = FUSE_KERNEL_VERSION;
  buffer.request.init_in.minor = FUSE_KERNEL_MINOR_VERSION;

  buffer.HandleInit();

  ASSERT_EQ(sizeof(fuse_out_header) + FUSE_COMPAT_22_INIT_OUT_SIZE,
            buffer.response.header.len);
  EXPECT_EQ(kFuseSuccess, buffer.response.header.error);
  EXPECT_EQ(static_cast<unsigned int>(FUSE_KERNEL_VERSION),
            buffer.response.init_out.major);
  EXPECT_EQ(15u, buffer.response.init_out.minor);
  EXPECT_EQ(static_cast<unsigned int>(FUSE_ATOMIC_O_TRUNC | FUSE_BIG_WRITES),
      buffer.response.init_out.flags);
  EXPECT_EQ(kFuseMaxWrite, buffer.response.init_out.max_write);
}

TEST(FuseBufferTest, HandleNotImpl) {
  FuseBuffer buffer;
  memset(&buffer, 0, sizeof(FuseBuffer));

  buffer.HandleNotImpl();

  ASSERT_EQ(sizeof(fuse_out_header), buffer.response.header.len);
  EXPECT_EQ(-ENOSYS, buffer.response.header.error);
}

TEST(SetupMessageSocketsTest, Stress) {
    constexpr int kCount = 1000;

    FuseRequest request;
    request.header.len = sizeof(FuseRequest);

    base::unique_fd fds[2];
    SetupMessageSockets(&fds);

    std::thread thread([&fds] {
        FuseRequest request;
        for (int i = 0; i < kCount; ++i) {
            ASSERT_TRUE(request.Read(fds[1]));
            usleep(1000);
        }
    });

    for (int i = 0; i < kCount; ++i) {
        ASSERT_TRUE(request.Write(fds[0]));
    }

    thread.join();
}

} // namespace fuse
} // namespace android
