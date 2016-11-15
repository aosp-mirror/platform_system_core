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

#include <sys/stat.h>

#include <android-base/logging.h>
#include <android-base/unique_fd.h>

namespace android {
namespace fuse {

namespace {

void HandleLookUp(FuseBuffer* buffer, FuseAppLoopCallback* callback) {
  // AppFuse does not support directory structure now.
  // It can lookup only files under the mount point.
  if (buffer->request.header.nodeid != FUSE_ROOT_ID) {
    LOG(ERROR) << "Nodeid is not FUSE_ROOT_ID.";
    buffer->response.Reset(0, -ENOENT, buffer->request.header.unique);
    return;
  }

  // Ensure that the filename ends with 0.
  const size_t filename_length =
      buffer->request.header.len - sizeof(fuse_in_header);
  if (buffer->request.lookup_name[filename_length - 1] != 0) {
    LOG(ERROR) << "File name does not end with 0.";
    buffer->response.Reset(0, -ENOENT, buffer->request.header.unique);
    return;
  }

  const uint64_t inode =
      static_cast<uint64_t>(atol(buffer->request.lookup_name));
  if (inode == 0 || inode == LONG_MAX) {
    LOG(ERROR) << "Invalid filename";
    buffer->response.Reset(0, -ENOENT, buffer->request.header.unique);
    return;
  }

  const int64_t size = callback->OnGetSize(inode);
  if (size < 0) {
    buffer->response.Reset(0, size, buffer->request.header.unique);
    return;
  }

  buffer->response.Reset(sizeof(fuse_entry_out), 0,
                         buffer->request.header.unique);
  buffer->response.entry_out.nodeid = inode;
  buffer->response.entry_out.attr_valid = 10;
  buffer->response.entry_out.entry_valid = 10;
  buffer->response.entry_out.attr.ino = inode;
  buffer->response.entry_out.attr.mode = S_IFREG | 0777;
  buffer->response.entry_out.attr.size = size;
}

void HandleGetAttr(FuseBuffer* buffer, FuseAppLoopCallback* callback) {
  const uint64_t nodeid = buffer->request.header.nodeid;
  int64_t size;
  uint32_t mode;
  if (nodeid == FUSE_ROOT_ID) {
    size = 0;
    mode = S_IFDIR | 0777;
  } else {
    size = callback->OnGetSize(buffer->request.header.nodeid);
    if (size < 0) {
      buffer->response.Reset(0, size, buffer->request.header.unique);
      return;
    }
    mode = S_IFREG | 0777;
  }

  buffer->response.Reset(sizeof(fuse_attr_out), 0,
                         buffer->request.header.unique);
  buffer->response.attr_out.attr_valid = 10;
  buffer->response.attr_out.attr.ino = nodeid;
  buffer->response.attr_out.attr.mode = mode;
  buffer->response.attr_out.attr.size = size;
}

void HandleOpen(FuseBuffer* buffer, FuseAppLoopCallback* callback) {
  const int32_t file_handle = callback->OnOpen(buffer->request.header.nodeid);
  if (file_handle < 0) {
    buffer->response.Reset(0, file_handle, buffer->request.header.unique);
    return;
  }
  buffer->response.Reset(sizeof(fuse_open_out), kFuseSuccess,
                         buffer->request.header.unique);
  buffer->response.open_out.fh = file_handle;
}

void HandleFsync(FuseBuffer* buffer, FuseAppLoopCallback* callback) {
  buffer->response.Reset(0, callback->OnFsync(buffer->request.header.nodeid),
                         buffer->request.header.unique);
}

void HandleRelease(FuseBuffer* buffer, FuseAppLoopCallback* callback) {
  buffer->response.Reset(0, callback->OnRelease(buffer->request.header.nodeid),
                         buffer->request.header.unique);
}

void HandleRead(FuseBuffer* buffer, FuseAppLoopCallback* callback) {
  const uint64_t unique = buffer->request.header.unique;
  const uint64_t nodeid = buffer->request.header.nodeid;
  const uint64_t offset = buffer->request.read_in.offset;
  const uint32_t size = buffer->request.read_in.size;

  if (size > kFuseMaxRead) {
    buffer->response.Reset(0, -EINVAL, buffer->request.header.unique);
    return;
  }

  const int32_t read_size = callback->OnRead(nodeid, offset, size,
                                             buffer->response.read_data);
  if (read_size < 0) {
    buffer->response.Reset(0, read_size, buffer->request.header.unique);
    return;
  }

  buffer->response.ResetHeader(read_size, kFuseSuccess, unique);
}

void HandleWrite(FuseBuffer* buffer, FuseAppLoopCallback* callback) {
  const uint64_t unique = buffer->request.header.unique;
  const uint64_t nodeid = buffer->request.header.nodeid;
  const uint64_t offset = buffer->request.write_in.offset;
  const uint32_t size = buffer->request.write_in.size;

  if (size > kFuseMaxWrite) {
    buffer->response.Reset(0, -EINVAL, buffer->request.header.unique);
    return;
  }

  const int32_t write_size = callback->OnWrite(nodeid, offset, size,
                                               buffer->request.write_data);
  if (write_size < 0) {
    buffer->response.Reset(0, write_size, buffer->request.header.unique);
    return;
  }

  buffer->response.Reset(sizeof(fuse_write_out), kFuseSuccess, unique);
  buffer->response.write_out.size = write_size;
}

} // namespace

bool StartFuseAppLoop(int raw_fd, FuseAppLoopCallback* callback) {
  base::unique_fd fd(raw_fd);
  FuseBuffer buffer;

  LOG(DEBUG) << "Start fuse loop.";
  while (callback->IsActive()) {
    if (!buffer.request.Read(fd)) {
      return false;
    }

    const uint32_t opcode = buffer.request.header.opcode;
    LOG(VERBOSE) << "Read a fuse packet, opcode=" << opcode;
    switch (opcode) {
      case FUSE_FORGET:
        // Do not reply to FUSE_FORGET.
        continue;

      case FUSE_LOOKUP:
        HandleLookUp(&buffer, callback);
        break;

      case FUSE_GETATTR:
        HandleGetAttr(&buffer, callback);
        break;

      case FUSE_OPEN:
        HandleOpen(&buffer, callback);
        break;

      case FUSE_READ:
        HandleRead(&buffer, callback);
        break;

      case FUSE_WRITE:
        HandleWrite(&buffer, callback);
        break;

      case FUSE_RELEASE:
        HandleRelease(&buffer, callback);
        break;

      case FUSE_FSYNC:
        HandleFsync(&buffer, callback);
        break;

      default:
        buffer.HandleNotImpl();
        break;
    }

    if (!buffer.response.Write(fd)) {
      LOG(ERROR) << "Failed to write a response to the device.";
      return false;
    }
  }

  return true;
}

}  // namespace fuse
}  // namespace android
