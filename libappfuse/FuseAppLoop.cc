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

#include <sys/eventfd.h>
#include <sys/stat.h>

#include <android-base/logging.h>
#include <android-base/unique_fd.h>

#include "libappfuse/EpollController.h"

namespace android {
namespace fuse {

namespace {

bool HandleLookUp(FuseAppLoop* loop, FuseBuffer* buffer, FuseAppLoopCallback* callback) {
    // AppFuse does not support directory structure now.
    // It can lookup only files under the mount point.
    if (buffer->request.header.nodeid != FUSE_ROOT_ID) {
        LOG(ERROR) << "Nodeid is not FUSE_ROOT_ID.";
        return loop->ReplySimple(buffer->request.header.unique, -ENOENT);
    }

    // Ensure that the filename ends with 0.
    const size_t filename_length = buffer->request.header.len - sizeof(fuse_in_header);
    if (buffer->request.lookup_name[filename_length - 1] != 0) {
        LOG(ERROR) << "File name does not end with 0.";
        return loop->ReplySimple(buffer->request.header.unique, -ENOENT);
    }

    const uint64_t inode = static_cast<uint64_t>(atol(buffer->request.lookup_name));
    if (inode == 0 || inode == LONG_MAX) {
        LOG(ERROR) << "Invalid filename";
        return loop->ReplySimple(buffer->request.header.unique, -ENOENT);
    }

    callback->OnLookup(buffer->request.header.unique, inode);
    return true;
}

bool HandleGetAttr(FuseAppLoop* loop, FuseBuffer* buffer, FuseAppLoopCallback* callback) {
    if (buffer->request.header.nodeid == FUSE_ROOT_ID) {
        return loop->ReplyGetAttr(buffer->request.header.unique, buffer->request.header.nodeid, 0,
                                  S_IFDIR | 0777);
    } else {
        callback->OnGetAttr(buffer->request.header.unique, buffer->request.header.nodeid);
        return true;
    }
}

bool HandleRead(FuseAppLoop* loop, FuseBuffer* buffer, FuseAppLoopCallback* callback) {
    if (buffer->request.read_in.size > kFuseMaxRead) {
        return loop->ReplySimple(buffer->request.header.unique, -EINVAL);
    }

    callback->OnRead(buffer->request.header.unique, buffer->request.header.nodeid,
                     buffer->request.read_in.offset, buffer->request.read_in.size);
    return true;
}

bool HandleWrite(FuseAppLoop* loop, FuseBuffer* buffer, FuseAppLoopCallback* callback) {
    if (buffer->request.write_in.size > kFuseMaxWrite) {
        return loop->ReplySimple(buffer->request.header.unique, -EINVAL);
    }

    callback->OnWrite(buffer->request.header.unique, buffer->request.header.nodeid,
                      buffer->request.write_in.offset, buffer->request.write_in.size,
                      buffer->request.write_data);
    return true;
}

bool HandleMessage(FuseAppLoop* loop, FuseBuffer* buffer, int fd, FuseAppLoopCallback* callback) {
    if (!buffer->request.Read(fd)) {
        return false;
    }

    const uint32_t opcode = buffer->request.header.opcode;
    LOG(VERBOSE) << "Read a fuse packet, opcode=" << opcode;
    switch (opcode) {
        case FUSE_FORGET:
            // Do not reply to FUSE_FORGET.
            return true;

        case FUSE_LOOKUP:
            return HandleLookUp(loop, buffer, callback);

        case FUSE_GETATTR:
            return HandleGetAttr(loop, buffer, callback);

        case FUSE_OPEN:
            callback->OnOpen(buffer->request.header.unique, buffer->request.header.nodeid);
            return true;

        case FUSE_READ:
            return HandleRead(loop, buffer, callback);

        case FUSE_WRITE:
            return HandleWrite(loop, buffer, callback);

        case FUSE_RELEASE:
            callback->OnRelease(buffer->request.header.unique, buffer->request.header.nodeid);
            return true;

        case FUSE_FSYNC:
            callback->OnFsync(buffer->request.header.unique, buffer->request.header.nodeid);
            return true;

        default:
            buffer->HandleNotImpl();
            return buffer->response.Write(fd);
    }
}

} // namespace

FuseAppLoopCallback::~FuseAppLoopCallback() = default;

FuseAppLoop::FuseAppLoop(base::unique_fd&& fd) : fd_(std::move(fd)) {}

void FuseAppLoop::Break() {
    const int64_t value = 1;
    if (write(break_fd_, &value, sizeof(value)) == -1) {
        PLOG(ERROR) << "Failed to send a break event";
    }
}

bool FuseAppLoop::ReplySimple(uint64_t unique, int32_t result) {
    if (result == -ENOSYS) {
        // We should not return -ENOSYS because the kernel stops delivering FUSE
        // command after receiving -ENOSYS as a result for the command.
        result = -EBADF;
    }
    FuseSimpleResponse response;
    response.Reset(0, result, unique);
    return response.Write(fd_);
}

bool FuseAppLoop::ReplyLookup(uint64_t unique, uint64_t inode, int64_t size) {
    FuseSimpleResponse response;
    response.Reset(sizeof(fuse_entry_out), 0, unique);
    response.entry_out.nodeid = inode;
    response.entry_out.attr_valid = 10;
    response.entry_out.entry_valid = 10;
    response.entry_out.attr.ino = inode;
    response.entry_out.attr.mode = S_IFREG | 0777;
    response.entry_out.attr.size = size;
    return response.Write(fd_);
}

bool FuseAppLoop::ReplyGetAttr(uint64_t unique, uint64_t inode, int64_t size, int mode) {
    CHECK(mode == (S_IFREG | 0777) || mode == (S_IFDIR | 0777));
    FuseSimpleResponse response;
    response.Reset(sizeof(fuse_attr_out), 0, unique);
    response.attr_out.attr_valid = 10;
    response.attr_out.attr.ino = inode;
    response.attr_out.attr.mode = mode;
    response.attr_out.attr.size = size;
    return response.Write(fd_);
}

bool FuseAppLoop::ReplyOpen(uint64_t unique, uint64_t fh) {
    FuseSimpleResponse response;
    response.Reset(sizeof(fuse_open_out), kFuseSuccess, unique);
    response.open_out.fh = fh;
    return response.Write(fd_);
}

bool FuseAppLoop::ReplyWrite(uint64_t unique, uint32_t size) {
    CHECK(size <= kFuseMaxWrite);
    FuseSimpleResponse response;
    response.Reset(sizeof(fuse_write_out), kFuseSuccess, unique);
    response.write_out.size = size;
    return response.Write(fd_);
}

bool FuseAppLoop::ReplyRead(uint64_t unique, uint32_t size, const void* data) {
    CHECK(size <= kFuseMaxRead);
    FuseSimpleResponse response;
    response.ResetHeader(size, kFuseSuccess, unique);
    return response.WriteWithBody(fd_, sizeof(FuseResponse), data);
}

void FuseAppLoop::Start(FuseAppLoopCallback* callback) {
    break_fd_.reset(eventfd(/* initval */ 0, EFD_CLOEXEC));
    if (break_fd_.get() == -1) {
        PLOG(ERROR) << "Failed to open FD for break event";
        return;
    }

    base::unique_fd epoll_fd(epoll_create1(EPOLL_CLOEXEC));
    if (epoll_fd.get() == -1) {
        PLOG(ERROR) << "Failed to open FD for epoll";
        return;
    }

    int last_event;
    int break_event;

    std::unique_ptr<EpollController> epoll_controller(new EpollController(std::move(epoll_fd)));
    if (!epoll_controller->AddFd(fd_, EPOLLIN, &last_event)) {
        return;
    }
    if (!epoll_controller->AddFd(break_fd_, EPOLLIN, &break_event)) {
        return;
    }

    last_event = 0;
    break_event = 0;

    FuseBuffer buffer;
    while (true) {
        if (!epoll_controller->Wait(1)) {
            break;
        }
        last_event = 0;
        *reinterpret_cast<int*>(epoll_controller->events()[0].data.ptr) =
            epoll_controller->events()[0].events;

        if (break_event != 0 || (last_event & ~EPOLLIN) != 0) {
            break;
        }

        if (!HandleMessage(this, &buffer, fd_, callback)) {
            break;
        }
    }

    LOG(VERBOSE) << "FuseAppLoop exit";
}

}  // namespace fuse
}  // namespace android
