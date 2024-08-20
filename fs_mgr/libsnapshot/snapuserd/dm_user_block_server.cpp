// Copyright (C) 2023 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <snapuserd/dm_user_block_server.h>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <snapuserd/snapuserd_kernel.h>
#include "snapuserd_logging.h"

namespace android {
namespace snapshot {

using android::base::unique_fd;

DmUserBlockServer::DmUserBlockServer(const std::string& misc_name, unique_fd&& ctrl_fd,
                                     Delegate* delegate, size_t buffer_size)
    : misc_name_(misc_name), ctrl_fd_(std::move(ctrl_fd)), delegate_(delegate) {
    buffer_.Initialize(sizeof(struct dm_user_header), buffer_size);
}

bool DmUserBlockServer::ProcessRequests() {
    struct dm_user_header* header =
            reinterpret_cast<struct dm_user_header*>(buffer_.GetHeaderPtr());
    if (!android::base::ReadFully(ctrl_fd_, header, sizeof(*header))) {
        if (errno != ENOTBLK) {
            SNAP_PLOG(ERROR) << "Control-read failed";
        }

        SNAP_PLOG(DEBUG) << "ReadDmUserHeader failed....";
        return false;
    }

    SNAP_LOG(DEBUG) << "Daemon: msg->seq: " << std::dec << header->seq;
    SNAP_LOG(DEBUG) << "Daemon: msg->len: " << std::dec << header->len;
    SNAP_LOG(DEBUG) << "Daemon: msg->sector: " << std::dec << header->sector;
    SNAP_LOG(DEBUG) << "Daemon: msg->type: " << std::dec << header->type;
    SNAP_LOG(DEBUG) << "Daemon: msg->flags: " << std::dec << header->flags;

    if (!ProcessRequest(header)) {
        if (header->type != DM_USER_RESP_ERROR) {
            SendError();
        }
        return false;
    }
    return true;
}

bool DmUserBlockServer::ProcessRequest(dm_user_header* header) {
    // Use the same header buffer as the response header.
    int request_type = header->type;
    header->type = DM_USER_RESP_SUCCESS;
    header_response_ = true;

    // Reset the output buffer.
    buffer_.ResetBufferOffset();

    switch (request_type) {
        case DM_USER_REQ_MAP_READ:
            return delegate_->RequestSectors(header->sector, header->len);

        case DM_USER_REQ_MAP_WRITE:
            // We should not get any write request to dm-user as we mount all
            // partitions as read-only.
            SNAP_LOG(ERROR) << "Unexpected write request from dm-user";
            return false;

        default:
            SNAP_LOG(ERROR) << "Unexpected request from dm-user: " << request_type;
            return false;
    }
}

void* DmUserBlockServer::GetResponseBuffer(size_t size, size_t to_write) {
    return buffer_.AcquireBuffer(size, to_write);
}

bool DmUserBlockServer::SendBufferedIo() {
    return WriteDmUserPayload(buffer_.GetPayloadBytesWritten());
}

void DmUserBlockServer::SendError() {
    struct dm_user_header* header =
            reinterpret_cast<struct dm_user_header*>(buffer_.GetHeaderPtr());
    header->type = DM_USER_RESP_ERROR;
    // This is an issue with the dm-user interface. There
    // is no way to propagate the I/O error back to dm-user
    // if we have already communicated the header back. Header
    // is responded once at the beginning; however I/O can
    // be processed in chunks. If we encounter an I/O error
    // somewhere in the middle of the processing, we can't communicate
    // this back to dm-user.
    //
    // TODO: Fix the interface
    CHECK(header_response_);

    WriteDmUserPayload(0);
}

bool DmUserBlockServer::WriteDmUserPayload(size_t size) {
    size_t payload_size = size;
    void* buf = buffer_.GetPayloadBufPtr();
    if (header_response_) {
        payload_size += sizeof(struct dm_user_header);
        buf = buffer_.GetBufPtr();
    }

    if (!android::base::WriteFully(ctrl_fd_, buf, payload_size)) {
        SNAP_PLOG(ERROR) << "Write to dm-user failed size: " << payload_size;
        return false;
    }

    // After the first header is sent in response to a request, we cannot
    // send any additional headers.
    header_response_ = false;

    // Reset the buffer for use by the next request.
    buffer_.ResetBufferOffset();
    return true;
}

DmUserBlockServerOpener::DmUserBlockServerOpener(const std::string& misc_name,
                                                 const std::string& dm_user_path)
    : misc_name_(misc_name), dm_user_path_(dm_user_path) {}

std::unique_ptr<IBlockServer> DmUserBlockServerOpener::Open(IBlockServer::Delegate* delegate,
                                                            size_t buffer_size) {
    unique_fd fd(open(dm_user_path_.c_str(), O_RDWR | O_CLOEXEC));
    if (fd < 0) {
        SNAP_PLOG(ERROR) << "Could not open dm-user path: " << dm_user_path_;
        return nullptr;
    }
    return std::make_unique<DmUserBlockServer>(misc_name_, std::move(fd), delegate, buffer_size);
}

std::shared_ptr<IBlockServerOpener> DmUserBlockServerFactory::CreateOpener(
        const std::string& misc_name) {
    auto dm_path = "/dev/dm-user/" + misc_name;
    return std::make_shared<DmUserBlockServerOpener>(misc_name, dm_path);
}

}  // namespace snapshot
}  // namespace android
