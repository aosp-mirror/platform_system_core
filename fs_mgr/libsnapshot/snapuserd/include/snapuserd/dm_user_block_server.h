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

#pragma once

#include <android-base/unique_fd.h>

#include <string>

#include <snapuserd/block_server.h>
#include <snapuserd/snapuserd_buffer.h>

namespace android {
namespace snapshot {

class DmUserBlockServer : public IBlockServer {
  public:
    DmUserBlockServer(const std::string& misc_name, android::base::unique_fd&& ctrl_fd,
                      Delegate* delegate, size_t buffer_size);

    bool ProcessRequests() override;
    void* GetResponseBuffer(size_t size, size_t to_write) override;
    bool SendBufferedIo() override;
    void SendError();

  private:
    bool ProcessRequest(dm_user_header* header);
    bool WriteDmUserPayload(size_t size);

    std::string misc_name_;
    android::base::unique_fd ctrl_fd_;
    Delegate* delegate_;

    // Per-request state.
    BufferSink buffer_;
    bool header_response_ = false;
};

class DmUserBlockServerOpener : public IBlockServerOpener {
  public:
    DmUserBlockServerOpener(const std::string& misc_name, const std::string& dm_user_path);

    std::unique_ptr<IBlockServer> Open(IBlockServer::Delegate* delegate,
                                       size_t buffer_size) override;

  private:
    std::string misc_name_;
    std::string dm_user_path_;
};

class DmUserBlockServerFactory : public IBlockServerFactory {
  public:
    std::shared_ptr<IBlockServerOpener> CreateOpener(const std::string& misc_name) override;
};

}  // namespace snapshot
}  // namespace android
