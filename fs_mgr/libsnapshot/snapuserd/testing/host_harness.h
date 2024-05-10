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

#include <condition_variable>
#include <mutex>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "harness.h"

namespace android {
namespace snapshot {

class TestBlockServerQueue final {
  public:
    void WaitForShutdown();
    void Shutdown();

  private:
    std::mutex m_;
    std::condition_variable cv_;
    bool shutdown_ = false;
};

class TestBlockServer final : public IBlockServer {
  public:
    TestBlockServer(std::shared_ptr<TestBlockServerQueue> queue, const std::string& misc_name);
    bool ProcessRequests() override;
    void* GetResponseBuffer(size_t size, size_t to_write) override;
    bool SendBufferedIo() override;

    std::string&& sent_io() { return std::move(sent_io_); }

  private:
    std::shared_ptr<TestBlockServerQueue> queue_;
    std::string misc_name_;
    std::string sent_io_;
    std::vector<std::pair<std::string, size_t>> buffered_;
};

class TestBlockServerOpener final : public IBlockServerOpener {
  public:
    TestBlockServerOpener(std::shared_ptr<TestBlockServerQueue> queue,
                          const std::string& misc_name);
    std::unique_ptr<IBlockServer> Open(IBlockServer::Delegate* delegate,
                                       size_t buffer_size) override;

  private:
    std::shared_ptr<TestBlockServerQueue> queue_;
    std::string misc_name_;
};

class TestBlockServerFactory final : public IBlockServerFactory {
  public:
    std::shared_ptr<IBlockServerOpener> CreateOpener(const std::string& misc_name) override;
    std::shared_ptr<TestBlockServerOpener> CreateTestOpener(const std::string& misc_name);
    bool DeleteQueue(const std::string& misc_name);

  private:
    std::unordered_map<std::string, std::shared_ptr<TestBlockServerQueue>> queues_;
};

class TestBlockServerFactory;

class HostUserDevice final : public IUserDevice {
  public:
    HostUserDevice(TestBlockServerFactory* factory, const std::string& misc_name);
    const std::string& GetPath() override { return empty_path_; }
    bool Destroy();

  private:
    TestBlockServerFactory* factory_;
    std::string misc_name_;
    std::string empty_path_;
};

class HostTestHarness final : public ITestHarness {
  public:
    std::unique_ptr<IUserDevice> CreateUserDevice(const std::string& dev_name,
                                                  const std::string& misc_name,
                                                  uint64_t num_sectors) override;
    IBlockServerFactory* GetBlockServerFactory() override;
    bool HasUserDevice() override { return false; }

  private:
    TestBlockServerFactory factory_;
};

}  // namespace snapshot
}  // namespace android
