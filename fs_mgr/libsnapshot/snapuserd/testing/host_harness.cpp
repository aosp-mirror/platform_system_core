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

#include "host_harness.h"

#include "snapuserd_logging.h"

namespace android {
namespace snapshot {

void TestBlockServerQueue::WaitForShutdown() {
    std::unique_lock lock(m_);
    if (shutdown_) {
        return;
    }
    cv_.wait(lock, [this]() -> bool { return shutdown_; });
}

void TestBlockServerQueue::Shutdown() {
    std::unique_lock lock(m_);
    shutdown_ = true;
    cv_.notify_all();
}

TestBlockServer::TestBlockServer(std::shared_ptr<TestBlockServerQueue> queue,
                                 const std::string& misc_name)
    : queue_(queue), misc_name_(misc_name) {}

bool TestBlockServer::ProcessRequests() {
    queue_->WaitForShutdown();
    return false;
}

void* TestBlockServer::GetResponseBuffer(size_t size, size_t to_write) {
    std::string buffer(size, '\0');
    buffered_.emplace_back(std::move(buffer), to_write);
    return buffered_.back().first.data();
}

bool TestBlockServer::SendBufferedIo() {
    for (const auto& [data, to_write] : buffered_) {
        sent_io_ += data.substr(0, to_write);
    }
    buffered_.clear();
    return true;
}

TestBlockServerOpener::TestBlockServerOpener(std::shared_ptr<TestBlockServerQueue> queue,
                                             const std::string& misc_name)
    : queue_(queue), misc_name_(misc_name) {}

std::unique_ptr<IBlockServer> TestBlockServerOpener::Open(IBlockServer::Delegate*, size_t) {
    return std::make_unique<TestBlockServer>(queue_, misc_name_);
}

std::shared_ptr<TestBlockServerOpener> TestBlockServerFactory::CreateTestOpener(
        const std::string& misc_name) {
    if (queues_.count(misc_name)) {
        LOG(ERROR) << "Cannot create opener for " << misc_name << ", already exists";
        return nullptr;
    }
    auto queue = std::make_shared<TestBlockServerQueue>();
    queues_.emplace(misc_name, queue);
    return std::make_shared<TestBlockServerOpener>(queue, misc_name);
}

std::shared_ptr<IBlockServerOpener> TestBlockServerFactory::CreateOpener(
        const std::string& misc_name) {
    return CreateTestOpener(misc_name);
}

bool TestBlockServerFactory::DeleteQueue(const std::string& misc_name) {
    auto iter = queues_.find(misc_name);
    if (iter == queues_.end()) {
        LOG(ERROR) << "Cannot delete queue " << misc_name << ", not found";
        return false;
    }
    iter->second->Shutdown();
    queues_.erase(iter);
    return true;
}

HostUserDevice::HostUserDevice(TestBlockServerFactory* factory, const std::string& misc_name)
    : factory_(factory), misc_name_(misc_name) {}

bool HostUserDevice::Destroy() {
    return factory_->DeleteQueue(misc_name_);
}

std::unique_ptr<IUserDevice> HostTestHarness::CreateUserDevice(const std::string&,
                                                               const std::string& misc_name,
                                                               uint64_t) {
    return std::make_unique<HostUserDevice>(&factory_, misc_name);
}

IBlockServerFactory* HostTestHarness::GetBlockServerFactory() {
    return &factory_;
}

}  // namespace snapshot
}  // namespace android
