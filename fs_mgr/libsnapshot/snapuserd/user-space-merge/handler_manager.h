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

#include <memory>
#include <queue>
#include <string>
#include <thread>
#include <vector>

#include <android-base/unique_fd.h>
#include <snapuserd/block_server.h>

namespace android {
namespace snapshot {

class SnapshotHandler;

class HandlerThread {
  public:
    explicit HandlerThread(std::shared_ptr<SnapshotHandler> snapuserd);

    void FreeResources();
    const std::shared_ptr<SnapshotHandler>& snapuserd() const { return snapuserd_; }
    std::thread& thread() { return thread_; }

    const std::string& misc_name() const { return misc_name_; }
    bool ThreadTerminated() { return thread_terminated_; }
    void SetThreadTerminated() { thread_terminated_ = true; }

  private:
    std::thread thread_;
    std::shared_ptr<SnapshotHandler> snapuserd_;
    std::string misc_name_;
    bool thread_terminated_ = false;
};

class ISnapshotHandlerManager {
  public:
    virtual ~ISnapshotHandlerManager() {}

    // Add a new snapshot handler but do not start serving requests yet.
    virtual std::shared_ptr<HandlerThread> AddHandler(
            const std::string& misc_name, const std::string& cow_device_path,
            const std::string& backing_device, const std::string& base_path_merge,
            std::shared_ptr<IBlockServerOpener> opener, int num_worker_threads, bool use_iouring,
            bool o_direct, uint32_t cow_op_merge_size) = 0;

    // Start serving requests on a snapshot handler.
    virtual bool StartHandler(const std::string& misc_name) = 0;

    // Stop serving requests on a snapshot handler and remove it.
    virtual bool DeleteHandler(const std::string& misc_name) = 0;

    // Begin merging blocks on the given snapshot handler.
    virtual bool InitiateMerge(const std::string& misc_name) = 0;

    // Return a string containing a status code indicating the merge status
    // on the handler. Returns empty on error.
    virtual std::string GetMergeStatus(const std::string& misc_name) = 0;

    // Wait until all handlers have terminated.
    virtual void JoinAllThreads() = 0;

    // Stop any in-progress merge threads.
    virtual void TerminateMergeThreads() = 0;

    // Returns the merge progress across all merging snapshot handlers.
    virtual double GetMergePercentage() = 0;

    // Returns whether all snapshots have verified.
    virtual bool GetVerificationStatus() = 0;

    // Disable partition verification
    virtual void DisableVerification() = 0;
};

class SnapshotHandlerManager final : public ISnapshotHandlerManager {
  public:
    SnapshotHandlerManager();
    std::shared_ptr<HandlerThread> AddHandler(const std::string& misc_name,
                                              const std::string& cow_device_path,
                                              const std::string& backing_device,
                                              const std::string& base_path_merge,
                                              std::shared_ptr<IBlockServerOpener> opener,
                                              int num_worker_threads, bool use_iouring,
                                              bool o_direct, uint32_t cow_op_merge_size) override;
    bool StartHandler(const std::string& misc_name) override;
    bool DeleteHandler(const std::string& misc_name) override;
    bool InitiateMerge(const std::string& misc_name) override;
    std::string GetMergeStatus(const std::string& misc_name) override;
    void JoinAllThreads() override;
    void TerminateMergeThreads() override;
    double GetMergePercentage() override;
    bool GetVerificationStatus() override;
    void DisableVerification() override { perform_verification_ = false; }

  private:
    bool StartHandler(const std::shared_ptr<HandlerThread>& handler);
    void RunThread(std::shared_ptr<HandlerThread> handler);
    bool StartMerge(std::lock_guard<std::mutex>* proof_of_lock,
                    const std::shared_ptr<HandlerThread>& handler);
    void MonitorMerge();
    void WakeupMonitorMergeThread();
    bool RemoveAndJoinHandler(const std::string& misc_name);

    // Find a HandlerThread within a lock.
    using HandlerList = std::vector<std::shared_ptr<HandlerThread>>;
    HandlerList::iterator FindHandler(std::lock_guard<std::mutex>* proof_of_lock,
                                      const std::string& misc_name);

    std::mutex lock_;
    HandlerList dm_users_;

    bool stop_monitor_merge_thread_ = false;
    int active_merge_threads_ = 0;
    std::thread merge_monitor_;
    int num_partitions_merge_complete_ = 0;
    std::queue<std::shared_ptr<HandlerThread>> merge_handlers_;
    android::base::unique_fd monitor_merge_event_fd_;
    bool perform_verification_ = true;
};

}  // namespace snapshot
}  // namespace android
