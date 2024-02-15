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

#include "handler_manager.h"

#include <pthread.h>
#include <sys/eventfd.h>

#include <android-base/logging.h>

#include "merge_worker.h"
#include "read_worker.h"
#include "snapuserd_core.h"

namespace android {
namespace snapshot {

static constexpr uint8_t kMaxMergeThreads = 2;

HandlerThread::HandlerThread(std::shared_ptr<SnapshotHandler> snapuserd)
    : snapuserd_(snapuserd), misc_name_(snapuserd_->GetMiscName()) {}

void HandlerThread::FreeResources() {
    // Each worker thread holds a reference to snapuserd.
    // Clear them so that all the resources
    // held by snapuserd is released
    if (snapuserd_) {
        snapuserd_->FreeResources();
        snapuserd_ = nullptr;
    }
}

SnapshotHandlerManager::SnapshotHandlerManager() {
    monitor_merge_event_fd_.reset(eventfd(0, EFD_CLOEXEC));
    if (monitor_merge_event_fd_ == -1) {
        PLOG(FATAL) << "monitor_merge_event_fd_: failed to create eventfd";
    }
}

std::shared_ptr<HandlerThread> SnapshotHandlerManager::AddHandler(
        const std::string& misc_name, const std::string& cow_device_path,
        const std::string& backing_device, const std::string& base_path_merge,
        std::shared_ptr<IBlockServerOpener> opener, int num_worker_threads, bool use_iouring,
        bool o_direct) {
    auto snapuserd = std::make_shared<SnapshotHandler>(
            misc_name, cow_device_path, backing_device, base_path_merge, opener, num_worker_threads,
            use_iouring, perform_verification_, o_direct);
    if (!snapuserd->InitCowDevice()) {
        LOG(ERROR) << "Failed to initialize Snapuserd";
        return nullptr;
    }

    if (!snapuserd->InitializeWorkers()) {
        LOG(ERROR) << "Failed to initialize workers";
        return nullptr;
    }

    auto handler = std::make_shared<HandlerThread>(snapuserd);
    {
        std::lock_guard<std::mutex> lock(lock_);
        if (FindHandler(&lock, misc_name) != dm_users_.end()) {
            LOG(ERROR) << "Handler already exists: " << misc_name;
            return nullptr;
        }
        dm_users_.push_back(handler);
    }
    return handler;
}

bool SnapshotHandlerManager::StartHandler(const std::string& misc_name) {
    std::lock_guard<std::mutex> lock(lock_);
    auto iter = FindHandler(&lock, misc_name);
    if (iter == dm_users_.end()) {
        LOG(ERROR) << "Could not find handler: " << misc_name;
        return false;
    }
    if (!(*iter)->snapuserd() || (*iter)->snapuserd()->IsAttached()) {
        LOG(ERROR) << "Tried to re-attach control device: " << misc_name;
        return false;
    }
    if (!StartHandler(*iter)) {
        return false;
    }
    return true;
}

bool SnapshotHandlerManager::StartHandler(const std::shared_ptr<HandlerThread>& handler) {
    if (handler->snapuserd()->IsAttached()) {
        LOG(ERROR) << "Handler already attached";
        return false;
    }

    handler->snapuserd()->AttachControlDevice();

    handler->thread() = std::thread(std::bind(&SnapshotHandlerManager::RunThread, this, handler));
    return true;
}

bool SnapshotHandlerManager::DeleteHandler(const std::string& misc_name) {
    {
        std::lock_guard<std::mutex> lock(lock_);
        auto iter = FindHandler(&lock, misc_name);
        if (iter == dm_users_.end()) {
            // After merge is completed, we swap dm-user table with
            // the underlying dm-linear base device. Hence, worker
            // threads would have terminted and was removed from
            // the list.
            LOG(DEBUG) << "Could not find handler: " << misc_name;
            return true;
        }

        if (!(*iter)->ThreadTerminated()) {
            (*iter)->snapuserd()->NotifyIOTerminated();
        }
    }
    if (!RemoveAndJoinHandler(misc_name)) {
        return false;
    }
    return true;
}

void SnapshotHandlerManager::RunThread(std::shared_ptr<HandlerThread> handler) {
    LOG(INFO) << "Entering thread for handler: " << handler->misc_name();

    pthread_setname_np(pthread_self(), "Handler");

    if (!handler->snapuserd()->Start()) {
        LOG(ERROR) << " Failed to launch all worker threads";
    }

    handler->snapuserd()->CloseFds();
    bool merge_completed = handler->snapuserd()->CheckMergeCompletionStatus();
    handler->snapuserd()->UnmapBufferRegion();

    auto misc_name = handler->misc_name();
    LOG(INFO) << "Handler thread about to exit: " << misc_name;

    {
        std::lock_guard<std::mutex> lock(lock_);
        if (merge_completed) {
            num_partitions_merge_complete_ += 1;
            active_merge_threads_ -= 1;
            WakeupMonitorMergeThread();
        }
        handler->SetThreadTerminated();
        auto iter = FindHandler(&lock, handler->misc_name());
        if (iter == dm_users_.end()) {
            // RemoveAndJoinHandler() already removed us from the list, and is
            // now waiting on a join(), so just return. Additionally, release
            // all the resources held by snapuserd object which are shared
            // by worker threads. This should be done when the last reference
            // of "handler" is released; but we will explicitly release here
            // to make sure snapuserd object is freed as it is the biggest
            // consumer of memory in the daemon.
            handler->FreeResources();
            LOG(INFO) << "Exiting handler thread to allow for join: " << misc_name;
            return;
        }

        LOG(INFO) << "Exiting handler thread and freeing resources: " << misc_name;

        if (handler->snapuserd()->IsAttached()) {
            handler->thread().detach();
        }

        // Important: free resources within the lock. This ensures that if
        // WaitForDelete() is called, the handler is either in the list, or
        // it's not and its resources are guaranteed to be freed.
        handler->FreeResources();
        dm_users_.erase(iter);
    }
}

bool SnapshotHandlerManager::InitiateMerge(const std::string& misc_name) {
    std::lock_guard<std::mutex> lock(lock_);
    auto iter = FindHandler(&lock, misc_name);
    if (iter == dm_users_.end()) {
        LOG(ERROR) << "Could not find handler: " << misc_name;
        return false;
    }

    return StartMerge(&lock, *iter);
}

bool SnapshotHandlerManager::StartMerge(std::lock_guard<std::mutex>* proof_of_lock,
                                        const std::shared_ptr<HandlerThread>& handler) {
    CHECK(proof_of_lock);

    if (!handler->snapuserd()->IsAttached()) {
        LOG(ERROR) << "Handler not attached to dm-user - Merge thread cannot be started";
        return false;
    }

    handler->snapuserd()->MonitorMerge();

    if (!merge_monitor_.joinable()) {
        merge_monitor_ = std::thread(&SnapshotHandlerManager::MonitorMerge, this);
    }

    merge_handlers_.push(handler);
    WakeupMonitorMergeThread();
    return true;
}

void SnapshotHandlerManager::WakeupMonitorMergeThread() {
    uint64_t notify = 1;
    ssize_t rc = TEMP_FAILURE_RETRY(write(monitor_merge_event_fd_.get(), &notify, sizeof(notify)));
    if (rc < 0) {
        PLOG(FATAL) << "failed to notify monitor merge thread";
    }
}

void SnapshotHandlerManager::MonitorMerge() {
    pthread_setname_np(pthread_self(), "Merge Monitor");
    while (!stop_monitor_merge_thread_) {
        uint64_t testVal;
        ssize_t ret =
                TEMP_FAILURE_RETRY(read(monitor_merge_event_fd_.get(), &testVal, sizeof(testVal)));
        if (ret == -1) {
            PLOG(FATAL) << "Failed to read from eventfd";
        } else if (ret == 0) {
            LOG(FATAL) << "Hit EOF on eventfd";
        }

        LOG(INFO) << "MonitorMerge: active-merge-threads: " << active_merge_threads_;
        {
            std::lock_guard<std::mutex> lock(lock_);
            while (active_merge_threads_ < kMaxMergeThreads && merge_handlers_.size() > 0) {
                auto handler = merge_handlers_.front();
                merge_handlers_.pop();

                if (!handler->snapuserd()) {
                    LOG(INFO) << "MonitorMerge: skipping deleted handler: " << handler->misc_name();
                    continue;
                }

                LOG(INFO) << "Starting merge for partition: "
                          << handler->snapuserd()->GetMiscName();
                handler->snapuserd()->InitiateMerge();
                active_merge_threads_ += 1;
            }
        }
    }

    LOG(INFO) << "Exiting MonitorMerge: size: " << merge_handlers_.size();
}

std::string SnapshotHandlerManager::GetMergeStatus(const std::string& misc_name) {
    std::lock_guard<std::mutex> lock(lock_);
    auto iter = FindHandler(&lock, misc_name);
    if (iter == dm_users_.end()) {
        LOG(ERROR) << "Could not find handler: " << misc_name;
        return {};
    }

    return (*iter)->snapuserd()->GetMergeStatus();
}

double SnapshotHandlerManager::GetMergePercentage() {
    std::lock_guard<std::mutex> lock(lock_);

    double percentage = 0.0;
    int n = 0;

    for (auto iter = dm_users_.begin(); iter != dm_users_.end(); iter++) {
        auto& th = (*iter)->thread();
        if (th.joinable()) {
            // Merge percentage by individual partitions wherein merge is still
            // in-progress
            percentage += (*iter)->snapuserd()->GetMergePercentage();
            n += 1;
        }
    }

    // Calculate final merge including those partitions where merge was already
    // completed - num_partitions_merge_complete_ will track them when each
    // thread exists in RunThread.
    int total_partitions = n + num_partitions_merge_complete_;

    if (total_partitions) {
        percentage = ((num_partitions_merge_complete_ * 100.0) + percentage) / total_partitions;
    }

    LOG(DEBUG) << "Merge %: " << percentage
               << " num_partitions_merge_complete_: " << num_partitions_merge_complete_
               << " total_partitions: " << total_partitions << " n: " << n;
    return percentage;
}

bool SnapshotHandlerManager::GetVerificationStatus() {
    std::lock_guard<std::mutex> lock(lock_);

    bool status = true;
    for (auto iter = dm_users_.begin(); iter != dm_users_.end(); iter++) {
        auto& th = (*iter)->thread();
        if (th.joinable() && status) {
            status = (*iter)->snapuserd()->CheckPartitionVerification() && status;
        } else {
            // return immediately if there is a failure
            return false;
        }
    }

    return status;
}

bool SnapshotHandlerManager::RemoveAndJoinHandler(const std::string& misc_name) {
    std::shared_ptr<HandlerThread> handler;
    {
        std::lock_guard<std::mutex> lock(lock_);

        auto iter = FindHandler(&lock, misc_name);
        if (iter == dm_users_.end()) {
            // Client already deleted.
            return true;
        }
        handler = std::move(*iter);
        dm_users_.erase(iter);
    }

    auto& th = handler->thread();
    if (th.joinable()) {
        th.join();
    }
    return true;
}

void SnapshotHandlerManager::TerminateMergeThreads() {
    std::lock_guard<std::mutex> guard(lock_);

    for (auto iter = dm_users_.begin(); iter != dm_users_.end(); iter++) {
        if (!(*iter)->ThreadTerminated()) {
            (*iter)->snapuserd()->NotifyIOTerminated();
        }
    }
}

void SnapshotHandlerManager::JoinAllThreads() {
    // Acquire the thread list within the lock.
    std::vector<std::shared_ptr<HandlerThread>> dm_users;
    {
        std::lock_guard<std::mutex> guard(lock_);
        dm_users = std::move(dm_users_);
    }

    for (auto& client : dm_users) {
        auto& th = client->thread();

        if (th.joinable()) th.join();
    }

    if (merge_monitor_.joinable()) {
        stop_monitor_merge_thread_ = true;
        WakeupMonitorMergeThread();

        merge_monitor_.join();
    }
}

auto SnapshotHandlerManager::FindHandler(std::lock_guard<std::mutex>* proof_of_lock,
                                         const std::string& misc_name) -> HandlerList::iterator {
    CHECK(proof_of_lock);

    for (auto iter = dm_users_.begin(); iter != dm_users_.end(); iter++) {
        if ((*iter)->misc_name() == misc_name) {
            return iter;
        }
    }
    return dm_users_.end();
}

}  // namespace snapshot
}  // namespace android
