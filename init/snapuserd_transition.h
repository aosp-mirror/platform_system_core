/*
 * Copyright (C) 2020 The Android Open Source Project
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
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <sys/types.h>

#include <optional>
#include <string>
#include <vector>

#include <libsnapshot/snapshot.h>

#include "block_dev_initializer.h"

namespace android {
namespace init {

// Fork and exec a new copy of snapuserd.
void LaunchFirstStageSnapuserd();

class SnapuserdSelinuxHelper final {
    using SnapshotManager = android::snapshot::SnapshotManager;

  public:
    SnapuserdSelinuxHelper(std::unique_ptr<SnapshotManager>&& sm, pid_t old_pid);

    void StartTransition();
    void FinishTransition();

    // Return a helper for facilitating the selinux transition of snapuserd.
    // If snapuserd is not in use, null is returned. StartTransition() should
    // be called after reading policy. FinishTransition() should be called
    // after loading policy. In between, no reads of /system or other dynamic
    // partitions are possible.
    static std::unique_ptr<SnapuserdSelinuxHelper> CreateIfNeeded();

  private:
    void RelaunchFirstStageSnapuserd();
    void ExecSnapuserd();
    bool TestSnapuserdIsReady();

    std::unique_ptr<SnapshotManager> sm_;
    BlockDevInitializer block_dev_init_;
    pid_t old_pid_;
    std::vector<std::string> argv_;
};

// Remove /dev/socket/snapuserd. This ensures that (1) the existing snapuserd
// will receive no new requests, and (2) the next copy we transition to can
// own the socket.
void CleanupSnapuserdSocket();

// Kill an instance of snapuserd given a pid.
void KillFirstStageSnapuserd(pid_t pid);

// Save an open fd to /system/bin (in the ramdisk) into an environment. This is
// used to later execveat() snapuserd.
void SaveRamdiskPathToSnapuserd();

// Returns true if first-stage snapuserd is running.
bool IsFirstStageSnapuserdRunning();

// Return the pid of the first-stage instances of snapuserd, if it was started.
std::optional<pid_t> GetSnapuserdFirstStagePid();

// Save an open fd to /system/bin (in the ramdisk) into an environment. This is
// used to later execveat() snapuserd.
void SaveRamdiskPathToSnapuserd();

// Returns true if first-stage snapuserd is running.
bool IsFirstStageSnapuserdRunning();

}  // namespace init
}  // namespace android
