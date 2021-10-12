/*
 * Copyright (C) 2021 The Android Open Source Project
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

#include "checkpoint_handling.h"
#include "log.h"

#include <fstab/fstab.h>
#include <cstring>
#include <string>

namespace {

bool checkpointingDoneForever = false;

}  // namespace

int is_data_checkpoint_active(bool* active) {
    if (!active) {
        ALOGE("active out parameter is null");
        return 0;
    }

    *active = false;

    if (checkpointingDoneForever) {
        return 0;
    }

    android::fs_mgr::Fstab procMounts;
    bool success = android::fs_mgr::ReadFstabFromFile("/proc/mounts", &procMounts);
    if (!success) {
        ALOGE("Could not parse /proc/mounts\n");
        /* Really bad. Tell the caller to abort the write. */
        return -1;
    }

    android::fs_mgr::FstabEntry* dataEntry =
            android::fs_mgr::GetEntryForMountPoint(&procMounts, "/data");
    if (dataEntry == NULL) {
        ALOGE("/data is not mounted yet\n");
        return 0;
    }

    /* We can't handle e.g., ext4. Nothing we can do about it for now. */
    if (dataEntry->fs_type != "f2fs") {
        ALOGW("Checkpoint status not supported for filesystem %s\n", dataEntry->fs_type.c_str());
        checkpointingDoneForever = true;
        return 0;
    }

    /*
     * The data entry looks like "... blah,checkpoint=disable:0,blah ...".
     * checkpoint=disable means checkpointing is on (yes, arguably reversed).
     */
    size_t checkpointPos = dataEntry->fs_options.find("checkpoint=disable");
    if (checkpointPos == std::string::npos) {
        /* Assumption is that once checkpointing turns off, it stays off */
        checkpointingDoneForever = true;
    } else {
        *active = true;
    }

    return 0;
}
