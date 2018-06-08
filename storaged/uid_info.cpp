/*
 * Copyright (C) 2017 The Android Open Source Project
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

#include <binder/Parcel.h>

#include "uid_info.h"

using namespace android;
using namespace android::os::storaged;

status_t UidInfo::writeToParcel(Parcel* parcel) const {
    parcel->writeInt32(uid);
    parcel->writeCString(name.c_str());
    parcel->write(&io, sizeof(io));

    parcel->writeInt32(tasks.size());
    for (const auto& task_it : tasks) {
        parcel->writeInt32(task_it.first);
        parcel->writeCString(task_it.second.comm.c_str());
        parcel->write(&task_it.second.io, sizeof(task_it.second.io));
    }
    return NO_ERROR;
}

status_t UidInfo::readFromParcel(const Parcel* parcel) {
    uid = parcel->readInt32();
    name = parcel->readCString();
    parcel->read(&io, sizeof(io));

    uint32_t tasks_size = parcel->readInt32();
    for (uint32_t i = 0; i < tasks_size; i++) {
        task_info task;
        task.pid = parcel->readInt32();
        task.comm = parcel->readCString();
        parcel->read(&task.io, sizeof(task.io));
        tasks[task.pid] = task;
    }
    return NO_ERROR;
}
