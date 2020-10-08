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

#include "LogReaderList.h"

// When we are notified a new log entry is available, inform
// listening sockets who are watching this entry's log id.
void LogReaderList::NotifyNewLog(LogMask log_mask) const {
    for (const auto& entry : reader_threads_) {
        if (!entry->IsWatchingMultiple(log_mask)) {
            continue;
        }
        if (entry->deadline().time_since_epoch().count() != 0) {
            continue;
        }
        entry->TriggerReader();
    }
}
