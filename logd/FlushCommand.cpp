/*
 * Copyright (C) 2012-2014 The Android Open Source Project
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

#include <stdlib.h>

#include <private/android_filesystem_config.h>

#include "FlushCommand.h"
#include "LogBuffer.h"
#include "LogBufferElement.h"
#include "LogCommand.h"
#include "LogReader.h"
#include "LogTimes.h"
#include "LogUtils.h"

// runSocketCommand is called once for every open client on the
// log reader socket. Here we manage and associated the reader
// client tracking and log region locks LastLogTimes list of
// LogTimeEntrys, and spawn a transitory per-client thread to
// work at filing data to the  socket.
//
// global LogTimeEntry::wrlock() is used to protect access,
// reference counts are used to ensure that individual
// LogTimeEntry lifetime is managed when not protected.
void FlushCommand::runSocketCommand(SocketClient* client) {
    LogTimeEntry* entry = nullptr;
    LastLogTimes& times = mReader.logbuf().mTimes;

    LogTimeEntry::wrlock();
    LastLogTimes::iterator it = times.begin();
    while (it != times.end()) {
        entry = it->get();
        if (entry->mClient == client) {
            if (!entry->isWatchingMultiple(mLogMask)) {
                LogTimeEntry::unlock();
                return;
            }
            if (entry->mTimeout.tv_sec || entry->mTimeout.tv_nsec) {
                if (mReader.logbuf().isMonotonic()) {
                    LogTimeEntry::unlock();
                    return;
                }
                // If the user changes the time in a gross manner that
                // invalidates the timeout, fall through and trigger.
                log_time now(CLOCK_REALTIME);
                if (((entry->mEnd + entry->mTimeout) > now) &&
                    (now > entry->mEnd)) {
                    LogTimeEntry::unlock();
                    return;
                }
            }
            entry->triggerReader_Locked();
            LogTimeEntry::unlock();
            return;
        }
        it++;
    }

    LogTimeEntry::unlock();
}

bool FlushCommand::hasReadLogs(SocketClient* client) {
    return clientHasLogCredentials(client);
}

static bool clientHasSecurityCredentials(SocketClient* client) {
    return (client->getUid() == AID_SYSTEM) || (client->getGid() == AID_SYSTEM);
}

bool FlushCommand::hasSecurityLogs(SocketClient* client) {
    return clientHasSecurityCredentials(client);
}
