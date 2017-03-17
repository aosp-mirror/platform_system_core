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

FlushCommand::FlushCommand(LogReader& reader, bool nonBlock, unsigned long tail,
                           unsigned int logMask, pid_t pid, log_time start,
                           uint64_t timeout)
    : mReader(reader),
      mNonBlock(nonBlock),
      mTail(tail),
      mLogMask(logMask),
      mPid(pid),
      mStart(start),
      mTimeout((start != log_time::EPOCH) ? timeout : 0) {
}

// runSocketCommand is called once for every open client on the
// log reader socket. Here we manage and associated the reader
// client tracking and log region locks LastLogTimes list of
// LogTimeEntrys, and spawn a transitory per-client thread to
// work at filing data to the  socket.
//
// global LogTimeEntry::lock() is used to protect access,
// reference counts are used to ensure that individual
// LogTimeEntry lifetime is managed when not protected.
void FlushCommand::runSocketCommand(SocketClient* client) {
    LogTimeEntry* entry = NULL;
    LastLogTimes& times = mReader.logbuf().mTimes;

    LogTimeEntry::lock();
    LastLogTimes::iterator it = times.begin();
    while (it != times.end()) {
        entry = (*it);
        if (entry->mClient == client) {
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
            if (entry->runningReader_Locked()) {
                LogTimeEntry::unlock();
                return;
            }
            entry->incRef_Locked();
            break;
        }
        it++;
    }

    if (it == times.end()) {
        // Create LogTimeEntry in notifyNewLog() ?
        if (mTail == (unsigned long)-1) {
            LogTimeEntry::unlock();
            return;
        }
        entry = new LogTimeEntry(mReader, client, mNonBlock, mTail, mLogMask,
                                 mPid, mStart, mTimeout);
        times.push_front(entry);
    }

    client->incRef();

    // release client and entry reference counts once done
    entry->startReader_Locked();
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
