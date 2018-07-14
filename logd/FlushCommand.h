/*
 * Copyright (C) 2012-2013 The Android Open Source Project
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
#ifndef _FLUSH_COMMAND_H
#define _FLUSH_COMMAND_H

#include <private/android_logger.h>
#include <sysutils/SocketClientCommand.h>

class LogBufferElement;

#include "LogTimes.h"

class LogReader;

class FlushCommand : public SocketClientCommand {
    LogReader& mReader;
    bool mNonBlock;
    unsigned long mTail;
    log_mask_t mLogMask;
    pid_t mPid;
    log_time mStart;
    uint64_t mTimeout;

   public:
    // for opening a reader
    explicit FlushCommand(LogReader& reader, bool nonBlock, unsigned long tail,
                          log_mask_t logMask, pid_t pid, log_time start,
                          uint64_t timeout)
        : mReader(reader),
          mNonBlock(nonBlock),
          mTail(tail),
          mLogMask(logMask),
          mPid(pid),
          mStart(start),
          mTimeout((start != log_time::EPOCH) ? timeout : 0) {
    }

    // for notification of an update
    explicit FlushCommand(LogReader& reader, log_mask_t logMask)
        : mReader(reader),
          mNonBlock(false),
          mTail(-1),
          mLogMask(logMask),
          mPid(0),
          mStart(log_time::EPOCH),
          mTimeout(0) {
    }

    virtual void runSocketCommand(SocketClient* client);

    static bool hasReadLogs(SocketClient* client);
    static bool hasSecurityLogs(SocketClient* client);
};

#endif
