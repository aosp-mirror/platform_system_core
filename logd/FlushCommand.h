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

#include <android/log.h>
#include <sysutils/SocketClientCommand.h>

class LogBufferElement;

#include "LogTimes.h"

class LogReader;

class FlushCommand : public SocketClientCommand {
    LogReader& mReader;
    bool mNonBlock;
    unsigned long mTail;
    unsigned int mLogMask;
    pid_t mPid;
    uint64_t mStart;
    uint64_t mTimeout;

   public:
    explicit FlushCommand(LogReader& mReader, bool nonBlock = false,
                          unsigned long tail = -1, unsigned int logMask = -1,
                          pid_t pid = 0, uint64_t start = 1,
                          uint64_t timeout = 0);
    virtual void runSocketCommand(SocketClient* client);

    static bool hasReadLogs(SocketClient* client);
    static bool hasSecurityLogs(SocketClient* client);
};

#endif
