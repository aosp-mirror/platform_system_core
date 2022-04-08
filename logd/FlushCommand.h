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
    log_mask_t mLogMask;

   public:
    explicit FlushCommand(LogReader& reader, log_mask_t logMask)
        : mReader(reader), mLogMask(logMask) {
    }

    virtual void runSocketCommand(SocketClient* client);

    static bool hasReadLogs(SocketClient* client);
    static bool hasSecurityLogs(SocketClient* client);
};

#endif
