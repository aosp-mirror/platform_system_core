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

#ifndef _LOGD_LOG_BUFFER_INTERFACE_H__
#define _LOGD_LOG_BUFFER_INTERFACE_H__

#include <sys/types.h>

#include <android-base/macros.h>
#include <log/log_id.h>
#include <log/log_time.h>

// Abstract interface that handles log when log available.
class LogBufferInterface {
   public:
    LogBufferInterface();
    virtual ~LogBufferInterface();
    // Handles a log entry when available in LogListener.
    // Returns the size of the handled log message.
    virtual int log(log_id_t log_id, log_time realtime, uid_t uid, pid_t pid,
                    pid_t tid, const char* msg, unsigned short len) = 0;

    virtual uid_t pidToUid(pid_t pid);
    virtual pid_t tidToPid(pid_t tid);

   private:
    DISALLOW_COPY_AND_ASSIGN(LogBufferInterface);
};

#endif  // _LOGD_LOG_BUFFER_INTERFACE_H__
