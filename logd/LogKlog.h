/*
 * Copyright (C) 2014 The Android Open Source Project
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

#include <private/android_logger.h>
#include <sysutils/SocketListener.h>

#include "LogBuffer.h"
#include "LogStatistics.h"

class LogKlog : public SocketListener {
    LogBuffer* logbuf;
    const log_time signature;
    // Set once thread is started, separates KLOG_ACTION_READ_ALL
    // and KLOG_ACTION_READ phases.
    bool initialized;
    // Used during each of the above phases to control logging.
    bool enableLogging;
    // set if we are also running auditd, to filter out audit reports from
    // our copy of the kernel log
    bool auditd;

    static log_time correction;

  public:
    LogKlog(LogBuffer* buf, int fdWrite, int fdRead, bool auditd, LogStatistics* stats);
    int log(const char* buf, ssize_t len);

    static void convertMonotonicToReal(log_time& real) { real += correction; }

  protected:
    log_time sniffTime(const char*& buf, ssize_t len, bool reverse);
    pid_t sniffPid(const char*& buf, ssize_t len);
    void calculateCorrection(const log_time& monotonic, const char* real_string, ssize_t len);
    virtual bool onDataAvailable(SocketClient* cli);

  private:
    LogStatistics* stats_;
};
