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

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <log/logger.h>

#include "LogBufferElement.h"
#include "LogReader.h"

const log_time LogBufferElement::FLUSH_ERROR((uint32_t)0, (uint32_t)0);

LogBufferElement::LogBufferElement(log_id_t log_id, log_time realtime,
                                   uid_t uid, pid_t pid, pid_t tid,
                                   const char *msg, unsigned short len)
        : mLogId(log_id)
        , mUid(uid)
        , mPid(pid)
        , mTid(tid)
        , mMsgLen(len)
        , mMonotonicTime(CLOCK_MONOTONIC)
        , mRealTime(realtime) {
    mMsg = new char[len];
    memcpy(mMsg, msg, len);
}

LogBufferElement::~LogBufferElement() {
    delete [] mMsg;
}

log_time LogBufferElement::flushTo(SocketClient *reader) {
    struct logger_entry_v3 entry;
    memset(&entry, 0, sizeof(struct logger_entry_v3));
    entry.hdr_size = sizeof(struct logger_entry_v3);
    entry.len = mMsgLen;
    entry.lid = mLogId;
    entry.pid = mPid;
    entry.tid = mTid;
    entry.sec = mRealTime.tv_sec;
    entry.nsec = mRealTime.tv_nsec;

    struct iovec iovec[2];
    iovec[0].iov_base = &entry;
    iovec[0].iov_len = sizeof(struct logger_entry_v3);
    iovec[1].iov_base = mMsg;
    iovec[1].iov_len = mMsgLen;
    if (reader->sendDatav(iovec, 2)) {
        return FLUSH_ERROR;
    }

    return mMonotonicTime;
}
