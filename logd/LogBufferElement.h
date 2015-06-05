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

#ifndef _LOGD_LOG_BUFFER_ELEMENT_H__
#define _LOGD_LOG_BUFFER_ELEMENT_H__

#include <stdatomic.h>
#include <stdlib.h>
#include <sys/types.h>

#include <sysutils/SocketClient.h>
#include <log/log.h>
#include <log/log_read.h>

// Hijack this header as a common include file used by most all sources
// to report some utilities defined here and there.

namespace android {

// Furnished in main.cpp. Caller must own and free returned value
char *uidToName(uid_t uid);

// Furnished in LogStatistics.cpp. Caller must own and free returned value
char *pidToName(pid_t pid);
char *tidToName(pid_t tid);

// Furnished in main.cpp. Thread safe.
const char *tagToName(uint32_t tag);

}

static inline bool worstUidEnabledForLogid(log_id_t id) {
    return (id != LOG_ID_CRASH) && (id != LOG_ID_KERNEL) && (id != LOG_ID_EVENTS);
}

class LogBuffer;

#define EXPIRE_HOUR_THRESHOLD 24 // Only expire chatty UID logs to preserve
                                 // non-chatty UIDs less than this age in hours
#define EXPIRE_THRESHOLD 10      // A smaller expire count is considered too
                                 // chatty for the temporal expire messages
#define EXPIRE_RATELIMIT 10      // maximum rate in seconds to report expiration

class LogBufferElement {
    const log_id_t mLogId;
    const uid_t mUid;
    const pid_t mPid;
    const pid_t mTid;
    char *mMsg;
    union {
        const unsigned short mMsgLen; // mMSg != NULL
        unsigned short mDropped;      // mMsg == NULL
    };
    const uint64_t mSequence;
    const log_time mRealTime;
    static atomic_int_fast64_t sequence;

    // assumption: mMsg == NULL
    size_t populateDroppedMessage(char *&buffer,
                                  LogBuffer *parent);

public:
    LogBufferElement(log_id_t log_id, log_time realtime,
                     uid_t uid, pid_t pid, pid_t tid,
                     const char *msg, unsigned short len);
    virtual ~LogBufferElement();

    log_id_t getLogId() const { return mLogId; }
    uid_t getUid(void) const { return mUid; }
    pid_t getPid(void) const { return mPid; }
    pid_t getTid(void) const { return mTid; }
    unsigned short getDropped(void) const { return mMsg ? 0 : mDropped; }
    unsigned short setDropped(unsigned short value) {
        if (mMsg) {
            free(mMsg);
            mMsg = NULL;
        }
        return mDropped = value;
    }
    unsigned short getMsgLen() const { return mMsg ? mMsgLen : 0; }
    uint64_t getSequence(void) const { return mSequence; }
    static uint64_t getCurrentSequence(void) { return sequence.load(memory_order_relaxed); }
    log_time getRealTime(void) const { return mRealTime; }

    uint32_t getTag(void) const;

    static const uint64_t FLUSH_ERROR;
    uint64_t flushTo(SocketClient *writer, LogBuffer *parent);
};

#endif
