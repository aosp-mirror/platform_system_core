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

#ifndef _LOGD_LOG_BUFFER_H__
#define _LOGD_LOG_BUFFER_H__

#include <sys/types.h>

#include <log/log.h>
#include <sysutils/SocketClient.h>
#include <utils/List.h>

#include "LogBufferElement.h"
#include "LogTimes.h"
#include "LogStatistics.h"
#include "LogWhiteBlackList.h"

typedef android::List<LogBufferElement *> LogBufferElementCollection;

class LogBuffer {
    LogBufferElementCollection mLogElements;
    pthread_mutex_t mLogElementsLock;

    LogStatistics stats;

    bool dgram_qlen_statistics;

#ifdef USERDEBUG_BUILD
    PruneList mPrune;

    unsigned long mMaxSize[LOG_ID_MAX];
#endif

public:
    LastLogTimes &mTimes;

    LogBuffer(LastLogTimes *times);

    void log(log_id_t log_id, log_time realtime,
             uid_t uid, pid_t pid, pid_t tid,
             const char *msg, unsigned short len);
    log_time flushTo(SocketClient *writer, const log_time start,
                     bool privileged,
                     bool (*filter)(const LogBufferElement *element, void *arg) = NULL,
                     void *arg = NULL);

    void clear(log_id_t id);
    unsigned long getSize(log_id_t id);
#ifdef USERDEBUG_BUILD
    int setSize(log_id_t id, unsigned long size);
#endif
    unsigned long getSizeUsed(log_id_t id);
    // *strp uses malloc, use free to release.
    void formatStatistics(char **strp, uid_t uid, unsigned int logMask);

    void enableDgramQlenStatistics() {
        stats.enableDgramQlenStatistics();
        dgram_qlen_statistics = true;
    }

#ifdef USERDEBUG_BUILD
    int initPrune(char *cp) { return mPrune.init(cp); }
    // *strp uses malloc, use free to release.
    void formatPrune(char **strp) { mPrune.format(strp); }
#endif

    // helper
    char *pidToName(pid_t pid) { return stats.pidToName(pid); }

private:
    void maybePrune(log_id_t id);
    void prune(log_id_t id, unsigned long pruneRows);

};

#endif // _LOGD_LOG_BUFFER_H__
