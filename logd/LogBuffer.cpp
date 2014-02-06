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

#include "LogBuffer.h"
#include "LogStatistics.h"
#include "LogReader.h"

#define LOG_BUFFER_SIZE (256 * 1024) // Tuned on a per-platform basis here?

LogBuffer::LogBuffer(LastLogTimes *times)
        : mTimes(*times) {
    pthread_mutex_init(&mLogElementsLock, NULL);
}

void LogBuffer::log(log_id_t log_id, log_time realtime,
                    uid_t uid, pid_t pid, const char *msg,
                    unsigned short len) {
    if ((log_id >= LOG_ID_MAX) || (log_id < 0)) {
        return;
    }
    LogBufferElement *elem = new LogBufferElement(log_id, realtime,
                                                  uid, pid, msg, len);

    pthread_mutex_lock(&mLogElementsLock);

    // Insert elements in time sorted order if possible
    //  NB: if end is region locked, place element at end of list
    LogBufferElementCollection::iterator it = mLogElements.end();
    LogBufferElementCollection::iterator last = it;
    while (--it != mLogElements.begin()) {
        if ((*it)->getRealTime() <= realtime) {
            break;
        }
        last = it;
    }

    if (last == mLogElements.end()) {
        mLogElements.push_back(elem);
    } else {
        log_time end;
        bool end_set = false;
        bool end_always = false;

        LogTimeEntry::lock();

        LastLogTimes::iterator t = mTimes.begin();
        while(t != mTimes.end()) {
            LogTimeEntry *entry = (*t);
            if (entry->owned_Locked()) {
                if (!entry->mNonBlock) {
                    end_always = true;
                    break;
                }
                if (!end_set || (end <= entry->mEnd)) {
                    end = entry->mEnd;
                    end_set = true;
                }
            }
            t++;
        }

        if (end_always
                || (end_set && (end >= (*last)->getMonotonicTime()))) {
            mLogElements.push_back(elem);
        } else {
            mLogElements.insert(last,elem);
        }

        LogTimeEntry::unlock();
    }

    stats.add(len, log_id, uid, pid);
    maybePrune(log_id);
    pthread_mutex_unlock(&mLogElementsLock);
}

// If we're using more than 256K of memory for log entries, prune
// at least 10% of the log entries.
//
// mLogElementsLock must be held when this function is called.
void LogBuffer::maybePrune(log_id_t id) {
    size_t sizes = stats.sizes(id);
    if (sizes > LOG_BUFFER_SIZE) {
        size_t sizeOver90Percent = sizes - ((LOG_BUFFER_SIZE * 9) / 10);
        size_t elements = stats.elements(id);
        unsigned long pruneRows = elements * sizeOver90Percent / sizes;
        elements /= 10;
        if (pruneRows <= elements) {
            pruneRows = elements;
        }
        prune(id, pruneRows);
    }
}

// prune "pruneRows" of type "id" from the buffer.
//
// mLogElementsLock must be held when this function is called.
void LogBuffer::prune(log_id_t id, unsigned long pruneRows) {
    LogTimeEntry *oldest = NULL;

    LogTimeEntry::lock();

    // Region locked?
    LastLogTimes::iterator t = mTimes.begin();
    while(t != mTimes.end()) {
        LogTimeEntry *entry = (*t);
        if (entry->owned_Locked()
                && (!oldest || (oldest->mStart > entry->mStart))) {
            oldest = entry;
        }
        t++;
    }

    LogBufferElementCollection::iterator it = mLogElements.begin();
    while((pruneRows > 0) && (it != mLogElements.end())) {
        LogBufferElement *e = *it;
        if (e->getLogId() == id) {
            if (oldest && (oldest->mStart <= e->getMonotonicTime())) {
                if (stats.sizes(id) > (2 * LOG_BUFFER_SIZE)) {
                    // kick a misbehaving log reader client off the island
                    oldest->release_Locked();
                } else {
                    oldest->triggerSkip_Locked(pruneRows);
                }
                break;
            }
            it = mLogElements.erase(it);
            stats.subtract(e->getMsgLen(), id, e->getUid(), e->getPid());
            delete e;
            pruneRows--;
        } else {
            it++;
        }
    }

    LogTimeEntry::unlock();
}

// clear all rows of type "id" from the buffer.
void LogBuffer::clear(log_id_t id) {
    pthread_mutex_lock(&mLogElementsLock);
    prune(id, ULONG_MAX);
    pthread_mutex_unlock(&mLogElementsLock);
}

// get the used space associated with "id".
unsigned long LogBuffer::getSizeUsed(log_id_t id) {
    pthread_mutex_lock(&mLogElementsLock);
    size_t retval = stats.sizes(id);
    pthread_mutex_unlock(&mLogElementsLock);
    return retval;
}

// get the total space allocated to "id"
unsigned long LogBuffer::getSize(log_id_t /*id*/) {
    return LOG_BUFFER_SIZE;
}

log_time LogBuffer::flushTo(
        SocketClient *reader, const log_time start, bool privileged,
        bool (*filter)(const LogBufferElement *element, void *arg), void *arg) {
    LogBufferElementCollection::iterator it;
    log_time max = start;
    uid_t uid = reader->getUid();

    pthread_mutex_lock(&mLogElementsLock);
    for (it = mLogElements.begin(); it != mLogElements.end(); ++it) {
        LogBufferElement *element = *it;

        if (!privileged && (element->getUid() != uid)) {
            continue;
        }

        if (element->getMonotonicTime() <= start) {
            continue;
        }

        // NB: calling out to another object with mLogElementsLock held (safe)
        if (filter && !(*filter)(element, arg)) {
            continue;
        }

        pthread_mutex_unlock(&mLogElementsLock);

        // range locking in LastLogTimes looks after us
        max = element->flushTo(reader);

        if (max == element->FLUSH_ERROR) {
            return max;
        }

        pthread_mutex_lock(&mLogElementsLock);
    }
    pthread_mutex_unlock(&mLogElementsLock);

    return max;
}

size_t LogBuffer::formatStatistics(char **strp, uid_t uid, unsigned int logMask) {
    log_time oldest(CLOCK_MONOTONIC);

    pthread_mutex_lock(&mLogElementsLock);

    // Find oldest element in the log(s)
    LogBufferElementCollection::iterator it;
    for (it = mLogElements.begin(); it != mLogElements.end(); ++it) {
        LogBufferElement *element = *it;

        if ((logMask & (1 << element->getLogId()))) {
            oldest = element->getMonotonicTime();
            break;
        }
    }

    size_t ret = stats.format(strp, uid, logMask, oldest);

    pthread_mutex_unlock(&mLogElementsLock);

    return ret;
}
