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
#include "LogWhiteBlackList.h"
#include "LogReader.h"

// Default
#define LOG_BUFFER_SIZE (256 * 1024) // Tuned on a per-platform basis here?
#ifdef USERDEBUG_BUILD
#define log_buffer_size(id) mMaxSize[id]
#else
#define log_buffer_size(id) LOG_BUFFER_SIZE
#endif

LogBuffer::LogBuffer(LastLogTimes *times)
        : mTimes(*times) {
    pthread_mutex_init(&mLogElementsLock, NULL);
#ifdef USERDEBUG_BUILD
    log_id_for_each(i) {
        mMaxSize[i] = LOG_BUFFER_SIZE;
    }
#endif
}

void LogBuffer::log(log_id_t log_id, log_time realtime,
                    uid_t uid, pid_t pid, pid_t tid,
                    const char *msg, unsigned short len) {
    if ((log_id >= LOG_ID_MAX) || (log_id < 0)) {
        return;
    }
    LogBufferElement *elem = new LogBufferElement(log_id, realtime,
                                                  uid, pid, tid, msg, len);

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
    if (sizes > log_buffer_size(id)) {
        size_t sizeOver90Percent = sizes - ((log_buffer_size(id) * 9) / 10);
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

    LogBufferElementCollection::iterator it;

    // prune by worst offender by uid
    while (pruneRows > 0) {
        // recalculate the worst offender on every batched pass
        uid_t worst = (uid_t) -1;
        size_t worst_sizes = 0;
        size_t second_worst_sizes = 0;

#ifdef USERDEBUG_BUILD
        if (mPrune.worstUidEnabled())
#endif
        {
            LidStatistics &l = stats.id(id);
            UidStatisticsCollection::iterator iu;
            for (iu = l.begin(); iu != l.end(); ++iu) {
                UidStatistics *u = (*iu);
                size_t sizes = u->sizes();
                if (worst_sizes < sizes) {
                    second_worst_sizes = worst_sizes;
                    worst_sizes = sizes;
                    worst = u->getUid();
                }
                if ((second_worst_sizes < sizes) && (sizes < worst_sizes)) {
                    second_worst_sizes = sizes;
                }
            }
        }

        bool kick = false;
        for(it = mLogElements.begin(); it != mLogElements.end();) {
            LogBufferElement *e = *it;

            if (oldest && (oldest->mStart <= e->getMonotonicTime())) {
                break;
            }

            if (e->getLogId() != id) {
                ++it;
                continue;
            }

            uid_t uid = e->getUid();

            if (uid == worst) {
                it = mLogElements.erase(it);
                unsigned short len = e->getMsgLen();
                stats.subtract(len, id, worst, e->getPid());
                delete e;
                kick = true;
                pruneRows--;
                if ((pruneRows == 0) || (worst_sizes < second_worst_sizes)) {
                    break;
                }
                worst_sizes -= len;
            }
#ifdef USERDEBUG_BUILD
            else if (mPrune.naughty(e)) { // BlackListed
                it = mLogElements.erase(it);
                stats.subtract(e->getMsgLen(), id, uid, e->getPid());
                delete e;
                pruneRows--;
                if (pruneRows == 0) {
                    break;
                }
            }
#endif
            else {
                ++it;
            }
        }

        if (!kick
#ifdef USERDEBUG_BUILD
                || !mPrune.worstUidEnabled()
#endif
        ) {
            break; // the following loop will ask bad clients to skip/drop
        }
    }

#ifdef USERDEBUG_BUILD
    bool whitelist = false;
#endif
    it = mLogElements.begin();
    while((pruneRows > 0) && (it != mLogElements.end())) {
        LogBufferElement *e = *it;
        if (e->getLogId() == id) {
            if (oldest && (oldest->mStart <= e->getMonotonicTime())) {
#ifdef USERDEBUG_BUILD
                if (!whitelist)
#endif
                {
                    if (stats.sizes(id) > (2 * log_buffer_size(id))) {
                        // kick a misbehaving log reader client off the island
                        oldest->release_Locked();
                    } else {
                        oldest->triggerSkip_Locked(pruneRows);
                    }
                }
                break;
            }
#ifdef USERDEBUG_BUILD
            if (mPrune.nice(e)) { // WhiteListed
                whitelist = true;
                it++;
                continue;
            }
#endif
            it = mLogElements.erase(it);
            stats.subtract(e->getMsgLen(), id, e->getUid(), e->getPid());
            delete e;
            pruneRows--;
        } else {
            it++;
        }
    }

#ifdef USERDEBUG_BUILD
    if (whitelist && (pruneRows > 0)) {
        it = mLogElements.begin();
        while((it != mLogElements.end()) && (pruneRows > 0)) {
            LogBufferElement *e = *it;
            if (e->getLogId() == id) {
                if (oldest && (oldest->mStart <= e->getMonotonicTime())) {
                    if (stats.sizes(id) > (2 * log_buffer_size(id))) {
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
    }
#endif

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

#ifdef USERDEBUG_BUILD

// set the total space allocated to "id"
int LogBuffer::setSize(log_id_t id, unsigned long size) {
    // Reasonable limits ...
    if ((size < (64 * 1024)) || ((256 * 1024 * 1024) < size)) {
        return -1;
    }
    pthread_mutex_lock(&mLogElementsLock);
    log_buffer_size(id) = size;
    pthread_mutex_unlock(&mLogElementsLock);
    return 0;
}

// get the total space allocated to "id"
unsigned long LogBuffer::getSize(log_id_t id) {
    pthread_mutex_lock(&mLogElementsLock);
    size_t retval = log_buffer_size(id);
    pthread_mutex_unlock(&mLogElementsLock);
    return retval;
}

#else // ! USERDEBUG_BUILD

// get the total space allocated to "id"
unsigned long LogBuffer::getSize(log_id_t /*id*/) {
    return log_buffer_size(id);
}

#endif

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

void LogBuffer::formatStatistics(char **strp, uid_t uid, unsigned int logMask) {
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

    stats.format(strp, uid, logMask, oldest);

    pthread_mutex_unlock(&mLogElementsLock);
}
