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

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/user.h>
#include <time.h>
#include <unistd.h>

#include <unordered_map>

#include <cutils/properties.h>
#include <log/logger.h>

#include "LogBuffer.h"
#include "LogReader.h"

// Default
#define LOG_BUFFER_SIZE (256 * 1024) // Tuned on a per-platform basis here?
#define log_buffer_size(id) mMaxSize[id]
#define LOG_BUFFER_MIN_SIZE (64 * 1024UL)
#define LOG_BUFFER_MAX_SIZE (256 * 1024 * 1024UL)

static bool valid_size(unsigned long value) {
    if ((value < LOG_BUFFER_MIN_SIZE) || (LOG_BUFFER_MAX_SIZE < value)) {
        return false;
    }

    long pages = sysconf(_SC_PHYS_PAGES);
    if (pages < 1) {
        return true;
    }

    long pagesize = sysconf(_SC_PAGESIZE);
    if (pagesize <= 1) {
        pagesize = PAGE_SIZE;
    }

    // maximum memory impact a somewhat arbitrary ~3%
    pages = (pages + 31) / 32;
    unsigned long maximum = pages * pagesize;

    if ((maximum < LOG_BUFFER_MIN_SIZE) || (LOG_BUFFER_MAX_SIZE < maximum)) {
        return true;
    }

    return value <= maximum;
}

static unsigned long property_get_size(const char *key) {
    char property[PROPERTY_VALUE_MAX];
    property_get(key, property, "");

    char *cp;
    unsigned long value = strtoul(property, &cp, 10);

    switch(*cp) {
    case 'm':
    case 'M':
        value *= 1024;
    /* FALLTHRU */
    case 'k':
    case 'K':
        value *= 1024;
    /* FALLTHRU */
    case '\0':
        break;

    default:
        value = 0;
    }

    if (!valid_size(value)) {
        value = 0;
    }

    return value;
}

void LogBuffer::init() {
    static const char global_tuneable[] = "persist.logd.size"; // Settings App
    static const char global_default[] = "ro.logd.size";       // BoardConfig.mk

    unsigned long default_size = property_get_size(global_tuneable);
    if (!default_size) {
        default_size = property_get_size(global_default);
    }

    log_id_for_each(i) {
        char key[PROP_NAME_MAX];

        snprintf(key, sizeof(key), "%s.%s",
                 global_tuneable, android_log_id_to_name(i));
        unsigned long property_size = property_get_size(key);

        if (!property_size) {
            snprintf(key, sizeof(key), "%s.%s",
                     global_default, android_log_id_to_name(i));
            property_size = property_get_size(key);
        }

        if (!property_size) {
            property_size = default_size;
        }

        if (!property_size) {
            property_size = LOG_BUFFER_SIZE;
        }

        if (setSize(i, property_size)) {
            setSize(i, LOG_BUFFER_MIN_SIZE);
        }
    }
}

LogBuffer::LogBuffer(LastLogTimes *times) : mTimes(*times) {
    pthread_mutex_init(&mLogElementsLock, NULL);

    init();
}

int LogBuffer::log(log_id_t log_id, log_time realtime,
                   uid_t uid, pid_t pid, pid_t tid,
                   const char *msg, unsigned short len) {
    if ((log_id >= LOG_ID_MAX) || (log_id < 0)) {
        return -EINVAL;
    }

    LogBufferElement *elem = new LogBufferElement(log_id, realtime,
                                                  uid, pid, tid, msg, len);
    int prio = ANDROID_LOG_INFO;
    const char *tag = NULL;
    if (log_id == LOG_ID_EVENTS) {
        tag = android::tagToName(elem->getTag());
    } else {
        prio = *msg;
        tag = msg + 1;
    }
    if (!__android_log_is_loggable(prio, tag, ANDROID_LOG_VERBOSE)) {
        // Log traffic received to total
        pthread_mutex_lock(&mLogElementsLock);
        stats.add(elem);
        stats.subtract(elem);
        pthread_mutex_unlock(&mLogElementsLock);
        delete elem;
        return -EACCES;
    }

    pthread_mutex_lock(&mLogElementsLock);

    // Insert elements in time sorted order if possible
    //  NB: if end is region locked, place element at end of list
    LogBufferElementCollection::iterator it = mLogElements.end();
    LogBufferElementCollection::iterator last = it;
    while (last != mLogElements.begin()) {
        --it;
        if ((*it)->getRealTime() <= realtime) {
            break;
        }
        last = it;
    }

    if (last == mLogElements.end()) {
        mLogElements.push_back(elem);
    } else {
        uint64_t end = 1;
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
                || (end_set && (end >= (*last)->getSequence()))) {
            mLogElements.push_back(elem);
        } else {
            mLogElements.insert(last,elem);
        }

        LogTimeEntry::unlock();
    }

    stats.add(elem);
    maybePrune(log_id);
    pthread_mutex_unlock(&mLogElementsLock);

    return len;
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

LogBufferElementCollection::iterator LogBuffer::erase(LogBufferElementCollection::iterator it) {
    LogBufferElement *e = *it;

    it = mLogElements.erase(it);
    stats.subtract(e);
    delete e;

    return it;
}

// Define a temporary mechanism to report the last LogBufferElement pointer
// for the specified uid, pid and tid. Used below to help merge-sort when
// pruning for worst UID.
class LogBufferElementKey {
    const union {
        struct {
            uint16_t uid;
            uint16_t pid;
            uint16_t tid;
            uint16_t padding;
        } __packed;
        uint64_t value;
    } __packed;

public:
    LogBufferElementKey(uid_t u, pid_t p, pid_t t):uid(u),pid(p),tid(t),padding(0) { }
    LogBufferElementKey(uint64_t k):value(k) { }

    uint64_t getKey() { return value; }
};

class LogBufferElementLast {

    typedef std::unordered_map<uint64_t, LogBufferElement *> LogBufferElementMap;
    LogBufferElementMap map;

public:

    bool merge(LogBufferElement *e, unsigned short dropped) {
        LogBufferElementKey key(e->getUid(), e->getPid(), e->getTid());
        LogBufferElementMap::iterator it = map.find(key.getKey());
        if (it != map.end()) {
            LogBufferElement *l = it->second;
            unsigned short d = l->getDropped();
            if ((dropped + d) > USHRT_MAX) {
                map.erase(it);
            } else {
                l->setDropped(dropped + d);
                return true;
            }
        }
        return false;
    }

    void add(LogBufferElement *e) {
        LogBufferElementKey key(e->getUid(), e->getPid(), e->getTid());
        map[key.getKey()] = e;
    }

    inline void clear() {
        map.clear();
    }

    void clear(LogBufferElement *e) {
        uint64_t current = e->getRealTime().nsec()
                         - (EXPIRE_RATELIMIT * NS_PER_SEC);
        for(LogBufferElementMap::iterator it = map.begin(); it != map.end();) {
            LogBufferElement *l = it->second;
            if ((l->getDropped() >= EXPIRE_THRESHOLD)
                    && (current > l->getRealTime().nsec())) {
                it = map.erase(it);
            } else {
                ++it;
            }
        }
    }

};

// prune "pruneRows" of type "id" from the buffer.
//
// mLogElementsLock must be held when this function is called.
void LogBuffer::prune(log_id_t id, unsigned long pruneRows, uid_t caller_uid) {
    LogTimeEntry *oldest = NULL;

    LogTimeEntry::lock();

    // Region locked?
    LastLogTimes::iterator t = mTimes.begin();
    while(t != mTimes.end()) {
        LogTimeEntry *entry = (*t);
        if (entry->owned_Locked() && entry->isWatching(id)
                && (!oldest || (oldest->mStart > entry->mStart))) {
            oldest = entry;
        }
        t++;
    }

    LogBufferElementCollection::iterator it;

    if (caller_uid != AID_ROOT) {
        for(it = mLogElements.begin(); it != mLogElements.end();) {
            LogBufferElement *e = *it;

            if (oldest && (oldest->mStart <= e->getSequence())) {
                break;
            }

            if (e->getLogId() != id) {
                ++it;
                continue;
            }

            if (e->getUid() == caller_uid) {
                it = erase(it);
                pruneRows--;
                if (pruneRows == 0) {
                    break;
                }
            } else {
                ++it;
            }
        }
        LogTimeEntry::unlock();
        return;
    }

    // prune by worst offender by uid
    bool hasBlacklist = mPrune.naughty();
    while (pruneRows > 0) {
        // recalculate the worst offender on every batched pass
        uid_t worst = (uid_t) -1;
        size_t worst_sizes = 0;
        size_t second_worst_sizes = 0;

        if (worstUidEnabledForLogid(id) && mPrune.worstUidEnabled()) {
            std::unique_ptr<const UidEntry *[]> sorted = stats.sort(2, id);

            if (sorted.get()) {
                if (sorted[0] && sorted[1]) {
                    worst_sizes = sorted[0]->getSizes();
                    // Calculate threshold as 12.5% of available storage
                    size_t threshold = log_buffer_size(id) / 8;
                    if (worst_sizes > threshold) {
                        worst = sorted[0]->getKey();
                        second_worst_sizes = sorted[1]->getSizes();
                        if (second_worst_sizes < threshold) {
                            second_worst_sizes = threshold;
                        }
                    }
                }
            }
        }

        // skip if we have neither worst nor naughty filters
        if ((worst == (uid_t) -1) && !hasBlacklist) {
            break;
        }

        bool kick = false;
        bool leading = true;
        LogBufferElementLast last;
        for(it = mLogElements.begin(); it != mLogElements.end();) {
            LogBufferElement *e = *it;

            if (oldest && (oldest->mStart <= e->getSequence())) {
                break;
            }

            if (e->getLogId() != id) {
                ++it;
                continue;
            }

            unsigned short dropped = e->getDropped();

            // remove any leading drops
            if (leading && dropped) {
                it = erase(it);
                continue;
            }

            // merge any drops
            if (dropped && last.merge(e, dropped)) {
                it = mLogElements.erase(it);
                stats.erase(e);
                delete e;
                continue;
            }

            if (hasBlacklist && mPrune.naughty(e)) {
                last.clear(e);
                it = erase(it);
                if (dropped) {
                    continue;
                }

                pruneRows--;
                if (pruneRows == 0) {
                    break;
                }

                if (e->getUid() == worst) {
                    kick = true;
                    if (worst_sizes < second_worst_sizes) {
                        break;
                    }
                    worst_sizes -= e->getMsgLen();
                }
                continue;
            }

            if (dropped) {
                last.add(e);
                ++it;
                continue;
            }

            if (e->getUid() != worst) {
                if (leading) {
                    static const timespec too_old = {
                        EXPIRE_HOUR_THRESHOLD * 60 * 60, 0
                    };
                    LogBufferElementCollection::iterator last;
                    last = mLogElements.end();
                    --last;
                    if ((e->getRealTime() < ((*last)->getRealTime() - too_old))
                            || (e->getRealTime() > (*last)->getRealTime())) {
                        break;
                    }
                }
                leading = false;
                last.clear(e);
                ++it;
                continue;
            }

            pruneRows--;
            if (pruneRows == 0) {
                break;
            }

            kick = true;

            unsigned short len = e->getMsgLen();

            // do not create any leading drops
            if (leading) {
                it = erase(it);
            } else {
                stats.drop(e);
                e->setDropped(1);
                if (last.merge(e, 1)) {
                    it = mLogElements.erase(it);
                    stats.erase(e);
                    delete e;
                } else {
                    last.add(e);
                    ++it;
                }
            }
            if (worst_sizes < second_worst_sizes) {
                break;
            }
            worst_sizes -= len;
        }
        last.clear();

        if (!kick || !mPrune.worstUidEnabled()) {
            break; // the following loop will ask bad clients to skip/drop
        }
    }

    bool whitelist = false;
    bool hasWhitelist = mPrune.nice();
    it = mLogElements.begin();
    while((pruneRows > 0) && (it != mLogElements.end())) {
        LogBufferElement *e = *it;

        if (e->getLogId() != id) {
            it++;
            continue;
        }

        if (oldest && (oldest->mStart <= e->getSequence())) {
            if (whitelist) {
                break;
            }

            if (stats.sizes(id) > (2 * log_buffer_size(id))) {
                // kick a misbehaving log reader client off the island
                oldest->release_Locked();
            } else {
                oldest->triggerSkip_Locked(id, pruneRows);
            }
            break;
        }

        if (hasWhitelist && !e->getDropped() && mPrune.nice(e)) { // WhiteListed
            whitelist = true;
            it++;
            continue;
        }

        it = erase(it);
        pruneRows--;
    }

    // Do not save the whitelist if we are reader range limited
    if (whitelist && (pruneRows > 0)) {
        it = mLogElements.begin();
        while((it != mLogElements.end()) && (pruneRows > 0)) {
            LogBufferElement *e = *it;

            if (e->getLogId() != id) {
                ++it;
                continue;
            }

            if (oldest && (oldest->mStart <= e->getSequence())) {
                if (stats.sizes(id) > (2 * log_buffer_size(id))) {
                    // kick a misbehaving log reader client off the island
                    oldest->release_Locked();
                } else {
                    oldest->triggerSkip_Locked(id, pruneRows);
                }
                break;
            }

            it = erase(it);
            pruneRows--;
        }
    }

    LogTimeEntry::unlock();
}

// clear all rows of type "id" from the buffer.
void LogBuffer::clear(log_id_t id, uid_t uid) {
    pthread_mutex_lock(&mLogElementsLock);
    prune(id, ULONG_MAX, uid);
    pthread_mutex_unlock(&mLogElementsLock);
}

// get the used space associated with "id".
unsigned long LogBuffer::getSizeUsed(log_id_t id) {
    pthread_mutex_lock(&mLogElementsLock);
    size_t retval = stats.sizes(id);
    pthread_mutex_unlock(&mLogElementsLock);
    return retval;
}

// set the total space allocated to "id"
int LogBuffer::setSize(log_id_t id, unsigned long size) {
    // Reasonable limits ...
    if (!valid_size(size)) {
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

uint64_t LogBuffer::flushTo(
        SocketClient *reader, const uint64_t start, bool privileged,
        int (*filter)(const LogBufferElement *element, void *arg), void *arg) {
    LogBufferElementCollection::iterator it;
    uint64_t max = start;
    uid_t uid = reader->getUid();

    pthread_mutex_lock(&mLogElementsLock);

    if (start <= 1) {
        // client wants to start from the beginning
        it = mLogElements.begin();
    } else {
        // Client wants to start from some specified time. Chances are
        // we are better off starting from the end of the time sorted list.
        for (it = mLogElements.end(); it != mLogElements.begin(); /* do nothing */) {
            --it;
            LogBufferElement *element = *it;
            if (element->getSequence() <= start) {
                it++;
                break;
            }
        }
    }

    for (; it != mLogElements.end(); ++it) {
        LogBufferElement *element = *it;

        if (!privileged && (element->getUid() != uid)) {
            continue;
        }

        if (element->getSequence() <= start) {
            continue;
        }

        // NB: calling out to another object with mLogElementsLock held (safe)
        if (filter) {
            int ret = (*filter)(element, arg);
            if (ret == false) {
                continue;
            }
            if (ret != true) {
                break;
            }
        }

        pthread_mutex_unlock(&mLogElementsLock);

        // range locking in LastLogTimes looks after us
        max = element->flushTo(reader, this);

        if (max == element->FLUSH_ERROR) {
            return max;
        }

        pthread_mutex_lock(&mLogElementsLock);
    }
    pthread_mutex_unlock(&mLogElementsLock);

    return max;
}

void LogBuffer::formatStatistics(char **strp, uid_t uid, unsigned int logMask) {
    pthread_mutex_lock(&mLogElementsLock);

    stats.format(strp, uid, logMask);

    pthread_mutex_unlock(&mLogElementsLock);
}
