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
// for manual checking of stale entries during LogBuffer::erase()
//#define DEBUG_CHECK_FOR_STALE_ENTRIES

#include <ctype.h>
#include <endian.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/cdefs.h>
#include <sys/user.h>
#include <time.h>
#include <unistd.h>

#include <unordered_map>
#include <utility>

#include <cutils/properties.h>
#include <private/android_logger.h>

#include "LogBuffer.h"
#include "LogKlog.h"
#include "LogReader.h"
#include "LogUtils.h"

#ifndef __predict_false
#define __predict_false(exp) __builtin_expect((exp) != 0, 0)
#endif

// Default
#define log_buffer_size(id) mMaxSize[id]

void LogBuffer::init() {
    log_id_for_each(i) {
        mLastSet[i] = false;
        mLast[i] = mLogElements.begin();

        if (setSize(i, __android_logger_get_buffer_size(i))) {
            setSize(i, LOG_BUFFER_MIN_SIZE);
        }
    }
    bool lastMonotonic = monotonic;
    monotonic = android_log_clockid() == CLOCK_MONOTONIC;
    if (lastMonotonic != monotonic) {
        //
        // Fixup all timestamps, may not be 100% accurate, but better than
        // throwing what we have away when we get 'surprised' by a change.
        // In-place element fixup so no need to check reader-lock. Entries
        // should already be in timestamp order, but we could end up with a
        // few out-of-order entries if new monotonics come in before we
        // are notified of the reinit change in status. A Typical example would
        // be:
        //  --------- beginning of system
        //      10.494082   184   201 D Cryptfs : Just triggered post_fs_data
        //  --------- beginning of kernel
        //       0.000000     0     0 I         : Initializing cgroup subsys
        // as the act of mounting /data would trigger persist.logd.timestamp to
        // be corrected. 1/30 corner case YMMV.
        //
        pthread_mutex_lock(&mLogElementsLock);
        LogBufferElementCollection::iterator it = mLogElements.begin();
        while ((it != mLogElements.end())) {
            LogBufferElement* e = *it;
            if (monotonic) {
                if (!android::isMonotonic(e->mRealTime)) {
                    LogKlog::convertRealToMonotonic(e->mRealTime);
                }
            } else {
                if (android::isMonotonic(e->mRealTime)) {
                    LogKlog::convertMonotonicToReal(e->mRealTime);
                }
            }
            ++it;
        }
        pthread_mutex_unlock(&mLogElementsLock);
    }

    // We may have been triggered by a SIGHUP. Release any sleeping reader
    // threads to dump their current content.
    //
    // NB: this is _not_ performed in the context of a SIGHUP, it is
    // performed during startup, and in context of reinit administrative thread
    LogTimeEntry::lock();

    LastLogTimes::iterator times = mTimes.begin();
    while (times != mTimes.end()) {
        LogTimeEntry* entry = (*times);
        if (entry->owned_Locked()) {
            entry->triggerReader_Locked();
        }
        times++;
    }

    LogTimeEntry::unlock();
}

LogBuffer::LogBuffer(LastLogTimes* times)
    : monotonic(android_log_clockid() == CLOCK_MONOTONIC), mTimes(*times) {
    pthread_mutex_init(&mLogElementsLock, NULL);

    log_id_for_each(i) {
        lastLoggedElements[i] = NULL;
        droppedElements[i] = NULL;
    }

    init();
}

LogBuffer::~LogBuffer() {
    log_id_for_each(i) {
        delete lastLoggedElements[i];
        delete droppedElements[i];
    }
}

enum match_type { DIFFERENT, SAME, SAME_LIBLOG };

static enum match_type identical(LogBufferElement* elem,
                                 LogBufferElement* last) {
    // is it mostly identical?
    //  if (!elem) return DIFFERENT;
    unsigned short lenl = elem->getMsgLen();
    if (!lenl) return DIFFERENT;
    //  if (!last) return DIFFERENT;
    unsigned short lenr = last->getMsgLen();
    if (!lenr) return DIFFERENT;
    //  if (elem->getLogId() != last->getLogId()) return DIFFERENT;
    if (elem->getUid() != last->getUid()) return DIFFERENT;
    if (elem->getPid() != last->getPid()) return DIFFERENT;
    if (elem->getTid() != last->getTid()) return DIFFERENT;

    // last is more than a minute old, stop squashing identical messages
    if (elem->getRealTime().nsec() >
        (last->getRealTime().nsec() + 60 * NS_PER_SEC))
        return DIFFERENT;

    // Identical message
    const char* msgl = elem->getMsg();
    const char* msgr = last->getMsg();
    if (lenl == lenr) {
        if (!fastcmp<memcmp>(msgl, msgr, lenl)) return SAME;
        // liblog tagged messages (content gets summed)
        if ((elem->getLogId() == LOG_ID_EVENTS) &&
            (lenl == sizeof(android_log_event_int_t)) &&
            !fastcmp<memcmp>(msgl, msgr, sizeof(android_log_event_int_t) -
                                             sizeof(int32_t)) &&
            (elem->getTag() == LIBLOG_LOG_TAG))
            return SAME_LIBLOG;
    }

    // audit message (except sequence number) identical?
    static const char avc[] = "): avc: ";

    if (last->isBinary()) {
        if (fastcmp<memcmp>(msgl, msgr, sizeof(android_log_event_string_t) -
                                            sizeof(int32_t)))
            return DIFFERENT;
        msgl += sizeof(android_log_event_string_t);
        lenl -= sizeof(android_log_event_string_t);
        msgr += sizeof(android_log_event_string_t);
        lenr -= sizeof(android_log_event_string_t);
    }
    const char* avcl = android::strnstr(msgl, lenl, avc);
    if (!avcl) return DIFFERENT;
    lenl -= avcl - msgl;
    const char* avcr = android::strnstr(msgr, lenr, avc);
    if (!avcr) return DIFFERENT;
    lenr -= avcr - msgr;
    if (lenl != lenr) return DIFFERENT;
    // TODO: After b/35468874 is addressed, revisit "lenl > strlen(avc)"
    // condition, it might become superflous.
    if (lenl > strlen(avc) &&
        fastcmp<memcmp>(avcl + strlen(avc), avcr + strlen(avc),
                        lenl - strlen(avc))) {
        return DIFFERENT;
    }
    return SAME;
}

int LogBuffer::log(log_id_t log_id, log_time realtime, uid_t uid, pid_t pid,
                   pid_t tid, const char* msg, unsigned short len) {
    if ((log_id >= LOG_ID_MAX) || (log_id < 0)) {
        return -EINVAL;
    }

    LogBufferElement* elem =
        new LogBufferElement(log_id, realtime, uid, pid, tid, msg, len);
    if (log_id != LOG_ID_SECURITY) {
        int prio = ANDROID_LOG_INFO;
        const char* tag = NULL;
        if (log_id == LOG_ID_EVENTS) {
            tag = tagToName(elem->getTag());
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
    }

    pthread_mutex_lock(&mLogElementsLock);
    LogBufferElement* currentLast = lastLoggedElements[log_id];
    if (currentLast) {
        LogBufferElement* dropped = droppedElements[log_id];
        unsigned short count = dropped ? dropped->getDropped() : 0;
        //
        // State Init
        //     incoming:
        //         dropped = NULL
        //         currentLast = NULL;
        //         elem = incoming message
        //     outgoing:
        //         dropped = NULL -> State 0
        //         currentLast = copy of elem
        //         log elem
        // State 0
        //     incoming:
        //         count = 0
        //         dropped = NULL
        //         currentLast = copy of last message
        //         elem = incoming message
        //     outgoing: if match != DIFFERENT
        //         dropped = copy of first identical message -> State 1
        //         currentLast = reference to elem
        //     break: if match == DIFFERENT
        //         dropped = NULL -> State 0
        //         delete copy of last message (incoming currentLast)
        //         currentLast = copy of elem
        //         log elem
        // State 1
        //     incoming:
        //         count = 0
        //         dropped = copy of first identical message
        //         currentLast = reference to last held-back incoming
        //                       message
        //         elem = incoming message
        //     outgoing: if match == SAME
        //         delete copy of first identical message (dropped)
        //         dropped = reference to last held-back incoming
        //                   message set to chatty count of 1 -> State 2
        //         currentLast = reference to elem
        //     outgoing: if match == SAME_LIBLOG
        //         dropped = copy of first identical message -> State 1
        //         take sum of currentLast and elem
        //         if sum overflows:
        //             log currentLast
        //             currentLast = reference to elem
        //         else
        //             delete currentLast
        //             currentLast = reference to elem, sum liblog.
        //     break: if match == DIFFERENT
        //         delete dropped
        //         dropped = NULL -> State 0
        //         log reference to last held-back (currentLast)
        //         currentLast = copy of elem
        //         log elem
        // State 2
        //     incoming:
        //         count = chatty count
        //         dropped = chatty message holding count
        //         currentLast = reference to last held-back incoming
        //                       message.
        //         dropped = chatty message holding count
        //         elem = incoming message
        //     outgoing: if match != DIFFERENT
        //         delete chatty message holding count
        //         dropped = reference to last held-back incoming
        //                   message, set to chatty count + 1
        //         currentLast = reference to elem
        //     break: if match == DIFFERENT
        //         log dropped (chatty message)
        //         dropped = NULL -> State 0
        //         log reference to last held-back (currentLast)
        //         currentLast = copy of elem
        //         log elem
        //
        enum match_type match = identical(elem, currentLast);
        if (match != DIFFERENT) {
            if (dropped) {
                // Sum up liblog tag messages?
                if ((count == 0) /* at Pass 1 */ && (match == SAME_LIBLOG)) {
                    android_log_event_int_t* event =
                        reinterpret_cast<android_log_event_int_t*>(
                            const_cast<char*>(currentLast->getMsg()));
                    //
                    // To unit test, differentiate with something like:
                    //    event->header.tag = htole32(CHATTY_LOG_TAG);
                    // here, then instead of delete currentLast below,
                    // log(currentLast) to see the incremental sums form.
                    //
                    uint32_t swab = event->payload.data;
                    unsigned long long total = htole32(swab);
                    event = reinterpret_cast<android_log_event_int_t*>(
                        const_cast<char*>(elem->getMsg()));
                    swab = event->payload.data;

                    lastLoggedElements[LOG_ID_EVENTS] = elem;
                    total += htole32(swab);
                    // check for overflow
                    if (total >= UINT32_MAX) {
                        log(currentLast);
                        pthread_mutex_unlock(&mLogElementsLock);
                        return len;
                    }
                    stats.add(currentLast);
                    stats.subtract(currentLast);
                    delete currentLast;
                    swab = total;
                    event->payload.data = htole32(swab);
                    pthread_mutex_unlock(&mLogElementsLock);
                    return len;
                }
                if (count == USHRT_MAX) {
                    log(dropped);
                    count = 1;
                } else {
                    delete dropped;
                    ++count;
                }
            }
            if (count) {
                stats.add(currentLast);
                stats.subtract(currentLast);
                currentLast->setDropped(count);
            }
            droppedElements[log_id] = currentLast;
            lastLoggedElements[log_id] = elem;
            pthread_mutex_unlock(&mLogElementsLock);
            return len;
        }
        if (dropped) {         // State 1 or 2
            if (count) {       // State 2
                log(dropped);  // report chatty
            } else {           // State 1
                delete dropped;
            }
            droppedElements[log_id] = NULL;
            log(currentLast);  // report last message in the series
        } else {               // State 0
            delete currentLast;
        }
    }
    lastLoggedElements[log_id] = new LogBufferElement(*elem);

    log(elem);
    pthread_mutex_unlock(&mLogElementsLock);

    return len;
}

// assumes mLogElementsLock held, owns elem, will look after garbage collection
void LogBuffer::log(LogBufferElement* elem) {
    // Insert elements in time sorted order if possible
    //  NB: if end is region locked, place element at end of list
    LogBufferElementCollection::iterator it = mLogElements.end();
    LogBufferElementCollection::iterator last = it;
    if (__predict_true(it != mLogElements.begin())) --it;
    if (__predict_false(it == mLogElements.begin()) ||
        __predict_true((*it)->getRealTime() <= elem->getRealTime())) {
        mLogElements.push_back(elem);
    } else {
        uint64_t end = 1;
        bool end_set = false;
        bool end_always = false;

        LogTimeEntry::lock();

        LastLogTimes::iterator times = mTimes.begin();
        while (times != mTimes.end()) {
            LogTimeEntry* entry = (*times);
            if (entry->owned_Locked()) {
                if (!entry->mNonBlock) {
                    end_always = true;
                    break;
                }
                // it passing mEnd is blocked by the following checks.
                if (!end_set || (end <= entry->mEnd)) {
                    end = entry->mEnd;
                    end_set = true;
                }
            }
            times++;
        }

        if (end_always || (end_set && (end > (*it)->getSequence()))) {
            mLogElements.push_back(elem);
        } else {
            // should be short as timestamps are localized near end()
            do {
                last = it;
                if (__predict_false(it == mLogElements.begin())) {
                    break;
                }

                std::swap((*it)->mSequence, elem->mSequence);

                --it;
            } while (((*it)->getRealTime() > elem->getRealTime()) &&
                     (!end_set || (end <= (*it)->getSequence())));
            mLogElements.insert(last, elem);
        }
        LogTimeEntry::unlock();
    }

    stats.add(elem);
    maybePrune(elem->getLogId());
}

// Prune at most 10% of the log entries or maxPrune, whichever is less.
//
// mLogElementsLock must be held when this function is called.
void LogBuffer::maybePrune(log_id_t id) {
    size_t sizes = stats.sizes(id);
    unsigned long maxSize = log_buffer_size(id);
    if (sizes > maxSize) {
        size_t sizeOver = sizes - ((maxSize * 9) / 10);
        size_t elements = stats.realElements(id);
        size_t minElements = elements / 100;
        if (minElements < minPrune) {
            minElements = minPrune;
        }
        unsigned long pruneRows = elements * sizeOver / sizes;
        if (pruneRows < minElements) {
            pruneRows = minElements;
        }
        if (pruneRows > maxPrune) {
            pruneRows = maxPrune;
        }
        prune(id, pruneRows);
    }
}

LogBufferElementCollection::iterator LogBuffer::erase(
    LogBufferElementCollection::iterator it, bool coalesce) {
    LogBufferElement* element = *it;
    log_id_t id = element->getLogId();

    // Remove iterator references in the various lists that will become stale
    // after the element is erased from the main logging list.

    {  // start of scope for found iterator
        int key = ((id == LOG_ID_EVENTS) || (id == LOG_ID_SECURITY))
                      ? element->getTag()
                      : element->getUid();
        LogBufferIteratorMap::iterator found = mLastWorst[id].find(key);
        if ((found != mLastWorst[id].end()) && (it == found->second)) {
            mLastWorst[id].erase(found);
        }
    }

    {  // start of scope for pid found iterator
        // element->getUid() may not be AID_SYSTEM for next-best-watermark.
        // will not assume id != LOG_ID_EVENTS or LOG_ID_SECURITY for KISS and
        // long term code stability, find() check should be fast for those ids.
        LogBufferPidIteratorMap::iterator found =
            mLastWorstPidOfSystem[id].find(element->getPid());
        if ((found != mLastWorstPidOfSystem[id].end()) &&
            (it == found->second)) {
            mLastWorstPidOfSystem[id].erase(found);
        }
    }

    bool setLast[LOG_ID_MAX];
    bool doSetLast = false;
    log_id_for_each(i) {
        doSetLast |= setLast[i] = mLastSet[i] && (it == mLast[i]);
    }
#ifdef DEBUG_CHECK_FOR_STALE_ENTRIES
    LogBufferElementCollection::iterator bad = it;
    int key = ((id == LOG_ID_EVENTS) || (id == LOG_ID_SECURITY))
                  ? element->getTag()
                  : element->getUid();
#endif
    it = mLogElements.erase(it);
    if (doSetLast) {
        log_id_for_each(i) {
            if (setLast[i]) {
                if (__predict_false(it == mLogElements.end())) {  // impossible
                    mLastSet[i] = false;
                    mLast[i] = mLogElements.begin();
                } else {
                    mLast[i] = it;  // push down the road as next-best-watermark
                }
            }
        }
    }
#ifdef DEBUG_CHECK_FOR_STALE_ENTRIES
    log_id_for_each(i) {
        for (auto b : mLastWorst[i]) {
            if (bad == b.second) {
                android::prdebug("stale mLastWorst[%d] key=%d mykey=%d\n", i,
                                 b.first, key);
            }
        }
        for (auto b : mLastWorstPidOfSystem[i]) {
            if (bad == b.second) {
                android::prdebug("stale mLastWorstPidOfSystem[%d] pid=%d\n", i,
                                 b.first);
            }
        }
        if (mLastSet[i] && (bad == mLast[i])) {
            android::prdebug("stale mLast[%d]\n", i);
            mLastSet[i] = false;
            mLast[i] = mLogElements.begin();
        }
    }
#endif
    if (coalesce) {
        stats.erase(element);
    } else {
        stats.subtract(element);
    }
    delete element;

    return it;
}

// Define a temporary mechanism to report the last LogBufferElement pointer
// for the specified uid, pid and tid. Used below to help merge-sort when
// pruning for worst UID.
class LogBufferElementKey {
    const union {
        struct {
            uint32_t uid;
            uint16_t pid;
            uint16_t tid;
        } __packed;
        uint64_t value;
    } __packed;

   public:
    LogBufferElementKey(uid_t uid, pid_t pid, pid_t tid)
        : uid(uid), pid(pid), tid(tid) {
    }
    explicit LogBufferElementKey(uint64_t key) : value(key) {
    }

    uint64_t getKey() {
        return value;
    }
};

class LogBufferElementLast {
    typedef std::unordered_map<uint64_t, LogBufferElement*> LogBufferElementMap;
    LogBufferElementMap map;

   public:
    bool coalesce(LogBufferElement* element, unsigned short dropped) {
        LogBufferElementKey key(element->getUid(), element->getPid(),
                                element->getTid());
        LogBufferElementMap::iterator it = map.find(key.getKey());
        if (it != map.end()) {
            LogBufferElement* found = it->second;
            unsigned short moreDropped = found->getDropped();
            if ((dropped + moreDropped) > USHRT_MAX) {
                map.erase(it);
            } else {
                found->setDropped(dropped + moreDropped);
                return true;
            }
        }
        return false;
    }

    void add(LogBufferElement* element) {
        LogBufferElementKey key(element->getUid(), element->getPid(),
                                element->getTid());
        map[key.getKey()] = element;
    }

    inline void clear() {
        map.clear();
    }

    void clear(LogBufferElement* element) {
        uint64_t current =
            element->getRealTime().nsec() - (EXPIRE_RATELIMIT * NS_PER_SEC);
        for (LogBufferElementMap::iterator it = map.begin(); it != map.end();) {
            LogBufferElement* mapElement = it->second;
            if ((mapElement->getDropped() >= EXPIRE_THRESHOLD) &&
                (current > mapElement->getRealTime().nsec())) {
                it = map.erase(it);
            } else {
                ++it;
            }
        }
    }
};

// prune "pruneRows" of type "id" from the buffer.
//
// This garbage collection task is used to expire log entries. It is called to
// remove all logs (clear), all UID logs (unprivileged clear), or every
// 256 or 10% of the total logs (whichever is less) to prune the logs.
//
// First there is a prep phase where we discover the reader region lock that
// acts as a backstop to any pruning activity to stop there and go no further.
//
// There are three major pruning loops that follow. All expire from the oldest
// entries. Since there are multiple log buffers, the Android logging facility
// will appear to drop entries 'in the middle' when looking at multiple log
// sources and buffers. This effect is slightly more prominent when we prune
// the worst offender by logging source. Thus the logs slowly loose content
// and value as you move back in time. This is preferred since chatty sources
// invariably move the logs value down faster as less chatty sources would be
// expired in the noise.
//
// The first loop performs blacklisting and worst offender pruning. Falling
// through when there are no notable worst offenders and have not hit the
// region lock preventing further worst offender pruning. This loop also looks
// after managing the chatty log entries and merging to help provide
// statistical basis for blame. The chatty entries are not a notification of
// how much logs you may have, but instead represent how much logs you would
// have had in a virtual log buffer that is extended to cover all the in-memory
// logs without loss. They last much longer than the represented pruned logs
// since they get multiplied by the gains in the non-chatty log sources.
//
// The second loop get complicated because an algorithm of watermarks and
// history is maintained to reduce the order and keep processing time
// down to a minimum at scale. These algorithms can be costly in the face
// of larger log buffers, or severly limited processing time granted to a
// background task at lowest priority.
//
// This second loop does straight-up expiration from the end of the logs
// (again, remember for the specified log buffer id) but does some whitelist
// preservation. Thus whitelist is a Hail Mary low priority, blacklists and
// spam filtration all take priority. This second loop also checks if a region
// lock is causing us to buffer too much in the logs to help the reader(s),
// and will tell the slowest reader thread to skip log entries, and if
// persistent and hits a further threshold, kill the reader thread.
//
// The third thread is optional, and only gets hit if there was a whitelist
// and more needs to be pruned against the backstop of the region lock.
//
// mLogElementsLock must be held when this function is called.
//
bool LogBuffer::prune(log_id_t id, unsigned long pruneRows, uid_t caller_uid) {
    LogTimeEntry* oldest = NULL;
    bool busy = false;
    bool clearAll = pruneRows == ULONG_MAX;

    LogTimeEntry::lock();

    // Region locked?
    LastLogTimes::iterator times = mTimes.begin();
    while (times != mTimes.end()) {
        LogTimeEntry* entry = (*times);
        if (entry->owned_Locked() && entry->isWatching(id) &&
            (!oldest || (oldest->mStart > entry->mStart) ||
             ((oldest->mStart == entry->mStart) &&
              (entry->mTimeout.tv_sec || entry->mTimeout.tv_nsec)))) {
            oldest = entry;
        }
        times++;
    }

    LogBufferElementCollection::iterator it;

    if (__predict_false(caller_uid != AID_ROOT)) {  // unlikely
        // Only here if clear all request from non system source, so chatty
        // filter logistics is not required.
        it = mLastSet[id] ? mLast[id] : mLogElements.begin();
        while (it != mLogElements.end()) {
            LogBufferElement* element = *it;

            if ((element->getLogId() != id) ||
                (element->getUid() != caller_uid)) {
                ++it;
                continue;
            }

            if (!mLastSet[id] || ((*mLast[id])->getLogId() != id)) {
                mLast[id] = it;
                mLastSet[id] = true;
            }

            if (oldest && (oldest->mStart <= element->getSequence())) {
                busy = true;
                if (oldest->mTimeout.tv_sec || oldest->mTimeout.tv_nsec) {
                    oldest->triggerReader_Locked();
                } else {
                    oldest->triggerSkip_Locked(id, pruneRows);
                }
                break;
            }

            it = erase(it);
            if (--pruneRows == 0) {
                break;
            }
        }
        LogTimeEntry::unlock();
        return busy;
    }

    // prune by worst offenders; by blacklist, UID, and by PID of system UID
    bool hasBlacklist = (id != LOG_ID_SECURITY) && mPrune.naughty();
    while (!clearAll && (pruneRows > 0)) {
        // recalculate the worst offender on every batched pass
        int worst = -1;  // not valid for getUid() or getKey()
        size_t worst_sizes = 0;
        size_t second_worst_sizes = 0;
        pid_t worstPid = 0;  // POSIX guarantees PID != 0

        if (worstUidEnabledForLogid(id) && mPrune.worstUidEnabled()) {
            // Calculate threshold as 12.5% of available storage
            size_t threshold = log_buffer_size(id) / 8;

            if ((id == LOG_ID_EVENTS) || (id == LOG_ID_SECURITY)) {
                stats.sortTags(AID_ROOT, (pid_t)0, 2, id)
                    .findWorst(worst, worst_sizes, second_worst_sizes,
                               threshold);
                // per-pid filter for AID_SYSTEM sources is too complex
            } else {
                stats.sort(AID_ROOT, (pid_t)0, 2, id)
                    .findWorst(worst, worst_sizes, second_worst_sizes,
                               threshold);

                if ((worst == AID_SYSTEM) && mPrune.worstPidOfSystemEnabled()) {
                    stats.sortPids(worst, (pid_t)0, 2, id)
                        .findWorst(worstPid, worst_sizes, second_worst_sizes);
                }
            }
        }

        // skip if we have neither worst nor naughty filters
        if ((worst == -1) && !hasBlacklist) {
            break;
        }

        bool kick = false;
        bool leading = true;
        it = mLastSet[id] ? mLast[id] : mLogElements.begin();
        // Perform at least one mandatory garbage collection cycle in following
        // - clear leading chatty tags
        // - coalesce chatty tags
        // - check age-out of preserved logs
        bool gc = pruneRows <= 1;
        if (!gc && (worst != -1)) {
            {  // begin scope for worst found iterator
                LogBufferIteratorMap::iterator found =
                    mLastWorst[id].find(worst);
                if ((found != mLastWorst[id].end()) &&
                    (found->second != mLogElements.end())) {
                    leading = false;
                    it = found->second;
                }
            }
            if (worstPid) {  // begin scope for pid worst found iterator
                // FYI: worstPid only set if !LOG_ID_EVENTS and
                //      !LOG_ID_SECURITY, not going to make that assumption ...
                LogBufferPidIteratorMap::iterator found =
                    mLastWorstPidOfSystem[id].find(worstPid);
                if ((found != mLastWorstPidOfSystem[id].end()) &&
                    (found->second != mLogElements.end())) {
                    leading = false;
                    it = found->second;
                }
            }
        }
        static const timespec too_old = { EXPIRE_HOUR_THRESHOLD * 60 * 60, 0 };
        LogBufferElementCollection::iterator lastt;
        lastt = mLogElements.end();
        --lastt;
        LogBufferElementLast last;
        while (it != mLogElements.end()) {
            LogBufferElement* element = *it;

            if (oldest && (oldest->mStart <= element->getSequence())) {
                busy = true;
                if (oldest->mTimeout.tv_sec || oldest->mTimeout.tv_nsec) {
                    oldest->triggerReader_Locked();
                }
                break;
            }

            if (element->getLogId() != id) {
                ++it;
                continue;
            }
            // below this point element->getLogId() == id

            if (leading && (!mLastSet[id] || ((*mLast[id])->getLogId() != id))) {
                mLast[id] = it;
                mLastSet[id] = true;
            }

            unsigned short dropped = element->getDropped();

            // remove any leading drops
            if (leading && dropped) {
                it = erase(it);
                continue;
            }

            if (dropped && last.coalesce(element, dropped)) {
                it = erase(it, true);
                continue;
            }

            int key = ((id == LOG_ID_EVENTS) || (id == LOG_ID_SECURITY))
                          ? element->getTag()
                          : element->getUid();

            if (hasBlacklist && mPrune.naughty(element)) {
                last.clear(element);
                it = erase(it);
                if (dropped) {
                    continue;
                }

                pruneRows--;
                if (pruneRows == 0) {
                    break;
                }

                if (key == worst) {
                    kick = true;
                    if (worst_sizes < second_worst_sizes) {
                        break;
                    }
                    worst_sizes -= element->getMsgLen();
                }
                continue;
            }

            if ((element->getRealTime() < ((*lastt)->getRealTime() - too_old)) ||
                (element->getRealTime() > (*lastt)->getRealTime())) {
                break;
            }

            if (dropped) {
                last.add(element);
                if (worstPid &&
                    ((!gc && (element->getPid() == worstPid)) ||
                     (mLastWorstPidOfSystem[id].find(element->getPid()) ==
                      mLastWorstPidOfSystem[id].end()))) {
                    // element->getUid() may not be AID_SYSTEM, next best
                    // watermark if current one empty. id is not LOG_ID_EVENTS
                    // or LOG_ID_SECURITY because of worstPid check.
                    mLastWorstPidOfSystem[id][element->getPid()] = it;
                }
                if ((!gc && !worstPid && (key == worst)) ||
                    (mLastWorst[id].find(key) == mLastWorst[id].end())) {
                    mLastWorst[id][key] = it;
                }
                ++it;
                continue;
            }

            if ((key != worst) ||
                (worstPid && (element->getPid() != worstPid))) {
                leading = false;
                last.clear(element);
                ++it;
                continue;
            }
            // key == worst below here
            // If worstPid set, then element->getPid() == worstPid below here

            pruneRows--;
            if (pruneRows == 0) {
                break;
            }

            kick = true;

            unsigned short len = element->getMsgLen();

            // do not create any leading drops
            if (leading) {
                it = erase(it);
            } else {
                stats.drop(element);
                element->setDropped(1);
                if (last.coalesce(element, 1)) {
                    it = erase(it, true);
                } else {
                    last.add(element);
                    if (worstPid &&
                        (!gc || (mLastWorstPidOfSystem[id].find(worstPid) ==
                                 mLastWorstPidOfSystem[id].end()))) {
                        // element->getUid() may not be AID_SYSTEM, next best
                        // watermark if current one empty. id is not
                        // LOG_ID_EVENTS or LOG_ID_SECURITY because of worstPid.
                        mLastWorstPidOfSystem[id][worstPid] = it;
                    }
                    if ((!gc && !worstPid) ||
                        (mLastWorst[id].find(worst) == mLastWorst[id].end())) {
                        mLastWorst[id][worst] = it;
                    }
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
            break;  // the following loop will ask bad clients to skip/drop
        }
    }

    bool whitelist = false;
    bool hasWhitelist = (id != LOG_ID_SECURITY) && mPrune.nice() && !clearAll;
    it = mLastSet[id] ? mLast[id] : mLogElements.begin();
    while ((pruneRows > 0) && (it != mLogElements.end())) {
        LogBufferElement* element = *it;

        if (element->getLogId() != id) {
            it++;
            continue;
        }

        if (!mLastSet[id] || ((*mLast[id])->getLogId() != id)) {
            mLast[id] = it;
            mLastSet[id] = true;
        }

        if (oldest && (oldest->mStart <= element->getSequence())) {
            busy = true;
            if (whitelist) {
                break;
            }

            if (stats.sizes(id) > (2 * log_buffer_size(id))) {
                // kick a misbehaving log reader client off the island
                oldest->release_Locked();
            } else if (oldest->mTimeout.tv_sec || oldest->mTimeout.tv_nsec) {
                oldest->triggerReader_Locked();
            } else {
                oldest->triggerSkip_Locked(id, pruneRows);
            }
            break;
        }

        if (hasWhitelist && !element->getDropped() && mPrune.nice(element)) {
            // WhiteListed
            whitelist = true;
            it++;
            continue;
        }

        it = erase(it);
        pruneRows--;
    }

    // Do not save the whitelist if we are reader range limited
    if (whitelist && (pruneRows > 0)) {
        it = mLastSet[id] ? mLast[id] : mLogElements.begin();
        while ((it != mLogElements.end()) && (pruneRows > 0)) {
            LogBufferElement* element = *it;

            if (element->getLogId() != id) {
                ++it;
                continue;
            }

            if (!mLastSet[id] || ((*mLast[id])->getLogId() != id)) {
                mLast[id] = it;
                mLastSet[id] = true;
            }

            if (oldest && (oldest->mStart <= element->getSequence())) {
                busy = true;
                if (stats.sizes(id) > (2 * log_buffer_size(id))) {
                    // kick a misbehaving log reader client off the island
                    oldest->release_Locked();
                } else if (oldest->mTimeout.tv_sec || oldest->mTimeout.tv_nsec) {
                    oldest->triggerReader_Locked();
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

    return (pruneRows > 0) && busy;
}

// clear all rows of type "id" from the buffer.
bool LogBuffer::clear(log_id_t id, uid_t uid) {
    bool busy = true;
    // If it takes more than 4 tries (seconds) to clear, then kill reader(s)
    for (int retry = 4;;) {
        if (retry == 1) {  // last pass
            // Check if it is still busy after the sleep, we say prune
            // one entry, not another clear run, so we are looking for
            // the quick side effect of the return value to tell us if
            // we have a _blocked_ reader.
            pthread_mutex_lock(&mLogElementsLock);
            busy = prune(id, 1, uid);
            pthread_mutex_unlock(&mLogElementsLock);
            // It is still busy, blocked reader(s), lets kill them all!
            // otherwise, lets be a good citizen and preserve the slow
            // readers and let the clear run (below) deal with determining
            // if we are still blocked and return an error code to caller.
            if (busy) {
                LogTimeEntry::lock();
                LastLogTimes::iterator times = mTimes.begin();
                while (times != mTimes.end()) {
                    LogTimeEntry* entry = (*times);
                    // Killer punch
                    if (entry->owned_Locked() && entry->isWatching(id)) {
                        entry->release_Locked();
                    }
                    times++;
                }
                LogTimeEntry::unlock();
            }
        }
        pthread_mutex_lock(&mLogElementsLock);
        busy = prune(id, ULONG_MAX, uid);
        pthread_mutex_unlock(&mLogElementsLock);
        if (!busy || !--retry) {
            break;
        }
        sleep(1);  // Let reader(s) catch up after notification
    }
    return busy;
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
    if (!__android_logger_valid_buffer_size(size)) {
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
    SocketClient* reader, const uint64_t start, bool privileged, bool security,
    int (*filter)(const LogBufferElement* element, void* arg), void* arg) {
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
        for (it = mLogElements.end(); it != mLogElements.begin();
             /* do nothing */) {
            --it;
            LogBufferElement* element = *it;
            if (element->getSequence() <= start) {
                it++;
                break;
            }
        }
    }

    // Help detect if the valid message before is from the same source so
    // we can differentiate chatty filter types.
    pid_t lastTid[LOG_ID_MAX] = { 0 };

    for (; it != mLogElements.end(); ++it) {
        LogBufferElement* element = *it;

        if (!privileged && (element->getUid() != uid)) {
            continue;
        }

        if (!security && (element->getLogId() == LOG_ID_SECURITY)) {
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

        bool sameTid = lastTid[element->getLogId()] == element->getTid();
        // Dropped (chatty) immediately following a valid log from the
        // same source in the same log buffer indicates we have a
        // multiple identical squash.  chatty that differs source
        // is due to spam filter.  chatty to chatty of different
        // source is also due to spam filter.
        lastTid[element->getLogId()] =
            (element->getDropped() && !sameTid) ? 0 : element->getTid();

        pthread_mutex_unlock(&mLogElementsLock);

        // range locking in LastLogTimes looks after us
        max = element->flushTo(reader, this, privileged, sameTid);

        if (max == element->FLUSH_ERROR) {
            return max;
        }

        pthread_mutex_lock(&mLogElementsLock);
    }
    pthread_mutex_unlock(&mLogElementsLock);

    return max;
}

std::string LogBuffer::formatStatistics(uid_t uid, pid_t pid,
                                        unsigned int logMask) {
    pthread_mutex_lock(&mLogElementsLock);

    std::string ret = stats.format(uid, pid, logMask);

    pthread_mutex_unlock(&mLogElementsLock);

    return ret;
}
