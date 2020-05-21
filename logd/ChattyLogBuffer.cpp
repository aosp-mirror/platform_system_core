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
// for manual checking of stale entries during ChattyLogBuffer::erase()
//#define DEBUG_CHECK_FOR_STALE_ENTRIES

#include "ChattyLogBuffer.h"

#include <ctype.h>
#include <endian.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/cdefs.h>
#include <sys/user.h>
#include <time.h>
#include <unistd.h>

#include <limits>
#include <unordered_map>
#include <utility>

#include <private/android_logger.h>

#include "LogUtils.h"

#ifndef __predict_false
#define __predict_false(exp) __builtin_expect((exp) != 0, 0)
#endif

// Default
#define log_buffer_size(id) mMaxSize[id]

void ChattyLogBuffer::Init() {
    log_id_for_each(i) {
        if (SetSize(i, __android_logger_get_buffer_size(i))) {
            SetSize(i, LOG_BUFFER_MIN_SIZE);
        }
    }
    // Release any sleeping reader threads to dump their current content.
    auto reader_threads_lock = std::lock_guard{reader_list_->reader_threads_lock()};
    for (const auto& reader_thread : reader_list_->reader_threads()) {
        reader_thread->triggerReader_Locked();
    }
}

ChattyLogBuffer::ChattyLogBuffer(LogReaderList* reader_list, LogTags* tags, PruneList* prune,
                                 LogStatistics* stats)
    : reader_list_(reader_list), tags_(tags), prune_(prune), stats_(stats) {
    pthread_rwlock_init(&mLogElementsLock, nullptr);

    log_id_for_each(i) {
        lastLoggedElements[i] = nullptr;
        droppedElements[i] = nullptr;
    }

    Init();
}

ChattyLogBuffer::~ChattyLogBuffer() {
    log_id_for_each(i) {
        delete lastLoggedElements[i];
        delete droppedElements[i];
    }
}

LogBufferElementCollection::iterator ChattyLogBuffer::GetOldest(log_id_t log_id) {
    auto it = mLogElements.begin();
    if (oldest_[log_id]) {
        it = *oldest_[log_id];
    }
    while (it != mLogElements.end() && (*it)->getLogId() != log_id) {
        it++;
    }
    if (it != mLogElements.end()) {
        oldest_[log_id] = it;
    }
    return it;
}

enum match_type { DIFFERENT, SAME, SAME_LIBLOG };

static enum match_type identical(LogBufferElement* elem, LogBufferElement* last) {
    // is it mostly identical?
    //  if (!elem) return DIFFERENT;
    ssize_t lenl = elem->getMsgLen();
    if (lenl <= 0) return DIFFERENT;  // value if this represents a chatty elem
    //  if (!last) return DIFFERENT;
    ssize_t lenr = last->getMsgLen();
    if (lenr <= 0) return DIFFERENT;  // value if this represents a chatty elem
    //  if (elem->getLogId() != last->getLogId()) return DIFFERENT;
    if (elem->getUid() != last->getUid()) return DIFFERENT;
    if (elem->getPid() != last->getPid()) return DIFFERENT;
    if (elem->getTid() != last->getTid()) return DIFFERENT;

    // last is more than a minute old, stop squashing identical messages
    if (elem->getRealTime().nsec() > (last->getRealTime().nsec() + 60 * NS_PER_SEC))
        return DIFFERENT;

    // Identical message
    const char* msgl = elem->getMsg();
    const char* msgr = last->getMsg();
    if (lenl == lenr) {
        if (!fastcmp<memcmp>(msgl, msgr, lenl)) return SAME;
        // liblog tagged messages (content gets summed)
        if (elem->getLogId() == LOG_ID_EVENTS && lenl == sizeof(android_log_event_int_t) &&
            !fastcmp<memcmp>(msgl, msgr, sizeof(android_log_event_int_t) - sizeof(int32_t)) &&
            elem->getTag() == LIBLOG_LOG_TAG) {
            return SAME_LIBLOG;
        }
    }

    // audit message (except sequence number) identical?
    if (last->isBinary() && lenl > static_cast<ssize_t>(sizeof(android_log_event_string_t)) &&
        lenr > static_cast<ssize_t>(sizeof(android_log_event_string_t))) {
        if (fastcmp<memcmp>(msgl, msgr, sizeof(android_log_event_string_t) - sizeof(int32_t))) {
            return DIFFERENT;
        }
        msgl += sizeof(android_log_event_string_t);
        lenl -= sizeof(android_log_event_string_t);
        msgr += sizeof(android_log_event_string_t);
        lenr -= sizeof(android_log_event_string_t);
    }
    static const char avc[] = "): avc: ";
    const char* avcl = android::strnstr(msgl, lenl, avc);
    if (!avcl) return DIFFERENT;
    lenl -= avcl - msgl;
    const char* avcr = android::strnstr(msgr, lenr, avc);
    if (!avcr) return DIFFERENT;
    lenr -= avcr - msgr;
    if (lenl != lenr) return DIFFERENT;
    if (fastcmp<memcmp>(avcl + strlen(avc), avcr + strlen(avc), lenl - strlen(avc))) {
        return DIFFERENT;
    }
    return SAME;
}

int ChattyLogBuffer::Log(log_id_t log_id, log_time realtime, uid_t uid, pid_t pid, pid_t tid,
                         const char* msg, uint16_t len) {
    if (log_id >= LOG_ID_MAX) {
        return -EINVAL;
    }

    // Slip the time by 1 nsec if the incoming lands on xxxxxx000 ns.
    // This prevents any chance that an outside source can request an
    // exact entry with time specified in ms or us precision.
    if ((realtime.tv_nsec % 1000) == 0) ++realtime.tv_nsec;

    LogBufferElement* elem = new LogBufferElement(log_id, realtime, uid, pid, tid, msg, len);

    // b/137093665: don't coalesce security messages.
    if (log_id == LOG_ID_SECURITY) {
        wrlock();
        log(elem);
        unlock();

        return len;
    }

    int prio = ANDROID_LOG_INFO;
    const char* tag = nullptr;
    size_t tag_len = 0;
    if (log_id == LOG_ID_EVENTS || log_id == LOG_ID_STATS) {
        tag = tags_->tagToName(elem->getTag());
        if (tag) {
            tag_len = strlen(tag);
        }
    } else {
        prio = *msg;
        tag = msg + 1;
        tag_len = strnlen(tag, len - 1);
    }
    if (!__android_log_is_loggable_len(prio, tag, tag_len, ANDROID_LOG_VERBOSE)) {
        // Log traffic received to total
        stats_->AddTotal(elem);
        delete elem;
        return -EACCES;
    }

    wrlock();
    LogBufferElement* currentLast = lastLoggedElements[log_id];
    if (currentLast) {
        LogBufferElement* dropped = droppedElements[log_id];
        uint16_t count = dropped ? dropped->getDropped() : 0;
        //
        // State Init
        //     incoming:
        //         dropped = nullptr
        //         currentLast = nullptr;
        //         elem = incoming message
        //     outgoing:
        //         dropped = nullptr -> State 0
        //         currentLast = copy of elem
        //         log elem
        // State 0
        //     incoming:
        //         count = 0
        //         dropped = nullptr
        //         currentLast = copy of last message
        //         elem = incoming message
        //     outgoing: if match != DIFFERENT
        //         dropped = copy of first identical message -> State 1
        //         currentLast = reference to elem
        //     break: if match == DIFFERENT
        //         dropped = nullptr -> State 0
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
        //         dropped = nullptr -> State 0
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
        //         dropped = nullptr -> State 0
        //         log reference to last held-back (currentLast)
        //         currentLast = copy of elem
        //         log elem
        //
        enum match_type match = identical(elem, currentLast);
        if (match != DIFFERENT) {
            if (dropped) {
                // Sum up liblog tag messages?
                if ((count == 0) /* at Pass 1 */ && (match == SAME_LIBLOG)) {
                    android_log_event_int_t* event = reinterpret_cast<android_log_event_int_t*>(
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
                    if (total >= std::numeric_limits<int32_t>::max()) {
                        log(currentLast);
                        unlock();
                        return len;
                    }
                    stats_->AddTotal(currentLast);
                    delete currentLast;
                    swab = total;
                    event->payload.data = htole32(swab);
                    unlock();
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
                stats_->AddTotal(currentLast);
                currentLast->setDropped(count);
            }
            droppedElements[log_id] = currentLast;
            lastLoggedElements[log_id] = elem;
            unlock();
            return len;
        }
        if (dropped) {         // State 1 or 2
            if (count) {       // State 2
                log(dropped);  // report chatty
            } else {           // State 1
                delete dropped;
            }
            droppedElements[log_id] = nullptr;
            log(currentLast);  // report last message in the series
        } else {               // State 0
            delete currentLast;
        }
    }
    lastLoggedElements[log_id] = new LogBufferElement(*elem);

    log(elem);
    unlock();

    return len;
}

// assumes ChattyLogBuffer::wrlock() held, owns elem, look after garbage collection
void ChattyLogBuffer::log(LogBufferElement* elem) {
    mLogElements.push_back(elem);
    stats_->Add(elem);
    maybePrune(elem->getLogId());
    reader_list_->NotifyNewLog(1 << elem->getLogId());
}

// ChattyLogBuffer::wrlock() must be held when this function is called.
void ChattyLogBuffer::maybePrune(log_id_t id) {
    unsigned long prune_rows;
    if (stats_->ShouldPrune(id, log_buffer_size(id), &prune_rows)) {
        prune(id, prune_rows);
    }
}

LogBufferElementCollection::iterator ChattyLogBuffer::erase(LogBufferElementCollection::iterator it,
                                                            bool coalesce) {
    LogBufferElement* element = *it;
    log_id_t id = element->getLogId();

    // Remove iterator references in the various lists that will become stale
    // after the element is erased from the main logging list.

    {  // start of scope for found iterator
        int key = (id == LOG_ID_EVENTS || id == LOG_ID_SECURITY) ? element->getTag()
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
        LogBufferPidIteratorMap::iterator found = mLastWorstPidOfSystem[id].find(element->getPid());
        if (found != mLastWorstPidOfSystem[id].end() && it == found->second) {
            mLastWorstPidOfSystem[id].erase(found);
        }
    }

    bool setLast[LOG_ID_MAX];
    bool doSetLast = false;
    log_id_for_each(i) { doSetLast |= setLast[i] = oldest_[i] && it == *oldest_[i]; }
#ifdef DEBUG_CHECK_FOR_STALE_ENTRIES
    LogBufferElementCollection::iterator bad = it;
    int key =
            (id == LOG_ID_EVENTS || id == LOG_ID_SECURITY) ? element->getTag() : element->getUid();
#endif
    it = mLogElements.erase(it);
    if (doSetLast) {
        log_id_for_each(i) {
            if (setLast[i]) {
                if (__predict_false(it == mLogElements.end())) {
                    oldest_[i] = std::nullopt;
                } else {
                    oldest_[i] = it;  // Store the next iterator even if it does not correspond to
                                      // the same log_id, as a starting point for GetOldest().
                }
            }
        }
    }
#ifdef DEBUG_CHECK_FOR_STALE_ENTRIES
    log_id_for_each(i) {
        for (auto b : mLastWorst[i]) {
            if (bad == b.second) {
                android::prdebug("stale mLastWorst[%d] key=%d mykey=%d\n", i, b.first, key);
            }
        }
        for (auto b : mLastWorstPidOfSystem[i]) {
            if (bad == b.second) {
                android::prdebug("stale mLastWorstPidOfSystem[%d] pid=%d\n", i, b.first);
            }
        }
    }
#endif
    if (coalesce) {
        stats_->Erase(element);
    } else {
        stats_->Subtract(element);
    }
    delete element;

    return it;
}

// Define a temporary mechanism to report the last LogBufferElement pointer
// for the specified uid, pid and tid. Used below to help merge-sort when
// pruning for worst UID.
class LogBufferElementLast {
    typedef std::unordered_map<uint64_t, LogBufferElement*> LogBufferElementMap;
    LogBufferElementMap map;

  public:
    bool coalesce(LogBufferElement* element, uint16_t dropped) {
        uint64_t key = LogBufferElementKey(element->getUid(), element->getPid(), element->getTid());
        LogBufferElementMap::iterator it = map.find(key);
        if (it != map.end()) {
            LogBufferElement* found = it->second;
            uint16_t moreDropped = found->getDropped();
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
        uint64_t key = LogBufferElementKey(element->getUid(), element->getPid(), element->getTid());
        map[key] = element;
    }

    void clear() { map.clear(); }

    void clear(LogBufferElement* element) {
        uint64_t current = element->getRealTime().nsec() - (EXPIRE_RATELIMIT * NS_PER_SEC);
        for (LogBufferElementMap::iterator it = map.begin(); it != map.end();) {
            LogBufferElement* mapElement = it->second;
            if (mapElement->getDropped() >= EXPIRE_THRESHOLD &&
                current > mapElement->getRealTime().nsec()) {
                it = map.erase(it);
            } else {
                ++it;
            }
        }
    }

  private:
    uint64_t LogBufferElementKey(uid_t uid, pid_t pid, pid_t tid) {
        return uint64_t(uid) << 32 | uint64_t(pid) << 16 | uint64_t(tid);
    }
};

// If the selected reader is blocking our pruning progress, decide on
// what kind of mitigation is necessary to unblock the situation.
void ChattyLogBuffer::kickMe(LogReaderThread* me, log_id_t id, unsigned long pruneRows) {
    if (stats_->Sizes(id) > (2 * log_buffer_size(id))) {  // +100%
        // A misbehaving or slow reader has its connection
        // dropped if we hit too much memory pressure.
        android::prdebug("Kicking blocked reader, %s, from ChattyLogBuffer::kickMe()\n",
                         me->name().c_str());
        me->release_Locked();
    } else if (me->deadline().time_since_epoch().count() != 0) {
        // Allow a blocked WRAP deadline reader to trigger and start reporting the log data.
        me->triggerReader_Locked();
    } else {
        // tell slow reader to skip entries to catch up
        android::prdebug(
                "Skipping %lu entries from slow reader, %s, from ChattyLogBuffer::kickMe()\n",
                pruneRows, me->name().c_str());
        me->triggerSkip_Locked(id, pruneRows);
    }
}

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
// ChattyLogBuffer::wrlock() must be held when this function is called.
//
bool ChattyLogBuffer::prune(log_id_t id, unsigned long pruneRows, uid_t caller_uid) {
    LogReaderThread* oldest = nullptr;
    bool busy = false;
    bool clearAll = pruneRows == ULONG_MAX;

    auto reader_threads_lock = std::lock_guard{reader_list_->reader_threads_lock()};

    // Region locked?
    for (const auto& reader_thread : reader_list_->reader_threads()) {
        if (!reader_thread->IsWatching(id)) {
            continue;
        }
        if (!oldest || oldest->start() > reader_thread->start() ||
            (oldest->start() == reader_thread->start() &&
             reader_thread->deadline().time_since_epoch().count() != 0)) {
            oldest = reader_thread.get();
        }
    }

    LogBufferElementCollection::iterator it;

    if (__predict_false(caller_uid != AID_ROOT)) {  // unlikely
        // Only here if clear all request from non system source, so chatty
        // filter logistics is not required.
        it = GetOldest(id);
        while (it != mLogElements.end()) {
            LogBufferElement* element = *it;

            if (element->getLogId() != id || element->getUid() != caller_uid) {
                ++it;
                continue;
            }

            if (oldest && oldest->start() <= element->getSequence()) {
                busy = true;
                kickMe(oldest, id, pruneRows);
                break;
            }

            it = erase(it);
            if (--pruneRows == 0) {
                break;
            }
        }
        return busy;
    }

    // prune by worst offenders; by blacklist, UID, and by PID of system UID
    bool hasBlacklist = (id != LOG_ID_SECURITY) && prune_->naughty();
    while (!clearAll && (pruneRows > 0)) {
        // recalculate the worst offender on every batched pass
        int worst = -1;  // not valid for getUid() or getKey()
        size_t worst_sizes = 0;
        size_t second_worst_sizes = 0;
        pid_t worstPid = 0;  // POSIX guarantees PID != 0

        if (worstUidEnabledForLogid(id) && prune_->worstUidEnabled()) {
            // Calculate threshold as 12.5% of available storage
            size_t threshold = log_buffer_size(id) / 8;

            if (id == LOG_ID_EVENTS || id == LOG_ID_SECURITY) {
                stats_->WorstTwoTags(threshold, &worst, &worst_sizes, &second_worst_sizes);
                // per-pid filter for AID_SYSTEM sources is too complex
            } else {
                stats_->WorstTwoUids(id, threshold, &worst, &worst_sizes, &second_worst_sizes);

                if (worst == AID_SYSTEM && prune_->worstPidOfSystemEnabled()) {
                    stats_->WorstTwoSystemPids(id, worst_sizes, &worstPid, &second_worst_sizes);
                }
            }
        }

        // skip if we have neither worst nor naughty filters
        if ((worst == -1) && !hasBlacklist) {
            break;
        }

        bool kick = false;
        bool leading = true;  // true if starting from the oldest log entry, false if starting from
                              // a specific chatty entry.
        // Perform at least one mandatory garbage collection cycle in following
        // - clear leading chatty tags
        // - coalesce chatty tags
        // - check age-out of preserved logs
        bool gc = pruneRows <= 1;
        if (!gc && (worst != -1)) {
            {  // begin scope for worst found iterator
                LogBufferIteratorMap::iterator found = mLastWorst[id].find(worst);
                if (found != mLastWorst[id].end() && found->second != mLogElements.end()) {
                    leading = false;
                    it = found->second;
                }
            }
            if (worstPid) {  // begin scope for pid worst found iterator
                // FYI: worstPid only set if !LOG_ID_EVENTS and
                //      !LOG_ID_SECURITY, not going to make that assumption ...
                LogBufferPidIteratorMap::iterator found = mLastWorstPidOfSystem[id].find(worstPid);
                if (found != mLastWorstPidOfSystem[id].end() &&
                    found->second != mLogElements.end()) {
                    leading = false;
                    it = found->second;
                }
            }
        }
        if (leading) {
            it = GetOldest(id);
        }
        static const log_time too_old{EXPIRE_HOUR_THRESHOLD * 60 * 60, 0};
        LogBufferElementCollection::iterator lastt;
        lastt = mLogElements.end();
        --lastt;
        LogBufferElementLast last;
        while (it != mLogElements.end()) {
            LogBufferElement* element = *it;

            if (oldest && oldest->start() <= element->getSequence()) {
                busy = true;
                // Do not let chatty eliding trigger any reader mitigation
                break;
            }

            if (element->getLogId() != id) {
                ++it;
                continue;
            }
            // below this point element->getLogId() == id

            uint16_t dropped = element->getDropped();

            // remove any leading drops
            if (leading && dropped) {
                it = erase(it);
                continue;
            }

            if (dropped && last.coalesce(element, dropped)) {
                it = erase(it, true);
                continue;
            }

            int key = (id == LOG_ID_EVENTS || id == LOG_ID_SECURITY) ? element->getTag()
                                                                     : element->getUid();

            if (hasBlacklist && prune_->naughty(element)) {
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
                if (worstPid && ((!gc && element->getPid() == worstPid) ||
                                 mLastWorstPidOfSystem[id].find(element->getPid()) ==
                                         mLastWorstPidOfSystem[id].end())) {
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

            if (key != worst || (worstPid && element->getPid() != worstPid)) {
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

            uint16_t len = element->getMsgLen();

            // do not create any leading drops
            if (leading) {
                it = erase(it);
            } else {
                stats_->Drop(element);
                element->setDropped(1);
                if (last.coalesce(element, 1)) {
                    it = erase(it, true);
                } else {
                    last.add(element);
                    if (worstPid && (!gc || mLastWorstPidOfSystem[id].find(worstPid) ==
                                                    mLastWorstPidOfSystem[id].end())) {
                        // element->getUid() may not be AID_SYSTEM, next best
                        // watermark if current one empty. id is not
                        // LOG_ID_EVENTS or LOG_ID_SECURITY because of worstPid.
                        mLastWorstPidOfSystem[id][worstPid] = it;
                    }
                    if ((!gc && !worstPid) || mLastWorst[id].find(worst) == mLastWorst[id].end()) {
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

        if (!kick || !prune_->worstUidEnabled()) {
            break;  // the following loop will ask bad clients to skip/drop
        }
    }

    bool whitelist = false;
    bool hasWhitelist = (id != LOG_ID_SECURITY) && prune_->nice() && !clearAll;
    it = GetOldest(id);
    while ((pruneRows > 0) && (it != mLogElements.end())) {
        LogBufferElement* element = *it;

        if (element->getLogId() != id) {
            it++;
            continue;
        }

        if (oldest && oldest->start() <= element->getSequence()) {
            busy = true;
            if (!whitelist) kickMe(oldest, id, pruneRows);
            break;
        }

        if (hasWhitelist && !element->getDropped() && prune_->nice(element)) {
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
        it = GetOldest(id);
        while ((it != mLogElements.end()) && (pruneRows > 0)) {
            LogBufferElement* element = *it;

            if (element->getLogId() != id) {
                ++it;
                continue;
            }

            if (oldest && oldest->start() <= element->getSequence()) {
                busy = true;
                kickMe(oldest, id, pruneRows);
                break;
            }

            it = erase(it);
            pruneRows--;
        }
    }

    return (pruneRows > 0) && busy;
}

// clear all rows of type "id" from the buffer.
bool ChattyLogBuffer::Clear(log_id_t id, uid_t uid) {
    bool busy = true;
    // If it takes more than 4 tries (seconds) to clear, then kill reader(s)
    for (int retry = 4;;) {
        if (retry == 1) {  // last pass
            // Check if it is still busy after the sleep, we say prune
            // one entry, not another clear run, so we are looking for
            // the quick side effect of the return value to tell us if
            // we have a _blocked_ reader.
            wrlock();
            busy = prune(id, 1, uid);
            unlock();
            // It is still busy, blocked reader(s), lets kill them all!
            // otherwise, lets be a good citizen and preserve the slow
            // readers and let the clear run (below) deal with determining
            // if we are still blocked and return an error code to caller.
            if (busy) {
                auto reader_threads_lock = std::lock_guard{reader_list_->reader_threads_lock()};
                for (const auto& reader_thread : reader_list_->reader_threads()) {
                    if (reader_thread->IsWatching(id)) {
                        android::prdebug(
                                "Kicking blocked reader, %s, from ChattyLogBuffer::clear()\n",
                                reader_thread->name().c_str());
                        reader_thread->release_Locked();
                    }
                }
            }
        }
        wrlock();
        busy = prune(id, ULONG_MAX, uid);
        unlock();
        if (!busy || !--retry) {
            break;
        }
        sleep(1);  // Let reader(s) catch up after notification
    }
    return busy;
}

// set the total space allocated to "id"
int ChattyLogBuffer::SetSize(log_id_t id, unsigned long size) {
    // Reasonable limits ...
    if (!__android_logger_valid_buffer_size(size)) {
        return -1;
    }
    wrlock();
    log_buffer_size(id) = size;
    unlock();
    return 0;
}

// get the total space allocated to "id"
unsigned long ChattyLogBuffer::GetSize(log_id_t id) {
    rdlock();
    size_t retval = log_buffer_size(id);
    unlock();
    return retval;
}

uint64_t ChattyLogBuffer::FlushTo(
        LogWriter* writer, uint64_t start, pid_t* lastTid,
        const std::function<FlushToResult(const LogBufferElement* element)>& filter) {
    LogBufferElementCollection::iterator it;
    uid_t uid = writer->uid();

    rdlock();

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

    uint64_t curr = start;

    for (; it != mLogElements.end(); ++it) {
        LogBufferElement* element = *it;

        if (!writer->privileged() && element->getUid() != uid) {
            continue;
        }

        if (!writer->can_read_security_logs() && element->getLogId() == LOG_ID_SECURITY) {
            continue;
        }

        // NB: calling out to another object with wrlock() held (safe)
        if (filter) {
            FlushToResult ret = filter(element);
            if (ret == FlushToResult::kSkip) {
                continue;
            }
            if (ret == FlushToResult::kStop) {
                break;
            }
        }

        bool sameTid = false;
        if (lastTid) {
            sameTid = lastTid[element->getLogId()] == element->getTid();
            // Dropped (chatty) immediately following a valid log from the
            // same source in the same log buffer indicates we have a
            // multiple identical squash.  chatty that differs source
            // is due to spam filter.  chatty to chatty of different
            // source is also due to spam filter.
            lastTid[element->getLogId()] =
                    (element->getDropped() && !sameTid) ? 0 : element->getTid();
        }

        unlock();

        curr = element->getSequence();
        // range locking in LastLogTimes looks after us
        if (!element->FlushTo(writer, stats_, sameTid)) {
            return FLUSH_ERROR;
        }

        rdlock();
    }
    unlock();

    return curr;
}
