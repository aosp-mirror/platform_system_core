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

ChattyLogBuffer::ChattyLogBuffer(LogReaderList* reader_list, LogTags* tags, PruneList* prune,
                                 LogStatistics* stats)
    : SimpleLogBuffer(reader_list, tags, stats), prune_(prune) {}

ChattyLogBuffer::~ChattyLogBuffer() {}

enum match_type { DIFFERENT, SAME, SAME_LIBLOG };

static enum match_type Identical(const LogBufferElement& elem, const LogBufferElement& last) {
    ssize_t lenl = elem.msg_len();
    if (lenl <= 0) return DIFFERENT;  // value if this represents a chatty elem
    ssize_t lenr = last.msg_len();
    if (lenr <= 0) return DIFFERENT;  // value if this represents a chatty elem
    if (elem.uid() != last.uid()) return DIFFERENT;
    if (elem.pid() != last.pid()) return DIFFERENT;
    if (elem.tid() != last.tid()) return DIFFERENT;

    // last is more than a minute old, stop squashing identical messages
    if (elem.realtime().nsec() > (last.realtime().nsec() + 60 * NS_PER_SEC)) return DIFFERENT;

    // Identical message
    const char* msgl = elem.msg();
    const char* msgr = last.msg();
    if (lenl == lenr) {
        if (!fastcmp<memcmp>(msgl, msgr, lenl)) return SAME;
        // liblog tagged messages (content gets summed)
        if (elem.log_id() == LOG_ID_EVENTS && lenl == sizeof(android_log_event_int_t) &&
            !fastcmp<memcmp>(msgl, msgr, sizeof(android_log_event_int_t) - sizeof(int32_t)) &&
            elem.GetTag() == LIBLOG_LOG_TAG) {
            return SAME_LIBLOG;
        }
    }

    // audit message (except sequence number) identical?
    if (IsBinary(last.log_id()) &&
        lenl > static_cast<ssize_t>(sizeof(android_log_event_string_t)) &&
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

void ChattyLogBuffer::LogInternal(LogBufferElement&& elem) {
    // b/137093665: don't coalesce security messages.
    if (elem.log_id() == LOG_ID_SECURITY) {
        SimpleLogBuffer::LogInternal(std::move(elem));
        return;
    }
    int log_id = elem.log_id();

    // Initialize last_logged_elements_ to a copy of elem if logging the first element for a log_id.
    if (!last_logged_elements_[log_id]) {
        last_logged_elements_[log_id].emplace(elem);
        SimpleLogBuffer::LogInternal(std::move(elem));
        return;
    }

    LogBufferElement& current_last = *last_logged_elements_[log_id];
    enum match_type match = Identical(elem, current_last);

    if (match == DIFFERENT) {
        if (duplicate_elements_[log_id]) {
            // If we previously had 3+ identical messages, log the chatty message.
            if (duplicate_elements_[log_id]->dropped_count() > 0) {
                SimpleLogBuffer::LogInternal(std::move(*duplicate_elements_[log_id]));
            }
            duplicate_elements_[log_id].reset();
            // Log the saved copy of the last identical message seen.
            SimpleLogBuffer::LogInternal(std::move(current_last));
        }
        last_logged_elements_[log_id].emplace(elem);
        SimpleLogBuffer::LogInternal(std::move(elem));
        return;
    }

    // 2 identical message: set duplicate_elements_ appropriately.
    if (!duplicate_elements_[log_id]) {
        duplicate_elements_[log_id].emplace(std::move(current_last));
        last_logged_elements_[log_id].emplace(std::move(elem));
        return;
    }

    // 3+ identical LIBLOG event messages: coalesce them into last_logged_elements_.
    if (match == SAME_LIBLOG) {
        const android_log_event_int_t* current_last_event =
                reinterpret_cast<const android_log_event_int_t*>(current_last.msg());
        int64_t current_last_count = current_last_event->payload.data;
        android_log_event_int_t* elem_event =
                reinterpret_cast<android_log_event_int_t*>(const_cast<char*>(elem.msg()));
        int64_t elem_count = elem_event->payload.data;

        int64_t total = current_last_count + elem_count;
        if (total > std::numeric_limits<int32_t>::max()) {
            SimpleLogBuffer::LogInternal(std::move(current_last));
            last_logged_elements_[log_id].emplace(std::move(elem));
            return;
        }
        stats()->AddTotal(current_last.log_id(), current_last.msg_len());
        elem_event->payload.data = total;
        last_logged_elements_[log_id].emplace(std::move(elem));
        return;
    }

    // 3+ identical messages (not LIBLOG) messages: increase the drop count.
    uint16_t dropped_count = duplicate_elements_[log_id]->dropped_count();
    if (dropped_count == std::numeric_limits<uint16_t>::max()) {
        SimpleLogBuffer::LogInternal(std::move(*duplicate_elements_[log_id]));
        dropped_count = 0;
    }
    // We're dropping the current_last log so add its stats to the total.
    stats()->AddTotal(current_last.log_id(), current_last.msg_len());
    // Use current_last for tracking the dropped count to always use the latest timestamp.
    current_last.SetDropped(dropped_count + 1);
    duplicate_elements_[log_id].emplace(std::move(current_last));
    last_logged_elements_[log_id].emplace(std::move(elem));
}

LogBufferElementCollection::iterator ChattyLogBuffer::Erase(LogBufferElementCollection::iterator it,
                                                            bool coalesce) {
    LogBufferElement& element = *it;
    log_id_t id = element.log_id();

    // Remove iterator references in the various lists that will become stale
    // after the element is erased from the main logging list.

    {  // start of scope for found iterator
        int key = (id == LOG_ID_EVENTS || id == LOG_ID_SECURITY) ? element.GetTag() : element.uid();
        LogBufferIteratorMap::iterator found = mLastWorst[id].find(key);
        if ((found != mLastWorst[id].end()) && (it == found->second)) {
            mLastWorst[id].erase(found);
        }
    }

    {  // start of scope for pid found iterator
        // element->uid() may not be AID_SYSTEM for next-best-watermark.
        // will not assume id != LOG_ID_EVENTS or LOG_ID_SECURITY for KISS and
        // long term code stability, find() check should be fast for those ids.
        LogBufferPidIteratorMap::iterator found = mLastWorstPidOfSystem[id].find(element.pid());
        if (found != mLastWorstPidOfSystem[id].end() && it == found->second) {
            mLastWorstPidOfSystem[id].erase(found);
        }
    }

#ifdef DEBUG_CHECK_FOR_STALE_ENTRIES
    LogBufferElementCollection::iterator bad = it;
    int key = (id == LOG_ID_EVENTS || id == LOG_ID_SECURITY) ? element->GetTag() : element->uid();
#endif

    if (coalesce) {
        stats()->Erase(element.ToLogStatisticsElement());
    } else {
        stats()->Subtract(element.ToLogStatisticsElement());
    }

    it = SimpleLogBuffer::Erase(it);

#ifdef DEBUG_CHECK_FOR_STALE_ENTRIES
    log_id_for_each(i) {
        for (auto b : mLastWorst[i]) {
            if (bad == b.second) {
                LOG(ERROR) << StringPrintf("stale mLastWorst[%d] key=%d mykey=%d", i, b.first, key);
            }
        }
        for (auto b : mLastWorstPidOfSystem[i]) {
            if (bad == b.second) {
                LOG(ERROR) << StringPrintf("stale mLastWorstPidOfSystem[%d] pid=%d", i, b.first);
            }
        }
    }
#endif
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
        uint64_t key = LogBufferElementKey(element->uid(), element->pid(), element->tid());
        LogBufferElementMap::iterator it = map.find(key);
        if (it != map.end()) {
            LogBufferElement* found = it->second;
            uint16_t moreDropped = found->dropped_count();
            if ((dropped + moreDropped) > USHRT_MAX) {
                map.erase(it);
            } else {
                found->SetDropped(dropped + moreDropped);
                return true;
            }
        }
        return false;
    }

    void add(LogBufferElement* element) {
        uint64_t key = LogBufferElementKey(element->uid(), element->pid(), element->tid());
        map[key] = element;
    }

    void clear() { map.clear(); }

    void clear(LogBufferElement* element) {
        uint64_t current = element->realtime().nsec() - (EXPIRE_RATELIMIT * NS_PER_SEC);
        for (LogBufferElementMap::iterator it = map.begin(); it != map.end();) {
            LogBufferElement* mapElement = it->second;
            if (mapElement->dropped_count() >= EXPIRE_THRESHOLD &&
                current > mapElement->realtime().nsec()) {
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
bool ChattyLogBuffer::Prune(log_id_t id, unsigned long pruneRows, uid_t caller_uid) {
    LogReaderThread* oldest = nullptr;
    bool busy = false;
    bool clearAll = pruneRows == ULONG_MAX;

    auto reader_threads_lock = std::lock_guard{reader_list()->reader_threads_lock()};

    // Region locked?
    for (const auto& reader_thread : reader_list()->reader_threads()) {
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
        while (it != logs().end()) {
            LogBufferElement& element = *it;

            if (element.log_id() != id || element.uid() != caller_uid) {
                ++it;
                continue;
            }

            if (oldest && oldest->start() <= element.sequence()) {
                busy = true;
                KickReader(oldest, id, pruneRows);
                break;
            }

            it = Erase(it);
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
        int worst = -1;  // not valid for uid() or getKey()
        size_t worst_sizes = 0;
        size_t second_worst_sizes = 0;
        pid_t worstPid = 0;  // POSIX guarantees PID != 0

        if (worstUidEnabledForLogid(id) && prune_->worstUidEnabled()) {
            // Calculate threshold as 12.5% of available storage
            size_t threshold = max_size(id) / 8;

            if (id == LOG_ID_EVENTS || id == LOG_ID_SECURITY) {
                stats()->WorstTwoTags(threshold, &worst, &worst_sizes, &second_worst_sizes);
                // per-pid filter for AID_SYSTEM sources is too complex
            } else {
                stats()->WorstTwoUids(id, threshold, &worst, &worst_sizes, &second_worst_sizes);

                if (worst == AID_SYSTEM && prune_->worstPidOfSystemEnabled()) {
                    stats()->WorstTwoSystemPids(id, worst_sizes, &worstPid, &second_worst_sizes);
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
                if (found != mLastWorst[id].end() && found->second != logs().end()) {
                    leading = false;
                    it = found->second;
                }
            }
            if (worstPid) {  // begin scope for pid worst found iterator
                // FYI: worstPid only set if !LOG_ID_EVENTS and
                //      !LOG_ID_SECURITY, not going to make that assumption ...
                LogBufferPidIteratorMap::iterator found = mLastWorstPidOfSystem[id].find(worstPid);
                if (found != mLastWorstPidOfSystem[id].end() && found->second != logs().end()) {
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
        lastt = logs().end();
        --lastt;
        LogBufferElementLast last;
        while (it != logs().end()) {
            LogBufferElement& element = *it;

            if (oldest && oldest->start() <= element.sequence()) {
                busy = true;
                // Do not let chatty eliding trigger any reader mitigation
                break;
            }

            if (element.log_id() != id) {
                ++it;
                continue;
            }
            // below this point element->log_id() == id

            uint16_t dropped = element.dropped_count();

            // remove any leading drops
            if (leading && dropped) {
                it = Erase(it);
                continue;
            }

            if (dropped && last.coalesce(&element, dropped)) {
                it = Erase(it, true);
                continue;
            }

            int key = (id == LOG_ID_EVENTS || id == LOG_ID_SECURITY) ? element.GetTag()
                                                                     : element.uid();

            if (hasBlacklist && prune_->naughty(&element)) {
                last.clear(&element);
                it = Erase(it);
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
                    worst_sizes -= element.msg_len();
                }
                continue;
            }

            if (element.realtime() < (lastt->realtime() - too_old) ||
                element.realtime() > lastt->realtime()) {
                break;
            }

            if (dropped) {
                last.add(&element);
                if (worstPid && ((!gc && element.pid() == worstPid) ||
                                 mLastWorstPidOfSystem[id].find(element.pid()) ==
                                         mLastWorstPidOfSystem[id].end())) {
                    // element->uid() may not be AID_SYSTEM, next best
                    // watermark if current one empty. id is not LOG_ID_EVENTS
                    // or LOG_ID_SECURITY because of worstPid check.
                    mLastWorstPidOfSystem[id][element.pid()] = it;
                }
                if ((!gc && !worstPid && (key == worst)) ||
                    (mLastWorst[id].find(key) == mLastWorst[id].end())) {
                    mLastWorst[id][key] = it;
                }
                ++it;
                continue;
            }

            if (key != worst || (worstPid && element.pid() != worstPid)) {
                leading = false;
                last.clear(&element);
                ++it;
                continue;
            }
            // key == worst below here
            // If worstPid set, then element->pid() == worstPid below here

            pruneRows--;
            if (pruneRows == 0) {
                break;
            }

            kick = true;

            uint16_t len = element.msg_len();

            // do not create any leading drops
            if (leading) {
                it = Erase(it);
            } else {
                stats()->Drop(element.ToLogStatisticsElement());
                element.SetDropped(1);
                if (last.coalesce(&element, 1)) {
                    it = Erase(it, true);
                } else {
                    last.add(&element);
                    if (worstPid && (!gc || mLastWorstPidOfSystem[id].find(worstPid) ==
                                                    mLastWorstPidOfSystem[id].end())) {
                        // element->uid() may not be AID_SYSTEM, next best
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
    while ((pruneRows > 0) && (it != logs().end())) {
        LogBufferElement& element = *it;

        if (element.log_id() != id) {
            it++;
            continue;
        }

        if (oldest && oldest->start() <= element.sequence()) {
            busy = true;
            if (!whitelist) KickReader(oldest, id, pruneRows);
            break;
        }

        if (hasWhitelist && !element.dropped_count() && prune_->nice(&element)) {
            // WhiteListed
            whitelist = true;
            it++;
            continue;
        }

        it = Erase(it);
        pruneRows--;
    }

    // Do not save the whitelist if we are reader range limited
    if (whitelist && (pruneRows > 0)) {
        it = GetOldest(id);
        while ((it != logs().end()) && (pruneRows > 0)) {
            LogBufferElement& element = *it;

            if (element.log_id() != id) {
                ++it;
                continue;
            }

            if (oldest && oldest->start() <= element.sequence()) {
                busy = true;
                KickReader(oldest, id, pruneRows);
                break;
            }

            it = Erase(it);
            pruneRows--;
        }
    }

    return (pruneRows > 0) && busy;
}
