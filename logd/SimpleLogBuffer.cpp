/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include "SimpleLogBuffer.h"

#include "LogBufferElement.h"

SimpleLogBuffer::SimpleLogBuffer(LogReaderList* reader_list, LogTags* tags, LogStatistics* stats)
    : reader_list_(reader_list), tags_(tags), stats_(stats) {
    Init();
}

SimpleLogBuffer::~SimpleLogBuffer() {}

void SimpleLogBuffer::Init() {
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

std::list<LogBufferElement>::iterator SimpleLogBuffer::GetOldest(log_id_t log_id) {
    auto it = logs().begin();
    if (oldest_[log_id]) {
        it = *oldest_[log_id];
    }
    while (it != logs().end() && it->getLogId() != log_id) {
        it++;
    }
    if (it != logs().end()) {
        oldest_[log_id] = it;
    }
    return it;
}

bool SimpleLogBuffer::ShouldLog(log_id_t log_id, const char* msg, uint16_t len) {
    if (log_id == LOG_ID_SECURITY) {
        return true;
    }

    int prio = ANDROID_LOG_INFO;
    const char* tag = nullptr;
    size_t tag_len = 0;
    if (log_id == LOG_ID_EVENTS || log_id == LOG_ID_STATS) {
        if (len < sizeof(android_event_header_t)) {
            return false;
        }
        int32_t numeric_tag = reinterpret_cast<const android_event_header_t*>(msg)->tag;
        tag = tags_->tagToName(numeric_tag);
        if (tag) {
            tag_len = strlen(tag);
        }
    } else {
        prio = *msg;
        tag = msg + 1;
        tag_len = strnlen(tag, len - 1);
    }
    return __android_log_is_loggable_len(prio, tag, tag_len, ANDROID_LOG_VERBOSE);
}

int SimpleLogBuffer::Log(log_id_t log_id, log_time realtime, uid_t uid, pid_t pid, pid_t tid,
                         const char* msg, uint16_t len) {
    if (log_id >= LOG_ID_MAX) {
        return -EINVAL;
    }

    if (!ShouldLog(log_id, msg, len)) {
        // Log traffic received to total
        stats_->AddTotal(log_id, len);
        return -EACCES;
    }

    // Slip the time by 1 nsec if the incoming lands on xxxxxx000 ns.
    // This prevents any chance that an outside source can request an
    // exact entry with time specified in ms or us precision.
    if ((realtime.tv_nsec % 1000) == 0) ++realtime.tv_nsec;

    auto lock = std::lock_guard{lock_};
    auto sequence = sequence_.fetch_add(1, std::memory_order_relaxed);
    LogInternal(LogBufferElement(log_id, realtime, uid, pid, tid, sequence, msg, len));
    return len;
}

void SimpleLogBuffer::LogInternal(LogBufferElement&& elem) {
    log_id_t log_id = elem.getLogId();

    logs_.emplace_back(std::move(elem));
    stats_->Add(&logs_.back());
    MaybePrune(log_id);
    reader_list_->NotifyNewLog(1 << log_id);
}

uint64_t SimpleLogBuffer::FlushTo(
        LogWriter* writer, uint64_t start, pid_t* last_tid,
        const std::function<FilterResult(log_id_t log_id, pid_t pid, uint64_t sequence,
                                         log_time realtime, uint16_t dropped_count)>& filter) {
    auto shared_lock = SharedLock{lock_};

    std::list<LogBufferElement>::iterator it;
    if (start <= 1) {
        // client wants to start from the beginning
        it = logs_.begin();
    } else {
        // Client wants to start from some specified time. Chances are
        // we are better off starting from the end of the time sorted list.
        for (it = logs_.end(); it != logs_.begin();
             /* do nothing */) {
            --it;
            if (it->getSequence() == start) {
                break;
            } else if (it->getSequence() < start) {
                it++;
                break;
            }
        }
    }

    uint64_t curr = start;

    for (; it != logs_.end(); ++it) {
        LogBufferElement& element = *it;

        if (!writer->privileged() && element.getUid() != writer->uid()) {
            continue;
        }

        if (!writer->can_read_security_logs() && element.getLogId() == LOG_ID_SECURITY) {
            continue;
        }

        if (filter) {
            FilterResult ret = filter(element.getLogId(), element.getPid(), element.getSequence(),
                                      element.getRealTime(), element.getDropped());
            if (ret == FilterResult::kSkip) {
                continue;
            }
            if (ret == FilterResult::kStop) {
                break;
            }
        }

        bool same_tid = false;
        if (last_tid) {
            same_tid = last_tid[element.getLogId()] == element.getTid();
            // Dropped (chatty) immediately following a valid log from the
            // same source in the same log buffer indicates we have a
            // multiple identical squash.  chatty that differs source
            // is due to spam filter.  chatty to chatty of different
            // source is also due to spam filter.
            last_tid[element.getLogId()] =
                    (element.getDropped() && !same_tid) ? 0 : element.getTid();
        }

        shared_lock.unlock();

        // We never prune logs equal to or newer than any LogReaderThreads' `start` value, so the
        // `element` pointer is safe here without the lock
        curr = element.getSequence();
        if (!element.FlushTo(writer, stats_, same_tid)) {
            return FLUSH_ERROR;
        }

        shared_lock.lock_shared();
    }

    return curr;
}

// clear all rows of type "id" from the buffer.
bool SimpleLogBuffer::Clear(log_id_t id, uid_t uid) {
    bool busy = true;
    // If it takes more than 4 tries (seconds) to clear, then kill reader(s)
    for (int retry = 4;;) {
        if (retry == 1) {  // last pass
            // Check if it is still busy after the sleep, we say prune
            // one entry, not another clear run, so we are looking for
            // the quick side effect of the return value to tell us if
            // we have a _blocked_ reader.
            {
                auto lock = std::lock_guard{lock_};
                busy = Prune(id, 1, uid);
            }
            // It is still busy, blocked reader(s), lets kill them all!
            // otherwise, lets be a good citizen and preserve the slow
            // readers and let the clear run (below) deal with determining
            // if we are still blocked and return an error code to caller.
            if (busy) {
                auto reader_threads_lock = std::lock_guard{reader_list_->reader_threads_lock()};
                for (const auto& reader_thread : reader_list_->reader_threads()) {
                    if (reader_thread->IsWatching(id)) {
                        android::prdebug("Kicking blocked reader, %s, from LogBuffer::clear()\n",
                                         reader_thread->name().c_str());
                        reader_thread->release_Locked();
                    }
                }
            }
        }
        {
            auto lock = std::lock_guard{lock_};
            busy = Prune(id, ULONG_MAX, uid);
        }

        if (!busy || !--retry) {
            break;
        }
        sleep(1);  // Let reader(s) catch up after notification
    }
    return busy;
}

// get the total space allocated to "id"
unsigned long SimpleLogBuffer::GetSize(log_id_t id) {
    auto lock = SharedLock{lock_};
    size_t retval = max_size_[id];
    return retval;
}

// set the total space allocated to "id"
int SimpleLogBuffer::SetSize(log_id_t id, unsigned long size) {
    // Reasonable limits ...
    if (!__android_logger_valid_buffer_size(size)) {
        return -1;
    }

    auto lock = std::lock_guard{lock_};
    max_size_[id] = size;
    return 0;
}

void SimpleLogBuffer::MaybePrune(log_id_t id) {
    unsigned long prune_rows;
    if (stats_->ShouldPrune(id, max_size_[id], &prune_rows)) {
        Prune(id, prune_rows, 0);
    }
}

bool SimpleLogBuffer::Prune(log_id_t id, unsigned long prune_rows, uid_t caller_uid) {
    auto reader_threads_lock = std::lock_guard{reader_list_->reader_threads_lock()};

    // Don't prune logs that are newer than the point at which any reader threads are reading from.
    LogReaderThread* oldest = nullptr;
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

    auto it = GetOldest(id);

    while (it != logs_.end()) {
        LogBufferElement& element = *it;

        if (element.getLogId() != id) {
            ++it;
            continue;
        }

        if (caller_uid != 0 && element.getUid() != caller_uid) {
            ++it;
            continue;
        }

        if (oldest && oldest->start() <= element.getSequence()) {
            KickReader(oldest, id, prune_rows);
            return true;
        }

        stats_->Subtract(&element);
        it = Erase(it);
        if (--prune_rows == 0) {
            return false;
        }
    }
    return false;
}

std::list<LogBufferElement>::iterator SimpleLogBuffer::Erase(
        std::list<LogBufferElement>::iterator it) {
    bool oldest_is_it[LOG_ID_MAX];
    log_id_for_each(i) { oldest_is_it[i] = oldest_[i] && it == *oldest_[i]; }

    it = logs_.erase(it);

    log_id_for_each(i) {
        if (oldest_is_it[i]) {
            if (__predict_false(it == logs().end())) {
                oldest_[i] = std::nullopt;
            } else {
                oldest_[i] = it;  // Store the next iterator even if it does not correspond to
                                  // the same log_id, as a starting point for GetOldest().
            }
        }
    }

    return it;
}

// If the selected reader is blocking our pruning progress, decide on
// what kind of mitigation is necessary to unblock the situation.
void SimpleLogBuffer::KickReader(LogReaderThread* reader, log_id_t id, unsigned long prune_rows) {
    if (stats_->Sizes(id) > (2 * max_size_[id])) {  // +100%
        // A misbehaving or slow reader has its connection
        // dropped if we hit too much memory pressure.
        android::prdebug("Kicking blocked reader, %s, from LogBuffer::kickMe()\n",
                         reader->name().c_str());
        reader->release_Locked();
    } else if (reader->deadline().time_since_epoch().count() != 0) {
        // Allow a blocked WRAP deadline reader to trigger and start reporting the log data.
        reader->triggerReader_Locked();
    } else {
        // tell slow reader to skip entries to catch up
        android::prdebug("Skipping %lu entries from slow reader, %s, from LogBuffer::kickMe()\n",
                         prune_rows, reader->name().c_str());
        reader->triggerSkip_Locked(id, prune_rows);
    }
}
