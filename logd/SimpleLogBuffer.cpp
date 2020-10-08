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

#include <android-base/logging.h>

#include "LogBufferElement.h"
#include "LogSize.h"

SimpleLogBuffer::SimpleLogBuffer(LogReaderList* reader_list, LogTags* tags, LogStatistics* stats)
    : reader_list_(reader_list), tags_(tags), stats_(stats) {
    Init();
}

SimpleLogBuffer::~SimpleLogBuffer() {}

void SimpleLogBuffer::Init() {
    log_id_for_each(i) {
        if (!SetSize(i, GetBufferSizeFromProperties(i))) {
            SetSize(i, kLogBufferMinSize);
        }
    }

    // Release any sleeping reader threads to dump their current content.
    auto lock = std::lock_guard{logd_lock};
    for (const auto& reader_thread : reader_list_->reader_threads()) {
        reader_thread->TriggerReader();
    }
}

std::list<LogBufferElement>::iterator SimpleLogBuffer::GetOldest(log_id_t log_id) {
    auto it = logs().begin();
    if (oldest_[log_id]) {
        it = *oldest_[log_id];
    }
    while (it != logs().end() && it->log_id() != log_id) {
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
    if (IsBinary(log_id)) {
        int32_t numeric_tag = MsgToTag(msg, len);
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

    auto lock = std::lock_guard{logd_lock};
    auto sequence = sequence_.fetch_add(1, std::memory_order_relaxed);
    LogInternal(LogBufferElement(log_id, realtime, uid, pid, tid, sequence, msg, len));
    return len;
}

void SimpleLogBuffer::LogInternal(LogBufferElement&& elem) {
    log_id_t log_id = elem.log_id();

    logs_.emplace_back(std::move(elem));
    stats_->Add(logs_.back().ToLogStatisticsElement());
    MaybePrune(log_id);
    reader_list_->NotifyNewLog(1 << log_id);
}

// These extra parameters are only required for chatty, but since they're a no-op for
// SimpleLogBuffer, it's easier to include them here, then to duplicate FlushTo() for
// ChattyLogBuffer.
class ChattyFlushToState : public FlushToState {
  public:
    ChattyFlushToState(uint64_t start, LogMask log_mask) : FlushToState(start, log_mask) {}

    pid_t* last_tid() { return last_tid_; }

    bool drop_chatty_messages() const { return drop_chatty_messages_; }
    void set_drop_chatty_messages(bool value) { drop_chatty_messages_ = value; }

  private:
    pid_t last_tid_[LOG_ID_MAX] = {};
    bool drop_chatty_messages_ = true;
};

std::unique_ptr<FlushToState> SimpleLogBuffer::CreateFlushToState(uint64_t start,
                                                                  LogMask log_mask) {
    return std::make_unique<ChattyFlushToState>(start, log_mask);
}

bool SimpleLogBuffer::FlushTo(
        LogWriter* writer, FlushToState& abstract_state,
        const std::function<FilterResult(log_id_t log_id, pid_t pid, uint64_t sequence,
                                         log_time realtime)>& filter) {
    auto& state = reinterpret_cast<ChattyFlushToState&>(abstract_state);

    std::list<LogBufferElement>::iterator it;
    if (state.start() <= 1) {
        // client wants to start from the beginning
        it = logs_.begin();
    } else {
        // Client wants to start from some specified time. Chances are
        // we are better off starting from the end of the time sorted list.
        for (it = logs_.end(); it != logs_.begin();
             /* do nothing */) {
            --it;
            if (it->sequence() == state.start()) {
                break;
            } else if (it->sequence() < state.start()) {
                it++;
                break;
            }
        }
    }

    for (; it != logs_.end(); ++it) {
        LogBufferElement& element = *it;

        state.set_start(element.sequence());

        if (!writer->privileged() && element.uid() != writer->uid()) {
            continue;
        }

        if (((1 << element.log_id()) & state.log_mask()) == 0) {
            continue;
        }

        if (filter) {
            FilterResult ret =
                    filter(element.log_id(), element.pid(), element.sequence(), element.realtime());
            if (ret == FilterResult::kSkip) {
                continue;
            }
            if (ret == FilterResult::kStop) {
                break;
            }
        }

        // drop_chatty_messages is initialized to true, so if the first message that we attempt to
        // flush is a chatty message, we drop it.  Once we see a non-chatty message it gets set to
        // false to let further chatty messages be printed.
        if (state.drop_chatty_messages()) {
            if (element.dropped_count() != 0) {
                continue;
            }
            state.set_drop_chatty_messages(false);
        }

        bool same_tid = state.last_tid()[element.log_id()] == element.tid();
        // Dropped (chatty) immediately following a valid log from the same source in the same log
        // buffer indicates we have a multiple identical squash.  chatty that differs source is due
        // to spam filter.  chatty to chatty of different source is also due to spam filter.
        state.last_tid()[element.log_id()] =
                (element.dropped_count() && !same_tid) ? 0 : element.tid();

        logd_lock.unlock();
        // We never prune logs equal to or newer than any LogReaderThreads' `start` value, so the
        // `element` pointer is safe here without the lock
        if (!element.FlushTo(writer, stats_, same_tid)) {
            logd_lock.lock();
            return false;
        }
        logd_lock.lock();
    }

    state.set_start(state.start() + 1);
    return true;
}

bool SimpleLogBuffer::Clear(log_id_t id, uid_t uid) {
    // Try three times to clear, then disconnect the readers and try one final time.
    for (int retry = 0; retry < 3; ++retry) {
        {
            auto lock = std::lock_guard{logd_lock};
            if (Prune(id, ULONG_MAX, uid)) {
                return true;
            }
        }
        sleep(1);
    }
    // Check if it is still busy after the sleep, we try to prune one entry, not another clear run,
    // so we are looking for the quick side effect of the return value to tell us if we have a
    // _blocked_ reader.
    bool busy = false;
    {
        auto lock = std::lock_guard{logd_lock};
        busy = !Prune(id, 1, uid);
    }
    // It is still busy, disconnect all readers.
    if (busy) {
        auto lock = std::lock_guard{logd_lock};
        for (const auto& reader_thread : reader_list_->reader_threads()) {
            if (reader_thread->IsWatching(id)) {
                LOG(WARNING) << "Kicking blocked reader, " << reader_thread->name()
                             << ", from LogBuffer::clear()";
                reader_thread->Release();
            }
        }
    }
    auto lock = std::lock_guard{logd_lock};
    return Prune(id, ULONG_MAX, uid);
}

// get the total space allocated to "id"
size_t SimpleLogBuffer::GetSize(log_id_t id) {
    auto lock = std::lock_guard{logd_lock};
    size_t retval = max_size_[id];
    return retval;
}

// set the total space allocated to "id"
bool SimpleLogBuffer::SetSize(log_id_t id, size_t size) {
    // Reasonable limits ...
    if (!IsValidBufferSize(size)) {
        return false;
    }

    auto lock = std::lock_guard{logd_lock};
    max_size_[id] = size;
    return true;
}

void SimpleLogBuffer::MaybePrune(log_id_t id) {
    unsigned long prune_rows;
    if (stats_->ShouldPrune(id, max_size_[id], &prune_rows)) {
        Prune(id, prune_rows, 0);
    }
}

bool SimpleLogBuffer::Prune(log_id_t id, unsigned long prune_rows, uid_t caller_uid) {
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

        if (element.log_id() != id) {
            ++it;
            continue;
        }

        if (caller_uid != 0 && element.uid() != caller_uid) {
            ++it;
            continue;
        }

        if (oldest && oldest->start() <= element.sequence()) {
            KickReader(oldest, id, prune_rows);
            return false;
        }

        stats_->Subtract(element.ToLogStatisticsElement());
        it = Erase(it);
        if (--prune_rows == 0) {
            return true;
        }
    }
    return true;
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
        LOG(WARNING) << "Kicking blocked reader, " << reader->name()
                     << ", from LogBuffer::kickMe()";
        reader->Release();
    } else if (reader->deadline().time_since_epoch().count() != 0) {
        // Allow a blocked WRAP deadline reader to trigger and start reporting the log data.
        reader->TriggerReader();
    } else {
        // tell slow reader to skip entries to catch up
        LOG(WARNING) << "Skipping " << prune_rows << " entries from slow reader, " << reader->name()
                     << ", from LogBuffer::kickMe()";
        reader->TriggerSkip(id, prune_rows);
    }
}
