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

#include "SerializedLogBuffer.h"

#include <sys/prctl.h>

#include <limits>

#include <android-base/logging.h>
#include <android-base/scopeguard.h>

#include "LogStatistics.h"
#include "SerializedFlushToState.h"

SerializedLogBuffer::SerializedLogBuffer(LogReaderList* reader_list, LogTags* tags,
                                         LogStatistics* stats)
    : reader_list_(reader_list), tags_(tags), stats_(stats) {
    Init();
}

SerializedLogBuffer::~SerializedLogBuffer() {
    if (deleter_thread_.joinable()) {
        deleter_thread_.join();
    }
}

void SerializedLogBuffer::Init() {
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

bool SerializedLogBuffer::ShouldLog(log_id_t log_id, const char* msg, uint16_t len) {
    if (log_id == LOG_ID_SECURITY) {
        return true;
    }

    int prio = ANDROID_LOG_INFO;
    const char* tag = nullptr;
    size_t tag_len = 0;
    if (IsBinary(log_id)) {
        int32_t tag_int = MsgToTag(msg, len);
        tag = tags_->tagToName(tag_int);
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

int SerializedLogBuffer::Log(log_id_t log_id, log_time realtime, uid_t uid, pid_t pid, pid_t tid,
                             const char* msg, uint16_t len) {
    if (log_id >= LOG_ID_MAX || len == 0) {
        return -EINVAL;
    }

    if (!ShouldLog(log_id, msg, len)) {
        stats_->AddTotal(log_id, len);
        return -EACCES;
    }

    auto sequence = sequence_.fetch_add(1, std::memory_order_relaxed);

    auto lock = std::lock_guard{lock_};

    if (logs_[log_id].empty()) {
        logs_[log_id].push_back(SerializedLogChunk(max_size_[log_id] / 4));
    }

    auto total_len = sizeof(SerializedLogEntry) + len;
    if (!logs_[log_id].back().CanLog(total_len)) {
        logs_[log_id].back().FinishWriting();
        logs_[log_id].push_back(SerializedLogChunk(max_size_[log_id] / 4));
    }

    auto entry = logs_[log_id].back().Log(sequence, realtime, uid, pid, tid, msg, len);
    stats_->Add(entry->ToLogStatisticsElement(log_id));

    MaybePrune(log_id);

    reader_list_->NotifyNewLog(1 << log_id);
    return len;
}

void SerializedLogBuffer::MaybePrune(log_id_t log_id) {
    size_t total_size = GetSizeUsed(log_id);
    size_t after_size = total_size;
    if (total_size > max_size_[log_id]) {
        Prune(log_id, total_size - max_size_[log_id], 0);
        after_size = GetSizeUsed(log_id);
        LOG(INFO) << "Pruned Logs from log_id: " << log_id << ", previous size: " << total_size
                  << " after size: " << after_size;
    }

    stats_->set_overhead(log_id, after_size);
}

void SerializedLogBuffer::StartDeleterThread() {
    if (deleter_thread_running_) {
        return;
    }
    if (deleter_thread_.joinable()) {
        deleter_thread_.join();
    }
    auto new_thread = std::thread([this] { DeleterThread(); });
    deleter_thread_.swap(new_thread);
    deleter_thread_running_ = true;
}

// Decompresses the chunks, call LogStatistics::Subtract() on each entry, then delete the chunks and
// the list.  Note that the SerializedLogChunk objects have been removed from logs_ and their
// references have been deleted from any SerializedFlushToState objects, so this can be safely done
// without holding lock_.  It is done in a separate thread to avoid delaying the writer thread.
void SerializedLogBuffer::DeleterThread() {
    prctl(PR_SET_NAME, "logd.deleter");
    while (true) {
        std::list<SerializedLogChunk> local_chunks_to_delete;
        log_id_t log_id;
        {
            auto lock = std::lock_guard{lock_};
            log_id_for_each(i) {
                if (!chunks_to_delete_[i].empty()) {
                    local_chunks_to_delete = std::move(chunks_to_delete_[i]);
                    chunks_to_delete_[i].clear();
                    log_id = i;
                    break;
                }
            }
            if (local_chunks_to_delete.empty()) {
                deleter_thread_running_ = false;
                return;
            }
        }

        for (auto& chunk : local_chunks_to_delete) {
            chunk.IncReaderRefCount();
            int read_offset = 0;
            while (read_offset < chunk.write_offset()) {
                auto* entry = chunk.log_entry(read_offset);
                stats_->Subtract(entry->ToLogStatisticsElement(log_id));
                read_offset += entry->total_len();
            }
            chunk.DecReaderRefCount(false);
        }
    }
}

void SerializedLogBuffer::NotifyReadersOfPrune(
        log_id_t log_id, const std::list<SerializedLogChunk>::iterator& chunk) {
    for (const auto& reader_thread : reader_list_->reader_threads()) {
        auto& state = reinterpret_cast<SerializedFlushToState&>(reader_thread->flush_to_state());
        state.Prune(log_id, chunk);
    }
}

bool SerializedLogBuffer::Prune(log_id_t log_id, size_t bytes_to_free, uid_t uid) {
    // Don't prune logs that are newer than the point at which any reader threads are reading from.
    LogReaderThread* oldest = nullptr;
    auto reader_threads_lock = std::lock_guard{reader_list_->reader_threads_lock()};
    for (const auto& reader_thread : reader_list_->reader_threads()) {
        if (!reader_thread->IsWatching(log_id)) {
            continue;
        }
        if (!oldest || oldest->start() > reader_thread->start() ||
            (oldest->start() == reader_thread->start() &&
             reader_thread->deadline().time_since_epoch().count() != 0)) {
            oldest = reader_thread.get();
        }
    }

    StartDeleterThread();

    auto& log_buffer = logs_[log_id];
    auto it = log_buffer.begin();
    while (it != log_buffer.end()) {
        if (oldest != nullptr && it->highest_sequence_number() >= oldest->start()) {
            break;
        }

        // Increment ahead of time since we're going to splice this iterator from the list.
        auto it_to_prune = it++;

        // The sequence number check ensures that all readers have read all logs in this chunk, but
        // they may still hold a reference to the chunk to track their last read log_position.
        // Notify them to delete the reference.
        NotifyReadersOfPrune(log_id, it_to_prune);

        if (uid != 0) {
            // Reorder the log buffer to remove logs from the given UID.  If there are no logs left
            // in the buffer after the removal, delete it.
            if (it_to_prune->ClearUidLogs(uid, log_id, stats_)) {
                log_buffer.erase(it_to_prune);
            }
        } else {
            size_t buffer_size = it_to_prune->PruneSize();
            chunks_to_delete_[log_id].splice(chunks_to_delete_[log_id].end(), log_buffer,
                                             it_to_prune);
            if (buffer_size >= bytes_to_free) {
                return true;
            }
            bytes_to_free -= buffer_size;
        }
    }

    // If we've deleted all buffers without bytes_to_free hitting 0, then we're called by Clear()
    // and should return true.
    if (it == log_buffer.end()) {
        return true;
    }

    // Otherwise we are stuck due to a reader, so mitigate it.
    CHECK(oldest != nullptr);
    KickReader(oldest, log_id, bytes_to_free);
    return false;
}

// If the selected reader is blocking our pruning progress, decide on
// what kind of mitigation is necessary to unblock the situation.
void SerializedLogBuffer::KickReader(LogReaderThread* reader, log_id_t id, size_t bytes_to_free) {
    if (bytes_to_free >= max_size_[id]) {  // +100%
        // A misbehaving or slow reader is dropped if we hit too much memory pressure.
        LOG(WARNING) << "Kicking blocked reader, " << reader->name()
                     << ", from LogBuffer::kickMe()";
        reader->release_Locked();
    } else if (reader->deadline().time_since_epoch().count() != 0) {
        // Allow a blocked WRAP deadline reader to trigger and start reporting the log data.
        reader->triggerReader_Locked();
    } else {
        // Tell slow reader to skip entries to catch up.
        unsigned long prune_rows = bytes_to_free / 300;
        LOG(WARNING) << "Skipping " << prune_rows << " entries from slow reader, " << reader->name()
                     << ", from LogBuffer::kickMe()";
        reader->triggerSkip_Locked(id, prune_rows);
    }
}

std::unique_ptr<FlushToState> SerializedLogBuffer::CreateFlushToState(uint64_t start,
                                                                      LogMask log_mask) {
    return std::make_unique<SerializedFlushToState>(start, log_mask);
}

bool SerializedLogBuffer::FlushTo(
        LogWriter* writer, FlushToState& abstract_state,
        const std::function<FilterResult(log_id_t log_id, pid_t pid, uint64_t sequence,
                                         log_time realtime)>& filter) {
    auto lock = std::unique_lock{lock_};

    auto& state = reinterpret_cast<SerializedFlushToState&>(abstract_state);
    state.InitializeLogs(logs_);

    while (state.HasUnreadLogs()) {
        MinHeapElement top = state.PopNextUnreadLog();
        auto* entry = top.entry;
        auto log_id = top.log_id;

        if (entry->sequence() < state.start()) {
            continue;
        }
        state.set_start(entry->sequence());

        if (!writer->privileged() && entry->uid() != writer->uid()) {
            continue;
        }

        if (filter) {
            auto ret = filter(log_id, entry->pid(), entry->sequence(), entry->realtime());
            if (ret == FilterResult::kSkip) {
                continue;
            }
            if (ret == FilterResult::kStop) {
                break;
            }
        }

        lock.unlock();
        // We never prune logs equal to or newer than any LogReaderThreads' `start` value, so the
        // `entry` pointer is safe here without the lock
        if (!entry->Flush(writer, log_id)) {
            return false;
        }
        lock.lock();
    }

    state.set_start(state.start() + 1);
    return true;
}

bool SerializedLogBuffer::Clear(log_id_t id, uid_t uid) {
    // Try three times to clear, then disconnect the readers and try one final time.
    for (int retry = 0; retry < 3; ++retry) {
        {
            auto lock = std::lock_guard{lock_};
            bool prune_success = Prune(id, ULONG_MAX, uid);
            if (prune_success) {
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
        auto lock = std::lock_guard{lock_};
        busy = !Prune(id, 1, uid);
    }
    // It is still busy, disconnect all readers.
    if (busy) {
        auto reader_threads_lock = std::lock_guard{reader_list_->reader_threads_lock()};
        for (const auto& reader_thread : reader_list_->reader_threads()) {
            if (reader_thread->IsWatching(id)) {
                LOG(WARNING) << "Kicking blocked reader, " << reader_thread->name()
                             << ", from LogBuffer::clear()";
                reader_thread->release_Locked();
            }
        }
    }
    auto lock = std::lock_guard{lock_};
    return Prune(id, ULONG_MAX, uid);
}

unsigned long SerializedLogBuffer::GetSizeUsed(log_id_t id) {
    size_t total_size = 0;
    for (const auto& chunk : logs_[id]) {
        total_size += chunk.PruneSize();
    }
    return total_size;
}

unsigned long SerializedLogBuffer::GetSize(log_id_t id) {
    auto lock = std::lock_guard{lock_};
    return max_size_[id];
}

// New SerializedLogChunk objects will be allocated according to the new size, but older one are
// unchanged.  MaybePrune() is called on the log buffer to reduce it to an appropriate size if the
// new size is lower.
int SerializedLogBuffer::SetSize(log_id_t id, unsigned long size) {
    // Reasonable limits ...
    if (!__android_logger_valid_buffer_size(size)) {
        return -1;
    }

    auto lock = std::lock_guard{lock_};
    max_size_[id] = size;

    MaybePrune(id);

    return 0;
}
