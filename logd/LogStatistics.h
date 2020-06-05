/*
 * Copyright (C) 2014 The Android Open Source Project
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

#pragma once

#include <ctype.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include <algorithm>  // std::max
#include <array>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>

#include <android-base/stringprintf.h>
#include <android-base/thread_annotations.h>
#include <android/log.h>
#include <log/log_time.h>
#include <private/android_filesystem_config.h>
#include <utils/FastStrcmp.h>

#include "LogUtils.h"

#define log_id_for_each(i) \
    for (log_id_t i = LOG_ID_MIN; (i) < LOG_ID_MAX; (i) = (log_id_t)((i) + 1))

class LogStatistics;
class UidEntry;
class PidEntry;

struct LogStatisticsElement {
    uid_t uid;
    pid_t pid;
    pid_t tid;
    uint32_t tag;
    log_time realtime;
    const char* msg;
    uint16_t msg_len;
    uint16_t dropped_count;
    log_id_t log_id;
};

template <typename TKey, typename TEntry>
class LogHashtable {
    std::unordered_map<TKey, TEntry> map;

    size_t bucket_size() const {
        size_t count = 0;
        for (size_t idx = 0; idx < map.bucket_count(); ++idx) {
            size_t bucket_size = map.bucket_size(idx);
            if (bucket_size == 0) bucket_size = 1;
            count += bucket_size;
        }
        float load_factor = map.max_load_factor();
        if (load_factor < 1.0) return count;
        return count * load_factor;
    }

    static const size_t unordered_map_per_entry_overhead = sizeof(void*);
    static const size_t unordered_map_bucket_overhead = sizeof(void*);

  public:
    size_t size() const {
        return map.size();
    }

    // Estimate unordered_map memory usage.
    size_t sizeOf() const {
        return sizeof(*this) +
               (size() * (sizeof(TEntry) + unordered_map_per_entry_overhead)) +
               (bucket_size() * sizeof(size_t) + unordered_map_bucket_overhead);
    }

    typedef typename std::unordered_map<TKey, TEntry>::iterator iterator;
    typedef
        typename std::unordered_map<TKey, TEntry>::const_iterator const_iterator;

    // Returns a sorted array of up to len highest entries sorted by size.  If fewer than len
    // entries are found, their positions are set to nullptr.
    template <size_t len>
    void MaxEntries(uid_t uid, pid_t pid, std::array<const TKey*, len>& out_keys,
                    std::array<const TEntry*, len>& out_entries) const {
        out_keys.fill(nullptr);
        out_entries.fill(nullptr);
        for (const auto& [key, entry] : map) {
            uid_t entry_uid = 0;
            if constexpr (std::is_same_v<TEntry, UidEntry>) {
                entry_uid = key;
            } else {
                entry_uid = entry.uid();
            }
            if (uid != AID_ROOT && uid != entry_uid) {
                continue;
            }
            pid_t entry_pid = 0;
            if constexpr (std::is_same_v<TEntry, PidEntry>) {
                entry_pid = key;
            } else {
                entry_pid = entry.pid();
            }
            if (pid && entry_pid && pid != entry_pid) {
                continue;
            }

            size_t sizes = entry.getSizes();
            ssize_t index = len - 1;
            while ((!out_entries[index] || sizes > out_entries[index]->getSizes()) && --index >= 0)
                ;
            if (++index < (ssize_t)len) {
                size_t num = len - index - 1;
                if (num) {
                    memmove(&out_keys[index + 1], &out_keys[index], num * sizeof(out_keys[0]));
                    memmove(&out_entries[index + 1], &out_entries[index],
                            num * sizeof(out_entries[0]));
                }
                out_keys[index] = &key;
                out_entries[index] = &entry;
            }
        }
    }

    iterator Add(const TKey& key, const LogStatisticsElement& element) {
        iterator it = map.find(key);
        if (it == map.end()) {
            it = map.insert(std::make_pair(key, TEntry(element))).first;
        } else {
            it->second.Add(element);
        }
        return it;
    }

    iterator Add(const TKey& key) {
        iterator it = map.find(key);
        if (it == map.end()) {
            it = map.insert(std::make_pair(key, TEntry(key))).first;
        } else {
            it->second.Add(key);
        }
        return it;
    }

    void Subtract(const TKey& key, const LogStatisticsElement& element) {
        iterator it = map.find(key);
        if (it != map.end() && it->second.Subtract(element)) {
            map.erase(it);
        }
    }

    void Drop(const TKey& key, const LogStatisticsElement& element) {
        iterator it = map.find(key);
        if (it != map.end()) {
            it->second.Drop(element);
        }
    }

    iterator begin() { return map.begin(); }
    const_iterator begin() const { return map.begin(); }
    iterator end() { return map.end(); }
    const_iterator end() const { return map.end(); }
};

class EntryBase {
  public:
    EntryBase() : size_(0) {}
    explicit EntryBase(const LogStatisticsElement& element) : size_(element.msg_len) {}

    size_t getSizes() const { return size_; }

    void Add(const LogStatisticsElement& element) { size_ += element.msg_len; }
    bool Subtract(const LogStatisticsElement& element) {
        size_ -= element.msg_len;
        return !size_;
    }

    static constexpr size_t PRUNED_LEN = 14;
    static constexpr size_t TOTAL_LEN = 80;

    static std::string formatLine(const std::string& name,
                                  const std::string& size,
                                  const std::string& pruned) {
        ssize_t drop_len = std::max(pruned.length() + 1, PRUNED_LEN);
        ssize_t size_len = std::max(size.length() + 1, TOTAL_LEN - name.length() - drop_len - 1);

        std::string ret = android::base::StringPrintf(
            "%s%*s%*s", name.c_str(), (int)size_len, size.c_str(),
            (int)drop_len, pruned.c_str());
        // remove any trailing spaces
        size_t pos = ret.size();
        size_t len = 0;
        while (pos && isspace(ret[--pos])) ++len;
        if (len) ret.erase(pos + 1, len);
        return ret + "\n";
    }

  private:
    size_t size_;
};

class EntryBaseDropped : public EntryBase {
  public:
    EntryBaseDropped() : dropped_(0) {}
    explicit EntryBaseDropped(const LogStatisticsElement& element)
        : EntryBase(element), dropped_(element.dropped_count) {}

    size_t dropped_count() const { return dropped_; }

    void Add(const LogStatisticsElement& element) {
        dropped_ += element.dropped_count;
        EntryBase::Add(element);
    }
    bool Subtract(const LogStatisticsElement& element) {
        dropped_ -= element.dropped_count;
        return EntryBase::Subtract(element) && !dropped_;
    }
    void Drop(const LogStatisticsElement& element) {
        dropped_ += 1;
        EntryBase::Subtract(element);
    }

  private:
    size_t dropped_;
};

class UidEntry : public EntryBaseDropped {
  public:
    explicit UidEntry(const LogStatisticsElement& element)
        : EntryBaseDropped(element), pid_(element.pid) {}

    pid_t pid() const { return pid_; }

    void Add(const LogStatisticsElement& element) {
        if (pid_ != element.pid) {
            pid_ = -1;
        }
        EntryBaseDropped::Add(element);
    }

    std::string formatHeader(const std::string& name, log_id_t id) const;
    std::string format(const LogStatistics& stat, log_id_t id, uid_t uid) const;

  private:
    pid_t pid_;
};

namespace android {
uid_t pidToUid(pid_t pid);
}

class PidEntry : public EntryBaseDropped {
  public:
    explicit PidEntry(pid_t pid)
        : EntryBaseDropped(),
          uid_(android::pidToUid(pid)),
          name_(android::pidToName(pid)) {}
    explicit PidEntry(const LogStatisticsElement& element)
        : EntryBaseDropped(element), uid_(element.uid), name_(android::pidToName(element.pid)) {}
    PidEntry(const PidEntry& element)
        : EntryBaseDropped(element),
          uid_(element.uid_),
          name_(element.name_ ? strdup(element.name_) : nullptr) {}
    ~PidEntry() { free(name_); }

    uid_t uid() const { return uid_; }
    const char* name() const { return name_; }

    void Add(pid_t new_pid) {
        if (name_ && !fastcmp<strncmp>(name_, "zygote", 6)) {
            free(name_);
            name_ = nullptr;
        }
        if (!name_) {
            name_ = android::pidToName(new_pid);
        }
    }

    void Add(const LogStatisticsElement& element) {
        uid_t incoming_uid = element.uid;
        if (uid() != incoming_uid) {
            uid_ = incoming_uid;
            free(name_);
            name_ = android::pidToName(element.pid);
        } else {
            Add(element.pid);
        }
        EntryBaseDropped::Add(element);
    }

    std::string formatHeader(const std::string& name, log_id_t id) const;
    std::string format(const LogStatistics& stat, log_id_t id, pid_t pid) const;

  private:
    uid_t uid_;
    char* name_;
};

class TidEntry : public EntryBaseDropped {
  public:
    TidEntry(pid_t tid, pid_t pid)
        : EntryBaseDropped(),
          pid_(pid),
          uid_(android::pidToUid(tid)),
          name_(android::tidToName(tid)) {}
    explicit TidEntry(const LogStatisticsElement& element)
        : EntryBaseDropped(element),
          pid_(element.pid),
          uid_(element.uid),
          name_(android::tidToName(element.tid)) {}
    TidEntry(const TidEntry& element)
        : EntryBaseDropped(element),
          pid_(element.pid_),
          uid_(element.uid_),
          name_(element.name_ ? strdup(element.name_) : nullptr) {}
    ~TidEntry() { free(name_); }

    pid_t pid() const { return pid_; }
    uid_t uid() const { return uid_; }
    const char* name() const { return name_; }

    void Add(pid_t incomingTid) {
        if (name_ && !fastcmp<strncmp>(name_, "zygote", 6)) {
            free(name_);
            name_ = nullptr;
        }
        if (!name_) {
            name_ = android::tidToName(incomingTid);
        }
    }

    void Add(const LogStatisticsElement& element) {
        uid_t incoming_uid = element.uid;
        pid_t incoming_pid = element.pid;
        if (uid() != incoming_uid || pid() != incoming_pid) {
            uid_ = incoming_uid;
            pid_ = incoming_pid;
            free(name_);
            name_ = android::tidToName(element.tid);
        } else {
            Add(element.tid);
        }
        EntryBaseDropped::Add(element);
    }

    std::string formatHeader(const std::string& name, log_id_t id) const;
    std::string format(const LogStatistics& stat, log_id_t id, pid_t pid) const;

  private:
    pid_t pid_;
    uid_t uid_;
    char* name_;
};

class TagEntry : public EntryBaseDropped {
  public:
    explicit TagEntry(const LogStatisticsElement& element)
        : EntryBaseDropped(element), tag_(element.tag), pid_(element.pid), uid_(element.uid) {}

    uint32_t key() const { return tag_; }
    pid_t pid() const { return pid_; }
    uid_t uid() const { return uid_; }
    const char* name() const { return android::tagToName(tag_); }

    void Add(const LogStatisticsElement& element) {
        if (uid_ != element.uid) {
            uid_ = -1;
        }
        if (pid_ != element.pid) {
            pid_ = -1;
        }
        EntryBaseDropped::Add(element);
    }

    std::string formatHeader(const std::string& name, log_id_t id) const;
    std::string format(const LogStatistics& stat, log_id_t id, uint32_t) const;

  private:
    const uint32_t tag_;
    pid_t pid_;
    uid_t uid_;
};

class TagNameEntry : public EntryBase {
  public:
    explicit TagNameEntry(const LogStatisticsElement& element)
        : EntryBase(element), tid_(element.tid), pid_(element.pid), uid_(element.uid) {}

    pid_t tid() const { return tid_; }
    pid_t pid() const { return pid_; }
    uid_t uid() const { return uid_; }

    void Add(const LogStatisticsElement& element) {
        if (uid_ != element.uid) {
            uid_ = -1;
        }
        if (pid_ != element.pid) {
            pid_ = -1;
        }
        if (tid_ != element.tid) {
            tid_ = -1;
        }
        EntryBase::Add(element);
    }

    std::string formatHeader(const std::string& name, log_id_t id) const;
    std::string format(const LogStatistics& stat, log_id_t id, const std::string& key_name) const;

  private:
    pid_t tid_;
    pid_t pid_;
    uid_t uid_;
};

class LogStatistics {
    friend UidEntry;
    friend PidEntry;
    friend TidEntry;

    size_t mSizes[LOG_ID_MAX] GUARDED_BY(lock_);
    size_t mElements[LOG_ID_MAX] GUARDED_BY(lock_);
    size_t mDroppedElements[LOG_ID_MAX] GUARDED_BY(lock_);
    size_t mSizesTotal[LOG_ID_MAX] GUARDED_BY(lock_);
    size_t mElementsTotal[LOG_ID_MAX] GUARDED_BY(lock_);
    log_time mOldest[LOG_ID_MAX] GUARDED_BY(lock_);
    log_time mNewest[LOG_ID_MAX] GUARDED_BY(lock_);
    log_time mNewestDropped[LOG_ID_MAX] GUARDED_BY(lock_);
    static std::atomic<size_t> SizesTotal;
    bool enable;

    // uid to size list
    typedef LogHashtable<uid_t, UidEntry> uidTable_t;
    uidTable_t uidTable[LOG_ID_MAX] GUARDED_BY(lock_);

    // pid of system to size list
    typedef LogHashtable<pid_t, PidEntry> pidSystemTable_t;
    pidSystemTable_t pidSystemTable[LOG_ID_MAX] GUARDED_BY(lock_);

    // pid to uid list
    typedef LogHashtable<pid_t, PidEntry> pidTable_t;
    pidTable_t pidTable GUARDED_BY(lock_);

    // tid to uid list
    typedef LogHashtable<pid_t, TidEntry> tidTable_t;
    tidTable_t tidTable GUARDED_BY(lock_);

    // tag list
    typedef LogHashtable<uint32_t, TagEntry> tagTable_t;
    tagTable_t tagTable GUARDED_BY(lock_);

    // security tag list
    tagTable_t securityTagTable GUARDED_BY(lock_);

    // global tag list
    typedef LogHashtable<std::string, TagNameEntry> tagNameTable_t;
    tagNameTable_t tagNameTable;

    size_t sizeOf() const REQUIRES(lock_) {
        size_t size = sizeof(*this) + pidTable.sizeOf() + tidTable.sizeOf() +
                      tagTable.sizeOf() + securityTagTable.sizeOf() +
                      tagNameTable.sizeOf() +
                      (pidTable.size() * sizeof(pidTable_t::iterator)) +
                      (tagTable.size() * sizeof(tagTable_t::iterator));
        for (auto it : pidTable) {
            const char* name = it.second.name();
            if (name) size += strlen(name) + 1;
        }
        for (auto it : tidTable) {
            const char* name = it.second.name();
            if (name) size += strlen(name) + 1;
        }
        for (auto it : tagNameTable) {
            size += sizeof(std::string);
            size_t len = it.first.size();
            // Account for short string optimization: if the string's length is <= 22 bytes for 64
            // bit or <= 10 bytes for 32 bit, then there is no additional allocation.
            if ((sizeof(std::string) == 24 && len > 22) ||
                (sizeof(std::string) != 24 && len > 10)) {
                size += len;
            }
        }
        log_id_for_each(id) {
            size += uidTable[id].sizeOf();
            size += uidTable[id].size() * sizeof(uidTable_t::iterator);
            size += pidSystemTable[id].sizeOf();
            size += pidSystemTable[id].size() * sizeof(pidSystemTable_t::iterator);
        }
        return size;
    }

  public:
    LogStatistics(bool enable_statistics);

    void AddTotal(log_id_t log_id, uint16_t size) EXCLUDES(lock_);
    void Add(const LogStatisticsElement& entry) EXCLUDES(lock_);
    void Subtract(const LogStatisticsElement& entry) EXCLUDES(lock_);
    // entry->setDropped(1) must follow this call
    void Drop(const LogStatisticsElement& entry) EXCLUDES(lock_);
    // Correct for coalescing two entries referencing dropped content
    void Erase(const LogStatisticsElement& element) EXCLUDES(lock_) {
        auto lock = std::lock_guard{lock_};
        log_id_t log_id = element.log_id;
        --mElements[log_id];
        --mDroppedElements[log_id];
    }

    void WorstTwoUids(log_id id, size_t threshold, int* worst, size_t* worst_sizes,
                      size_t* second_worst_sizes) const EXCLUDES(lock_);
    void WorstTwoTags(size_t threshold, int* worst, size_t* worst_sizes,
                      size_t* second_worst_sizes) const EXCLUDES(lock_);
    void WorstTwoSystemPids(log_id id, size_t worst_uid_sizes, int* worst,
                            size_t* second_worst_sizes) const EXCLUDES(lock_);

    bool ShouldPrune(log_id id, unsigned long max_size, unsigned long* prune_rows) const
            EXCLUDES(lock_);

    // Snapshot of the sizes for a given log buffer.
    size_t Sizes(log_id_t id) const EXCLUDES(lock_) {
        auto lock = std::lock_guard{lock_};
        return mSizes[id];
    }
    // TODO: Get rid of this entirely.
    static size_t sizesTotal() {
        return SizesTotal;
    }

    std::string Format(uid_t uid, pid_t pid, unsigned int logMask) const EXCLUDES(lock_);

    const char* PidToName(pid_t pid) const EXCLUDES(lock_);
    uid_t PidToUid(pid_t pid) EXCLUDES(lock_);
    const char* UidToName(uid_t uid) const EXCLUDES(lock_);

  private:
    template <typename TKey, typename TEntry>
    void WorstTwoWithThreshold(const LogHashtable<TKey, TEntry>& table, size_t threshold,
                               int* worst, size_t* worst_sizes, size_t* second_worst_sizes) const;
    template <typename TKey, typename TEntry>
    std::string FormatTable(const LogHashtable<TKey, TEntry>& table, uid_t uid, pid_t pid,
                            const std::string& name = std::string(""),
                            log_id_t id = LOG_ID_MAX) const REQUIRES(lock_);
    void FormatTmp(const char* nameTmp, uid_t uid, std::string& name, std::string& size,
                   size_t nameLen) const REQUIRES(lock_);
    const char* UidToNameLocked(uid_t uid) const REQUIRES(lock_);

    mutable std::mutex lock_;
};
