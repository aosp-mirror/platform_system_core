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

#include "LogBufferElement.h"
#include "LogUtils.h"

#define log_id_for_each(i) \
    for (log_id_t i = LOG_ID_MIN; (i) < LOG_ID_MAX; (i) = (log_id_t)((i) + 1))

class LogStatistics;

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
    void MaxEntries(uid_t uid, pid_t pid, std::array<const TEntry*, len>* out) const {
        auto& retval = *out;
        retval.fill(nullptr);
        for (const_iterator it = map.begin(); it != map.end(); ++it) {
            const TEntry& entry = it->second;

            if (uid != AID_ROOT && uid != entry.uid()) {
                continue;
            }
            if (pid && entry.pid() && pid != entry.pid()) {
                continue;
            }

            size_t sizes = entry.getSizes();
            ssize_t index = len - 1;
            while ((!retval[index] || (sizes > retval[index]->getSizes())) &&
                   (--index >= 0))
                ;
            if (++index < (ssize_t)len) {
                size_t num = len - index - 1;
                if (num) {
                    memmove(&retval[index + 1], &retval[index],
                            num * sizeof(retval[0]));
                }
                retval[index] = &entry;
            }
        }
    }

    iterator Add(const TKey& key, const LogBufferElement& element) {
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

    void Subtract(const TKey& key, const LogBufferElement& element) {
        iterator it = map.find(key);
        if (it != map.end() && it->second.Subtract(element)) {
            map.erase(it);
        }
    }

    void Drop(const TKey& key, const LogBufferElement& element) {
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
    explicit EntryBase(const LogBufferElement& element) : size_(element.msg_len()) {}

    size_t getSizes() const { return size_; }

    void Add(const LogBufferElement& element) { size_ += element.msg_len(); }
    bool Subtract(const LogBufferElement& element) {
        size_ -= element.msg_len();
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
    explicit EntryBaseDropped(const LogBufferElement& element)
        : EntryBase(element), dropped_(element.dropped_count()) {}

    size_t dropped_count() const { return dropped_; }

    void Add(const LogBufferElement& element) {
        dropped_ += element.dropped_count();
        EntryBase::Add(element);
    }
    bool Subtract(const LogBufferElement& element) {
        dropped_ -= element.dropped_count();
        return EntryBase::Subtract(element) && !dropped_;
    }
    void Drop(const LogBufferElement& element) {
        dropped_ += 1;
        EntryBase::Subtract(element);
    }

  private:
    size_t dropped_;
};

class UidEntry : public EntryBaseDropped {
  public:
    explicit UidEntry(const LogBufferElement& element)
        : EntryBaseDropped(element), uid_(element.uid()), pid_(element.pid()) {}

    uid_t key() const { return uid_; }
    uid_t uid() const { return key(); }
    pid_t pid() const { return pid_; }

    void Add(const LogBufferElement& element) {
        if (pid_ != element.pid()) {
            pid_ = -1;
        }
        EntryBaseDropped::Add(element);
    }

    std::string formatHeader(const std::string& name, log_id_t id) const;
    std::string format(const LogStatistics& stat, log_id_t id) const;

  private:
    const uid_t uid_;
    pid_t pid_;
};

namespace android {
uid_t pidToUid(pid_t pid);
}

class PidEntry : public EntryBaseDropped {
  public:
    explicit PidEntry(pid_t pid)
        : EntryBaseDropped(),
          pid_(pid),
          uid_(android::pidToUid(pid)),
          name_(android::pidToName(pid)) {}
    explicit PidEntry(const LogBufferElement& element)
        : EntryBaseDropped(element),
          pid_(element.pid()),
          uid_(element.uid()),
          name_(android::pidToName(pid_)) {}
    PidEntry(const PidEntry& element)
        : EntryBaseDropped(element),
          pid_(element.pid_),
          uid_(element.uid_),
          name_(element.name_ ? strdup(element.name_) : nullptr) {}
    ~PidEntry() { free(name_); }

    pid_t key() const { return pid_; }
    pid_t pid() const { return key(); }
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

    void Add(const LogBufferElement& element) {
        uid_t incoming_uid = element.uid();
        if (uid() != incoming_uid) {
            uid_ = incoming_uid;
            free(name_);
            name_ = android::pidToName(element.pid());
        } else {
            Add(element.pid());
        }
        EntryBaseDropped::Add(element);
    }

    std::string formatHeader(const std::string& name, log_id_t id) const;
    std::string format(const LogStatistics& stat, log_id_t id) const;

  private:
    const pid_t pid_;
    uid_t uid_;
    char* name_;
};

class TidEntry : public EntryBaseDropped {
  public:
    TidEntry(pid_t tid, pid_t pid)
        : EntryBaseDropped(),
          tid_(tid),
          pid_(pid),
          uid_(android::pidToUid(tid)),
          name_(android::tidToName(tid)) {}
    explicit TidEntry(const LogBufferElement& element)
        : EntryBaseDropped(element),
          tid_(element.tid()),
          pid_(element.pid()),
          uid_(element.uid()),
          name_(android::tidToName(tid_)) {}
    TidEntry(const TidEntry& element)
        : EntryBaseDropped(element),
          tid_(element.tid_),
          pid_(element.pid_),
          uid_(element.uid_),
          name_(element.name_ ? strdup(element.name_) : nullptr) {}
    ~TidEntry() { free(name_); }

    pid_t key() const { return tid_; }
    pid_t tid() const { return key(); }
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

    void Add(const LogBufferElement& element) {
        uid_t incoming_uid = element.uid();
        pid_t incoming_pid = element.pid();
        if (uid() != incoming_uid || pid() != incoming_pid) {
            uid_ = incoming_uid;
            pid_ = incoming_pid;
            free(name_);
            name_ = android::tidToName(element.tid());
        } else {
            Add(element.tid());
        }
        EntryBaseDropped::Add(element);
    }

    std::string formatHeader(const std::string& name, log_id_t id) const;
    std::string format(const LogStatistics& stat, log_id_t id) const;

  private:
    const pid_t tid_;
    pid_t pid_;
    uid_t uid_;
    char* name_;
};

class TagEntry : public EntryBaseDropped {
  public:
    explicit TagEntry(const LogBufferElement& element)
        : EntryBaseDropped(element),
          tag_(element.GetTag()),
          pid_(element.pid()),
          uid_(element.uid()) {}

    uint32_t key() const { return tag_; }
    pid_t pid() const { return pid_; }
    uid_t uid() const { return uid_; }
    const char* name() const { return android::tagToName(tag_); }

    void Add(const LogBufferElement& element) {
        if (uid_ != element.uid()) {
            uid_ = -1;
        }
        if (pid_ != element.pid()) {
            pid_ = -1;
        }
        EntryBaseDropped::Add(element);
    }

    std::string formatHeader(const std::string& name, log_id_t id) const;
    std::string format(const LogStatistics& stat, log_id_t id) const;

  private:
    const uint32_t tag_;
    pid_t pid_;
    uid_t uid_;
};

struct TagNameKey {
    std::string* alloc;
    std::string_view name;  // Saves space if const char*

    explicit TagNameKey(const LogBufferElement& element) : alloc(nullptr), name("", strlen("")) {
        if (element.IsBinary()) {
            uint32_t tag = element.GetTag();
            if (tag) {
                const char* cp = android::tagToName(tag);
                if (cp) {
                    name = std::string_view(cp, strlen(cp));
                    return;
                }
            }
            alloc = new std::string(
                android::base::StringPrintf("[%" PRIu32 "]", tag));
            if (!alloc) return;
            name = std::string_view(alloc->c_str(), alloc->size());
            return;
        }
        const char* msg = element.msg();
        if (!msg) {
            name = std::string_view("chatty", strlen("chatty"));
            return;
        }
        ++msg;
        uint16_t len = element.msg_len();
        len = (len <= 1) ? 0 : strnlen(msg, len - 1);
        if (!len) {
            name = std::string_view("<NULL>", strlen("<NULL>"));
            return;
        }
        alloc = new std::string(msg, len);
        if (!alloc) return;
        name = std::string_view(alloc->c_str(), alloc->size());
    }

    explicit TagNameKey(TagNameKey&& rval) noexcept
        : alloc(rval.alloc), name(rval.name.data(), rval.name.length()) {
        rval.alloc = nullptr;
    }

    explicit TagNameKey(const TagNameKey& rval)
        : alloc(rval.alloc ? new std::string(*rval.alloc) : nullptr),
          name(alloc ? alloc->data() : rval.name.data(), rval.name.length()) {
    }

    ~TagNameKey() {
        if (alloc) delete alloc;
    }

    operator const std::string_view() const {
        return name;
    }

    const char* data() const {
        return name.data();
    }
    size_t length() const {
        return name.length();
    }

    bool operator==(const TagNameKey& rval) const {
        if (length() != rval.length()) return false;
        if (length() == 0) return true;
        return fastcmp<strncmp>(data(), rval.data(), length()) == 0;
    }
    bool operator!=(const TagNameKey& rval) const {
        return !(*this == rval);
    }

    size_t getAllocLength() const {
        return alloc ? alloc->length() + 1 + sizeof(std::string) : 0;
    }
};

// Hash for TagNameKey
template <>
struct std::hash<TagNameKey>
    : public std::unary_function<const TagNameKey&, size_t> {
    size_t operator()(const TagNameKey& __t) const noexcept {
        if (!__t.length()) return 0;
        return std::hash<std::string_view>()(std::string_view(__t));
    }
};

class TagNameEntry : public EntryBase {
  public:
    explicit TagNameEntry(const LogBufferElement& element)
        : EntryBase(element),
          tid_(element.tid()),
          pid_(element.pid()),
          uid_(element.uid()),
          name_(element) {}

    const TagNameKey& key() const { return name_; }
    pid_t tid() const { return tid_; }
    pid_t pid() const { return pid_; }
    uid_t uid() const { return uid_; }
    const char* name() const { return name_.data(); }
    size_t getNameAllocLength() const { return name_.getAllocLength(); }

    void Add(const LogBufferElement& element) {
        if (uid_ != element.uid()) {
            uid_ = -1;
        }
        if (pid_ != element.pid()) {
            pid_ = -1;
        }
        if (tid_ != element.tid()) {
            tid_ = -1;
        }
        EntryBase::Add(element);
    }

    std::string formatHeader(const std::string& name, log_id_t id) const;
    std::string format(const LogStatistics& stat, log_id_t id) const;

  private:
    pid_t tid_;
    pid_t pid_;
    uid_t uid_;
    TagNameKey name_;
};

// Log Statistics
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
    typedef LogHashtable<TagNameKey, TagNameEntry> tagNameTable_t;
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
        for (auto it : tagNameTable) size += it.second.getNameAllocLength();
        log_id_for_each(id) {
            size += uidTable[id].sizeOf();
            size += uidTable[id].size() * sizeof(uidTable_t::iterator);
            size += pidSystemTable[id].sizeOf();
            size +=
                pidSystemTable[id].size() * sizeof(pidSystemTable_t::iterator);
        }
        return size;
    }

  public:
    LogStatistics(bool enable_statistics);

    void AddTotal(log_id_t log_id, uint16_t size) EXCLUDES(lock_);
    void Add(const LogBufferElement& entry) EXCLUDES(lock_);
    void Subtract(const LogBufferElement& entry) EXCLUDES(lock_);
    // entry->setDropped(1) must follow this call
    void Drop(const LogBufferElement& entry) EXCLUDES(lock_);
    // Correct for coalescing two entries referencing dropped content
    void Erase(const LogBufferElement& element) EXCLUDES(lock_) {
        auto lock = std::lock_guard{lock_};
        log_id_t log_id = element.log_id();
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
