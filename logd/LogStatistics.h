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

#ifndef _LOGD_LOG_STATISTICS_H__
#define _LOGD_LOG_STATISTICS_H__

#include <ctype.h>
#include <stdlib.h>
#include <sys/types.h>

#include <algorithm>  // std::max
#include <memory>
#include <string>  // std::string
#include <unordered_map>

#include <android-base/stringprintf.h>
#include <android/log.h>
#include <private/android_filesystem_config.h>

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

    std::unique_ptr<const TEntry* []> sort(uid_t uid, pid_t pid,
                                           size_t len) const {
        if (!len) {
            std::unique_ptr<const TEntry* []> sorted(NULL);
            return sorted;
        }

        const TEntry** retval = new const TEntry*[len];
        memset(retval, 0, sizeof(*retval) * len);

        for (const_iterator it = map.begin(); it != map.end(); ++it) {
            const TEntry& entry = it->second;

            if ((uid != AID_ROOT) && (uid != entry.getUid())) {
                continue;
            }
            if (pid && entry.getPid() && (pid != entry.getPid())) {
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
        std::unique_ptr<const TEntry* []> sorted(retval);
        return sorted;
    }

    inline iterator add(TKey key, LogBufferElement* element) {
        iterator it = map.find(key);
        if (it == map.end()) {
            it = map.insert(std::make_pair(key, TEntry(element))).first;
        } else {
            it->second.add(element);
        }
        return it;
    }

    inline iterator add(TKey key) {
        iterator it = map.find(key);
        if (it == map.end()) {
            it = map.insert(std::make_pair(key, TEntry(key))).first;
        } else {
            it->second.add(key);
        }
        return it;
    }

    void subtract(TKey key, LogBufferElement* element) {
        iterator it = map.find(key);
        if ((it != map.end()) && it->second.subtract(element)) {
            map.erase(it);
        }
    }

    inline void drop(TKey key, LogBufferElement* element) {
        iterator it = map.find(key);
        if (it != map.end()) {
            it->second.drop(element);
        }
    }

    inline iterator begin() {
        return map.begin();
    }
    inline const_iterator begin() const {
        return map.begin();
    }
    inline iterator end() {
        return map.end();
    }
    inline const_iterator end() const {
        return map.end();
    }

    std::string format(const LogStatistics& stat, uid_t uid, pid_t pid,
                       const std::string& name = std::string(""),
                       log_id_t id = LOG_ID_MAX) const {
        static const size_t maximum_sorted_entries = 32;
        std::string output;
        std::unique_ptr<const TEntry* []> sorted =
            sort(uid, pid, maximum_sorted_entries);
        if (!sorted.get()) {
            return output;
        }
        bool headerPrinted = false;
        for (size_t index = 0; index < maximum_sorted_entries; ++index) {
            const TEntry* entry = sorted[index];
            if (!entry) {
                break;
            }
            if (entry->getSizes() <= (sorted[0]->getSizes() / 100)) {
                break;
            }
            if (!headerPrinted) {
                output += "\n\n";
                output += entry->formatHeader(name, id);
                headerPrinted = true;
            }
            output += entry->format(stat, id);
        }
        return output;
    }
};

namespace EntryBaseConstants {
static constexpr size_t pruned_len = 14;
static constexpr size_t total_len = 80;
}

struct EntryBase {
    size_t size;

    EntryBase() : size(0) {
    }
    explicit EntryBase(LogBufferElement* element) : size(element->getMsgLen()) {
    }

    size_t getSizes() const {
        return size;
    }

    inline void add(LogBufferElement* element) {
        size += element->getMsgLen();
    }
    inline bool subtract(LogBufferElement* element) {
        size -= element->getMsgLen();
        return !size;
    }

    static std::string formatLine(const std::string& name,
                                  const std::string& size,
                                  const std::string& pruned) {
        ssize_t drop_len =
            std::max(pruned.length() + 1, EntryBaseConstants::pruned_len);
        ssize_t size_len =
            std::max(size.length() + 1, EntryBaseConstants::total_len -
                                            name.length() - drop_len - 1);

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
};

struct EntryBaseDropped : public EntryBase {
    size_t dropped;

    EntryBaseDropped() : dropped(0) {
    }
    explicit EntryBaseDropped(LogBufferElement* element)
        : EntryBase(element), dropped(element->getDropped()) {
    }

    size_t getDropped() const {
        return dropped;
    }

    inline void add(LogBufferElement* element) {
        dropped += element->getDropped();
        EntryBase::add(element);
    }
    inline bool subtract(LogBufferElement* element) {
        dropped -= element->getDropped();
        return EntryBase::subtract(element) && !dropped;
    }
    inline void drop(LogBufferElement* element) {
        dropped += 1;
        EntryBase::subtract(element);
    }
};

struct UidEntry : public EntryBaseDropped {
    const uid_t uid;
    pid_t pid;

    explicit UidEntry(LogBufferElement* element)
        : EntryBaseDropped(element),
          uid(element->getUid()),
          pid(element->getPid()) {
    }

    inline const uid_t& getKey() const {
        return uid;
    }
    inline const uid_t& getUid() const {
        return getKey();
    }
    inline const pid_t& getPid() const {
        return pid;
    }

    inline void add(LogBufferElement* element) {
        if (pid != element->getPid()) {
            pid = -1;
        }
        EntryBaseDropped::add(element);
    }

    std::string formatHeader(const std::string& name, log_id_t id) const;
    std::string format(const LogStatistics& stat, log_id_t id) const;
};

namespace android {
uid_t pidToUid(pid_t pid);
}

struct PidEntry : public EntryBaseDropped {
    const pid_t pid;
    uid_t uid;
    char* name;

    explicit PidEntry(pid_t pid)
        : EntryBaseDropped(),
          pid(pid),
          uid(android::pidToUid(pid)),
          name(android::pidToName(pid)) {
    }
    explicit PidEntry(LogBufferElement* element)
        : EntryBaseDropped(element),
          pid(element->getPid()),
          uid(element->getUid()),
          name(android::pidToName(pid)) {
    }
    PidEntry(const PidEntry& element)
        : EntryBaseDropped(element),
          pid(element.pid),
          uid(element.uid),
          name(element.name ? strdup(element.name) : NULL) {
    }
    ~PidEntry() {
        free(name);
    }

    const pid_t& getKey() const {
        return pid;
    }
    const pid_t& getPid() const {
        return getKey();
    }
    const uid_t& getUid() const {
        return uid;
    }
    const char* getName() const {
        return name;
    }

    inline void add(pid_t newPid) {
        if (name && !fastcmp<strncmp>(name, "zygote", 6)) {
            free(name);
            name = NULL;
        }
        if (!name) {
            name = android::pidToName(newPid);
        }
    }

    inline void add(LogBufferElement* element) {
        uid_t incomingUid = element->getUid();
        if (getUid() != incomingUid) {
            uid = incomingUid;
            free(name);
            name = android::pidToName(element->getPid());
        } else {
            add(element->getPid());
        }
        EntryBaseDropped::add(element);
    }

    std::string formatHeader(const std::string& name, log_id_t id) const;
    std::string format(const LogStatistics& stat, log_id_t id) const;
};

struct TidEntry : public EntryBaseDropped {
    const pid_t tid;
    pid_t pid;
    uid_t uid;
    char* name;

    TidEntry(pid_t tid, pid_t pid)
        : EntryBaseDropped(),
          tid(tid),
          pid(pid),
          uid(android::pidToUid(tid)),
          name(android::tidToName(tid)) {
    }
    explicit TidEntry(LogBufferElement* element)
        : EntryBaseDropped(element),
          tid(element->getTid()),
          pid(element->getPid()),
          uid(element->getUid()),
          name(android::tidToName(tid)) {
    }
    TidEntry(const TidEntry& element)
        : EntryBaseDropped(element),
          tid(element.tid),
          pid(element.pid),
          uid(element.uid),
          name(element.name ? strdup(element.name) : NULL) {
    }
    ~TidEntry() {
        free(name);
    }

    const pid_t& getKey() const {
        return tid;
    }
    const pid_t& getTid() const {
        return getKey();
    }
    const pid_t& getPid() const {
        return pid;
    }
    const uid_t& getUid() const {
        return uid;
    }
    const char* getName() const {
        return name;
    }

    inline void add(pid_t incomingTid) {
        if (name && !fastcmp<strncmp>(name, "zygote", 6)) {
            free(name);
            name = NULL;
        }
        if (!name) {
            name = android::tidToName(incomingTid);
        }
    }

    inline void add(LogBufferElement* element) {
        uid_t incomingUid = element->getUid();
        pid_t incomingPid = element->getPid();
        if ((getUid() != incomingUid) || (getPid() != incomingPid)) {
            uid = incomingUid;
            pid = incomingPid;
            free(name);
            name = android::tidToName(element->getTid());
        } else {
            add(element->getTid());
        }
        EntryBaseDropped::add(element);
    }

    std::string formatHeader(const std::string& name, log_id_t id) const;
    std::string format(const LogStatistics& stat, log_id_t id) const;
};

struct TagEntry : public EntryBaseDropped {
    const uint32_t tag;
    pid_t pid;
    uid_t uid;

    explicit TagEntry(LogBufferElement* element)
        : EntryBaseDropped(element),
          tag(element->getTag()),
          pid(element->getPid()),
          uid(element->getUid()) {
    }

    const uint32_t& getKey() const {
        return tag;
    }
    const pid_t& getPid() const {
        return pid;
    }
    const uid_t& getUid() const {
        return uid;
    }
    const char* getName() const {
        return android::tagToName(tag);
    }

    inline void add(LogBufferElement* element) {
        if (uid != element->getUid()) {
            uid = -1;
        }
        if (pid != element->getPid()) {
            pid = -1;
        }
        EntryBaseDropped::add(element);
    }

    std::string formatHeader(const std::string& name, log_id_t id) const;
    std::string format(const LogStatistics& stat, log_id_t id) const;
};

template <typename TEntry>
class LogFindWorst {
    std::unique_ptr<const TEntry* []> sorted;

   public:
    explicit LogFindWorst(std::unique_ptr<const TEntry* []>&& sorted)
        : sorted(std::move(sorted)) {
    }

    void findWorst(int& worst, size_t& worst_sizes, size_t& second_worst_sizes,
                   size_t threshold) {
        if (sorted.get() && sorted[0] && sorted[1]) {
            worst_sizes = sorted[0]->getSizes();
            if ((worst_sizes > threshold)
                // Allow time horizon to extend roughly tenfold, assume
                // average entry length is 100 characters.
                && (worst_sizes > (10 * sorted[0]->getDropped()))) {
                worst = sorted[0]->getKey();
                second_worst_sizes = sorted[1]->getSizes();
                if (second_worst_sizes < threshold) {
                    second_worst_sizes = threshold;
                }
            }
        }
    }

    void findWorst(int& worst, size_t worst_sizes, size_t& second_worst_sizes) {
        if (sorted.get() && sorted[0] && sorted[1]) {
            worst = sorted[0]->getKey();
            second_worst_sizes =
                worst_sizes - sorted[0]->getSizes() + sorted[1]->getSizes();
        }
    }
};

// Log Statistics
class LogStatistics {
    friend UidEntry;

    size_t mSizes[LOG_ID_MAX];
    size_t mElements[LOG_ID_MAX];
    size_t mDroppedElements[LOG_ID_MAX];
    size_t mSizesTotal[LOG_ID_MAX];
    size_t mElementsTotal[LOG_ID_MAX];
    static size_t SizesTotal;
    bool enable;

    // uid to size list
    typedef LogHashtable<uid_t, UidEntry> uidTable_t;
    uidTable_t uidTable[LOG_ID_MAX];

    // pid of system to size list
    typedef LogHashtable<pid_t, PidEntry> pidSystemTable_t;
    pidSystemTable_t pidSystemTable[LOG_ID_MAX];

    // pid to uid list
    typedef LogHashtable<pid_t, PidEntry> pidTable_t;
    pidTable_t pidTable;

    // tid to uid list
    typedef LogHashtable<pid_t, TidEntry> tidTable_t;
    tidTable_t tidTable;

    // tag list
    typedef LogHashtable<uint32_t, TagEntry> tagTable_t;
    tagTable_t tagTable;

    // security tag list
    tagTable_t securityTagTable;

    size_t sizeOf() const {
        size_t size = sizeof(*this) + pidTable.sizeOf() + tidTable.sizeOf() +
                      tagTable.sizeOf() + securityTagTable.sizeOf() +
                      (pidTable.size() * sizeof(pidTable_t::iterator)) +
                      (tagTable.size() * sizeof(tagTable_t::iterator));
        for (auto it : pidTable) {
            const char* name = it.second.getName();
            if (name) size += strlen(name) + 1;
        }
        for (auto it : tidTable) {
            const char* name = it.second.getName();
            if (name) size += strlen(name) + 1;
        }
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
    LogStatistics();

    void enableStatistics() {
        enable = true;
    }

    void add(LogBufferElement* entry);
    void subtract(LogBufferElement* entry);
    // entry->setDropped(1) must follow this call
    void drop(LogBufferElement* entry);
    // Correct for coalescing two entries referencing dropped content
    void erase(LogBufferElement* element) {
        log_id_t log_id = element->getLogId();
        --mElements[log_id];
        --mDroppedElements[log_id];
    }

    LogFindWorst<UidEntry> sort(uid_t uid, pid_t pid, size_t len, log_id id) {
        return LogFindWorst<UidEntry>(uidTable[id].sort(uid, pid, len));
    }
    LogFindWorst<PidEntry> sortPids(uid_t uid, pid_t pid, size_t len,
                                    log_id id) {
        return LogFindWorst<PidEntry>(pidSystemTable[id].sort(uid, pid, len));
    }
    LogFindWorst<TagEntry> sortTags(uid_t uid, pid_t pid, size_t len, log_id) {
        return LogFindWorst<TagEntry>(tagTable.sort(uid, pid, len));
    }

    // fast track current value by id only
    size_t sizes(log_id_t id) const {
        return mSizes[id];
    }
    size_t elements(log_id_t id) const {
        return mElements[id];
    }
    size_t realElements(log_id_t id) const {
        return mElements[id] - mDroppedElements[id];
    }
    size_t sizesTotal(log_id_t id) const {
        return mSizesTotal[id];
    }
    size_t elementsTotal(log_id_t id) const {
        return mElementsTotal[id];
    }
    static size_t sizesTotal() {
        return SizesTotal;
    }

    std::string format(uid_t uid, pid_t pid, unsigned int logMask) const;

    // helper (must be locked directly or implicitly by mLogElementsLock)
    const char* pidToName(pid_t pid) const;
    uid_t pidToUid(pid_t pid);
    const char* uidToName(uid_t uid) const;
};

#endif  // _LOGD_LOG_STATISTICS_H__
