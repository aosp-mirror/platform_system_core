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

#include <memory>
#include <stdlib.h>
#include <sys/types.h>

#include <log/log.h>
#include <utils/BasicHashtable.h>

#include "LogBufferElement.h"

#define log_id_for_each(i) \
    for (log_id_t i = LOG_ID_MIN; i < LOG_ID_MAX; i = (log_id_t) (i + 1))

template <typename TKey, typename TEntry>
class LogHashtable : public android::BasicHashtable<TKey, TEntry> {
public:
    std::unique_ptr<const TEntry *[]> sort(size_t n) {
        if (!n) {
            std::unique_ptr<const TEntry *[]> sorted(NULL);
            return sorted;
        }

        const TEntry **retval = new const TEntry* [n];
        memset(retval, 0, sizeof(*retval) * n);

        ssize_t index = -1;
        while ((index = android::BasicHashtable<TKey, TEntry>::next(index)) >= 0) {
            const TEntry &entry = android::BasicHashtable<TKey, TEntry>::entryAt(index);
            size_t s = entry.getSizes();
            ssize_t i = n - 1;
            while ((!retval[i] || (s > retval[i]->getSizes())) && (--i >= 0))
                ;
            if (++i < (ssize_t)n) {
                size_t b = n - i - 1;
                if (b) {
                    memmove(&retval[i+1], &retval[i], b * sizeof(retval[0]));
                }
                retval[i] = &entry;
            }
        }
        std::unique_ptr<const TEntry *[]> sorted(retval);
        return sorted;
    }

    // Iteration handler for the sort method output
    static ssize_t next(ssize_t index, std::unique_ptr<const TEntry *[]> &sorted, size_t n) {
        ++index;
        if (!sorted.get() || (index < 0) || (n <= (size_t)index) || !sorted[index]
         || (sorted[index]->getSizes() <= (sorted[0]->getSizes() / 100))) {
            return -1;
        }
        return index;
    }

    ssize_t next(ssize_t index) {
        return android::BasicHashtable<TKey, TEntry>::next(index);
    }

    size_t add(TKey key, LogBufferElement *e) {
        android::hash_t hash = android::hash_type(key);
        ssize_t index = android::BasicHashtable<TKey, TEntry>::find(-1, hash, key);
        if (index == -1) {
            return android::BasicHashtable<TKey, TEntry>::add(hash, TEntry(e));
        }
        android::BasicHashtable<TKey, TEntry>::editEntryAt(index).add(e);
        return index;
    }

    inline size_t add(TKey key) {
        android::hash_t hash = android::hash_type(key);
        ssize_t index = android::BasicHashtable<TKey, TEntry>::find(-1, hash, key);
        if (index == -1) {
            return android::BasicHashtable<TKey, TEntry>::add(hash, TEntry(key));
        }
        android::BasicHashtable<TKey, TEntry>::editEntryAt(index).add(key);
        return index;
    }

    void subtract(TKey key, LogBufferElement *e) {
        ssize_t index = android::BasicHashtable<TKey, TEntry>::find(-1, android::hash_type(key), key);
        if ((index != -1)
         && android::BasicHashtable<TKey, TEntry>::editEntryAt(index).subtract(e)) {
            android::BasicHashtable<TKey, TEntry>::removeAt(index);
        }
    }

    inline void drop(TKey key, LogBufferElement *e) {
        ssize_t index = android::BasicHashtable<TKey, TEntry>::find(-1, android::hash_type(key), key);
        if (index != -1) {
            android::BasicHashtable<TKey, TEntry>::editEntryAt(index).drop(e);
        }
    }

};

struct EntryBase {
    size_t size;

    EntryBase():size(0) { }
    EntryBase(LogBufferElement *e):size(e->getMsgLen()) { }

    size_t getSizes() const { return size; }

    inline void add(LogBufferElement *e) { size += e->getMsgLen(); }
    inline bool subtract(LogBufferElement *e) { size -= e->getMsgLen(); return !size; }
};

struct EntryBaseDropped : public EntryBase {
    size_t dropped;

    EntryBaseDropped():dropped(0) { }
    EntryBaseDropped(LogBufferElement *e):EntryBase(e),dropped(e->getDropped()){ }

    size_t getDropped() const { return dropped; }

    inline void add(LogBufferElement *e) {
        dropped += e->getDropped();
        EntryBase::add(e);
    }
    inline bool subtract(LogBufferElement *e) {
        dropped -= e->getDropped();
        return EntryBase::subtract(e) && !dropped;
    }
    inline void drop(LogBufferElement *e) {
        dropped += 1;
        EntryBase::subtract(e);
    }
};

struct UidEntry : public EntryBaseDropped {
    const uid_t uid;

    UidEntry(LogBufferElement *e):EntryBaseDropped(e),uid(e->getUid()) { }

    inline const uid_t&getKey() const { return uid; }
};

namespace android {
// caller must own and free character string
char *pidToName(pid_t pid);
uid_t pidToUid(pid_t pid);
}

struct PidEntry : public EntryBaseDropped {
    const pid_t pid;
    uid_t uid;
    char *name;

    PidEntry(pid_t p):
        EntryBaseDropped(),
        pid(p),
        uid(android::pidToUid(p)),
        name(android::pidToName(pid)) { }
    PidEntry(LogBufferElement *e):
        EntryBaseDropped(e),
        pid(e->getPid()),
        uid(e->getUid()),
        name(android::pidToName(e->getPid())) { }
    PidEntry(const PidEntry &c):
        EntryBaseDropped(c),
        pid(c.pid),
        uid(c.uid),
        name(c.name ? strdup(c.name) : NULL) { }
    ~PidEntry() { free(name); }

    const pid_t&getKey() const { return pid; }
    const uid_t&getUid() const { return uid; }
    const char*getName() const { return name; }

    inline void add(pid_t p) {
        if (name && !strncmp(name, "zygote", 6)) {
            free(name);
            name = NULL;
        }
        if (!name) {
            char *n = android::pidToName(p);
            if (n) {
                name = n;
            }
        }
    }

    inline void add(LogBufferElement *e) {
        uid_t u = e->getUid();
        if (getUid() != u) {
            uid = u;
            free(name);
            name = android::pidToName(e->getPid());
        } else {
            add(e->getPid());
        }
        EntryBaseDropped::add(e);
    }

};

// Log Statistics
class LogStatistics {
    size_t mSizes[LOG_ID_MAX];
    size_t mElements[LOG_ID_MAX];
    size_t mSizesTotal[LOG_ID_MAX];
    size_t mElementsTotal[LOG_ID_MAX];
    bool enable;

    // uid to size list
    typedef LogHashtable<uid_t, UidEntry> uidTable_t;
    uidTable_t uidTable[LOG_ID_MAX];

    // pid to uid list
    typedef LogHashtable<pid_t, PidEntry> pidTable_t;
    pidTable_t pidTable;

public:
    LogStatistics();

    void enableStatistics() { enable = true; }

    void add(LogBufferElement *entry);
    void subtract(LogBufferElement *entry);
    // entry->setDropped(1) must follow this call
    void drop(LogBufferElement *entry);
    // Correct for merging two entries referencing dropped content
    void erase(LogBufferElement *e) { --mElements[e->getLogId()]; }

    std::unique_ptr<const UidEntry *[]> sort(size_t n, log_id i) { return uidTable[i].sort(n); }

    // fast track current value by id only
    size_t sizes(log_id_t id) const { return mSizes[id]; }
    size_t elements(log_id_t id) const { return mElements[id]; }
    size_t sizesTotal(log_id_t id) const { return mSizesTotal[id]; }
    size_t elementsTotal(log_id_t id) const { return mElementsTotal[id]; }

    // *strp = malloc, balance with free
    void format(char **strp, uid_t uid, unsigned int logMask);

    // helper
    char *pidToName(pid_t pid);
    uid_t pidToUid(pid_t pid);
    char *uidToName(uid_t uid);
};

#endif // _LOGD_LOG_STATISTICS_H__
