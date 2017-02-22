/*
 * Copyright (C) 2017 The Android Open Source Project
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

#ifndef _LOGD_LOG_TAGS_H__
#define _LOGD_LOG_TAGS_H__

#include <unordered_map>
#include <unordered_set>
#include <string>

#include <utils/RWLock.h>

class LogTags {
    // This lock protects all the unordered_map accesses below.  It
    // is a reader/writer lock so that contentions are kept to a
    // minimum since writes are rare, even administratably when
    // reads are extended.  Resist the temptation to use the writer
    // lock to protect anything outside the following unordered_maps
    // as that would increase the reader contentions.  Use a separate
    // mutex to protect the other entities.
    android::RWLock rwlock;

    // key is Name + "+" + Format
    std::unordered_map<std::string, uint32_t> key2tag;
    typedef std::unordered_map<std::string, uint32_t>::const_iterator key2tag_const_iterator;

    // Allows us to manage access permissions based on uid registrants
    // Global entries are specifically erased.
    typedef std::unordered_set<uid_t> uid_list;
    std::unordered_map<uint32_t, uid_list> tag2uid;
    typedef std::unordered_map<uint32_t, uid_list>::const_iterator tag2uid_const_iterator;

    std::unordered_map<uint32_t, std::string> tag2name;
    typedef std::unordered_map<uint32_t, std::string>::const_iterator tag2name_const_iterator;

    std::unordered_map<uint32_t, std::string> tag2format;
    typedef std::unordered_map<uint32_t, std::string>::const_iterator tag2format_const_iterator;

    static const size_t max_per_uid = 256; // Put a cap on the tags per uid
    std::unordered_map<uid_t, size_t> uid2count;
    typedef std::unordered_map<uid_t, size_t>::const_iterator uid2count_const_iterator;

    // Dynamic entries are assigned
    std::unordered_map<uint32_t, size_t> tag2total;
    typedef std::unordered_map<uint32_t, size_t>::const_iterator tag2total_const_iterator;

    // emplace unique tag
    uint32_t nameToTag(uid_t uid, const char* name, const char* format);
    // find unique or associated tag
    uint32_t nameToTag_locked(const std::string& name, const char* format, bool &unique);

    // Record expected file watermarks to detect corruption.
    std::unordered_map<std::string, size_t> file2watermark;
    typedef std::unordered_map<std::string, size_t>::const_iterator file2watermark_const_iterator;

    void ReadPersistEventLogTags();

    // format helpers
    // format a single entry, does not need object data
    static std::string formatEntry(uint32_t tag, uid_t uid,
                                   const char* name, const char* format);
    // caller locks, database lookup, authenticate against uid
    std::string formatEntry_locked(uint32_t tag, uid_t uid,
                                   bool authenticate = true);

    bool RebuildFileEventLogTags(const char* filename, bool warn = true);

    void AddEventLogTags(uint32_t tag, uid_t uid,
                         const std::string& Name, const std::string& Format,
                         const char* source = NULL, bool warn = false);

    void WriteDynamicEventLogTags(uint32_t tag, uid_t uid);
    void WriteDebugEventLogTags(uint32_t tag, uid_t uid);
    // push tag details to persistent storage
    void WritePersistEventLogTags(uint32_t tag,
                                  uid_t uid = AID_ROOT,
                                  const char* source = NULL);

    static const uint32_t emptyTag = uint32_t(-1);

public:

    static const char system_event_log_tags[];
    static const char dynamic_event_log_tags[];
    // Only for userdebug and eng
    static const char debug_event_log_tags[];

    LogTags();

    void WritePmsgEventLogTags(uint32_t tag, uid_t uid = AID_ROOT);
    void ReadFileEventLogTags(const char* filename, bool warn = true);

    // reverse lookup from tag
    const char* tagToName(uint32_t tag) const;
    const char* tagToFormat(uint32_t tag) const;
    std::string formatEntry(uint32_t tag, uid_t uid);
    // find associated tag
    uint32_t nameToTag(const char* name) const;

    // emplace tag if necessary, provide event-log-tag formated output in string
    std::string formatGetEventTag(uid_t uid,
                                  const char* name,
                                  const char* format);
};

#endif // _LOGD_LOG_TAGS_H__
