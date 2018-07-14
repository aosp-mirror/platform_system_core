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

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <string>

#include <android-base/file.h>
#include <android-base/macros.h>
#include <android-base/stringprintf.h>
#include <log/log_event_list.h>
#include <log/log_properties.h>
#include <private/android_filesystem_config.h>

#include "LogTags.h"
#include "LogUtils.h"

static LogTags* logtags;

const char LogTags::system_event_log_tags[] = "/system/etc/event-log-tags";
const char LogTags::dynamic_event_log_tags[] = "/dev/event-log-tags";
// Only for debug
const char LogTags::debug_event_log_tags[] = "/data/misc/logd/event-log-tags";

// Sniff for first uid=%d in utf8z comment string
static uid_t sniffUid(const char* comment, const char* endp) {
    if (!comment) return AID_ROOT;

    if (*comment == '#') ++comment;
    while ((comment < endp) && (*comment != '\n') && isspace(*comment))
        ++comment;
    static const char uid_str[] = "uid=";
    if (((comment + strlen(uid_str)) >= endp) ||
        fastcmp<strncmp>(comment, uid_str, strlen(uid_str)) ||
        !isdigit(comment[strlen(uid_str)]))
        return AID_ROOT;
    char* cp;
    unsigned long Uid = strtoul(comment + 4, &cp, 10);
    if ((cp > endp) || (Uid >= INT_MAX)) return AID_ROOT;

    return Uid;
}

// Checks for file corruption, and report false if there was no need
// to rebuild the referenced file.  Failure to rebuild is only logged,
// does not cause a return value of false.
bool LogTags::RebuildFileEventLogTags(const char* filename, bool warn) {
    int fd;

    {
        android::RWLock::AutoRLock readLock(rwlock);

        if (tag2total.begin() == tag2total.end()) {
            return false;
        }

        file2watermark_const_iterator iwater = file2watermark.find(filename);
        if (iwater == file2watermark.end()) {
            return false;
        }

        struct stat sb;
        if (!stat(filename, &sb) && ((size_t)sb.st_size >= iwater->second)) {
            return false;
        }

        // dump what we already know back into the file?
        fd = TEMP_FAILURE_RETRY(open(
            filename, O_WRONLY | O_TRUNC | O_CLOEXEC | O_NOFOLLOW | O_BINARY));
        if (fd >= 0) {
            time_t now = time(nullptr);
            struct tm tm;
            localtime_r(&now, &tm);
            char timebuf[20];
            size_t len =
                strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", &tm);
            android::base::WriteStringToFd(
                android::base::StringPrintf(
                    "# Rebuilt %.20s, content owned by logd\n", timebuf),
                fd);
            for (const auto& it : tag2total) {
                android::base::WriteStringToFd(
                    formatEntry_locked(it.first, AID_ROOT), fd);
            }
            close(fd);
        }
    }

    if (warn) {
        android::prdebug(
            ((fd < 0) ? "%s failed to rebuild"
                      : "%s missing, damaged or truncated; rebuilt"),
            filename);
    }

    if (fd >= 0) {
        android::RWLock::AutoWLock writeLock(rwlock);

        struct stat sb;
        if (!stat(filename, &sb)) file2watermark[filename] = sb.st_size;
    }

    return true;
}

void LogTags::AddEventLogTags(uint32_t tag, uid_t uid, const std::string& Name,
                              const std::string& Format, const char* source,
                              bool warn) {
    std::string Key = Name;
    if (Format.length()) Key += "+" + Format;

    bool update = !source || !!strcmp(source, system_event_log_tags);
    bool newOne;

    {
        android::RWLock::AutoWLock writeLock(rwlock);

        tag2total_const_iterator itot = tag2total.find(tag);

        // unlikely except for dupes, or updates to uid list (more later)
        if (itot != tag2total.end()) update = false;

        newOne = tag2name.find(tag) == tag2name.end();
        key2tag[Key] = tag;

        if (Format.length()) {
            if (key2tag.find(Name) == key2tag.end()) {
                key2tag[Name] = tag;
            }
            tag2format[tag] = Format;
        }
        tag2name[tag] = Name;

        tag2uid_const_iterator ut = tag2uid.find(tag);
        if (ut != tag2uid.end()) {
            if (uid == AID_ROOT) {
                tag2uid.erase(ut);
                update = true;
            } else if (ut->second.find(uid) == ut->second.end()) {
                const_cast<uid_list&>(ut->second).emplace(uid);
                update = true;
            }
        } else if (newOne && (uid != AID_ROOT)) {
            tag2uid[tag].emplace(uid);
            update = true;
        }

        // updatePersist -> trigger output on modified
        // content, reset tag2total if available
        if (update && (itot != tag2total.end())) tag2total[tag] = 0;
    }

    if (update) {
        WritePersistEventLogTags(tag, uid, source);
    } else if (warn && !newOne && source) {
        // For the files, we want to report dupes.
        android::prdebug("Multiple tag %" PRIu32 " %s %s %s", tag, Name.c_str(),
                         Format.c_str(), source);
    }
}

// Read the event log tags file, and build up our internal database
void LogTags::ReadFileEventLogTags(const char* filename, bool warn) {
    bool etc = !strcmp(filename, system_event_log_tags);
    bool debug = !etc && !strcmp(filename, debug_event_log_tags);

    if (!etc) {
        RebuildFileEventLogTags(filename, warn);
    }
    std::string content;
    if (android::base::ReadFileToString(filename, &content)) {
        char* cp = (char*)content.c_str();
        char* endp = cp + content.length();

        {
            android::RWLock::AutoRLock writeLock(rwlock);

            file2watermark[filename] = content.length();
        }

        char* lineStart = cp;
        while (cp < endp) {
            if (*cp == '\n') {
                lineStart = cp;
            } else if (lineStart) {
                if (*cp == '#') {
                    /* comment; just scan to end */
                    lineStart = nullptr;
                } else if (isdigit(*cp)) {
                    unsigned long Tag = strtoul(cp, &cp, 10);
                    if (warn && (Tag > emptyTag)) {
                        android::prdebug("tag too large %lu", Tag);
                    }
                    while ((cp < endp) && (*cp != '\n') && isspace(*cp)) ++cp;
                    if (cp >= endp) break;
                    if (*cp == '\n') continue;
                    const char* name = cp;
                    /* Determine whether it is a valid tag name [a-zA-Z0-9_] */
                    bool hasAlpha = false;
                    while ((cp < endp) && (isalnum(*cp) || (*cp == '_'))) {
                        if (!isdigit(*cp)) hasAlpha = true;
                        ++cp;
                    }
                    std::string Name(name, cp - name);
#ifdef ALLOW_NOISY_LOGGING_OF_PROBLEM_WITH_LOTS_OF_TECHNICAL_DEBT
                    static const size_t maximum_official_tag_name_size = 24;
                    if (warn &&
                        (Name.length() > maximum_official_tag_name_size)) {
                        android::prdebug("tag name too long %s", Name.c_str());
                    }
#endif
                    if (hasAlpha &&
                        ((cp >= endp) || (*cp == '#') || isspace(*cp))) {
                        if (Tag > emptyTag) {
                            if (*cp != '\n') lineStart = nullptr;
                            continue;
                        }
                        while ((cp < endp) && (*cp != '\n') && isspace(*cp))
                            ++cp;
                        const char* format = cp;
                        uid_t uid = AID_ROOT;
                        while ((cp < endp) && (*cp != '\n')) {
                            if (*cp == '#') {
                                uid = sniffUid(cp, endp);
                                lineStart = nullptr;
                                break;
                            }
                            ++cp;
                        }
                        while ((cp > format) && isspace(cp[-1])) {
                            --cp;
                            lineStart = nullptr;
                        }
                        std::string Format(format, cp - format);

                        AddEventLogTags((uint32_t)Tag, uid, Name, Format,
                                        filename, warn);
                    } else {
                        if (warn) {
                            android::prdebug("tag name invalid %.*s",
                                             (int)(cp - name + 1), name);
                        }
                        lineStart = nullptr;
                    }
                } else if (!isspace(*cp)) {
                    break;
                }
            }
            cp++;
        }
    } else if (warn) {
        android::prdebug("Cannot read %s", filename);
    }
}

// Extract a 4-byte value from a byte stream.
static inline uint32_t get4LE(const char* msg) {
    const uint8_t* src = reinterpret_cast<const uint8_t*>(msg);
    return src[0] | (src[1] << 8) | (src[2] << 16) | (src[3] << 24);
}

// Additional persistent sources for invented log tags.  Read the
// special pmsg event for log tags, and build up our internal
// database with any found.
void LogTags::ReadPersistEventLogTags() {
    struct logger_list* logger_list = android_logger_list_alloc(
        ANDROID_LOG_RDONLY | ANDROID_LOG_PSTORE | ANDROID_LOG_NONBLOCK, 0,
        (pid_t)0);
    if (!logger_list) return;

    struct logger* e = android_logger_open(logger_list, LOG_ID_EVENTS);
    struct logger* s = android_logger_open(logger_list, LOG_ID_SECURITY);
    if (!e && !s) {
        android_logger_list_free(logger_list);
        return;
    }

    for (;;) {
        struct log_msg log_msg;
        int ret = android_logger_list_read(logger_list, &log_msg);
        if (ret <= 0) break;

        const char* msg = log_msg.msg();
        if (!msg) continue;
        if (log_msg.entry.len <= sizeof(uint32_t)) continue;
        uint32_t Tag = get4LE(msg);
        if (Tag != TAG_DEF_LOG_TAG) continue;
        uid_t uid = (log_msg.entry.hdr_size >= sizeof(logger_entry_v4))
                        ? log_msg.entry.uid
                        : AID_ROOT;

        std::string Name;
        std::string Format;
        android_log_list_element elem;
        {
            android_log_event_list ctx(log_msg);
            elem = ctx.read();
            if (elem.type != EVENT_TYPE_LIST) {
                continue;
            }
            elem = ctx.read();
            if (elem.type != EVENT_TYPE_INT) {
                continue;
            }
            Tag = elem.data.int32;
            elem = ctx.read();
            if (elem.type != EVENT_TYPE_STRING) {
                continue;
            }
            Name = std::string(elem.data.string, elem.len);
            elem = ctx.read();
            if (elem.type != EVENT_TYPE_STRING) {
                continue;
            }
            Format = std::string(elem.data.string, elem.len);
            elem = ctx.read();
        }
        if ((elem.type != EVENT_TYPE_LIST_STOP) || !elem.complete) continue;

        AddEventLogTags(Tag, uid, Name, Format);
    }
    android_logger_list_free(logger_list);
}

LogTags::LogTags() {
    ReadFileEventLogTags(system_event_log_tags);
    // Following will likely fail on boot, but is required if logd restarts
    ReadFileEventLogTags(dynamic_event_log_tags, false);
    if (__android_log_is_debuggable()) {
        ReadFileEventLogTags(debug_event_log_tags, false);
    }
    ReadPersistEventLogTags();

    logtags = this;
}

// Converts an event tag into a name
const char* LogTags::tagToName(uint32_t tag) const {
    tag2name_const_iterator it;

    android::RWLock::AutoRLock readLock(const_cast<android::RWLock&>(rwlock));

    it = tag2name.find(tag);
    if ((it == tag2name.end()) || (it->second.length() == 0)) return nullptr;

    return it->second.c_str();
}

// Prototype in LogUtils.h allowing external access to our database.
//
// This must be a pure reader to our database, as everything else is
// guaranteed single-threaded except this access point which is
// asynchonous and can be multithreaded and thus rentrant.  The
// object's rwlock is only used to guarantee atomic access to the
// unordered_map to prevent corruption, with a requirement to be a
// low chance of contention for this call.  If we end up changing
// this algorithm resulting in write, then we should use a different
// lock than the object's rwlock to protect groups of associated
// actions.
const char* android::tagToName(uint32_t tag) {
    LogTags* me = logtags;

    if (!me) return nullptr;
    me->WritePmsgEventLogTags(tag);
    return me->tagToName(tag);
}

// Prototype in LogUtils.h allowing external access to our database.
//
// This only works on userdebug and eng devices to re-read the
// /data/misc/logd/event-log-tags file right after /data is mounted.
// The operation is near to boot and should only happen once.  There
// are races associated with its use since it can trigger a Rebuild
// of the file, but that is a can-not-happen since the file was not
// read yet.  More dangerous if called later, but if all is well it
// should just skip over everything and not write any new entries.
void android::ReReadEventLogTags() {
    LogTags* me = logtags;

    if (me && __android_log_is_debuggable()) {
        me->ReadFileEventLogTags(me->debug_event_log_tags);
    }
}

// converts an event tag into a format
const char* LogTags::tagToFormat(uint32_t tag) const {
    tag2format_const_iterator iform;

    android::RWLock::AutoRLock readLock(const_cast<android::RWLock&>(rwlock));

    iform = tag2format.find(tag);
    if (iform == tag2format.end()) return nullptr;

    return iform->second.c_str();
}

// converts a name into an event tag
uint32_t LogTags::nameToTag(const char* name) const {
    uint32_t ret = emptyTag;

    // Bug: Only works for a single entry, we can have multiple entries,
    // one for each format, so we find first entry recorded, or entry with
    // no format associated with it.

    android::RWLock::AutoRLock readLock(const_cast<android::RWLock&>(rwlock));

    key2tag_const_iterator ik = key2tag.find(std::string(name));
    if (ik != key2tag.end()) ret = ik->second;

    return ret;
}

// Caller must perform locks, can be under reader (for pre-check) or
// writer lock.  We use this call to invent a new deterministically
// random tag, unique is cleared if no conflicts.  If format is NULL,
// we are in readonly mode.
uint32_t LogTags::nameToTag_locked(const std::string& name, const char* format,
                                   bool& unique) {
    key2tag_const_iterator ik;

    bool write = format != nullptr;
    unique = write;

    if (!write) {
        // Bug: Only works for a single entry, we can have multiple entries,
        // one for each format, so we find first entry recorded, or entry with
        // no format associated with it.
        ik = key2tag.find(name);
        if (ik == key2tag.end()) return emptyTag;
        return ik->second;
    }

    std::string Key(name);
    if (*format) Key += std::string("+") + format;

    ik = key2tag.find(Key);
    if (ik != key2tag.end()) {
        unique = false;
        return ik->second;
    }

    size_t Hash = key2tag.hash_function()(Key);
    uint32_t Tag = Hash;
    // This sets an upper limit on the conflics we are allowed to deal with.
    for (unsigned i = 0; i < 256;) {
        tag2name_const_iterator it = tag2name.find(Tag);
        if (it == tag2name.end()) return Tag;
        std::string localKey(it->second);
        tag2format_const_iterator iform = tag2format.find(Tag);
        if ((iform == tag2format.end()) && iform->second.length()) {
            localKey += "+" + iform->second;
        }
        unique = !!it->second.compare(localKey);
        if (!unique) return Tag;  // unlikely except in a race

        ++i;
        // Algorithm to convert hash to next tag
        if (i < 32) {
            Tag = (Hash >> i);
            // size_t is 32 bits, or upper word zero, rotate
            if ((sizeof(Hash) <= 4) || ((Hash & (uint64_t(-1LL) << 32)) == 0)) {
                Tag |= Hash << (32 - i);
            }
        } else {
            Tag = Hash + i - 31;
        }
    }
    return emptyTag;
}

static int openFile(const char* name, int mode, bool warning) {
    int fd = TEMP_FAILURE_RETRY(open(name, mode));
    if ((fd < 0) && warning) {
        android::prdebug("Failed open %s (%d)", name, errno);
    }
    return fd;
}

void LogTags::WritePmsgEventLogTags(uint32_t tag, uid_t uid) {
    android::RWLock::AutoRLock readLock(rwlock);

    tag2total_const_iterator itot = tag2total.find(tag);
    if (itot == tag2total.end()) return;  // source is a static entry

    size_t lastTotal = itot->second;

    // Every 16K (half the smallest configurable pmsg buffer size) record
    static const size_t rate_to_pmsg = 16 * 1024;
    if (lastTotal && ((android::sizesTotal() - lastTotal) < rate_to_pmsg)) {
        return;
    }

    static int pmsg_fd = -1;
    if (pmsg_fd < 0) {
        pmsg_fd = TEMP_FAILURE_RETRY(open("/dev/pmsg0", O_WRONLY | O_CLOEXEC));
        // unlikely, but deal with partners with borken pmsg
        if (pmsg_fd < 0) return;
    }

    std::string Name = tag2name[tag];
    tag2format_const_iterator iform = tag2format.find(tag);
    std::string Format = (iform != tag2format.end()) ? iform->second : "";

    __android_log_event_list ctx(TAG_DEF_LOG_TAG);
    ctx << tag << Name << Format;
    std::string buffer(ctx);
    if (buffer.length() <= 0) return;  // unlikely

    /*
     *  struct {
     *      // what we provide to pstore
     *      android_pmsg_log_header_t pmsgHeader;
     *      // what we provide to file
     *      android_log_header_t header;
     *      // caller provides
     *      union {
     *          struct {
     *              char     prio;
     *              char     payload[];
     *          } string;
     *          struct {
     *              uint32_t tag
     *              char     payload[];
     *          } binary;
     *      };
     *  };
     */

    struct timespec ts;
    clock_gettime(android_log_clockid(), &ts);

    android_log_header_t header = {
        .id = LOG_ID_EVENTS,
        .tid = (uint16_t)gettid(),
        .realtime.tv_sec = (uint32_t)ts.tv_sec,
        .realtime.tv_nsec = (uint32_t)ts.tv_nsec,
    };

    uint32_t outTag = TAG_DEF_LOG_TAG;
    outTag = get4LE((const char*)&outTag);

    android_pmsg_log_header_t pmsgHeader = {
        .magic = LOGGER_MAGIC,
        .len = (uint16_t)(sizeof(pmsgHeader) + sizeof(header) + sizeof(outTag) +
                          buffer.length()),
        .uid = (uint16_t)AID_ROOT,
        .pid = (uint16_t)getpid(),
    };

    struct iovec Vec[] = { { (unsigned char*)&pmsgHeader, sizeof(pmsgHeader) },
                           { (unsigned char*)&header, sizeof(header) },
                           { (unsigned char*)&outTag, sizeof(outTag) },
                           { (unsigned char*)const_cast<char*>(buffer.data()),
                             buffer.length() } };

    tag2uid_const_iterator ut = tag2uid.find(tag);
    if (ut == tag2uid.end()) {
        TEMP_FAILURE_RETRY(writev(pmsg_fd, Vec, arraysize(Vec)));
    } else if (uid != AID_ROOT) {
        pmsgHeader.uid = (uint16_t)uid;
        TEMP_FAILURE_RETRY(writev(pmsg_fd, Vec, arraysize(Vec)));
    } else {
        for (auto& it : ut->second) {
            pmsgHeader.uid = (uint16_t)it;
            TEMP_FAILURE_RETRY(writev(pmsg_fd, Vec, arraysize(Vec)));
        }
    }
}

void LogTags::WriteDynamicEventLogTags(uint32_t tag, uid_t uid) {
    static const int mode =
        O_WRONLY | O_APPEND | O_CLOEXEC | O_NOFOLLOW | O_BINARY;

    int fd = openFile(dynamic_event_log_tags, mode, true);
    if (fd < 0) return;

    android::RWLock::AutoWLock writeLock(rwlock);

    std::string ret = formatEntry_locked(tag, uid, false);
    android::base::WriteStringToFd(ret, fd);
    close(fd);

    size_t size = 0;
    file2watermark_const_iterator iwater;

    iwater = file2watermark.find(dynamic_event_log_tags);
    if (iwater != file2watermark.end()) size = iwater->second;

    file2watermark[dynamic_event_log_tags] = size + ret.length();
}

void LogTags::WriteDebugEventLogTags(uint32_t tag, uid_t uid) {
    static const int mode =
        O_WRONLY | O_APPEND | O_CLOEXEC | O_NOFOLLOW | O_BINARY;

    static bool one = true;
    int fd = openFile(debug_event_log_tags, mode, one);
    one = fd >= 0;
    if (!one) return;

    android::RWLock::AutoWLock writeLock(rwlock);

    std::string ret = formatEntry_locked(tag, uid, false);
    android::base::WriteStringToFd(ret, fd);
    close(fd);

    size_t size = 0;
    file2watermark_const_iterator iwater;

    iwater = file2watermark.find(debug_event_log_tags);
    if (iwater != file2watermark.end()) size = iwater->second;

    file2watermark[debug_event_log_tags] = size + ret.length();
}

// How we maintain some runtime or reboot stickiness
void LogTags::WritePersistEventLogTags(uint32_t tag, uid_t uid,
                                       const char* source) {
    // very unlikely
    bool etc = source && !strcmp(source, system_event_log_tags);
    if (etc) return;

    bool dynamic = source && !strcmp(source, dynamic_event_log_tags);
    bool debug = (!dynamic && source && !strcmp(source, debug_event_log_tags)) ||
                 !__android_log_is_debuggable();

    WritePmsgEventLogTags(tag, uid);

    size_t lastTotal = 0;
    {
        android::RWLock::AutoRLock readLock(rwlock);

        tag2total_const_iterator itot = tag2total.find(tag);
        if (itot != tag2total.end()) lastTotal = itot->second;
    }

    if (lastTotal == 0) {  // denotes first time for this one
        if (!dynamic || !RebuildFileEventLogTags(dynamic_event_log_tags)) {
            WriteDynamicEventLogTags(tag, uid);
        }

        if (!debug && !RebuildFileEventLogTags(debug_event_log_tags)) {
            WriteDebugEventLogTags(tag, uid);
        }
    }

    lastTotal = android::sizesTotal();
    if (!lastTotal) ++lastTotal;

    // record totals for next watermark.
    android::RWLock::AutoWLock writeLock(rwlock);
    tag2total[tag] = lastTotal;
}

// nameToTag converts a name into an event tag. If format is NULL, then we
// are in readonly mode.
uint32_t LogTags::nameToTag(uid_t uid, const char* name, const char* format) {
    std::string Name = std::string(name);
    bool write = format != nullptr;
    bool updateUid = uid != AID_ROOT;
    bool updateFormat = format && *format;
    bool unique;
    uint32_t Tag;

    {
        android::RWLock::AutoRLock readLock(rwlock);

        Tag = nameToTag_locked(Name, format, unique);
        if (updateUid && (Tag != emptyTag) && !unique) {
            tag2uid_const_iterator ut = tag2uid.find(Tag);
            if (updateUid) {
                if ((ut != tag2uid.end()) &&
                    (ut->second.find(uid) == ut->second.end())) {
                    unique = write;  // write passthrough to update uid counts
                    if (!write) Tag = emptyTag;  // deny read access
                }
            } else {
                unique = write && (ut != tag2uid.end());
            }
        }
    }

    if (Tag == emptyTag) return Tag;
    WritePmsgEventLogTags(Tag, uid);  // record references periodically
    if (!unique) return Tag;

    bool updateWrite = false;
    bool updateTag;

    // Special case of AddEventLogTags, checks per-uid counter which makes
    // no sense there, and is also optimized somewhat to reduce write times.
    {
        android::RWLock::AutoWLock writeLock(rwlock);

        // double check after switch from read lock to write lock for Tag
        updateTag = tag2name.find(Tag) == tag2name.end();
        // unlikely, either update, race inviting conflict or multiple uids
        if (!updateTag) {
            Tag = nameToTag_locked(Name, format, unique);
            if (Tag == emptyTag) return Tag;
            // is it multiple uid's setting this value
            if (!unique) {
                tag2uid_const_iterator ut = tag2uid.find(Tag);
                if (updateUid) {
                    // Add it to the uid list
                    if ((ut == tag2uid.end()) ||
                        (ut->second.find(uid) != ut->second.end())) {
                        return Tag;
                    }
                    const_cast<uid_list&>(ut->second).emplace(uid);
                    updateWrite = true;
                } else {
                    if (ut == tag2uid.end()) return Tag;
                    // (system) adding a global one, erase the uid list
                    tag2uid.erase(ut);
                    updateWrite = true;
                }
            }
        }

        // Update section
        size_t count;
        if (updateUid) {
            count = 0;
            uid2count_const_iterator ci = uid2count.find(uid);
            if (ci != uid2count.end()) {
                count = ci->second;
                if (count >= max_per_uid) {
                    if (!updateWrite) return emptyTag;
                    // If we are added to the per-Uid perms, leak the Tag
                    // if it already exists.
                    updateUid = false;
                    updateTag = false;
                    updateFormat = false;
                }
            }
        }

        // updateWrite -> trigger output on modified content, reset tag2total
        //    also sets static to dynamic entries if they are alterred,
        //    only occurs if they have a uid, and runtime adds another uid.
        if (updateWrite) tag2total[Tag] = 0;

        if (updateTag) {
            // mark as a dynamic entry, but do not upset current total counter
            tag2total_const_iterator itot = tag2total.find(Tag);
            if (itot == tag2total.end()) tag2total[Tag] = 0;

            if (*format) {
                key2tag[Name + "+" + format] = Tag;
                if (key2tag.find(Name) == key2tag.end()) key2tag[Name] = Tag;
            } else {
                key2tag[Name] = Tag;
            }
            tag2name[Tag] = Name;
        }
        if (updateFormat) tag2format[Tag] = format;

        if (updateUid) {
            tag2uid[Tag].emplace(uid);
            uid2count[uid] = count + 1;
        }
    }

    if (updateTag || updateFormat || updateWrite) {
        WritePersistEventLogTags(Tag, uid);
    }

    return Tag;
}

std::string LogTags::formatEntry(uint32_t tag, uid_t uid, const char* name,
                                 const char* format) {
    if (!format || !format[0]) {
        return android::base::StringPrintf("%" PRIu32 "\t%s\n", tag, name);
    }
    size_t len = (strlen(name) + 7) / 8;
    static const char tabs[] = "\t\t\t";
    if (len > strlen(tabs)) len = strlen(tabs);
    std::string Uid;
    if (uid != AID_ROOT) Uid = android::base::StringPrintf(" # uid=%u", uid);
    return android::base::StringPrintf("%" PRIu32 "\t%s%s\t%s%s\n", tag, name,
                                       &tabs[len], format, Uid.c_str());
}

std::string LogTags::formatEntry_locked(uint32_t tag, uid_t uid,
                                        bool authenticate) {
    const char* name = tag2name[tag].c_str();

    const char* format = "";
    tag2format_const_iterator iform = tag2format.find(tag);
    if (iform != tag2format.end()) format = iform->second.c_str();

    // Access permission test, do not report dynamic entries
    // that do not belong to us.
    tag2uid_const_iterator ut = tag2uid.find(tag);
    if (ut == tag2uid.end()) {
        return formatEntry(tag, AID_ROOT, name, format);
    }
    if (uid != AID_ROOT) {
        if (authenticate && (ut->second.find(uid) == ut->second.end())) {
            return std::string("");
        }
        return formatEntry(tag, uid, name, format);
    }

    // Show all, one for each registered uid (we are group root)
    std::string ret;
    for (auto& it : ut->second) {
        ret += formatEntry(tag, it, name, format);
    }
    return ret;
}

std::string LogTags::formatEntry(uint32_t tag, uid_t uid) {
    android::RWLock::AutoRLock readLock(rwlock);
    return formatEntry_locked(tag, uid);
}

std::string LogTags::formatGetEventTag(uid_t uid, const char* name,
                                       const char* format) {
    bool all = name && (name[0] == '*') && !name[1];
    bool list = !name || all;
    std::string ret;

    if (!list) {
        // switch to read entry only if format == "*"
        if (format && (format[0] == '*') && !format[1]) format = nullptr;

        // WAI: for null format, only works for a single entry, we can have
        // multiple entries, one for each format, so we find first entry
        // recorded, or entry with no format associated with it.
        // We may desire to print all that match the name, but we did not
        // add a mapping table for that and the cost is too high.
        uint32_t tag = nameToTag(uid, name, format);
        if (tag == emptyTag) return std::string("-1 ESRCH");
        if (uid == AID_ROOT) {
            android::RWLock::AutoRLock readLock(rwlock);

            // first uid in list so as to manufacture an accurate reference
            tag2uid_const_iterator ut = tag2uid.find(tag);
            if ((ut != tag2uid.end()) &&
                (ut->second.begin() != ut->second.end())) {
                uid = *(ut->second.begin());
            }
        }
        ret = formatEntry(tag, uid, name, format ?: tagToFormat(tag));
        if (!ret.length()) return std::string("-1 ESRCH");
        return ret;
    }

    android::RWLock::AutoRLock readLock(rwlock);
    if (all) {
        // everything under the sun
        for (const auto& it : tag2name) {
            ret += formatEntry_locked(it.first, uid);
        }
    } else {
        // set entries are dynamic
        for (const auto& it : tag2total) {
            ret += formatEntry_locked(it.first, uid);
        }
    }
    return ret;
}
