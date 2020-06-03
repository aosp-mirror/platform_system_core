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

#include "LogStatistics.h"

#include <ctype.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include <list>

#include <private/android_logger.h>

#include "LogBufferElement.h"

static const uint64_t hourSec = 60 * 60;
static const uint64_t monthSec = 31 * 24 * hourSec;

std::atomic<size_t> LogStatistics::SizesTotal;

LogStatistics::LogStatistics(bool enable_statistics) : enable(enable_statistics) {
    log_time now(CLOCK_REALTIME);
    log_id_for_each(id) {
        mSizes[id] = 0;
        mElements[id] = 0;
        mDroppedElements[id] = 0;
        mSizesTotal[id] = 0;
        mElementsTotal[id] = 0;
        mOldest[id] = now;
        mNewest[id] = now;
        mNewestDropped[id] = now;
    }
}

namespace android {

size_t sizesTotal() {
    return LogStatistics::sizesTotal();
}

// caller must own and free character string
char* pidToName(pid_t pid) {
    char* retval = nullptr;
    if (pid == 0) {  // special case from auditd/klogd for kernel
        retval = strdup("logd");
    } else {
        char buffer[512];
        snprintf(buffer, sizeof(buffer), "/proc/%u/cmdline", pid);
        int fd = open(buffer, O_RDONLY);
        if (fd >= 0) {
            ssize_t ret = read(fd, buffer, sizeof(buffer));
            if (ret > 0) {
                buffer[sizeof(buffer) - 1] = '\0';
                // frameworks intermediate state
                if (fastcmp<strcmp>(buffer, "<pre-initialized>")) {
                    retval = strdup(buffer);
                }
            }
            close(fd);
        }
    }
    return retval;
}
}

void LogStatistics::AddTotal(log_id_t log_id, uint16_t size) {
    auto lock = std::lock_guard{lock_};

    mSizesTotal[log_id] += size;
    SizesTotal += size;
    ++mElementsTotal[log_id];
}

void LogStatistics::Add(const LogStatisticsElement& element) {
    auto lock = std::lock_guard{lock_};
    log_id_t log_id = element.log_id;
    uint16_t size = element.msg_len;
    mSizes[log_id] += size;
    ++mElements[log_id];

    // When caller adding a chatty entry, they will have already
    // called add() and subtract() for each entry as they are
    // evaluated and trimmed, thus recording size and number of
    // elements, but we must recognize the manufactured dropped
    // entry as not contributing to the lifetime totals.
    if (element.dropped_count) {
        ++mDroppedElements[log_id];
    } else {
        mSizesTotal[log_id] += size;
        SizesTotal += size;
        ++mElementsTotal[log_id];
    }

    log_time stamp(element.realtime);
    if (mNewest[log_id] < stamp) {
        // A major time update invalidates the statistics :-(
        log_time diff = stamp - mNewest[log_id];
        mNewest[log_id] = stamp;

        if (diff.tv_sec > hourSec) {
            // approximate Do-Your-Best fixup
            diff += mOldest[log_id];
            if ((diff > stamp) && ((diff - stamp).tv_sec < hourSec)) {
                diff = stamp;
            }
            if (diff <= stamp) {
                mOldest[log_id] = diff;
                if (mNewestDropped[log_id] < diff) {
                    mNewestDropped[log_id] = diff;
                }
            }
        }
    }

    if (log_id == LOG_ID_KERNEL) {
        return;
    }

    uidTable[log_id].Add(element.uid, element);
    if (element.uid == AID_SYSTEM) {
        pidSystemTable[log_id].Add(element.pid, element);
    }

    if (!enable) {
        return;
    }

    pidTable.Add(element.pid, element);
    tidTable.Add(element.tid, element);

    uint32_t tag = element.tag;
    if (tag) {
        if (log_id == LOG_ID_SECURITY) {
            securityTagTable.Add(tag, element);
        } else {
            tagTable.Add(tag, element);
        }
    }

    if (!element.dropped_count) {
        tagNameTable.Add(TagNameKey(element), element);
    }
}

void LogStatistics::Subtract(const LogStatisticsElement& element) {
    auto lock = std::lock_guard{lock_};
    log_id_t log_id = element.log_id;
    uint16_t size = element.msg_len;
    mSizes[log_id] -= size;
    --mElements[log_id];
    if (element.dropped_count) {
        --mDroppedElements[log_id];
    }

    if (mOldest[log_id] < element.realtime) {
        mOldest[log_id] = element.realtime;
    }

    if (log_id == LOG_ID_KERNEL) {
        return;
    }

    uidTable[log_id].Subtract(element.uid, element);
    if (element.uid == AID_SYSTEM) {
        pidSystemTable[log_id].Subtract(element.pid, element);
    }

    if (!enable) {
        return;
    }

    pidTable.Subtract(element.pid, element);
    tidTable.Subtract(element.tid, element);

    uint32_t tag = element.tag;
    if (tag) {
        if (log_id == LOG_ID_SECURITY) {
            securityTagTable.Subtract(tag, element);
        } else {
            tagTable.Subtract(tag, element);
        }
    }

    if (!element.dropped_count) {
        tagNameTable.Subtract(TagNameKey(element), element);
    }
}

// Atomically set an entry to drop
// entry->setDropped(1) must follow this call, caller should do this explicitly.
void LogStatistics::Drop(const LogStatisticsElement& element) {
    auto lock = std::lock_guard{lock_};
    log_id_t log_id = element.log_id;
    uint16_t size = element.msg_len;
    mSizes[log_id] -= size;
    ++mDroppedElements[log_id];

    if (mNewestDropped[log_id] < element.realtime) {
        mNewestDropped[log_id] = element.realtime;
    }

    uidTable[log_id].Drop(element.uid, element);
    if (element.uid == AID_SYSTEM) {
        pidSystemTable[log_id].Drop(element.pid, element);
    }

    if (!enable) {
        return;
    }

    pidTable.Drop(element.pid, element);
    tidTable.Drop(element.tid, element);

    uint32_t tag = element.tag;
    if (tag) {
        if (log_id == LOG_ID_SECURITY) {
            securityTagTable.Drop(tag, element);
        } else {
            tagTable.Drop(tag, element);
        }
    }

    tagNameTable.Subtract(TagNameKey(element), element);
}

const char* LogStatistics::UidToName(uid_t uid) const {
    auto lock = std::lock_guard{lock_};
    return UidToNameLocked(uid);
}

// caller must own and free character string
const char* LogStatistics::UidToNameLocked(uid_t uid) const {
    // Local hard coded favourites
    if (uid == AID_LOGD) {
        return strdup("auditd");
    }

    // Android system
    if (uid < AID_APP) {
        // in bionic, thread safe as long as we copy the results
        struct passwd* pwd = getpwuid(uid);
        if (pwd) {
            return strdup(pwd->pw_name);
        }
    }

    // Parse /data/system/packages.list
    uid_t userId = uid % AID_USER_OFFSET;
    const char* name = android::uidToName(userId);
    if (!name && (userId > (AID_SHARED_GID_START - AID_APP))) {
        name = android::uidToName(userId - (AID_SHARED_GID_START - AID_APP));
    }
    if (name) {
        return name;
    }

    // Android application
    if (uid >= AID_APP) {
        struct passwd* pwd = getpwuid(uid);
        if (pwd) {
            return strdup(pwd->pw_name);
        }
    }

    // report uid -> pid(s) -> pidToName if unique
    for (pidTable_t::const_iterator it = pidTable.begin(); it != pidTable.end();
         ++it) {
        const PidEntry& entry = it->second;

        if (entry.uid() == uid) {
            const char* nameTmp = entry.name();

            if (nameTmp) {
                if (!name) {
                    name = strdup(nameTmp);
                } else if (fastcmp<strcmp>(name, nameTmp)) {
                    free(const_cast<char*>(name));
                    name = nullptr;
                    break;
                }
            }
        }
    }

    // No one
    return name;
}

template <typename TKey, typename TEntry>
void LogStatistics::WorstTwoWithThreshold(const LogHashtable<TKey, TEntry>& table, size_t threshold,
                                          int* worst, size_t* worst_sizes,
                                          size_t* second_worst_sizes) const {
    std::array<const TKey*, 2> max_keys;
    std::array<const TEntry*, 2> max_entries;
    table.MaxEntries(AID_ROOT, 0, max_keys, max_entries);
    if (max_entries[0] == nullptr || max_entries[1] == nullptr) {
        return;
    }
    *worst_sizes = max_entries[0]->getSizes();
    // b/24782000: Allow time horizon to extend roughly tenfold, assume average entry length is
    // 100 characters.
    if (*worst_sizes > threshold && *worst_sizes > (10 * max_entries[0]->dropped_count())) {
        *worst = *max_keys[0];
        *second_worst_sizes = max_entries[1]->getSizes();
        if (*second_worst_sizes < threshold) {
            *second_worst_sizes = threshold;
        }
    }
}

void LogStatistics::WorstTwoUids(log_id id, size_t threshold, int* worst, size_t* worst_sizes,
                                 size_t* second_worst_sizes) const {
    auto lock = std::lock_guard{lock_};
    WorstTwoWithThreshold(uidTable[id], threshold, worst, worst_sizes, second_worst_sizes);
}

void LogStatistics::WorstTwoTags(size_t threshold, int* worst, size_t* worst_sizes,
                                 size_t* second_worst_sizes) const {
    auto lock = std::lock_guard{lock_};
    WorstTwoWithThreshold(tagTable, threshold, worst, worst_sizes, second_worst_sizes);
}

void LogStatistics::WorstTwoSystemPids(log_id id, size_t worst_uid_sizes, int* worst,
                                       size_t* second_worst_sizes) const {
    auto lock = std::lock_guard{lock_};
    std::array<const pid_t*, 2> max_keys;
    std::array<const PidEntry*, 2> max_entries;
    pidSystemTable[id].MaxEntries(AID_SYSTEM, 0, max_keys, max_entries);
    if (max_entries[0] == nullptr || max_entries[1] == nullptr) {
        return;
    }

    *worst = *max_keys[0];
    *second_worst_sizes = worst_uid_sizes - max_entries[0]->getSizes() + max_entries[1]->getSizes();
}

// Prune at most 10% of the log entries or maxPrune, whichever is less.
bool LogStatistics::ShouldPrune(log_id id, unsigned long max_size,
                                unsigned long* prune_rows) const {
    static constexpr size_t kMinPrune = 4;
    static constexpr size_t kMaxPrune = 256;

    auto lock = std::lock_guard{lock_};
    size_t sizes = mSizes[id];
    if (sizes <= max_size) {
        return false;
    }
    size_t size_over = sizes - ((max_size * 9) / 10);
    size_t elements = mElements[id] - mDroppedElements[id];
    size_t min_elements = elements / 100;
    if (min_elements < kMinPrune) {
        min_elements = kMinPrune;
    }
    *prune_rows = elements * size_over / sizes;
    if (*prune_rows < min_elements) {
        *prune_rows = min_elements;
    }
    if (*prune_rows > kMaxPrune) {
        *prune_rows = kMaxPrune;
    }

    return true;
}

std::string UidEntry::formatHeader(const std::string& name, log_id_t id) const {
    bool isprune = worstUidEnabledForLogid(id);
    return formatLine(android::base::StringPrintf(name.c_str(),
                                                  android_log_id_to_name(id)),
                      std::string("Size"),
                      std::string(isprune ? "+/-  Pruned" : "")) +
           formatLine(std::string("UID   PACKAGE"), std::string("BYTES"),
                      std::string(isprune ? "NUM" : ""));
}

// Helper to truncate name, if too long, and add name dressings
void LogStatistics::FormatTmp(const char* nameTmp, uid_t uid, std::string& name, std::string& size,
                              size_t nameLen) const {
    const char* allocNameTmp = nullptr;
    if (!nameTmp) nameTmp = allocNameTmp = UidToNameLocked(uid);
    if (nameTmp) {
        size_t lenSpace = std::max(nameLen - name.length(), (size_t)1);
        size_t len = EntryBase::TOTAL_LEN - EntryBase::PRUNED_LEN - size.length() - name.length() -
                     lenSpace - 2;
        size_t lenNameTmp = strlen(nameTmp);
        while ((len < lenNameTmp) && (lenSpace > 1)) {
            ++len;
            --lenSpace;
        }
        name += android::base::StringPrintf("%*s", (int)lenSpace, "");
        if (len < lenNameTmp) {
            name += "...";
            nameTmp += lenNameTmp - std::max(len - 3, (size_t)1);
        }
        name += nameTmp;
        free(const_cast<char*>(allocNameTmp));
    }
}

std::string UidEntry::format(const LogStatistics& stat, log_id_t id, uid_t uid) const
        REQUIRES(stat.lock_) {
    std::string name = android::base::StringPrintf("%u", uid);
    std::string size = android::base::StringPrintf("%zu", getSizes());

    stat.FormatTmp(nullptr, uid, name, size, 6);

    std::string pruned = "";
    if (worstUidEnabledForLogid(id)) {
        size_t totalDropped = 0;
        for (LogStatistics::uidTable_t::const_iterator it =
                 stat.uidTable[id].begin();
             it != stat.uidTable[id].end(); ++it) {
            totalDropped += it->second.dropped_count();
        }
        size_t sizes = stat.mSizes[id];
        size_t totalSize = stat.mSizesTotal[id];
        size_t totalElements = stat.mElementsTotal[id];
        float totalVirtualSize =
            (float)sizes + (float)totalDropped * totalSize / totalElements;
        size_t entrySize = getSizes();
        float virtualEntrySize = entrySize;
        int realPermille = virtualEntrySize * 1000.0 / sizes;
        size_t dropped = dropped_count();
        if (dropped) {
            pruned = android::base::StringPrintf("%zu", dropped);
            virtualEntrySize += (float)dropped * totalSize / totalElements;
        }
        int virtualPermille = virtualEntrySize * 1000.0 / totalVirtualSize;
        int permille =
            (realPermille - virtualPermille) * 1000L / (virtualPermille ?: 1);
        if ((permille < -1) || (1 < permille)) {
            std::string change;
            const char* units = "%";
            const char* prefix = (permille > 0) ? "+" : "";

            if (permille > 999) {
                permille = (permille + 1000) / 100;  // Now tenths fold
                units = "X";
                prefix = "";
            }
            if ((-99 < permille) && (permille < 99)) {
                change = android::base::StringPrintf(
                    "%s%d.%u%s", prefix, permille / 10,
                    ((permille < 0) ? (-permille % 10) : (permille % 10)),
                    units);
            } else {
                change = android::base::StringPrintf(
                    "%s%d%s", prefix, (permille + 5) / 10, units);
            }
            ssize_t spaces = EntryBase::PRUNED_LEN - 2 - pruned.length() - change.length();
            if ((spaces <= 0) && pruned.length()) {
                spaces = 1;
            }
            if (spaces > 0) {
                change += android::base::StringPrintf("%*s", (int)spaces, "");
            }
            pruned = change + pruned;
        }
    }

    std::string output = formatLine(name, size, pruned);

    if (uid != AID_SYSTEM) {
        return output;
    }

    static const size_t maximum_sorted_entries = 32;
    std::array<const pid_t*, maximum_sorted_entries> sorted_pids;
    std::array<const PidEntry*, maximum_sorted_entries> sorted_entries;
    stat.pidSystemTable[id].MaxEntries(uid, 0, sorted_pids, sorted_entries);

    std::string byPid;
    size_t index;
    bool hasDropped = false;
    for (index = 0; index < maximum_sorted_entries; ++index) {
        const PidEntry* entry = sorted_entries[index];
        if (!entry) {
            break;
        }
        if (entry->getSizes() <= (getSizes() / 100)) {
            break;
        }
        if (entry->dropped_count()) {
            hasDropped = true;
        }
        byPid += entry->format(stat, id, *sorted_pids[index]);
    }
    if (index > 1) {  // print this only if interesting
        std::string ditto("\" ");
        output += formatLine(std::string("  PID/UID   COMMAND LINE"), ditto,
                             hasDropped ? ditto : std::string(""));
        output += byPid;
    }

    return output;
}

std::string PidEntry::formatHeader(const std::string& name,
                                   log_id_t /* id */) const {
    return formatLine(name, std::string("Size"), std::string("Pruned")) +
           formatLine(std::string("  PID/UID   COMMAND LINE"),
                      std::string("BYTES"), std::string("NUM"));
}

std::string PidEntry::format(const LogStatistics& stat, log_id_t, pid_t pid) const
        REQUIRES(stat.lock_) {
    std::string name = android::base::StringPrintf("%5u/%u", pid, uid_);
    std::string size = android::base::StringPrintf("%zu", getSizes());

    stat.FormatTmp(name_, uid_, name, size, 12);

    std::string pruned = "";
    size_t dropped = dropped_count();
    if (dropped) {
        pruned = android::base::StringPrintf("%zu", dropped);
    }

    return formatLine(name, size, pruned);
}

std::string TidEntry::formatHeader(const std::string& name,
                                   log_id_t /* id */) const {
    return formatLine(name, std::string("Size"), std::string("Pruned")) +
           formatLine(std::string("  TID/UID   COMM"), std::string("BYTES"),
                      std::string("NUM"));
}

std::string TidEntry::format(const LogStatistics& stat, log_id_t, pid_t tid) const
        REQUIRES(stat.lock_) {
    std::string name = android::base::StringPrintf("%5u/%u", tid, uid_);
    std::string size = android::base::StringPrintf("%zu", getSizes());

    stat.FormatTmp(name_, uid_, name, size, 12);

    std::string pruned = "";
    size_t dropped = dropped_count();
    if (dropped) {
        pruned = android::base::StringPrintf("%zu", dropped);
    }

    return formatLine(name, size, pruned);
}

std::string TagEntry::formatHeader(const std::string& name, log_id_t id) const {
    bool isprune = worstUidEnabledForLogid(id);
    return formatLine(name, std::string("Size"),
                      std::string(isprune ? "Prune" : "")) +
           formatLine(std::string("    TAG/UID   TAGNAME"),
                      std::string("BYTES"), std::string(isprune ? "NUM" : ""));
}

std::string TagEntry::format(const LogStatistics&, log_id_t, uint32_t) const {
    std::string name;
    if (uid_ == (uid_t)-1) {
        name = android::base::StringPrintf("%7u", key());
    } else {
        name = android::base::StringPrintf("%7u/%u", key(), uid_);
    }
    const char* nameTmp = this->name();
    if (nameTmp) {
        name += android::base::StringPrintf(
            "%*s%s", (int)std::max(14 - name.length(), (size_t)1), "", nameTmp);
    }

    std::string size = android::base::StringPrintf("%zu", getSizes());

    std::string pruned = "";
    size_t dropped = dropped_count();
    if (dropped) {
        pruned = android::base::StringPrintf("%zu", dropped);
    }

    return formatLine(name, size, pruned);
}

std::string TagNameEntry::formatHeader(const std::string& name,
                                       log_id_t /* id */) const {
    return formatLine(name, std::string("Size"), std::string("")) +
           formatLine(std::string("  TID/PID/UID   LOG_TAG NAME"),
                      std::string("BYTES"), std::string(""));
}

std::string TagNameEntry::format(const LogStatistics&, log_id_t, const TagNameKey& key_name) const {
    std::string name;
    std::string pidstr;
    if (pid_ != (pid_t)-1) {
        pidstr = android::base::StringPrintf("%u", pid_);
        if (tid_ != (pid_t)-1 && tid_ != pid_) pidstr = "/" + pidstr;
    }
    int len = 9 - pidstr.length();
    if (len < 0) len = 0;
    if (tid_ == (pid_t)-1 || tid_ == pid_) {
        name = android::base::StringPrintf("%*s", len, "");
    } else {
        name = android::base::StringPrintf("%*u", len, tid_);
    }
    name += pidstr;
    if (uid_ != (uid_t)-1) {
        name += android::base::StringPrintf("/%u", uid_);
    }

    std::string size = android::base::StringPrintf("%zu", getSizes());

    const char* nameTmp = key_name.data();
    if (nameTmp) {
        size_t lenSpace = std::max(16 - name.length(), (size_t)1);
        size_t len = EntryBase::TOTAL_LEN - EntryBase::PRUNED_LEN - size.length() - name.length() -
                     lenSpace - 2;
        size_t lenNameTmp = strlen(nameTmp);
        while ((len < lenNameTmp) && (lenSpace > 1)) {
            ++len;
            --lenSpace;
        }
        name += android::base::StringPrintf("%*s", (int)lenSpace, "");
        if (len < lenNameTmp) {
            name += "...";
            nameTmp += lenNameTmp - std::max(len - 3, (size_t)1);
        }
        name += nameTmp;
    }

    std::string pruned = "";

    return formatLine(name, size, pruned);
}

static std::string formatMsec(uint64_t val) {
    static const unsigned subsecDigits = 3;
    static const uint64_t sec = MS_PER_SEC;

    static const uint64_t minute = 60 * sec;
    static const uint64_t hour = 60 * minute;
    static const uint64_t day = 24 * hour;

    std::string output;
    if (val < sec) return output;

    if (val >= day) {
        output = android::base::StringPrintf("%" PRIu64 "d ", val / day);
        val = (val % day) + day;
    }
    if (val >= minute) {
        if (val >= hour) {
            output += android::base::StringPrintf("%" PRIu64 ":",
                                                  (val / hour) % (day / hour));
        }
        output += android::base::StringPrintf(
            (val >= hour) ? "%02" PRIu64 ":" : "%" PRIu64 ":",
            (val / minute) % (hour / minute));
    }
    output +=
        android::base::StringPrintf((val >= minute) ? "%02" PRIu64 : "%" PRIu64,
                                    (val / sec) % (minute / sec));
    val %= sec;
    unsigned digits = subsecDigits;
    while (digits && ((val % 10) == 0)) {
        val /= 10;
        --digits;
    }
    if (digits) {
        output += android::base::StringPrintf(".%0*" PRIu64, digits, val);
    }
    return output;
}

template <typename TKey, typename TEntry>
std::string LogStatistics::FormatTable(const LogHashtable<TKey, TEntry>& table, uid_t uid,
                                       pid_t pid, const std::string& name, log_id_t id) const
        REQUIRES(lock_) {
    static const size_t maximum_sorted_entries = 32;
    std::string output;
    std::array<const TKey*, maximum_sorted_entries> sorted_keys;
    std::array<const TEntry*, maximum_sorted_entries> sorted_entries;
    table.MaxEntries(uid, pid, sorted_keys, sorted_entries);
    bool header_printed = false;
    for (size_t index = 0; index < maximum_sorted_entries; ++index) {
        const TEntry* entry = sorted_entries[index];
        if (!entry) {
            break;
        }
        if (entry->getSizes() <= (sorted_entries[0]->getSizes() / 100)) {
            break;
        }
        if (!header_printed) {
            output += "\n\n";
            output += entry->formatHeader(name, id);
            header_printed = true;
        }
        output += entry->format(*this, id, *sorted_keys[index]);
    }
    return output;
}

std::string LogStatistics::Format(uid_t uid, pid_t pid, unsigned int logMask) const {
    auto lock = std::lock_guard{lock_};

    static const uint16_t spaces_total = 19;

    // Report on total logging, current and for all time

    std::string output = "size/num";
    size_t oldLength;
    int16_t spaces = 1;

    log_id_for_each(id) {
        if (!(logMask & (1 << id))) continue;
        oldLength = output.length();
        if (spaces < 0) spaces = 0;
        output += android::base::StringPrintf("%*s%s", spaces, "",
                                              android_log_id_to_name(id));
        spaces += spaces_total + oldLength - output.length();
    }
    if (spaces < 0) spaces = 0;
    output += android::base::StringPrintf("%*sTotal", spaces, "");

    static const char TotalStr[] = "\nTotal";
    spaces = 10 - strlen(TotalStr);
    output += TotalStr;

    size_t totalSize = 0;
    size_t totalEls = 0;
    log_id_for_each(id) {
        if (!(logMask & (1 << id))) continue;
        oldLength = output.length();
        if (spaces < 0) spaces = 0;
        size_t szs = mSizesTotal[id];
        totalSize += szs;
        size_t els = mElementsTotal[id];
        totalEls += els;
        output +=
            android::base::StringPrintf("%*s%zu/%zu", spaces, "", szs, els);
        spaces += spaces_total + oldLength - output.length();
    }
    if (spaces < 0) spaces = 0;
    output += android::base::StringPrintf("%*s%zu/%zu", spaces, "", totalSize,
                                          totalEls);

    static const char NowStr[] = "\nNow";
    spaces = 10 - strlen(NowStr);
    output += NowStr;

    totalSize = 0;
    totalEls = 0;
    log_id_for_each(id) {
        if (!(logMask & (1 << id))) continue;

        size_t els = mElements[id];
        if (els) {
            oldLength = output.length();
            if (spaces < 0) spaces = 0;
            size_t szs = mSizes[id];
            totalSize += szs;
            totalEls += els;
            output +=
                android::base::StringPrintf("%*s%zu/%zu", spaces, "", szs, els);
            spaces -= output.length() - oldLength;
        }
        spaces += spaces_total;
    }
    if (spaces < 0) spaces = 0;
    output += android::base::StringPrintf("%*s%zu/%zu", spaces, "", totalSize,
                                          totalEls);

    static const char SpanStr[] = "\nLogspan";
    spaces = 10 - strlen(SpanStr);
    output += SpanStr;

    // Total reports the greater of the individual maximum time span, or the
    // validated minimum start and maximum end time span if it makes sense.
    uint64_t minTime = UINT64_MAX;
    uint64_t maxTime = 0;
    uint64_t maxSpan = 0;
    totalSize = 0;

    log_id_for_each(id) {
        if (!(logMask & (1 << id))) continue;

        // validity checking
        uint64_t oldest = mOldest[id].msec();
        uint64_t newest = mNewest[id].msec();
        if (newest <= oldest) {
            spaces += spaces_total;
            continue;
        }

        uint64_t span = newest - oldest;
        if (span > (monthSec * MS_PER_SEC)) {
            spaces += spaces_total;
            continue;
        }

        // total span
        if (minTime > oldest) minTime = oldest;
        if (maxTime < newest) maxTime = newest;
        if (span > maxSpan) maxSpan = span;
        totalSize += span;

        uint64_t dropped = mNewestDropped[id].msec();
        if (dropped < oldest) dropped = oldest;
        if (dropped > newest) dropped = newest;

        oldLength = output.length();
        output += android::base::StringPrintf("%*s%s", spaces, "",
                                              formatMsec(span).c_str());
        unsigned permille = ((newest - dropped) * 1000 + (span / 2)) / span;
        if ((permille > 1) && (permille < 999)) {
            output += android::base::StringPrintf("(%u", permille / 10);
            permille %= 10;
            if (permille) {
                output += android::base::StringPrintf(".%u", permille);
            }
            output += android::base::StringPrintf("%%)");
        }
        spaces -= output.length() - oldLength;
        spaces += spaces_total;
    }
    if ((maxTime > minTime) && ((maxTime -= minTime) < totalSize) &&
        (maxTime > maxSpan)) {
        maxSpan = maxTime;
    }
    if (spaces < 0) spaces = 0;
    output += android::base::StringPrintf("%*s%s", spaces, "",
                                          formatMsec(maxSpan).c_str());

    static const char OverheadStr[] = "\nOverhead";
    spaces = 10 - strlen(OverheadStr);
    output += OverheadStr;

    totalSize = 0;
    log_id_for_each(id) {
        if (!(logMask & (1 << id))) continue;

        size_t els = mElements[id];
        if (els) {
            oldLength = output.length();
            if (spaces < 0) spaces = 0;
            // estimate the std::list overhead.
            static const size_t overhead =
                ((sizeof(LogBufferElement) + sizeof(uint64_t) - 1) &
                 -sizeof(uint64_t)) +
                sizeof(std::list<LogBufferElement*>);
            size_t szs = mSizes[id] + els * overhead;
            totalSize += szs;
            output += android::base::StringPrintf("%*s%zu", spaces, "", szs);
            spaces -= output.length() - oldLength;
        }
        spaces += spaces_total;
    }
    totalSize += sizeOf();
    if (spaces < 0) spaces = 0;
    output += android::base::StringPrintf("%*s%zu", spaces, "", totalSize);

    // Report on Chattiest

    std::string name;

    // Chattiest by application (UID)
    log_id_for_each(id) {
        if (!(logMask & (1 << id))) continue;

        name = (uid == AID_ROOT) ? "Chattiest UIDs in %s log buffer:"
                                 : "Logging for your UID in %s log buffer:";
        output += FormatTable(uidTable[id], uid, pid, name, id);
    }

    if (enable) {
        name = ((uid == AID_ROOT) && !pid) ? "Chattiest PIDs:"
                                           : "Logging for this PID:";
        output += FormatTable(pidTable, uid, pid, name);
        name = "Chattiest TIDs";
        if (pid) name += android::base::StringPrintf(" for PID %d", pid);
        name += ":";
        output += FormatTable(tidTable, uid, pid, name);
    }

    if (enable && (logMask & (1 << LOG_ID_EVENTS))) {
        name = "Chattiest events log buffer TAGs";
        if (pid) name += android::base::StringPrintf(" for PID %d", pid);
        name += ":";
        output += FormatTable(tagTable, uid, pid, name, LOG_ID_EVENTS);
    }

    if (enable && (logMask & (1 << LOG_ID_SECURITY))) {
        name = "Chattiest security log buffer TAGs";
        if (pid) name += android::base::StringPrintf(" for PID %d", pid);
        name += ":";
        output += FormatTable(securityTagTable, uid, pid, name, LOG_ID_SECURITY);
    }

    if (enable) {
        name = "Chattiest TAGs";
        if (pid) name += android::base::StringPrintf(" for PID %d", pid);
        name += ":";
        output += FormatTable(tagNameTable, uid, pid, name);
    }

    return output;
}

namespace android {

uid_t pidToUid(pid_t pid) {
    char buffer[512];
    snprintf(buffer, sizeof(buffer), "/proc/%u/status", pid);
    FILE* fp = fopen(buffer, "r");
    if (fp) {
        while (fgets(buffer, sizeof(buffer), fp)) {
            int uid = AID_LOGD;
            char space = 0;
            if ((sscanf(buffer, "Uid: %d%c", &uid, &space) == 2) &&
                isspace(space)) {
                fclose(fp);
                return uid;
            }
        }
        fclose(fp);
    }
    return AID_LOGD;  // associate this with the logger
}
}

uid_t LogStatistics::PidToUid(pid_t pid) {
    auto lock = std::lock_guard{lock_};
    return pidTable.Add(pid)->second.uid();
}

// caller must free character string
const char* LogStatistics::PidToName(pid_t pid) const {
    auto lock = std::lock_guard{lock_};
    // An inconvenient truth ... getName() can alter the object
    pidTable_t& writablePidTable = const_cast<pidTable_t&>(pidTable);
    const char* name = writablePidTable.Add(pid)->second.name();
    if (!name) {
        return nullptr;
    }
    return strdup(name);
}
