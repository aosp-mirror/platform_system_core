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

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <log/logger.h>

#include "LogStatistics.h"

LogStatistics::LogStatistics() : enable(false) {
    log_id_for_each(id) {
        mSizes[id] = 0;
        mElements[id] = 0;
        mDroppedElements[id] = 0;
        mSizesTotal[id] = 0;
        mElementsTotal[id] = 0;
    }
}

namespace android {

// caller must own and free character string
char *pidToName(pid_t pid) {
    char *retval = NULL;
    if (pid == 0) { // special case from auditd/klogd for kernel
        retval = strdup("logd");
    } else {
        char buffer[512];
        snprintf(buffer, sizeof(buffer), "/proc/%u/cmdline", pid);
        int fd = open(buffer, O_RDONLY);
        if (fd >= 0) {
            ssize_t ret = read(fd, buffer, sizeof(buffer));
            if (ret > 0) {
                buffer[sizeof(buffer)-1] = '\0';
                // frameworks intermediate state
                if (fast<strcmp>(buffer, "<pre-initialized>")) {
                    retval = strdup(buffer);
                }
            }
            close(fd);
        }
    }
    return retval;
}

}

void LogStatistics::add(LogBufferElement *element) {
    log_id_t log_id = element->getLogId();
    unsigned short size = element->getMsgLen();
    mSizes[log_id] += size;
    ++mElements[log_id];

    mSizesTotal[log_id] += size;
    ++mElementsTotal[log_id];

    if (log_id == LOG_ID_KERNEL) {
        return;
    }

    uidTable[log_id].add(element->getUid(), element);

    if (!enable) {
        return;
    }

    pidTable.add(element->getPid(), element);
    tidTable.add(element->getTid(), element);

    uint32_t tag = element->getTag();
    if (tag) {
        tagTable.add(tag, element);
    }
}

void LogStatistics::subtract(LogBufferElement *element) {
    log_id_t log_id = element->getLogId();
    unsigned short size = element->getMsgLen();
    mSizes[log_id] -= size;
    --mElements[log_id];
    if (element->getDropped()) {
        --mDroppedElements[log_id];
    }

    if (log_id == LOG_ID_KERNEL) {
        return;
    }

    uidTable[log_id].subtract(element->getUid(), element);

    if (!enable) {
        return;
    }

    pidTable.subtract(element->getPid(), element);
    tidTable.subtract(element->getTid(), element);

    uint32_t tag = element->getTag();
    if (tag) {
        tagTable.subtract(tag, element);
    }
}

// Atomically set an entry to drop
// entry->setDropped(1) must follow this call, caller should do this explicitly.
void LogStatistics::drop(LogBufferElement *element) {
    log_id_t log_id = element->getLogId();
    unsigned short size = element->getMsgLen();
    mSizes[log_id] -= size;
    ++mDroppedElements[log_id];

    uidTable[log_id].drop(element->getUid(), element);

    if (!enable) {
        return;
    }

    pidTable.drop(element->getPid(), element);
    tidTable.drop(element->getTid(), element);
}

// caller must own and free character string
const char *LogStatistics::uidToName(uid_t uid) const {
    // Local hard coded favourites
    if (uid == AID_LOGD) {
        return strdup("auditd");
    }

    // Android hard coded
    const struct android_id_info *info = android_ids;

    for (size_t i = 0; i < android_id_count; ++i) {
        if (info->aid == uid) {
            return strdup(info->name);
        }
        ++info;
    }

    // Parse /data/system/packages.list
    uid_t userId = uid % AID_USER;
    const char *name = android::uidToName(userId);
    if (!name && (userId > (AID_SHARED_GID_START - AID_APP))) {
        name = android::uidToName(userId - (AID_SHARED_GID_START - AID_APP));
    }
    if (name) {
        return name;
    }

    // report uid -> pid(s) -> pidToName if unique
    for(pidTable_t::const_iterator it = pidTable.begin(); it != pidTable.end(); ++it) {
        const PidEntry &entry = it->second;

        if (entry.getUid() == uid) {
            const char *nameTmp = entry.getName();

            if (nameTmp) {
                if (!name) {
                    name = strdup(nameTmp);
                } else if (fast<strcmp>(name, nameTmp)) {
                    free(const_cast<char *>(name));
                    name = NULL;
                    break;
                }
            }
        }
    }

    // No one
    return name;
}

std::string UidEntry::formatHeader(const std::string &name, log_id_t id) const {
    bool isprune = worstUidEnabledForLogid(id);
    return formatLine(android::base::StringPrintf(
                          name.c_str(), android_log_id_to_name(id)),
                      std::string("Size"),
                      std::string(isprune ? "+/-  Pruned" : ""))
         + formatLine(std::string("UID   PACKAGE"),
                      std::string("BYTES"),
                      std::string(isprune ? "NUM" : ""));
}

std::string UidEntry::format(const LogStatistics &stat, log_id_t id) const {
    uid_t uid = getKey();
    std::string name = android::base::StringPrintf("%u", uid);
    const char *nameTmp = stat.uidToName(uid);
    if (nameTmp) {
        name += android::base::StringPrintf(
            "%*s%s", (int)std::max(6 - name.length(), (size_t)1),
            "", nameTmp);
        free(const_cast<char *>(nameTmp));
    }

    std::string size = android::base::StringPrintf("%zu", getSizes());

    std::string pruned = "";
    if (worstUidEnabledForLogid(id)) {
        size_t totalDropped = 0;
        for (LogStatistics::uidTable_t::const_iterator it = stat.uidTable[id].begin();
                it != stat.uidTable[id].end(); ++it) {
            totalDropped += it->second.getDropped();
        }
        size_t sizes = stat.sizes(id);
        size_t totalSize = stat.sizesTotal(id);
        size_t totalElements = stat.elementsTotal(id);
        float totalVirtualSize = (float)sizes + (float)totalDropped * totalSize
                                / totalElements;
        size_t entrySize = getSizes();
        float virtualEntrySize = entrySize;
        int realPermille = virtualEntrySize * 1000.0 / sizes;
        size_t dropped = getDropped();
        if (dropped) {
            pruned = android::base::StringPrintf("%zu", dropped);
            virtualEntrySize += (float)dropped * totalSize / totalElements;
        }
        int virtualPermille = virtualEntrySize * 1000.0 / totalVirtualSize;
        int permille = (realPermille - virtualPermille) * 1000L
                     / (virtualPermille ?: 1);
        if ((permille < -1) || (1 < permille)) {
            std::string change;
            const char *units = "%";
            const char *prefix = (permille > 0) ? "+" : "";

            if (permille > 999) {
                permille = (permille + 1000) / 100; // Now tenths fold
                units = "X";
                prefix = "";
            }
            if ((-99 < permille) && (permille < 99)) {
                change = android::base::StringPrintf("%s%d.%u%s",
                    prefix,
                    permille / 10,
                    ((permille < 0) ? (-permille % 10) : (permille % 10)),
                    units);
            } else {
                change = android::base::StringPrintf("%s%d%s",
                    prefix,
                    (permille + 5) / 10, units);
            }
            ssize_t spaces = EntryBaseConstants::pruned_len
                           - 2 - pruned.length() - change.length();
            if ((spaces <= 0) && pruned.length()) {
                spaces = 1;
            }
            if (spaces > 0) {
                change += android::base::StringPrintf("%*s", (int)spaces, "");
            }
            pruned = change + pruned;
        }
    }

    return formatLine(name, size, pruned);
}

std::string PidEntry::formatHeader(const std::string &name, log_id_t /* id */) const {
    return formatLine(name,
                      std::string("Size"),
                      std::string("Pruned"))
         + formatLine(std::string("  PID/UID   COMMAND LINE"),
                      std::string("BYTES"),
                      std::string("NUM"));
}

std::string PidEntry::format(const LogStatistics &stat, log_id_t /* id */) const {
    uid_t uid = getUid();
    std::string name = android::base::StringPrintf("%5u/%u",
                                                   getKey(), uid);
    const char *nameTmp = getName();
    if (nameTmp) {
        name += android::base::StringPrintf(
            "%*s%s", (int)std::max(12 - name.length(), (size_t)1),
            "", nameTmp);
    } else if ((nameTmp = stat.uidToName(uid))) {
        name += android::base::StringPrintf(
            "%*s%s", (int)std::max(12 - name.length(), (size_t)1),
            "", nameTmp);
        free(const_cast<char *>(nameTmp));
    }

    std::string size = android::base::StringPrintf("%zu",
                                                   getSizes());

    std::string pruned = "";
    size_t dropped = getDropped();
    if (dropped) {
        pruned = android::base::StringPrintf("%zu", dropped);
    }

    return formatLine(name, size, pruned);
}

std::string TidEntry::formatHeader(const std::string &name, log_id_t /* id */) const {
    return formatLine(name,
                      std::string("Size"),
                      std::string("Pruned"))
         + formatLine(std::string("  TID/UID   COMM"),
                      std::string("BYTES"),
                      std::string("NUM"));
}

std::string TidEntry::format(const LogStatistics &stat, log_id_t /* id */) const {
    uid_t uid = getUid();
    std::string name = android::base::StringPrintf("%5u/%u",
                                                   getKey(), uid);
    const char *nameTmp = getName();
    if (nameTmp) {
        name += android::base::StringPrintf(
            "%*s%s", (int)std::max(12 - name.length(), (size_t)1),
            "", nameTmp);
    } else if ((nameTmp = stat.uidToName(uid))) {
        // if we do not have a PID name, lets punt to try UID name?
        name += android::base::StringPrintf(
            "%*s%s", (int)std::max(12 - name.length(), (size_t)1),
            "", nameTmp);
        free(const_cast<char *>(nameTmp));
        // We tried, better to not have a name at all, we still
        // have TID/UID by number to report in any case.
    }

    std::string size = android::base::StringPrintf("%zu",
                                                   getSizes());

    std::string pruned = "";
    size_t dropped = getDropped();
    if (dropped) {
        pruned = android::base::StringPrintf("%zu", dropped);
    }

    return formatLine(name, size, pruned);
}

std::string TagEntry::formatHeader(const std::string &name, log_id_t id) const {
    bool isprune = worstUidEnabledForLogid(id);
    return formatLine(name,
                      std::string("Size"),
                      std::string(isprune ? "Prune" : ""))
         + formatLine(std::string("    TAG/UID   TAGNAME"),
                      std::string("BYTES"),
                      std::string(isprune ? "NUM" : ""));
}

std::string TagEntry::format(const LogStatistics & /* stat */, log_id_t /* id */) const {
    std::string name;
    uid_t uid = getUid();
    if (uid == (uid_t)-1) {
        name = android::base::StringPrintf("%7u",
                                           getKey());
    } else {
        name = android::base::StringPrintf("%7u/%u",
                                           getKey(), uid);
    }
    const char *nameTmp = getName();
    if (nameTmp) {
        name += android::base::StringPrintf(
            "%*s%s", (int)std::max(14 - name.length(), (size_t)1),
            "", nameTmp);
    }

    std::string size = android::base::StringPrintf("%zu",
                                                   getSizes());

    std::string pruned = "";

    return formatLine(name, size, pruned);
}

std::string LogStatistics::format(uid_t uid, unsigned int logMask) const {
    static const unsigned short spaces_total = 19;

    // Report on total logging, current and for all time

    std::string output = "size/num";
    size_t oldLength;
    short spaces = 1;

    log_id_for_each(id) {
        if (!(logMask & (1 << id))) {
            continue;
        }
        oldLength = output.length();
        if (spaces < 0) {
            spaces = 0;
        }
        output += android::base::StringPrintf("%*s%s", spaces, "",
                                              android_log_id_to_name(id));
        spaces += spaces_total + oldLength - output.length();
    }

    spaces = 4;
    output += "\nTotal";

    log_id_for_each(id) {
        if (!(logMask & (1 << id))) {
            continue;
        }
        oldLength = output.length();
        if (spaces < 0) {
            spaces = 0;
        }
        output += android::base::StringPrintf("%*s%zu/%zu", spaces, "",
                                              sizesTotal(id),
                                              elementsTotal(id));
        spaces += spaces_total + oldLength - output.length();
    }

    spaces = 6;
    output += "\nNow";

    log_id_for_each(id) {
        if (!(logMask & (1 << id))) {
            continue;
        }

        size_t els = elements(id);
        if (els) {
            oldLength = output.length();
            if (spaces < 0) {
                spaces = 0;
            }
            output += android::base::StringPrintf("%*s%zu/%zu", spaces, "",
                                                  sizes(id), els);
            spaces -= output.length() - oldLength;
        }
        spaces += spaces_total;
    }

    // Report on Chattiest

    std::string name;

    // Chattiest by application (UID)
    log_id_for_each(id) {
        if (!(logMask & (1 << id))) {
            continue;
        }

        name = (uid == AID_ROOT)
            ? "Chattiest UIDs in %s log buffer:"
            : "Logging for your UID in %s log buffer:";
        output += uidTable[id].format(*this, uid, name, id);
    }

    if (enable) {
        name = (uid == AID_ROOT) ? "Chattiest PIDs:" : "Logging for this PID:";
        output += pidTable.format(*this, uid, name);
        name = "Chattiest TIDs:";
        output += tidTable.format(*this, uid, name);
    }

    if (enable && (logMask & (1 << LOG_ID_EVENTS))) {
        name = "Chattiest events log buffer TAGs:";
        output += tagTable.format(*this, uid, name, LOG_ID_EVENTS);
    }

    return output;
}

namespace android {

uid_t pidToUid(pid_t pid) {
    char buffer[512];
    snprintf(buffer, sizeof(buffer), "/proc/%u/status", pid);
    FILE *fp = fopen(buffer, "r");
    if (fp) {
        while (fgets(buffer, sizeof(buffer), fp)) {
            int uid;
            if (sscanf(buffer, "Uid: %d", &uid) == 1) {
                fclose(fp);
                return uid;
            }
        }
        fclose(fp);
    }
    return AID_LOGD; // associate this with the logger
}

}

uid_t LogStatistics::pidToUid(pid_t pid) {
    return pidTable.add(pid)->second.getUid();
}

// caller must free character string
const char *LogStatistics::pidToName(pid_t pid) const {
    // An inconvenient truth ... getName() can alter the object
    pidTable_t &writablePidTable = const_cast<pidTable_t &>(pidTable);
    const char *name = writablePidTable.add(pid)->second.getName();
    if (!name) {
        return NULL;
    }
    return strdup(name);
}
