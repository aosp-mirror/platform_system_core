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

#include <algorithm> // std::max
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <string>

#include <base/stringprintf.h>
#include <log/logger.h>
#include <private/android_filesystem_config.h>

#include "LogStatistics.h"

LogStatistics::LogStatistics() : enable(false) {
    log_id_for_each(id) {
        mSizes[id] = 0;
        mElements[id] = 0;
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
                if (strcmp(buffer, "<pre-initialized>")) {
                    retval = strdup(buffer);
                }
            }
            close(fd);
        }
    }
    return retval;
}

}

void LogStatistics::add(LogBufferElement *e) {
    log_id_t log_id = e->getLogId();
    unsigned short size = e->getMsgLen();
    mSizes[log_id] += size;
    ++mElements[log_id];

    mSizesTotal[log_id] += size;
    ++mElementsTotal[log_id];

    if (log_id == LOG_ID_KERNEL) {
        return;
    }

    uidTable[log_id].add(e->getUid(), e);

    if (!enable) {
        return;
    }

    pidTable.add(e->getPid(), e);
    tidTable.add(e->getTid(), e);

    uint32_t tag = e->getTag();
    if (tag) {
        tagTable.add(tag, e);
    }
}

void LogStatistics::subtract(LogBufferElement *e) {
    log_id_t log_id = e->getLogId();
    unsigned short size = e->getMsgLen();
    mSizes[log_id] -= size;
    --mElements[log_id];

    if (log_id == LOG_ID_KERNEL) {
        return;
    }

    uidTable[log_id].subtract(e->getUid(), e);

    if (!enable) {
        return;
    }

    pidTable.subtract(e->getPid(), e);
    tidTable.subtract(e->getTid(), e);

    uint32_t tag = e->getTag();
    if (tag) {
        tagTable.subtract(tag, e);
    }
}

// Atomically set an entry to drop
// entry->setDropped(1) must follow this call, caller should do this explicitly.
void LogStatistics::drop(LogBufferElement *e) {
    log_id_t log_id = e->getLogId();
    unsigned short size = e->getMsgLen();
    mSizes[log_id] -= size;

    uidTable[log_id].drop(e->getUid(), e);

    if (!enable) {
        return;
    }

    pidTable.drop(e->getPid(), e);
    tidTable.drop(e->getTid(), e);
}

// caller must own and free character string
char *LogStatistics::uidToName(uid_t uid) {
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
    char *name = android::uidToName(userId);
    if (!name && (userId > (AID_SHARED_GID_START - AID_APP))) {
        name = android::uidToName(userId - (AID_SHARED_GID_START - AID_APP));
    }
    if (name) {
        return name;
    }

    // report uid -> pid(s) -> pidToName if unique
    for(pidTable_t::iterator it = pidTable.begin(); it != pidTable.end(); ++it) {
        const PidEntry &entry = it->second;

        if (entry.getUid() == uid) {
            const char *n = entry.getName();

            if (n) {
                if (!name) {
                    name = strdup(n);
                } else if (strcmp(name, n)) {
                    free(name);
                    name = NULL;
                    break;
                }
            }
        }
    }

    // No one
    return name;
}

static std::string format_line(
        const std::string &name,
        const std::string &size,
        const std::string &pruned) {
    static const size_t pruned_len = 6;
    static const size_t total_len = 70 + pruned_len;

    ssize_t drop_len = std::max(pruned.length() + 1, pruned_len);
    ssize_t size_len = std::max(size.length() + 1,
                                total_len - name.length() - drop_len - 1);

    if (pruned.length()) {
        return android::base::StringPrintf("%s%*s%*s\n", name.c_str(),
                                           (int)size_len, size.c_str(),
                                           (int)drop_len, pruned.c_str());
    } else {
        return android::base::StringPrintf("%s%*s\n", name.c_str(),
                                           (int)size_len, size.c_str());
    }
}

void LogStatistics::format(char **buf, uid_t uid, unsigned int logMask) {
    static const unsigned short spaces_total = 19;

    if (*buf) {
        free(*buf);
        *buf = NULL;
    }

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
    output += android::base::StringPrintf("\nTotal");

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
    output += android::base::StringPrintf("\nNow");

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

    // Chattiest by application (UID)
    static const size_t maximum_sorted_entries = 32;
    log_id_for_each(id) {
        if (!(logMask & (1 << id))) {
            continue;
        }

        bool headerPrinted = false;
        std::unique_ptr<const UidEntry *[]> sorted = sort(maximum_sorted_entries, id);
        ssize_t index = -1;
        while ((index = uidTable_t::next(index, sorted, maximum_sorted_entries)) >= 0) {
            const UidEntry *entry = sorted[index];
            uid_t u = entry->getKey();
            if ((uid != AID_ROOT) && (u != uid)) {
                continue;
            }

            if (!headerPrinted) {
                output += android::base::StringPrintf("\n\n");
                std::string name;
                if (uid == AID_ROOT) {
                    name = android::base::StringPrintf(
                        "Chattiest UIDs in %s log buffer:",
                        android_log_id_to_name(id));
                } else {
                    name = android::base::StringPrintf(
                        "Logging for your UID in %s log buffer:",
                        android_log_id_to_name(id));
                }
                std::string size = "Size";
                std::string pruned = "Pruned";
                if (!worstUidEnabledForLogid(id)) {
                    pruned = "";
                }
                output += format_line(name, size, pruned);

                name = "UID   PACKAGE";
                size = "BYTES";
                pruned = "LINES";
                if (!worstUidEnabledForLogid(id)) {
                    pruned = "";
                }
                output += format_line(name, size, pruned);

                headerPrinted = true;
            }

            std::string name = android::base::StringPrintf("%u", u);
            char *n = uidToName(u);
            if (n) {
                name += android::base::StringPrintf(
                    "%*s%s", (int)std::max(6 - name.length(), (size_t)1),
                    "", n);
                free(n);
            }

            std::string size = android::base::StringPrintf("%zu",
                                                           entry->getSizes());

            std::string pruned = "";
            size_t dropped = entry->getDropped();
            if (dropped) {
                pruned = android::base::StringPrintf("%zu", dropped);
            }

            output += format_line(name, size, pruned);
        }
    }

    if (enable) {
        // Pid table
        bool headerPrinted = false;
        std::unique_ptr<const PidEntry *[]> sorted = pidTable.sort(maximum_sorted_entries);
        ssize_t index = -1;
        while ((index = pidTable.next(index, sorted, maximum_sorted_entries)) >= 0) {
            const PidEntry *entry = sorted[index];
            uid_t u = entry->getUid();
            if ((uid != AID_ROOT) && (u != uid)) {
                continue;
            }

            if (!headerPrinted) {
                output += android::base::StringPrintf("\n\n");
                std::string name;
                if (uid == AID_ROOT) {
                    name = android::base::StringPrintf("Chattiest PIDs:");
                } else {
                    name = android::base::StringPrintf("Logging for this PID:");
                }
                std::string size = "Size";
                std::string pruned = "Pruned";
                output += format_line(name, size, pruned);

                name = "  PID/UID   COMMAND LINE";
                size = "BYTES";
                pruned = "LINES";
                output += format_line(name, size, pruned);

                headerPrinted = true;
            }

            std::string name = android::base::StringPrintf("%5u/%u",
                                                           entry->getKey(), u);
            const char *n = entry->getName();
            if (n) {
                name += android::base::StringPrintf(
                    "%*s%s", (int)std::max(12 - name.length(), (size_t)1),
                    "", n);
            } else {
                char *un = uidToName(u);
                if (un) {
                    name += android::base::StringPrintf(
                        "%*s%s", (int)std::max(12 - name.length(), (size_t)1),
                        "", un);
                    free(un);
                }
            }

            std::string size = android::base::StringPrintf("%zu",
                                                           entry->getSizes());

            std::string pruned = "";
            size_t dropped = entry->getDropped();
            if (dropped) {
                pruned = android::base::StringPrintf("%zu", dropped);
            }

            output += format_line(name, size, pruned);
        }
    }

    if (enable) {
        // Tid table
        bool headerPrinted = false;
        // sort() returns list of references, unique_ptr makes sure self-delete
        std::unique_ptr<const TidEntry *[]> sorted = tidTable.sort(maximum_sorted_entries);
        ssize_t index = -1;
        while ((index = tidTable.next(index, sorted, maximum_sorted_entries)) >= 0) {
            const TidEntry *entry = sorted[index];
            uid_t u = entry->getUid();
            if ((uid != AID_ROOT) && (u != uid)) {
                continue;
            }

            if (!headerPrinted) { // Only print header if we have table to print
                output += android::base::StringPrintf("\n\n");
                std::string name = "Chattiest TIDs:";
                std::string size = "Size";
                std::string pruned = "Pruned";
                output += format_line(name, size, pruned);

                name = "  TID/UID   COMM";
                size = "BYTES";
                pruned = "LINES";
                output += format_line(name, size, pruned);

                headerPrinted = true;
            }

            std::string name = android::base::StringPrintf("%5u/%u",
                                                           entry->getKey(), u);
            const char *n = entry->getName();
            if (n) {
                name += android::base::StringPrintf(
                    "%*s%s", (int)std::max(12 - name.length(), (size_t)1),
                    "", n);
            } else {
                // if we do not have a PID name, lets punt to try UID name?
                char *un = uidToName(u);
                if (un) {
                    name += android::base::StringPrintf(
                        "%*s%s", (int)std::max(12 - name.length(), (size_t)1),
                        "", un);
                    free(un);
                }
                // We tried, better to not have a name at all, we still
                // have TID/UID by number to report in any case.
            }

            std::string size = android::base::StringPrintf("%zu",
                                                           entry->getSizes());

            std::string pruned = "";
            size_t dropped = entry->getDropped();
            if (dropped) {
                pruned = android::base::StringPrintf("%zu", dropped);
            }

            output += format_line(name, size, pruned);
        }
    }

    if (enable && (logMask & (1 << LOG_ID_EVENTS))) {
        // Tag table
        bool headerPrinted = false;
        std::unique_ptr<const TagEntry *[]> sorted = tagTable.sort(maximum_sorted_entries);
        ssize_t index = -1;
        while ((index = tagTable.next(index, sorted, maximum_sorted_entries)) >= 0) {
            const TagEntry *entry = sorted[index];
            uid_t u = entry->getUid();
            if ((uid != AID_ROOT) && (u != uid)) {
                continue;
            }

            std::string pruned = "";

            if (!headerPrinted) {
                output += android::base::StringPrintf("\n\n");
                std::string name = "Chattiest events log buffer TAGs:";
                std::string size = "Size";
                output += format_line(name, size, pruned);

                name = "    TAG/UID   TAGNAME";
                size = "BYTES";
                output += format_line(name, size, pruned);

                headerPrinted = true;
            }

            std::string name;
            if (u == (uid_t)-1) {
                name = android::base::StringPrintf("%7u",
                                                   entry->getKey());
            } else {
                name = android::base::StringPrintf("%7u/%u",
                                                   entry->getKey(), u);
            }
            const char *n = entry->getName();
            if (n) {
                name += android::base::StringPrintf(
                    "%*s%s", (int)std::max(14 - name.length(), (size_t)1),
                    "", n);
            }

            std::string size = android::base::StringPrintf("%zu",
                                                           entry->getSizes());

            output += format_line(name, size, pruned);
        }
    }

    *buf = strdup(output.c_str());
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
char *LogStatistics::pidToName(pid_t pid) {
    const char *name = pidTable.add(pid)->second.getName();
    if (!name) {
        return NULL;
    }
    return strdup(name);
}
