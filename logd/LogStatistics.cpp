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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <log/logger.h>
#include <private/android_filesystem_config.h>
#include <utils/String8.h>

#include "LogStatistics.h"

LogStatistics::LogStatistics() {
    log_id_for_each(id) {
        mSizes[id] = 0;
        mElements[id] = 0;
        mSizesTotal[id] = 0;
        mElementsTotal[id] = 0;
    }
}

// caller must own and free character string
char *LogStatistics::pidToName(pid_t pid) {
    char *retval = NULL;
    if (pid == 0) { // special case from auditd for kernel
        retval = strdup("logd.auditd");
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

void LogStatistics::add(LogBufferElement *e) {
    log_id_t log_id = e->getLogId();
    unsigned short size = e->getMsgLen();
    mSizes[log_id] += size;
    ++mElements[log_id];

    uid_t uid = e->getUid();
    android::hash_t hash = android::hash_type(uid);
    uidTable_t &table = uidTable[log_id];
    ssize_t index = table.find(-1, hash, uid);
    if (index == -1) {
        UidEntry initEntry(uid);
        initEntry.add(size);
        table.add(hash, initEntry);
    } else {
        UidEntry &entry = table.editEntryAt(index);
        entry.add(size);
    }

    mSizesTotal[log_id] += size;
    ++mElementsTotal[log_id];
}

void LogStatistics::subtract(LogBufferElement *e) {
    log_id_t log_id = e->getLogId();
    unsigned short size = e->getMsgLen();
    mSizes[log_id] -= size;
    --mElements[log_id];

    uid_t uid = e->getUid();
    android::hash_t hash = android::hash_type(uid);
    uidTable_t &table = uidTable[log_id];
    ssize_t index = table.find(-1, hash, uid);
    if (index != -1) {
        UidEntry &entry = table.editEntryAt(index);
        if (entry.subtract(size)) {
            table.removeAt(index);
        }
    }
}

// caller must own and delete UidEntry array
const UidEntry **LogStatistics::sort(size_t n, log_id id) {
    if (!n) {
        return NULL;
    }

    const UidEntry **retval = new const UidEntry* [n];
    memset(retval, 0, sizeof(*retval) * n);

    uidTable_t &table = uidTable[id];
    ssize_t index = -1;
    while ((index = table.next(index)) >= 0) {
        const UidEntry &entry = table.entryAt(index);
        size_t s = entry.getSizes();
        ssize_t i = n - 1;
        while ((!retval[i] || (s > retval[i]->getSizes())) && (--i >= 0));
        if (++i < (ssize_t)n) {
            size_t b = n - i - 1;
            if (b) {
                memmove(&retval[i+1], &retval[i], b * sizeof(retval[0]));
            }
            retval[i] = &entry;
        }
    }
    return retval;
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

    // No one
    return NULL;
}

static void format_line(android::String8 &output,
        android::String8 &name, android::String8 &size) {
    static const size_t total_len = 70;

    output.appendFormat("%s%*s\n", name.string(),
        (int)std::max(total_len - name.length() - 1, size.length() + 1)
        size.string());
}

void LogStatistics::format(char **buf, uid_t uid, unsigned int logMask) {
    static const unsigned short spaces_total = 19;

    if (*buf) {
        free(*buf);
        *buf = NULL;
    }

    // Report on total logging, current and for all time

    android::String8 output("size/num");
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
        output.appendFormat("%*s%s", spaces, "", android_log_id_to_name(id));
        spaces += spaces_total + oldLength - output.length();
    }

    spaces = 4;
    output.appendFormat("\nTotal");

    log_id_for_each(id) {
        if (!(logMask & (1 << id))) {
            continue;
        }
        oldLength = output.length();
        if (spaces < 0) {
            spaces = 0;
        }
        output.appendFormat("%*s%zu/%zu", spaces, "",
                            sizesTotal(id), elementsTotal(id));
        spaces += spaces_total + oldLength - output.length();
    }

    spaces = 6;
    output.appendFormat("\nNow");

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
            output.appendFormat("%*s%zu/%zu", spaces, "", sizes(id), els);
            spaces -= output.length() - oldLength;
        }
        spaces += spaces_total;
    }

    // Report on Chattiest

    // Chattiest by application (UID)
    log_id_for_each(id) {
        if (!(logMask & (1 << id))) {
            continue;
        }

        static const size_t maximum_sorted_entries = 32;
        const UidEntry **sorted = sort(maximum_sorted_entries, id);

        if (!sorted) {
            continue;
        }

        bool print = false;
        for(size_t index = 0; index < maximum_sorted_entries; ++index) {
            const UidEntry *entry = sorted[index];

            if (!entry) {
                break;
            }

            size_t sizes = entry->getSizes();
            if (sizes < (65536/100)) {
                break;
            }

            uid_t u = entry->getKey();
            if ((uid != AID_ROOT) && (u != uid)) {
                continue;
            }

            if (!print) {
                if (uid == AID_ROOT) {
                    output.appendFormat(
                        "\n\nChattiest UIDs in %s:\n",
                        android_log_id_to_name(id));
                    android::String8 name("UID");
                    android::String8 size("Size");
                    format_line(output, name, size);
                } else {
                    output.appendFormat(
                        "\n\nLogging for your UID in %s:\n",
                        android_log_id_to_name(id));
                }
                print = true;
            }

            android::String8 name("");
            name.appendFormat("%u", u);
            char *n = uidToName(u);
            if (n) {
                name.appendFormat("%*s%s", (int)std::max(6 - name.length(), (size_t)1), "", n);
                free(n);
            }

            android::String8 size("");
            size.appendFormat("%zu", sizes);

            format_line(output, name, size);
        }

        delete [] sorted;
    }

    *buf = strdup(output.string());
}

uid_t LogStatistics::pidToUid(pid_t pid) {
    char buffer[512];
    snprintf(buffer, sizeof(buffer), "/proc/%u/status", pid);
    FILE *fp = fopen(buffer, "r");
    if (fp) {
        while (fgets(buffer, sizeof(buffer), fp)) {
            int uid;
            if (sscanf(buffer, "Groups: %d", &uid) == 1) {
                fclose(fp);
                return uid;
            }
        }
        fclose(fp);
    }
    return getuid(); // associate this with the logger
}
