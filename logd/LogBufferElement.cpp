/*
 * Copyright (C) 2012-2014 The Android Open Source Project
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

#include "LogBufferElement.h"

#include <ctype.h>
#include <endian.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <log/log_read.h>
#include <private/android_logger.h>

#include "LogStatistics.h"
#include "LogUtils.h"

LogBufferElement::LogBufferElement(log_id_t log_id, log_time realtime, uid_t uid, pid_t pid,
                                   pid_t tid, uint64_t sequence, const char* msg, uint16_t len)
    : uid_(uid),
      pid_(pid),
      tid_(tid),
      sequence_(sequence),
      realtime_(realtime),
      msg_len_(len),
      log_id_(log_id),
      dropped_(false) {
    msg_ = new char[len];
    memcpy(msg_, msg, len);
}

LogBufferElement::LogBufferElement(const LogBufferElement& elem)
    : uid_(elem.uid_),
      pid_(elem.pid_),
      tid_(elem.tid_),
      sequence_(elem.sequence_),
      realtime_(elem.realtime_),
      msg_len_(elem.msg_len_),
      log_id_(elem.log_id_),
      dropped_(elem.dropped_) {
    if (dropped_) {
        tag_ = elem.GetTag();
    } else {
        msg_ = new char[msg_len_];
        memcpy(msg_, elem.msg_, msg_len_);
    }
}

LogBufferElement::LogBufferElement(LogBufferElement&& elem) noexcept
    : uid_(elem.uid_),
      pid_(elem.pid_),
      tid_(elem.tid_),
      sequence_(elem.sequence_),
      realtime_(elem.realtime_),
      msg_len_(elem.msg_len_),
      log_id_(elem.log_id_),
      dropped_(elem.dropped_) {
    if (dropped_) {
        tag_ = elem.GetTag();
    } else {
        msg_ = elem.msg_;
        elem.msg_ = nullptr;
    }
}

LogBufferElement::~LogBufferElement() {
    if (!dropped_) {
        delete[] msg_;
    }
}

uint32_t LogBufferElement::GetTag() const {
    // Binary buffers have no tag.
    if (!IsBinary(log_id())) {
        return 0;
    }

    // Dropped messages store the tag in place of msg_.
    if (dropped_) {
        return tag_;
    }

    return MsgToTag(msg(), msg_len());
}

LogStatisticsElement LogBufferElement::ToLogStatisticsElement() const {
    return LogStatisticsElement{
            .uid = uid(),
            .pid = pid(),
            .tid = tid(),
            .tag = GetTag(),
            .realtime = realtime(),
            .msg = msg(),
            .msg_len = msg_len(),
            .dropped_count = dropped_count(),
            .log_id = log_id(),
    };
}

uint16_t LogBufferElement::SetDropped(uint16_t value) {
    if (dropped_) {
        return dropped_count_ = value;
    }

    // The tag information is saved in msg_ data, which is in a union with tag_, used after dropped_
    // is set to true. Therefore we save the tag value aside, delete msg_, then set tag_ to the tag
    // value in its place.
    auto old_tag = GetTag();
    delete[] msg_;
    msg_ = nullptr;

    tag_ = old_tag;
    dropped_ = true;
    return dropped_count_ = value;
}

// caller must own and free character string
char* android::tidToName(pid_t tid) {
    char* retval = nullptr;
    char buffer[256];
    snprintf(buffer, sizeof(buffer), "/proc/%u/comm", tid);
    int fd = open(buffer, O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        ssize_t ret = read(fd, buffer, sizeof(buffer));
        if (ret >= (ssize_t)sizeof(buffer)) {
            ret = sizeof(buffer) - 1;
        }
        while ((ret > 0) && isspace(buffer[ret - 1])) {
            --ret;
        }
        if (ret > 0) {
            buffer[ret] = '\0';
            retval = strdup(buffer);
        }
        close(fd);
    }

    // if nothing for comm, check out cmdline
    char* name = android::pidToName(tid);
    if (!retval) {
        retval = name;
        name = nullptr;
    }

    // check if comm is truncated, see if cmdline has full representation
    if (name) {
        // impossible for retval to be NULL if name not NULL
        size_t retval_len = strlen(retval);
        size_t name_len = strlen(name);
        // KISS: ToDo: Only checks prefix truncated, not suffix, or both
        if ((retval_len < name_len) &&
            !fastcmp<strcmp>(retval, name + name_len - retval_len)) {
            free(retval);
            retval = name;
        } else {
            free(name);
        }
    }
    return retval;
}

// assumption: msg_ == NULL
size_t LogBufferElement::PopulateDroppedMessage(char*& buffer, LogStatistics* stats,
                                                bool lastSame) {
    static const char tag[] = "chatty";

    if (!__android_log_is_loggable_len(ANDROID_LOG_INFO, tag, strlen(tag),
                                       ANDROID_LOG_VERBOSE)) {
        return 0;
    }

    static const char format_uid[] = "uid=%u%s%s %s %u line%s";
    const char* name = stats->UidToName(uid_);
    const char* commName = android::tidToName(tid_);
    if (!commName && (tid_ != pid_)) {
        commName = android::tidToName(pid_);
    }
    if (!commName) {
        commName = stats->PidToName(pid_);
    }
    if (name && name[0] && commName && (name[0] == commName[0])) {
        size_t len = strlen(name + 1);
        if (!strncmp(name + 1, commName + 1, len)) {
            if (commName[len + 1] == '\0') {
                free(const_cast<char*>(commName));
                commName = nullptr;
            } else {
                free(const_cast<char*>(name));
                name = nullptr;
            }
        }
    }
    if (name) {
        char* buf = nullptr;
        int result = asprintf(&buf, "(%s)", name);
        if (result != -1) {
            free(const_cast<char*>(name));
            name = buf;
        }
    }
    if (commName) {
        char* buf = nullptr;
        int result = asprintf(&buf, " %s", commName);
        if (result != -1) {
            free(const_cast<char*>(commName));
            commName = buf;
        }
    }
    // identical to below to calculate the buffer size required
    const char* type = lastSame ? "identical" : "expire";
    size_t len = snprintf(nullptr, 0, format_uid, uid_, name ? name : "", commName ? commName : "",
                          type, dropped_count(), (dropped_count() > 1) ? "s" : "");

    size_t hdrLen;
    if (IsBinary(log_id())) {
        hdrLen = sizeof(android_log_event_string_t);
    } else {
        hdrLen = 1 + sizeof(tag);
    }

    buffer = static_cast<char*>(calloc(1, hdrLen + len + 1));
    if (!buffer) {
        free(const_cast<char*>(name));
        free(const_cast<char*>(commName));
        return 0;
    }

    size_t retval = hdrLen + len;
    if (IsBinary(log_id())) {
        android_log_event_string_t* event =
            reinterpret_cast<android_log_event_string_t*>(buffer);

        event->header.tag = htole32(CHATTY_LOG_TAG);
        event->type = EVENT_TYPE_STRING;
        event->length = htole32(len);
    } else {
        ++retval;
        buffer[0] = ANDROID_LOG_INFO;
        strcpy(buffer + 1, tag);
    }

    snprintf(buffer + hdrLen, len + 1, format_uid, uid_, name ? name : "", commName ? commName : "",
             type, dropped_count(), (dropped_count() > 1) ? "s" : "");
    free(const_cast<char*>(name));
    free(const_cast<char*>(commName));

    return retval;
}

bool LogBufferElement::FlushTo(LogWriter* writer, LogStatistics* stats, bool lastSame) {
    struct logger_entry entry = {};

    entry.hdr_size = sizeof(struct logger_entry);
    entry.lid = log_id_;
    entry.pid = pid_;
    entry.tid = tid_;
    entry.uid = uid_;
    entry.sec = realtime_.tv_sec;
    entry.nsec = realtime_.tv_nsec;

    char* buffer = nullptr;
    const char* msg;
    if (dropped_) {
        entry.len = PopulateDroppedMessage(buffer, stats, lastSame);
        if (!entry.len) return true;
        msg = buffer;
    } else {
        msg = msg_;
        entry.len = msg_len_;
    }

    bool retval = writer->Write(entry, msg);

    if (buffer) free(buffer);

    return retval;
}
