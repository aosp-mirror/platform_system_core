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

#include <ctype.h>
#include <endian.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <private/android_logger.h>

#include "LogBuffer.h"
#include "LogBufferElement.h"
#include "LogCommand.h"
#include "LogReader.h"
#include "LogUtils.h"

const uint64_t LogBufferElement::FLUSH_ERROR(0);
atomic_int_fast64_t LogBufferElement::sequence(1);

LogBufferElement::LogBufferElement(log_id_t log_id, log_time realtime,
                                   uid_t uid, pid_t pid, pid_t tid,
                                   const char* msg, unsigned short len)
    : mUid(uid),
      mPid(pid),
      mTid(tid),
      mSequence(sequence.fetch_add(1, memory_order_relaxed)),
      mRealTime(realtime),
      mMsgLen(len),
      mLogId(log_id) {
    mMsg = new char[len];
    memcpy(mMsg, msg, len);
    mTag = (isBinary() && (mMsgLen >= sizeof(uint32_t)))
               ? le32toh(reinterpret_cast<android_event_header_t*>(mMsg)->tag)
               : 0;
}

LogBufferElement::LogBufferElement(const LogBufferElement& elem)
    : mTag(elem.mTag),
      mUid(elem.mUid),
      mPid(elem.mPid),
      mTid(elem.mTid),
      mSequence(elem.mSequence),
      mRealTime(elem.mRealTime),
      mMsgLen(elem.mMsgLen),
      mLogId(elem.mLogId) {
    mMsg = new char[mMsgLen];
    memcpy(mMsg, elem.mMsg, mMsgLen);
}

LogBufferElement::~LogBufferElement() {
    delete[] mMsg;
}

// caller must own and free character string
char* android::tidToName(pid_t tid) {
    char* retval = NULL;
    char buffer[256];
    snprintf(buffer, sizeof(buffer), "/proc/%u/comm", tid);
    int fd = open(buffer, O_RDONLY);
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
        name = NULL;
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

// assumption: mMsg == NULL
size_t LogBufferElement::populateDroppedMessage(char*& buffer, LogBuffer* parent,
                                                bool lastSame) {
    static const char tag[] = "chatty";

    if (!__android_log_is_loggable_len(ANDROID_LOG_INFO, tag, strlen(tag),
                                       ANDROID_LOG_VERBOSE)) {
        return 0;
    }

    static const char format_uid[] = "uid=%u%s%s %s %u line%s";
    parent->lock();
    const char* name = parent->uidToName(mUid);
    parent->unlock();
    const char* commName = android::tidToName(mTid);
    if (!commName && (mTid != mPid)) {
        commName = android::tidToName(mPid);
    }
    if (!commName) {
        parent->lock();
        commName = parent->pidToName(mPid);
        parent->unlock();
    }
    if (name && name[0] && commName && (name[0] == commName[0])) {
        size_t len = strlen(name + 1);
        if (!strncmp(name + 1, commName + 1, len)) {
            if (commName[len + 1] == '\0') {
                free(const_cast<char*>(commName));
                commName = NULL;
            } else {
                free(const_cast<char*>(name));
                name = NULL;
            }
        }
    }
    if (name) {
        char* buf = NULL;
        asprintf(&buf, "(%s)", name);
        if (buf) {
            free(const_cast<char*>(name));
            name = buf;
        }
    }
    if (commName) {
        char* buf = NULL;
        asprintf(&buf, " %s", commName);
        if (buf) {
            free(const_cast<char*>(commName));
            commName = buf;
        }
    }
    // identical to below to calculate the buffer size required
    const char* type = lastSame ? "identical" : "expire";
    size_t len = snprintf(NULL, 0, format_uid, mUid, name ? name : "",
                          commName ? commName : "", type, mDropped,
                          (mDropped > 1) ? "s" : "");

    size_t hdrLen;
    if (isBinary()) {
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
    if (isBinary()) {
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

    snprintf(buffer + hdrLen, len + 1, format_uid, mUid, name ? name : "",
             commName ? commName : "", type, mDropped,
             (mDropped > 1) ? "s" : "");
    free(const_cast<char*>(name));
    free(const_cast<char*>(commName));

    return retval;
}

uint64_t LogBufferElement::flushTo(SocketClient* reader, LogBuffer* parent,
                                   bool privileged, bool lastSame) {
    struct logger_entry_v4 entry;

    memset(&entry, 0, sizeof(struct logger_entry_v4));

    entry.hdr_size = privileged ? sizeof(struct logger_entry_v4)
                                : sizeof(struct logger_entry_v3);
    entry.lid = mLogId;
    entry.pid = mPid;
    entry.tid = mTid;
    entry.uid = mUid;
    entry.sec = mRealTime.tv_sec;
    entry.nsec = mRealTime.tv_nsec;

    struct iovec iovec[2];
    iovec[0].iov_base = &entry;
    iovec[0].iov_len = entry.hdr_size;

    char* buffer = NULL;

    if (!mMsg) {
        entry.len = populateDroppedMessage(buffer, parent, lastSame);
        if (!entry.len) return mSequence;
        iovec[1].iov_base = buffer;
    } else {
        entry.len = mMsgLen;
        iovec[1].iov_base = mMsg;
    }
    iovec[1].iov_len = entry.len;

    uint64_t retval = reader->sendDatav(iovec, 2) ? FLUSH_ERROR : mSequence;

    if (buffer) free(buffer);

    return retval;
}
