/*
 * Copyright (C) 2007-2016 The Android Open Source Project
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

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>

#include <private/android_filesystem_config.h>
#include <private/android_logger.h>

#include "config_read.h"
#include "logger.h"

static int pmsgAvailable(log_id_t logId);
static int pmsgVersion(struct android_log_logger *logger,
                       struct android_log_transport_context *transp);
static int pmsgRead(struct android_log_logger_list *logger_list,
                    struct android_log_transport_context *transp,
                    struct log_msg *log_msg);
static void pmsgClose(struct android_log_logger_list *logger_list,
                      struct android_log_transport_context *transp);
static int pmsgClear(struct android_log_logger *logger,
                     struct android_log_transport_context *transp);

LIBLOG_HIDDEN struct android_log_transport_read pmsgLoggerRead = {
    .node = { &pmsgLoggerRead.node, &pmsgLoggerRead.node },
    .name = "pmsg",
    .available = pmsgAvailable,
    .version = pmsgVersion,
    .read = pmsgRead,
    .poll = NULL,
    .close = pmsgClose,
    .clear = pmsgClear,
    .setSize = NULL,
    .getSize = NULL,
    .getReadableSize = NULL,
    .getPrune = NULL,
    .setPrune = NULL,
    .getStats = NULL,
};

static int pmsgAvailable(log_id_t logId)
{
    if (logId > LOG_ID_SECURITY) {
        return -EINVAL;
    }
    if (access("/dev/pmsg0", W_OK) == 0) {
        return 0;
    }
    return -EBADF;
}

/* Determine the credentials of the caller */
static bool uid_has_log_permission(uid_t uid)
{
    return (uid == AID_SYSTEM) || (uid == AID_LOG) || (uid == AID_ROOT);
}

static uid_t get_best_effective_uid()
{
    uid_t euid;
    uid_t uid;
    gid_t gid;
    ssize_t i;
    static uid_t last_uid = (uid_t) -1;

    if (last_uid != (uid_t) -1) {
        return last_uid;
    }
    uid = __android_log_uid();
    if (uid_has_log_permission(uid)) {
        return last_uid = uid;
    }
    euid = geteuid();
    if (uid_has_log_permission(euid)) {
        return last_uid = euid;
    }
    gid = getgid();
    if (uid_has_log_permission(gid)) {
        return last_uid = gid;
    }
    gid = getegid();
    if (uid_has_log_permission(gid)) {
        return last_uid = gid;
    }
    i = getgroups((size_t) 0, NULL);
    if (i > 0) {
        gid_t list[i];

        getgroups(i, list);
        while (--i >= 0) {
            if (uid_has_log_permission(list[i])) {
                return last_uid = list[i];
            }
        }
    }
    return last_uid = uid;
}

static int pmsgClear(struct android_log_logger *logger __unused,
                     struct android_log_transport_context *transp __unused)
{
    if (uid_has_log_permission(get_best_effective_uid())) {
        return unlink("/sys/fs/pstore/pmsg-ramoops-0");
    }
    errno = EPERM;
    return -1;
}

/*
 * returns the logger version
 */
static int pmsgVersion(struct android_log_logger *logger __unused,
                       struct android_log_transport_context *transp __unused)
{
    return 4;
}

static int pmsgRead(struct android_log_logger_list *logger_list,
                    struct android_log_transport_context *transp,
                    struct log_msg *log_msg)
{
    ssize_t ret;
    off_t current, next;
    uid_t uid;
    struct android_log_logger *logger;
    struct __attribute__((__packed__)) {
        android_pmsg_log_header_t p;
        android_log_header_t l;
    } buf;
    static uint8_t preread_count;
    bool is_system;

    memset(log_msg, 0, sizeof(*log_msg));

    if (transp->context.fd <= 0) {
        int fd = open("/sys/fs/pstore/pmsg-ramoops-0", O_RDONLY);

        if (fd < 0) {
            return -errno;
        }
        if (fd == 0) { /* Argggg */
            fd = open("/sys/fs/pstore/pmsg-ramoops-0", O_RDONLY);
            close(0);
            if (fd < 0) {
                return -errno;
            }
        }
        transp->context.fd = fd;
        preread_count = 0;
    }

    while(1) {
        if (preread_count < sizeof(buf)) {
            ret = TEMP_FAILURE_RETRY(read(transp->context.fd,
                                          &buf.p.magic + preread_count,
                                          sizeof(buf) - preread_count));
            if (ret < 0) {
                return -errno;
            }
            preread_count += ret;
        }
        if (preread_count != sizeof(buf)) {
            return preread_count ? -EIO : -EAGAIN;
        }
        if ((buf.p.magic != LOGGER_MAGIC)
         || (buf.p.len <= sizeof(buf))
         || (buf.p.len > (sizeof(buf) + LOGGER_ENTRY_MAX_PAYLOAD))
         || (buf.l.id >= LOG_ID_MAX)
         || (buf.l.realtime.tv_nsec >= NS_PER_SEC)) {
            do {
                memmove(&buf.p.magic, &buf.p.magic + 1, --preread_count);
            } while (preread_count && (buf.p.magic != LOGGER_MAGIC));
            continue;
        }
        preread_count = 0;

        if ((transp->logMask & (1 << buf.l.id)) &&
                ((!logger_list->start.tv_sec && !logger_list->start.tv_nsec) ||
                    ((logger_list->start.tv_sec <= buf.l.realtime.tv_sec) &&
                        ((logger_list->start.tv_sec != buf.l.realtime.tv_sec) ||
                            (logger_list->start.tv_nsec <=
                                buf.l.realtime.tv_nsec)))) &&
                (!logger_list->pid || (logger_list->pid == buf.p.pid))) {
            uid = get_best_effective_uid();
            is_system = uid_has_log_permission(uid);
            if (is_system || (uid == buf.p.uid)) {
                ret = TEMP_FAILURE_RETRY(read(transp->context.fd,
                                          is_system ?
                                              log_msg->entry_v4.msg :
                                              log_msg->entry_v3.msg,
                                          buf.p.len - sizeof(buf)));
                if (ret < 0) {
                    return -errno;
                }
                if (ret != (ssize_t)(buf.p.len - sizeof(buf))) {
                    return -EIO;
                }

                log_msg->entry_v4.len = buf.p.len - sizeof(buf);
                log_msg->entry_v4.hdr_size = is_system ?
                    sizeof(log_msg->entry_v4) :
                    sizeof(log_msg->entry_v3);
                log_msg->entry_v4.pid = buf.p.pid;
                log_msg->entry_v4.tid = buf.l.tid;
                log_msg->entry_v4.sec = buf.l.realtime.tv_sec;
                log_msg->entry_v4.nsec = buf.l.realtime.tv_nsec;
                log_msg->entry_v4.lid = buf.l.id;
                if (is_system) {
                    log_msg->entry_v4.uid = buf.p.uid;
                }

                return ret;
            }
        }

        current = TEMP_FAILURE_RETRY(lseek(transp->context.fd,
                                           (off_t)0, SEEK_CUR));
        if (current < 0) {
            return -errno;
        }
        next = TEMP_FAILURE_RETRY(lseek(transp->context.fd,
                                        (off_t)(buf.p.len - sizeof(buf)),
                                        SEEK_CUR));
        if (next < 0) {
            return -errno;
        }
        if ((next - current) != (ssize_t)(buf.p.len - sizeof(buf))) {
            return -EIO;
        }
    }
}

static void pmsgClose(struct android_log_logger_list *logger_list __unused,
                      struct android_log_transport_context *transp) {
    if (transp->context.fd > 0) {
        close (transp->context.fd);
    }
    transp->context.fd = 0;
}
