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

/*
 * pmsg write handler
 */

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>

#include <log/log.h>
#include <log/logger.h>

#include <private/android_filesystem_config.h>
#include <private/android_logger.h>

#include "config_write.h"
#include "log_portability.h"
#include "logger.h"

static int pmsgOpen();
static void pmsgClose();
static int pmsgAvailable(log_id_t logId);
static int pmsgWrite(log_id_t logId, struct timespec *ts,
                      struct iovec *vec, size_t nr);

LIBLOG_HIDDEN struct android_log_transport_write pmsgLoggerWrite = {
    .node = { &pmsgLoggerWrite.node, &pmsgLoggerWrite.node },
    .context.fd = -1,
    .name = "pmsg",
    .available = pmsgAvailable,
    .open = pmsgOpen,
    .close = pmsgClose,
    .write = pmsgWrite,
};

static int pmsgOpen()
{
    if (pmsgLoggerWrite.context.fd < 0) {
        pmsgLoggerWrite.context.fd = TEMP_FAILURE_RETRY(open("/dev/pmsg0", O_WRONLY));
    }

    return pmsgLoggerWrite.context.fd;
}

static void pmsgClose()
{
    if (pmsgLoggerWrite.context.fd >= 0) {
        close(pmsgLoggerWrite.context.fd);
        pmsgLoggerWrite.context.fd = -1;
    }
}

static int pmsgAvailable(log_id_t logId)
{
    if (logId > LOG_ID_SECURITY) {
        return -EINVAL;
    }
    if (pmsgLoggerWrite.context.fd < 0) {
        if (access("/dev/pmsg0", W_OK) == 0) {
            return 0;
        }
        return -EBADF;
    }
    return 1;
}

static int pmsgWrite(log_id_t logId, struct timespec *ts,
                      struct iovec *vec, size_t nr)
{
    static const unsigned headerLength = 2;
    struct iovec newVec[nr + headerLength];
    android_log_header_t header;
    android_pmsg_log_header_t pmsgHeader;
    size_t i, payloadSize;
    ssize_t ret;

    if (pmsgLoggerWrite.context.fd < 0) {
        return -EBADF;
    }

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

    pmsgHeader.magic = LOGGER_MAGIC;
    pmsgHeader.len = sizeof(pmsgHeader) + sizeof(header);
    pmsgHeader.uid = __android_log_uid();
    pmsgHeader.pid = __android_log_pid();

    header.id = logId;
    header.tid = gettid();
    header.realtime.tv_sec = ts->tv_sec;
    header.realtime.tv_nsec = ts->tv_nsec;

    newVec[0].iov_base   = (unsigned char *)&pmsgHeader;
    newVec[0].iov_len    = sizeof(pmsgHeader);
    newVec[1].iov_base   = (unsigned char *)&header;
    newVec[1].iov_len    = sizeof(header);

    for (payloadSize = 0, i = headerLength; i < nr + headerLength; i++) {
        newVec[i].iov_base = vec[i - headerLength].iov_base;
        payloadSize += newVec[i].iov_len = vec[i - headerLength].iov_len;

        if (payloadSize > LOGGER_ENTRY_MAX_PAYLOAD) {
            newVec[i].iov_len -= payloadSize - LOGGER_ENTRY_MAX_PAYLOAD;
            if (newVec[i].iov_len) {
                ++i;
            }
            payloadSize = LOGGER_ENTRY_MAX_PAYLOAD;
            break;
        }
    }
    pmsgHeader.len += payloadSize;

    ret = TEMP_FAILURE_RETRY(writev(pmsgLoggerWrite.context.fd, newVec, i));
    if (ret < 0) {
        ret = errno ? -errno : -ENOTCONN;
    }

    if (ret > (ssize_t)(sizeof(header) + sizeof(pmsgHeader))) {
        ret -= sizeof(header) - sizeof(pmsgHeader);
    }

    return ret;
}
