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

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/klog.h>
#include <sys/prctl.h>
#include <sys/uio.h>

#include "libaudit.h"
#include "LogAudit.h"

LogAudit::LogAudit(LogBuffer *buf, LogReader *reader, int fdDmsg)
        : SocketListener(getLogSocket(), false)
        , logbuf(buf)
        , reader(reader)
        , fdDmesg(-1) {
    logDmesg();
    fdDmesg = fdDmsg;
}

bool LogAudit::onDataAvailable(SocketClient *cli) {
    prctl(PR_SET_NAME, "logd.auditd");

    struct audit_message rep;

    rep.nlh.nlmsg_type = 0;
    rep.nlh.nlmsg_len = 0;
    rep.data[0] = '\0';

    if (audit_get_reply(cli->getSocket(), &rep, GET_REPLY_BLOCKING, 0) < 0) {
        SLOGE("Failed on audit_get_reply with error: %s", strerror(errno));
        return false;
    }

    logPrint("type=%d %.*s", rep.nlh.nlmsg_type, rep.nlh.nlmsg_len, rep.data);

    return true;
}

int LogAudit::logPrint(const char *fmt, ...) {
    if (fmt == NULL) {
        return -EINVAL;
    }

    va_list args;

    char *str = NULL;
    va_start(args, fmt);
    int rc = vasprintf(&str, fmt, args);
    va_end(args);

    if (rc < 0) {
        return rc;
    }

    if (fdDmesg >= 0) {
        struct iovec iov[2];

        iov[0].iov_base = str;
        iov[0].iov_len = strlen(str);
        iov[1].iov_base = const_cast<char *>("\n");
        iov[1].iov_len = 1;

        writev(fdDmesg, iov, sizeof(iov) / sizeof(iov[0]));
    }

    pid_t pid = getpid();
    pid_t tid = gettid();
    uid_t uid = getuid();
    log_time now;

    static const char audit_str[] = " audit(";
    char *timeptr = strstr(str, audit_str);
    char *cp;
    if (timeptr
            && ((cp = now.strptime(timeptr + sizeof(audit_str) - 1, "%s.%q")))
            && (*cp == ':')) {
        memcpy(timeptr + sizeof(audit_str) - 1, "0.0", 3);
        strcpy(timeptr + sizeof(audit_str) - 1 + 3, cp);
    } else {
        now.strptime("", ""); // side effect of setting CLOCK_REALTIME
    }

    static const char pid_str[] = " pid=";
    char *pidptr = strstr(str, pid_str);
    if (pidptr && isdigit(pidptr[sizeof(pid_str) - 1])) {
        cp = pidptr + sizeof(pid_str) - 1;
        pid = 0;
        while (isdigit(*cp)) {
            pid = (pid * 10) + (*cp - '0');
            ++cp;
        }
        tid = pid;
        uid = logbuf->pidToUid(pid);
        strcpy(pidptr, cp);
    }

    size_t n = strlen(str);
    n += sizeof(uint32_t) + sizeof(uint8_t) + sizeof(uint32_t);

    char *newstr = reinterpret_cast<char *>(malloc(n));
    if (!newstr) {
        free(str);
        return -ENOMEM;
    }

    char *msg = newstr;
    *msg++ = AUDITD_LOG_TAG & 0xFF;
    *msg++ = (AUDITD_LOG_TAG >> 8) & 0xFF;
    *msg++ = (AUDITD_LOG_TAG >> 16) & 0xFF;
    *msg++ = (AUDITD_LOG_TAG >> 24) & 0xFF;
    *msg++ = EVENT_TYPE_STRING;
    size_t l = n - sizeof(uint32_t) - sizeof(uint8_t) - sizeof(uint32_t);
    *msg++ = l & 0xFF;
    *msg++ = (l >> 8) & 0xFF;
    *msg++ = (l >> 16) & 0xFF;
    *msg++ = (l >> 24) & 0xFF;
    memcpy(msg, str, l);
    free(str);

    logbuf->log(LOG_ID_EVENTS, now, uid, pid, tid, newstr,
                (n <= USHRT_MAX) ? (unsigned short) n : USHRT_MAX);
    reader->notifyNewLog();

    free(newstr);

    return rc;
}

void LogAudit::logDmesg() {
    int len = klogctl(KLOG_SIZE_BUFFER, NULL, 0);
    if (len <= 0) {
        return;
    }

    len++;
    char buf[len];

    int rc = klogctl(KLOG_READ_ALL, buf, len);

    buf[len - 1] = '\0';

    for(char *tok = buf; (rc >= 0) && ((tok = strtok(tok, "\r\n"))); tok = NULL) {
        char *audit = strstr(tok, " audit(");
        if (!audit) {
            continue;
        }

        *audit++ = '\0';

        char *type = strstr(tok, "type=");
        if (type) {
            rc = logPrint("%s %s", type, audit);
        } else {
            rc = logPrint("%s", audit);
        }
    }
}

int LogAudit::getLogSocket() {
    int fd = audit_open();
    if (fd < 0) {
        return fd;
    }
    if (audit_set_pid(fd, getpid(), WAIT_YES) < 0) {
        audit_close(fd);
        fd = -1;
    }
    return fd;
}
