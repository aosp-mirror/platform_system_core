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
#include <syslog.h>

#include "libaudit.h"
#include "LogAudit.h"

#define KMSG_PRIORITY(PRI)         \
    '<',                           \
    '0' + (LOG_AUTH | (PRI)) / 10, \
    '0' + (LOG_AUTH | (PRI)) % 10, \
    '>'

LogAudit::LogAudit(LogBuffer *buf, LogReader *reader, int fdDmsg)
        : SocketListener(getLogSocket(), false)
        , logbuf(buf)
        , reader(reader)
        , fdDmesg(-1) {
    static const char auditd_message[] = { KMSG_PRIORITY(LOG_INFO),
        'l', 'o', 'g', 'd', '.', 'a', 'u', 'd', 'i', 't', 'd', ':',
        ' ', 's', 't', 'a', 'r', 't', '\n' };
    write(fdDmsg, auditd_message, sizeof(auditd_message));
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

    char *cp;
    while ((cp = strstr(str, "  "))) {
        memmove(cp, cp + 1, strlen(cp + 1) + 1);
    }

    bool info = strstr(str, " permissive=1") || strstr(str, " policy loaded ");
    if (fdDmesg >= 0) {
        struct iovec iov[3];
        static const char log_info[] = { KMSG_PRIORITY(LOG_INFO) };
        static const char log_warning[] = { KMSG_PRIORITY(LOG_WARNING) };

        iov[0].iov_base = info ? const_cast<char *>(log_info)
                               : const_cast<char *>(log_warning);
        iov[0].iov_len = info ? sizeof(log_info) : sizeof(log_warning);
        iov[1].iov_base = str;
        iov[1].iov_len = strlen(str);
        iov[2].iov_base = const_cast<char *>("\n");
        iov[2].iov_len = 1;

        writev(fdDmesg, iov, sizeof(iov) / sizeof(iov[0]));
    }

    pid_t pid = getpid();
    pid_t tid = gettid();
    uid_t uid = getuid();
    log_time now;

    static const char audit_str[] = " audit(";
    char *timeptr = strstr(str, audit_str);
    if (timeptr
            && ((cp = now.strptime(timeptr + sizeof(audit_str) - 1, "%s.%q")))
            && (*cp == ':')) {
        memcpy(timeptr + sizeof(audit_str) - 1, "0.0", 3);
        memmove(timeptr + sizeof(audit_str) - 1 + 3, cp, strlen(cp) + 1);
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
        memmove(pidptr, cp, strlen(cp) + 1);
    }

    // log to events

    size_t l = strlen(str);
    size_t n = l + sizeof(uint32_t) + sizeof(uint8_t) + sizeof(uint32_t);

    bool notify = false;

    char *newstr = reinterpret_cast<char *>(malloc(n));
    if (!newstr) {
        rc = -ENOMEM;
    } else {
        cp = newstr;
        *cp++ = AUDITD_LOG_TAG & 0xFF;
        *cp++ = (AUDITD_LOG_TAG >> 8) & 0xFF;
        *cp++ = (AUDITD_LOG_TAG >> 16) & 0xFF;
        *cp++ = (AUDITD_LOG_TAG >> 24) & 0xFF;
        *cp++ = EVENT_TYPE_STRING;
        *cp++ = l & 0xFF;
        *cp++ = (l >> 8) & 0xFF;
        *cp++ = (l >> 16) & 0xFF;
        *cp++ = (l >> 24) & 0xFF;
        memcpy(cp, str, l);

        logbuf->log(LOG_ID_EVENTS, now, uid, pid, tid, newstr,
                    (n <= USHRT_MAX) ? (unsigned short) n : USHRT_MAX);
        free(newstr);

        notify = true;
    }

    // log to main

    static const char comm_str[] = " comm=\"";
    const char *comm = strstr(str, comm_str);
    const char *estr = str + strlen(str);
    if (comm) {
        estr = comm;
        comm += sizeof(comm_str) - 1;
    } else if (pid == getpid()) {
        pid = tid;
        comm = "auditd";
    } else if (!(comm = logbuf->pidToName(pid))) {
        comm = "unknown";
    }

    const char *ecomm = strchr(comm, '"');
    if (ecomm) {
        ++ecomm;
        l = ecomm - comm;
    } else {
        l = strlen(comm) + 1;
        ecomm = "";
    }
    n = (estr - str) + strlen(ecomm) + l + 2;

    newstr = reinterpret_cast<char *>(malloc(n));
    if (!newstr) {
        rc = -ENOMEM;
    } else {
        *newstr = info ? ANDROID_LOG_INFO : ANDROID_LOG_WARN;
        strlcpy(newstr + 1, comm, l);
        strncpy(newstr + 1 + l, str, estr - str);
        strcpy(newstr + 1 + l + (estr - str), ecomm);

        logbuf->log(LOG_ID_MAIN, now, uid, pid, tid, newstr,
                    (n <= USHRT_MAX) ? (unsigned short) n : USHRT_MAX);
        free(newstr);

        notify = true;
    }

    free(str);

    if (notify) {
        reader->notifyNewLog();
    }

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
    if (audit_setup(fd, getpid()) < 0) {
        audit_close(fd);
        fd = -1;
    }
    return fd;
}
