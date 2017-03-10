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
#include <endian.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/uio.h>
#include <syslog.h>

#include <android-base/macros.h>
#include <private/android_filesystem_config.h>
#include <private/android_logger.h>

#include "LogAudit.h"
#include "LogBuffer.h"
#include "LogKlog.h"
#include "LogReader.h"
#include "LogUtils.h"
#include "libaudit.h"

#define KMSG_PRIORITY(PRI)                               \
    '<', '0' + LOG_MAKEPRI(LOG_AUTH, LOG_PRI(PRI)) / 10, \
        '0' + LOG_MAKEPRI(LOG_AUTH, LOG_PRI(PRI)) % 10, '>'

LogAudit::LogAudit(LogBuffer* buf, LogReader* reader, int fdDmesg)
    : SocketListener(mSock = getLogSocket(), false),
      logbuf(buf),
      reader(reader),
      fdDmesg(fdDmesg),
      main(__android_logger_property_get_bool("ro.logd.auditd.main",
                                              BOOL_DEFAULT_TRUE)),
      events(__android_logger_property_get_bool("ro.logd.auditd.events",
                                                BOOL_DEFAULT_TRUE)),
      initialized(false),
      tooFast(false) {
    static const char auditd_message[] = { KMSG_PRIORITY(LOG_INFO),
                                           'l',
                                           'o',
                                           'g',
                                           'd',
                                           '.',
                                           'a',
                                           'u',
                                           'd',
                                           'i',
                                           't',
                                           'd',
                                           ':',
                                           ' ',
                                           's',
                                           't',
                                           'a',
                                           'r',
                                           't',
                                           '\n' };
    write(fdDmesg, auditd_message, sizeof(auditd_message));
}

void LogAudit::checkRateLimit() {
    // trim list for AUDIT_RATE_LIMIT_BURST_DURATION of history
    log_time oldest(AUDIT_RATE_LIMIT_BURST_DURATION, 0);
    bucket.emplace(android_log_clockid());
    oldest = bucket.back() - oldest;
    while (bucket.front() < oldest) bucket.pop();

    static const size_t upperThreshold =
        ((AUDIT_RATE_LIMIT_BURST_DURATION *
          (AUDIT_RATE_LIMIT_DEFAULT + AUDIT_RATE_LIMIT_MAX)) +
         1) /
        2;
    if (bucket.size() >= upperThreshold) {
        // Hit peak, slow down source
        if (!tooFast) {
            tooFast = true;
            audit_rate_limit(mSock, AUDIT_RATE_LIMIT_MAX);
        }

        // We do not need to hold on to the full set of timing data history,
        // let's ensure it does not grow without bounds.  This also ensures
        // that std::dequeue underneath behaves almost like a ring buffer.
        do {
            bucket.pop();
        } while (bucket.size() >= upperThreshold);
        return;
    }

    if (!tooFast) return;

    static const size_t lowerThreshold =
        AUDIT_RATE_LIMIT_BURST_DURATION * AUDIT_RATE_LIMIT_MAX;

    if (bucket.size() >= lowerThreshold) return;

    tooFast = false;
    // Went below max sustained rate, allow source to speed up
    audit_rate_limit(mSock, AUDIT_RATE_LIMIT_DEFAULT);
}

bool LogAudit::onDataAvailable(SocketClient* cli) {
    if (!initialized) {
        prctl(PR_SET_NAME, "logd.auditd");
        initialized = true;
    }

    checkRateLimit();

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

int LogAudit::logPrint(const char* fmt, ...) {
    if (fmt == NULL) {
        return -EINVAL;
    }

    va_list args;

    char* str = NULL;
    va_start(args, fmt);
    int rc = vasprintf(&str, fmt, args);
    va_end(args);

    if (rc < 0) {
        return rc;
    }

    char* cp;
    // Work around kernels missing
    // https://github.com/torvalds/linux/commit/b8f89caafeb55fba75b74bea25adc4e4cd91be67
    // Such kernels improperly add newlines inside audit messages.
    while ((cp = strchr(str, '\n'))) {
        *cp = ' ';
    }

    while ((cp = strstr(str, "  "))) {
        memmove(cp, cp + 1, strlen(cp + 1) + 1);
    }

    bool info = strstr(str, " permissive=1") || strstr(str, " policy loaded ");
    if ((fdDmesg >= 0) && initialized) {
        struct iovec iov[3];
        static const char log_info[] = { KMSG_PRIORITY(LOG_INFO) };
        static const char log_warning[] = { KMSG_PRIORITY(LOG_WARNING) };
        static const char newline[] = "\n";

        // Dedupe messages, checking for identical messages starting with avc:
        static unsigned count;
        static char* last_str;
        static bool last_info;

        if (last_str != NULL) {
            static const char avc[] = "): avc: ";
            char* avcl = strstr(last_str, avc);
            bool skip = false;

            if (avcl) {
                char* avcr = strstr(str, avc);

                skip = avcr &&
                       !fastcmp<strcmp>(avcl + strlen(avc), avcr + strlen(avc));
                if (skip) {
                    ++count;
                    free(last_str);
                    last_str = strdup(str);
                    last_info = info;
                }
            }
            if (!skip) {
                static const char resume[] = " duplicate messages suppressed\n";

                iov[0].iov_base = last_info ? const_cast<char*>(log_info)
                                            : const_cast<char*>(log_warning);
                iov[0].iov_len =
                    last_info ? sizeof(log_info) : sizeof(log_warning);
                iov[1].iov_base = last_str;
                iov[1].iov_len = strlen(last_str);
                if (count > 1) {
                    iov[2].iov_base = const_cast<char*>(resume);
                    iov[2].iov_len = strlen(resume);
                } else {
                    iov[2].iov_base = const_cast<char*>(newline);
                    iov[2].iov_len = strlen(newline);
                }

                writev(fdDmesg, iov, arraysize(iov));
                free(last_str);
                last_str = NULL;
            }
        }
        if (last_str == NULL) {
            count = 0;
            last_str = strdup(str);
            last_info = info;
        }
        if (count == 0) {
            iov[0].iov_base = info ? const_cast<char*>(log_info)
                                   : const_cast<char*>(log_warning);
            iov[0].iov_len = info ? sizeof(log_info) : sizeof(log_warning);
            iov[1].iov_base = str;
            iov[1].iov_len = strlen(str);
            iov[2].iov_base = const_cast<char*>(newline);
            iov[2].iov_len = strlen(newline);

            writev(fdDmesg, iov, arraysize(iov));
        }
    }

    if (!main && !events) {
        free(str);
        return 0;
    }

    pid_t pid = getpid();
    pid_t tid = gettid();
    uid_t uid = AID_LOGD;
    log_time now;

    static const char audit_str[] = " audit(";
    char* timeptr = strstr(str, audit_str);
    if (timeptr &&
        ((cp = now.strptime(timeptr + sizeof(audit_str) - 1, "%s.%q"))) &&
        (*cp == ':')) {
        memcpy(timeptr + sizeof(audit_str) - 1, "0.0", 3);
        memmove(timeptr + sizeof(audit_str) - 1 + 3, cp, strlen(cp) + 1);
        if (!isMonotonic()) {
            if (android::isMonotonic(now)) {
                LogKlog::convertMonotonicToReal(now);
            }
        } else {
            if (!android::isMonotonic(now)) {
                LogKlog::convertRealToMonotonic(now);
            }
        }
    } else if (isMonotonic()) {
        now = log_time(CLOCK_MONOTONIC);
    } else {
        now = log_time(CLOCK_REALTIME);
    }

    static const char pid_str[] = " pid=";
    char* pidptr = strstr(str, pid_str);
    if (pidptr && isdigit(pidptr[sizeof(pid_str) - 1])) {
        cp = pidptr + sizeof(pid_str) - 1;
        pid = 0;
        while (isdigit(*cp)) {
            pid = (pid * 10) + (*cp - '0');
            ++cp;
        }
        tid = pid;
        logbuf->lock();
        uid = logbuf->pidToUid(pid);
        logbuf->unlock();
        memmove(pidptr, cp, strlen(cp) + 1);
    }

    // log to events

    size_t l = strnlen(str, LOGGER_ENTRY_MAX_PAYLOAD);
    size_t n = l + sizeof(android_log_event_string_t);

    bool notify = false;

    if (events) {  // begin scope for event buffer
        uint32_t buffer[(n + sizeof(uint32_t) - 1) / sizeof(uint32_t)];

        android_log_event_string_t* event =
            reinterpret_cast<android_log_event_string_t*>(buffer);
        event->header.tag = htole32(AUDITD_LOG_TAG);
        event->type = EVENT_TYPE_STRING;
        event->length = htole32(l);
        memcpy(event->data, str, l);

        rc = logbuf->log(LOG_ID_EVENTS, now, uid, pid, tid,
                         reinterpret_cast<char*>(event),
                         (n <= USHRT_MAX) ? (unsigned short)n : USHRT_MAX);
        if (rc >= 0) {
            notify = true;
        }
        // end scope for event buffer
    }

    // log to main

    static const char comm_str[] = " comm=\"";
    const char* comm = strstr(str, comm_str);
    const char* estr = str + strlen(str);
    const char* commfree = NULL;
    if (comm) {
        estr = comm;
        comm += sizeof(comm_str) - 1;
    } else if (pid == getpid()) {
        pid = tid;
        comm = "auditd";
    } else {
        logbuf->lock();
        comm = commfree = logbuf->pidToName(pid);
        logbuf->unlock();
        if (!comm) {
            comm = "unknown";
        }
    }

    const char* ecomm = strchr(comm, '"');
    if (ecomm) {
        ++ecomm;
        l = ecomm - comm;
    } else {
        l = strlen(comm) + 1;
        ecomm = "";
    }
    size_t b = estr - str;
    if (b > LOGGER_ENTRY_MAX_PAYLOAD) {
        b = LOGGER_ENTRY_MAX_PAYLOAD;
    }
    size_t e = strnlen(ecomm, LOGGER_ENTRY_MAX_PAYLOAD - b);
    n = b + e + l + 2;

    if (main) {  // begin scope for main buffer
        char newstr[n];

        *newstr = info ? ANDROID_LOG_INFO : ANDROID_LOG_WARN;
        strlcpy(newstr + 1, comm, l);
        strncpy(newstr + 1 + l, str, b);
        strncpy(newstr + 1 + l + b, ecomm, e);

        rc = logbuf->log(LOG_ID_MAIN, now, uid, pid, tid, newstr,
                         (n <= USHRT_MAX) ? (unsigned short)n : USHRT_MAX);

        if (rc >= 0) {
            notify = true;
        }
        // end scope for main buffer
    }

    free(const_cast<char*>(commfree));
    free(str);

    if (notify) {
        reader->notifyNewLog();
        if (rc < 0) {
            rc = n;
        }
    }

    return rc;
}

int LogAudit::log(char* buf, size_t len) {
    char* audit = strstr(buf, " audit(");
    if (!audit || (audit >= &buf[len])) {
        return 0;
    }

    *audit = '\0';

    int rc;
    char* type = strstr(buf, "type=");
    if (type && (type < &buf[len])) {
        rc = logPrint("%s %s", type, audit + 1);
    } else {
        rc = logPrint("%s", audit + 1);
    }
    *audit = ' ';
    return rc;
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
    (void)audit_rate_limit(fd, AUDIT_RATE_LIMIT_DEFAULT);
    return fd;
}
