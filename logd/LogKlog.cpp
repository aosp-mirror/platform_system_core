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
#include <inttypes.h>
#include <limits.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/uio.h>
#include <syslog.h>

#include <log/logger.h>

#include "LogKlog.h"

#define KMSG_PRIORITY(PRI)           \
    '<',                             \
    '0' + (LOG_SYSLOG | (PRI)) / 10, \
    '0' + (LOG_SYSLOG | (PRI)) % 10, \
    '>'

static const char priority_message[] = { KMSG_PRIORITY(LOG_INFO), '\0' };

// Parsing is hard

// called if we see a '<', s is the next character, returns pointer after '>'
static char *is_prio(char *s, size_t len) {
    if (!len || !isdigit(*s++)) {
        return NULL;
    }
    --len;
    static const size_t max_prio_len = (len < 4) ? len : 4;
    size_t priolen = 0;
    char c;
    while (((c = *s++)) && (++priolen <= max_prio_len)) {
        if (!isdigit(c)) {
            return ((c == '>') && (*s == '[')) ? s : NULL;
        }
    }
    return NULL;
}

// called if we see a '[', s is the next character, returns pointer after ']'
static char *is_timestamp(char *s, size_t len) {
    while (len && (*s == ' ')) {
        ++s;
        --len;
    }
    if (!len || !isdigit(*s++)) {
        return NULL;
    }
    --len;
    bool first_period = true;
    char c;
    while (len && ((c = *s++))) {
        --len;
        if ((c == '.') && first_period) {
            first_period = false;
        } else if (!isdigit(c)) {
            return ((c == ']') && !first_period && (*s == ' ')) ? s : NULL;
        }
    }
    return NULL;
}

// Like strtok_r with "\r\n" except that we look for log signatures (regex)
//  \(\(<[0-9]\{1,4\}>\)\([[] *[0-9]+[.][0-9]+[]] \)\{0,1\}\|[[] *[0-9]+[.][0-9]+[]] \)
// and split if we see a second one without a newline.
// We allow nuls in content, monitoring the overall length and sub-length of
// the discovered tokens.

#define SIGNATURE_MASK     0xF0
// <digit> following ('0' to '9' masked with ~SIGNATURE_MASK) added to signature
#define LESS_THAN_SIG      SIGNATURE_MASK
#define OPEN_BRACKET_SIG   ((SIGNATURE_MASK << 1) & SIGNATURE_MASK)
// space is one more than <digit> of 9
#define OPEN_BRACKET_SPACE ((char)(OPEN_BRACKET_SIG | 10))

char *log_strntok_r(char *s, size_t *len, char **last, size_t *sublen) {
    *sublen = 0;
    if (!*len) {
        return NULL;
    }
    if (!s) {
        if (!(s = *last)) {
            return NULL;
        }
        // fixup for log signature split <,
        // LESS_THAN_SIG + <digit>
        if ((*s & SIGNATURE_MASK) == LESS_THAN_SIG) {
            *s = (*s & ~SIGNATURE_MASK) + '0';
            *--s = '<';
            ++*len;
        }
        // fixup for log signature split [,
        // OPEN_BRACKET_SPACE is space, OPEN_BRACKET_SIG + <digit>
        if ((*s & SIGNATURE_MASK) == OPEN_BRACKET_SIG) {
            if (*s == OPEN_BRACKET_SPACE) {
                *s = ' ';
            } else {
                *s = (*s & ~SIGNATURE_MASK) + '0';
            }
            *--s = '[';
            ++*len;
        }
    }

    while (*len && ((*s == '\r') || (*s == '\n'))) {
        ++s;
        --*len;
    }

    if (!*len) {
        *last = NULL;
        return NULL;
    }
    char *peek, *tok = s;

    for (;;) {
        if (*len == 0) {
            *last = NULL;
            return tok;
        }
        char c = *s++;
        --*len;
        size_t adjust;
        switch (c) {
        case '\r':
        case '\n':
            s[-1] = '\0';
            *last = s;
            return tok;

        case '<':
            peek = is_prio(s, *len);
            if (!peek) {
                break;
            }
            if (s != (tok + 1)) { // not first?
                s[-1] = '\0';
                *s &= ~SIGNATURE_MASK;
                *s |= LESS_THAN_SIG; // signature for '<'
                *last = s;
                return tok;
            }
            adjust = peek - s;
            if (adjust > *len) {
                adjust = *len;
            }
            *sublen += adjust;
            *len -= adjust;
            s = peek;
            if ((*s == '[') && ((peek = is_timestamp(s + 1, *len - 1)))) {
                adjust = peek - s;
                if (adjust > *len) {
                    adjust = *len;
                }
                *sublen += adjust;
                *len -= adjust;
                s = peek;
            }
            break;

        case '[':
            peek = is_timestamp(s, *len);
            if (!peek) {
                break;
            }
            if (s != (tok + 1)) { // not first?
                s[-1] = '\0';
                if (*s == ' ') {
                    *s = OPEN_BRACKET_SPACE;
                } else {
                    *s &= ~SIGNATURE_MASK;
                    *s |= OPEN_BRACKET_SIG; // signature for '['
                }
                *last = s;
                return tok;
            }
            adjust = peek - s;
            if (adjust > *len) {
                adjust = *len;
            }
            *sublen += adjust;
            *len -= adjust;
            s = peek;
            break;
        }
        ++*sublen;
    }
    // NOTREACHED
}

log_time LogKlog::correction = log_time(CLOCK_REALTIME) - log_time(CLOCK_MONOTONIC);

LogKlog::LogKlog(LogBuffer *buf, LogReader *reader, int fdWrite, int fdRead, bool auditd) :
        SocketListener(fdRead, false),
        logbuf(buf),
        reader(reader),
        signature(CLOCK_MONOTONIC),
        initialized(false),
        enableLogging(true),
        auditd(auditd) {
    static const char klogd_message[] = "%slogd.klogd: %" PRIu64 "\n";
    char buffer[sizeof(priority_message) + sizeof(klogd_message) + 20 - 4];
    snprintf(buffer, sizeof(buffer), klogd_message, priority_message,
        signature.nsec());
    write(fdWrite, buffer, strlen(buffer));
}

bool LogKlog::onDataAvailable(SocketClient *cli) {
    if (!initialized) {
        prctl(PR_SET_NAME, "logd.klogd");
        initialized = true;
        enableLogging = false;
    }

    char buffer[LOGGER_ENTRY_MAX_PAYLOAD];
    size_t len = 0;

    for(;;) {
        ssize_t retval = 0;
        if ((sizeof(buffer) - 1 - len) > 0) {
            retval = read(cli->getSocket(), buffer + len, sizeof(buffer) - 1 - len);
        }
        if ((retval == 0) && (len == 0)) {
            break;
        }
        if (retval < 0) {
            return false;
        }
        len += retval;
        bool full = len == (sizeof(buffer) - 1);
        char *ep = buffer + len;
        *ep = '\0';
        size_t sublen;
        for(char *ptr = NULL, *tok = buffer;
                ((tok = log_strntok_r(tok, &len, &ptr, &sublen)));
                tok = NULL) {
            if (((tok + sublen) >= ep) && (retval != 0) && full) {
                memmove(buffer, tok, sublen);
                len = sublen;
                break;
            }
            if (*tok) {
                log(tok, sublen);
            }
        }
    }

    return true;
}


void LogKlog::calculateCorrection(const log_time &monotonic,
                                  const char *real_string,
                                  size_t len) {
    log_time real;
    const char *ep = real.strptime(real_string, "%Y-%m-%d %H:%M:%S.%09q UTC");
    if (!ep || (ep > &real_string[len])) {
        return;
    }
    // kernel report UTC, log_time::strptime is localtime from calendar.
    // Bionic and liblog strptime does not support %z or %Z to pick up
    // timezone so we are calculating our own correction.
    time_t now = real.tv_sec;
    struct tm tm;
    memset(&tm, 0, sizeof(tm));
    tm.tm_isdst = -1;
    localtime_r(&now, &tm);
    real.tv_sec += tm.tm_gmtoff;
    correction = real - monotonic;
}

static const char suspendStr[] = "PM: suspend entry ";
static const char resumeStr[] = "PM: suspend exit ";
static const char suspendedStr[] = "Suspended for ";

static const char *strnstr(const char *s, size_t len, const char *needle) {
    char c;

    if (!len) {
        return NULL;
    }
    if ((c = *needle++) != 0) {
        size_t needleLen = strlen(needle);
        do {
            do {
                if (len <= needleLen) {
                    return NULL;
                }
                --len;
            } while (*s++ != c);
        } while (fast<memcmp>(s, needle, needleLen));
        s--;
    }
    return s;
}

void LogKlog::sniffTime(log_time &now,
                        const char **buf, size_t len,
                        bool reverse) {
    const char *cp = now.strptime(*buf, "[ %s.%q]");
    if (cp && (cp >= &(*buf)[len])) {
        cp = NULL;
    }
    len -= cp - *buf;
    if (cp) {
        static const char healthd[] = "healthd";
        static const char battery[] = ": battery ";

        if (len && isspace(*cp)) {
            ++cp;
            --len;
        }
        *buf = cp;

        const char *b;
        if (((b = strnstr(cp, len, suspendStr)))
                && ((size_t)((b += sizeof(suspendStr) - 1) - cp) < len)) {
            len -= b - cp;
            calculateCorrection(now, b, len);
        } else if (((b = strnstr(cp, len, resumeStr)))
                && ((size_t)((b += sizeof(resumeStr) - 1) - cp) < len)) {
            len -= b - cp;
            calculateCorrection(now, b, len);
        } else if (((b = strnstr(cp, len, healthd)))
                && ((size_t)((b += sizeof(healthd) - 1) - cp) < len)
                && ((b = strnstr(b, len -= b - cp, battery)))
                && ((size_t)((b += sizeof(battery) - 1) - cp) < len)) {
            len -= b - cp;
            // NB: healthd is roughly 150us late, worth the price to deal with
            //     ntp-induced or hardware clock drift.
            // look for " 2???-??-?? ??:??:??.????????? ???"
            for (; len && *b && (*b != '\n'); ++b, --len) {
                if ((b[0] == ' ') && (b[1] == '2') && (b[5] == '-')) {
                    calculateCorrection(now, b + 1, len - 1);
                    break;
                }
            }
        } else if (((b = strnstr(cp, len, suspendedStr)))
                && ((size_t)((b += sizeof(suspendStr) - 1) - cp) < len)) {
            len -= b - cp;
            log_time real;
            char *endp;
            real.tv_sec = strtol(b, &endp, 10);
            if ((*endp == '.') && ((size_t)(endp - b) < len)) {
                unsigned long multiplier = NS_PER_SEC;
                real.tv_nsec = 0;
                len -= endp - b;
                while (--len && isdigit(*++endp) && (multiplier /= 10)) {
                    real.tv_nsec += (*endp - '0') * multiplier;
                }
                if (reverse) {
                    correction -= real;
                } else {
                    correction += real;
                }
            }
        }

        convertMonotonicToReal(now);
    } else {
        now = log_time(CLOCK_REALTIME);
    }
}

pid_t LogKlog::sniffPid(const char *cp, size_t len) {
    while (len) {
        // Mediatek kernels with modified printk
        if (*cp == '[') {
            int pid = 0;
            char dummy;
            if (sscanf(cp, "[%d:%*[a-z_./0-9:A-Z]]%c", &pid, &dummy) == 2) {
                return pid;
            }
            break; // Only the first one
        }
        ++cp;
        --len;
    }
    return 0;
}

// kernel log prefix, convert to a kernel log priority number
static int parseKernelPrio(const char **buf, size_t len) {
    int pri = LOG_USER | LOG_INFO;
    const char *cp = *buf;
    if (len && (*cp == '<')) {
        pri = 0;
        while(--len && isdigit(*++cp)) {
            pri = (pri * 10) + *cp - '0';
        }
        if (len && (*cp == '>')) {
            ++cp;
        } else {
            cp = *buf;
            pri = LOG_USER | LOG_INFO;
        }
        *buf = cp;
    }
    return pri;
}

// Passed the entire SYSLOG_ACTION_READ_ALL buffer and interpret a
// compensated start time.
void LogKlog::synchronize(const char *buf, size_t len) {
    const char *cp = strnstr(buf, len, suspendStr);
    if (!cp) {
        cp = strnstr(buf, len, resumeStr);
        if (!cp) {
            return;
        }
    } else {
        const char *rp = strnstr(buf, len, resumeStr);
        if (rp && (rp < cp)) {
            cp = rp;
        }
    }

    do {
        --cp;
    } while ((cp > buf) && (*cp != '\n'));
    if (*cp == '\n') {
        ++cp;
    }
    parseKernelPrio(&cp, len - (cp - buf));

    log_time now;
    sniffTime(now, &cp, len - (cp - buf), true);

    const char *suspended = strnstr(buf, len, suspendedStr);
    if (!suspended || (suspended > cp)) {
        return;
    }
    cp = suspended;

    do {
        --cp;
    } while ((cp > buf) && (*cp != '\n'));
    if (*cp == '\n') {
        ++cp;
    }
    parseKernelPrio(&cp, len - (cp - buf));

    sniffTime(now, &cp, len - (cp - buf), true);
}

// Convert kernel log priority number into an Android Logger priority number
static int convertKernelPrioToAndroidPrio(int pri) {
    switch(pri & LOG_PRIMASK) {
    case LOG_EMERG:
        // FALLTHRU
    case LOG_ALERT:
        // FALLTHRU
    case LOG_CRIT:
        return ANDROID_LOG_FATAL;

    case LOG_ERR:
        return ANDROID_LOG_ERROR;

    case LOG_WARNING:
        return ANDROID_LOG_WARN;

    default:
        // FALLTHRU
    case LOG_NOTICE:
        // FALLTHRU
    case LOG_INFO:
        break;

    case LOG_DEBUG:
        return ANDROID_LOG_DEBUG;
    }

    return ANDROID_LOG_INFO;
}

static const char *strnrchr(const char *s, size_t len, char c) {
  const char *save = NULL;
  for (;len; ++s, len--) {
    if (*s == c) {
      save = s;
    }
  }
  return save;
}

//
// log a message into the kernel log buffer
//
// Filter rules to parse <PRI> <TIME> <tag> and <message> in order for
// them to appear correct in the logcat output:
//
// LOG_KERN (0):
// <PRI>[<TIME>] <tag> ":" <message>
// <PRI>[<TIME>] <tag> <tag> ":" <message>
// <PRI>[<TIME>] <tag> <tag>_work ":" <message>
// <PRI>[<TIME>] <tag> '<tag>.<num>' ":" <message>
// <PRI>[<TIME>] <tag> '<tag><num>' ":" <message>
// <PRI>[<TIME>] <tag>_host '<tag>.<num>' ":" <message>
// (unimplemented) <PRI>[<TIME>] <tag> '<num>.<tag>' ":" <message>
// <PRI>[<TIME>] "[INFO]"<tag> : <message>
// <PRI>[<TIME>] "------------[ cut here ]------------"   (?)
// <PRI>[<TIME>] "---[ end trace 3225a3070ca3e4ac ]---"   (?)
// LOG_USER, LOG_MAIL, LOG_DAEMON, LOG_AUTH, LOG_SYSLOG, LOG_LPR, LOG_NEWS
// LOG_UUCP, LOG_CRON, LOG_AUTHPRIV, LOG_FTP:
// <PRI+TAG>[<TIME>] (see sys/syslog.h)
// Observe:
//  Minimum tag length = 3   NB: drops things like r5:c00bbadf, but allow PM:
//  Maximum tag words = 2
//  Maximum tag length = 16  NB: we are thinking of how ugly logcat can get.
//  Not a Tag if there is no message content.
//  leading additional spaces means no tag, inherit last tag.
//  Not a Tag if <tag>: is "ERROR:", "WARNING:", "INFO:" or "CPU:"
// Drop:
//  empty messages
//  messages with ' audit(' in them if auditd is running
//  logd.klogd:
// return -1 if message logd.klogd: <signature>
//
int LogKlog::log(const char *buf, size_t len) {
    if (auditd && strnstr(buf, len, " audit(")) {
        return 0;
    }

    const char *p = buf;
    int pri = parseKernelPrio(&p, len);

    log_time now;
    sniffTime(now, &p, len - (p - buf), false);

    // sniff for start marker
    const char klogd_message[] = "logd.klogd: ";
    const char *start = strnstr(p, len - (p - buf), klogd_message);
    if (start) {
        uint64_t sig = strtoll(start + sizeof(klogd_message) - 1, NULL, 10);
        if (sig == signature.nsec()) {
            if (initialized) {
                enableLogging = true;
            } else {
                enableLogging = false;
            }
            return -1;
        }
        return 0;
    }

    if (!enableLogging) {
        return 0;
    }

    // Parse pid, tid and uid
    const pid_t pid = sniffPid(p, len - (p - buf));
    const pid_t tid = pid;
    const uid_t uid = pid ? logbuf->pidToUid(pid) : 0;

    // Parse (rules at top) to pull out a tag from the incoming kernel message.
    // Some may view the following as an ugly heuristic, the desire is to
    // beautify the kernel logs into an Android Logging format; the goal is
    // admirable but costly.
    while ((isspace(*p) || !*p) && (p < &buf[len])) {
        ++p;
    }
    if (p >= &buf[len]) { // timestamp, no content
        return 0;
    }
    start = p;
    const char *tag = "";
    const char *etag = tag;
    size_t taglen = len - (p - buf);
    if (!isspace(*p) && *p) {
        const char *bt, *et, *cp;

        bt = p;
        if (!fast<strncmp>(p, "[INFO]", 6)) {
            // <PRI>[<TIME>] "[INFO]"<tag> ":" message
            bt = p + 6;
            taglen -= 6;
        }
        for(et = bt; taglen && *et && (*et != ':') && !isspace(*et); ++et, --taglen) {
           // skip ':' within [ ... ]
           if (*et == '[') {
               while (taglen && *et && *et != ']') {
                   ++et;
                   --taglen;
               }
            }
        }
        for(cp = et; taglen && isspace(*cp); ++cp, --taglen);
        size_t size;

        if (*cp == ':') {
            // One Word
            tag = bt;
            etag = et;
            p = cp + 1;
        } else if (taglen) {
            size = et - bt;
            if ((*bt == *cp) && fast<strncmp>(bt + 1, cp + 1, size - 1)) {
                // <PRI>[<TIME>] <tag>_host '<tag>.<num>' : message
                if (!fast<strncmp>(bt + size - 5, "_host", 5)
                        && !fast<strncmp>(bt + 1, cp + 1, size - 6)) {
                    const char *b = cp;
                    cp += size - 5;
                    taglen -= size - 5;
                    if (*cp == '.') {
                        while (--taglen && !isspace(*++cp) && (*cp != ':'));
                        const char *e;
                        for(e = cp; taglen && isspace(*cp); ++cp, --taglen);
                        if (*cp == ':') {
                            tag = b;
                            etag = e;
                            p = cp + 1;
                        }
                    }
                } else {
                    while (--taglen && !isspace(*++cp) && (*cp != ':'));
                    const char *e;
                    for(e = cp; taglen && isspace(*cp); ++cp, --taglen);
                    // Two words
                    if (*cp == ':') {
                        tag = bt;
                        etag = e;
                        p = cp + 1;
                    }
                }
            } else if (isspace(cp[size])) {
                cp += size;
                taglen -= size;
                while (--taglen && isspace(*++cp));
                // <PRI>[<TIME>] <tag> <tag> : message
                if (*cp == ':') {
                    tag = bt;
                    etag = et;
                    p = cp + 1;
                }
            } else if (cp[size] == ':') {
                // <PRI>[<TIME>] <tag> <tag> : message
                tag = bt;
                etag = et;
                p = cp + size + 1;
            } else if ((cp[size] == '.') || isdigit(cp[size])) {
                // <PRI>[<TIME>] <tag> '<tag>.<num>' : message
                // <PRI>[<TIME>] <tag> '<tag><num>' : message
                const char *b = cp;
                cp += size;
                taglen -= size;
                while (--taglen && !isspace(*++cp) && (*cp != ':'));
                const char *e = cp;
                while (taglen && isspace(*cp)) {
                    ++cp;
                    --taglen;
                }
                if (*cp == ':') {
                    tag = b;
                    etag = e;
                    p = cp + 1;
                }
            } else {
                while (--taglen && !isspace(*++cp) && (*cp != ':'));
                const char *e = cp;
                while (taglen && isspace(*cp)) {
                    ++cp;
                    --taglen;
                }
                // Two words
                if (*cp == ':') {
                    tag = bt;
                    etag = e;
                    p = cp + 1;
                }
            }
        }
        size = etag - tag;
        if ((size <= 1)
            // register names like x9
                || ((size == 2) && (isdigit(tag[0]) || isdigit(tag[1])))
            // register names like x18 but not driver names like en0
                || ((size == 3) && (isdigit(tag[1]) && isdigit(tag[2])))
            // blacklist
                || ((size == 3) && !fast<strncmp>(tag, "CPU", 3))
                || ((size == 7) && !fast<strncasecmp>(tag, "WARNING", 7))
                || ((size == 5) && !fast<strncasecmp>(tag, "ERROR", 5))
                || ((size == 4) && !fast<strncasecmp>(tag, "INFO", 4))) {
            p = start;
            etag = tag = "";
        }
    }
    // Suppress additional stutter in tag:
    //   eg: [143:healthd]healthd -> [143:healthd]
    taglen = etag - tag;
    // Mediatek-special printk induced stutter
    const char *mp = strnrchr(tag, ']', taglen);
    if (mp && (++mp < etag)) {
        size_t s = etag - mp;
        if (((s + s) < taglen) && !fast<memcmp>(mp, mp - 1 - s, s)) {
            taglen = mp - tag;
        }
    }
    // skip leading space
    while ((isspace(*p) || !*p) && (p < &buf[len])) {
        ++p;
    }
    // truncate trailing space or nuls
    size_t b = len - (p - buf);
    while (b && (isspace(p[b-1]) || !p[b-1])) {
        --b;
    }
    // trick ... allow tag with empty content to be logged. log() drops empty
    if (!b && taglen) {
        p = " ";
        b = 1;
    }
    if (b > LOGGER_ENTRY_MAX_PAYLOAD) {
        b = LOGGER_ENTRY_MAX_PAYLOAD;
    }
    size_t n = 1 + taglen + 1 + b + 1;
    int rc = n;
    if ((taglen > n) || (b > n)) { // Can not happen ...
        rc = -EINVAL;
        return rc;
    }

    char newstr[n];
    char *np = newstr;

    // Convert priority into single-byte Android logger priority
    *np = convertKernelPrioToAndroidPrio(pri);
    ++np;

    // Copy parsed tag following priority
    memcpy(np, tag, taglen);
    np += taglen;
    *np = '\0';
    ++np;

    // Copy main message to the remainder
    memcpy(np, p, b);
    np[b] = '\0';

    // Log message
    rc = logbuf->log(LOG_ID_KERNEL, now, uid, pid, tid, newstr,
                     (n <= USHRT_MAX) ? (unsigned short) n : USHRT_MAX);

    // notify readers
    if (!rc) {
        reader->notifyNewLog();
    }

    return rc;
}
