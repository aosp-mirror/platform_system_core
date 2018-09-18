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
#include <string.h>
#include <sys/prctl.h>
#include <sys/uio.h>
#include <syslog.h>

#include <private/android_filesystem_config.h>
#include <private/android_logger.h>

#include "LogBuffer.h"
#include "LogKlog.h"
#include "LogReader.h"

#define KMSG_PRIORITY(PRI) \
    '<', '0' + (LOG_SYSLOG | (PRI)) / 10, '0' + (LOG_SYSLOG | (PRI)) % 10, '>'

static const char priority_message[] = { KMSG_PRIORITY(LOG_INFO), '\0' };

// List of the _only_ needles we supply here to android::strnstr
static const char suspendStr[] = "PM: suspend entry ";
static const char resumeStr[] = "PM: suspend exit ";
static const char suspendedStr[] = "Suspended for ";
static const char healthdStr[] = "healthd";
static const char batteryStr[] = ": battery ";
static const char auditStr[] = " audit(";
static const char klogdStr[] = "logd.klogd: ";

// Parsing is hard

// called if we see a '<', s is the next character, returns pointer after '>'
static char* is_prio(char* s, ssize_t len) {
    if ((len <= 0) || !isdigit(*s++)) return nullptr;
    --len;
    static const size_t max_prio_len = (len < 4) ? len : 4;
    size_t priolen = 0;
    char c;
    while (((c = *s++)) && (++priolen <= max_prio_len)) {
        if (!isdigit(c)) return ((c == '>') && (*s == '[')) ? s : nullptr;
    }
    return nullptr;
}

// called if we see a '[', s is the next character, returns pointer after ']'
static char* is_timestamp(char* s, ssize_t len) {
    while ((len > 0) && (*s == ' ')) {
        ++s;
        --len;
    }
    if ((len <= 0) || !isdigit(*s++)) return nullptr;
    --len;
    bool first_period = true;
    char c;
    while ((len > 0) && ((c = *s++))) {
        --len;
        if ((c == '.') && first_period) {
            first_period = false;
        } else if (!isdigit(c)) {
            return ((c == ']') && !first_period && (*s == ' ')) ? s : nullptr;
        }
    }
    return nullptr;
}

// Like strtok_r with "\r\n" except that we look for log signatures (regex)
//  \(\(<[0-9]\{1,4\}>\)\([[] *[0-9]+[.][0-9]+[]] \)\{0,1\}\|[[]
//  *[0-9]+[.][0-9]+[]] \)
// and split if we see a second one without a newline.
// We allow nuls in content, monitoring the overall length and sub-length of
// the discovered tokens.

#define SIGNATURE_MASK 0xF0
// <digit> following ('0' to '9' masked with ~SIGNATURE_MASK) added to signature
#define LESS_THAN_SIG SIGNATURE_MASK
#define OPEN_BRACKET_SIG ((SIGNATURE_MASK << 1) & SIGNATURE_MASK)
// space is one more than <digit> of 9
#define OPEN_BRACKET_SPACE ((char)(OPEN_BRACKET_SIG | 10))

char* android::log_strntok_r(char* s, ssize_t& len, char*& last,
                             ssize_t& sublen) {
    sublen = 0;
    if (len <= 0) return nullptr;
    if (!s) {
        if (!(s = last)) return nullptr;
        // fixup for log signature split <,
        // LESS_THAN_SIG + <digit>
        if ((*s & SIGNATURE_MASK) == LESS_THAN_SIG) {
            *s = (*s & ~SIGNATURE_MASK) + '0';
            *--s = '<';
            ++len;
        }
        // fixup for log signature split [,
        // OPEN_BRACKET_SPACE is space, OPEN_BRACKET_SIG + <digit>
        if ((*s & SIGNATURE_MASK) == OPEN_BRACKET_SIG) {
            *s = (*s == OPEN_BRACKET_SPACE) ? ' ' : (*s & ~SIGNATURE_MASK) + '0';
            *--s = '[';
            ++len;
        }
    }

    while ((len > 0) && ((*s == '\r') || (*s == '\n'))) {
        ++s;
        --len;
    }

    if (len <= 0) return last = nullptr;
    char *peek, *tok = s;

    for (;;) {
        if (len <= 0) {
            last = nullptr;
            return tok;
        }
        char c = *s++;
        --len;
        ssize_t adjust;
        switch (c) {
            case '\r':
            case '\n':
                s[-1] = '\0';
                last = s;
                return tok;

            case '<':
                peek = is_prio(s, len);
                if (!peek) break;
                if (s != (tok + 1)) {  // not first?
                    s[-1] = '\0';
                    *s &= ~SIGNATURE_MASK;
                    *s |= LESS_THAN_SIG;  // signature for '<'
                    last = s;
                    return tok;
                }
                adjust = peek - s;
                if (adjust > len) {
                    adjust = len;
                }
                sublen += adjust;
                len -= adjust;
                s = peek;
                if ((*s == '[') && ((peek = is_timestamp(s + 1, len - 1)))) {
                    adjust = peek - s;
                    if (adjust > len) {
                        adjust = len;
                    }
                    sublen += adjust;
                    len -= adjust;
                    s = peek;
                }
                break;

            case '[':
                peek = is_timestamp(s, len);
                if (!peek) break;
                if (s != (tok + 1)) {  // not first?
                    s[-1] = '\0';
                    if (*s == ' ') {
                        *s = OPEN_BRACKET_SPACE;
                    } else {
                        *s &= ~SIGNATURE_MASK;
                        *s |= OPEN_BRACKET_SIG;  // signature for '['
                    }
                    last = s;
                    return tok;
                }
                adjust = peek - s;
                if (adjust > len) {
                    adjust = len;
                }
                sublen += adjust;
                len -= adjust;
                s = peek;
                break;
        }
        ++sublen;
    }
    // NOTREACHED
}

log_time LogKlog::correction =
    (log_time(CLOCK_REALTIME) < log_time(CLOCK_MONOTONIC))
        ? log_time::EPOCH
        : (log_time(CLOCK_REALTIME) - log_time(CLOCK_MONOTONIC));

LogKlog::LogKlog(LogBuffer* buf, LogReader* reader, int fdWrite, int fdRead,
                 bool auditd)
    : SocketListener(fdRead, false),
      logbuf(buf),
      reader(reader),
      signature(CLOCK_MONOTONIC),
      initialized(false),
      enableLogging(true),
      auditd(auditd) {
    static const char klogd_message[] = "%s%s%" PRIu64 "\n";
    char buffer[strlen(priority_message) + strlen(klogdStr) +
                strlen(klogd_message) + 20];
    snprintf(buffer, sizeof(buffer), klogd_message, priority_message, klogdStr,
             signature.nsec());
    write(fdWrite, buffer, strlen(buffer));
}

bool LogKlog::onDataAvailable(SocketClient* cli) {
    if (!initialized) {
        prctl(PR_SET_NAME, "logd.klogd");
        initialized = true;
        enableLogging = false;
    }

    char buffer[LOGGER_ENTRY_MAX_PAYLOAD];
    ssize_t len = 0;

    for (;;) {
        ssize_t retval = 0;
        if (len < (ssize_t)(sizeof(buffer) - 1)) {
            retval =
                read(cli->getSocket(), buffer + len, sizeof(buffer) - 1 - len);
        }
        if ((retval == 0) && (len <= 0)) {
            break;
        }
        if (retval < 0) {
            return false;
        }
        len += retval;
        bool full = len == (sizeof(buffer) - 1);
        char* ep = buffer + len;
        *ep = '\0';
        ssize_t sublen;
        for (char *ptr = nullptr, *tok = buffer;
             !!(tok = android::log_strntok_r(tok, len, ptr, sublen));
             tok = nullptr) {
            if (((tok + sublen) >= ep) && (retval != 0) && full) {
                if (sublen > 0) memmove(buffer, tok, sublen);
                len = sublen;
                break;
            }
            if ((sublen > 0) && *tok) {
                log(tok, sublen);
            }
        }
    }

    return true;
}

void LogKlog::calculateCorrection(const log_time& monotonic,
                                  const char* real_string, ssize_t len) {
    static const char real_format[] = "%Y-%m-%d %H:%M:%S.%09q UTC";
    if (len < (ssize_t)(strlen(real_format) + 5)) return;

    log_time real;
    const char* ep = real.strptime(real_string, real_format);
    if (!ep || (ep > &real_string[len]) || (real > log_time(CLOCK_REALTIME))) {
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
    if ((tm.tm_gmtoff < 0) && ((-tm.tm_gmtoff) > (long)real.tv_sec)) {
        real = log_time::EPOCH;
    } else {
        real.tv_sec += tm.tm_gmtoff;
    }
    if (monotonic > real) {
        correction = log_time::EPOCH;
    } else {
        correction = real - monotonic;
    }
}

void LogKlog::sniffTime(log_time& now, const char*& buf, ssize_t len,
                        bool reverse) {
    if (len <= 0) return;

    const char* cp = nullptr;
    if ((len > 10) && (*buf == '[')) {
        cp = now.strptime(buf, "[ %s.%q]");  // can index beyond buffer bounds
        if (cp && (cp > &buf[len - 1])) cp = nullptr;
    }
    if (cp) {
        len -= cp - buf;
        if ((len > 0) && isspace(*cp)) {
            ++cp;
            --len;
        }
        buf = cp;

        if (isMonotonic()) return;

        const char* b;
        if (((b = android::strnstr(cp, len, suspendStr))) &&
            (((b += strlen(suspendStr)) - cp) < len)) {
            len -= b - cp;
            calculateCorrection(now, b, len);
        } else if (((b = android::strnstr(cp, len, resumeStr))) &&
                   (((b += strlen(resumeStr)) - cp) < len)) {
            len -= b - cp;
            calculateCorrection(now, b, len);
        } else if (((b = android::strnstr(cp, len, healthdStr))) &&
                   (((b += strlen(healthdStr)) - cp) < len) &&
                   ((b = android::strnstr(b, len -= b - cp, batteryStr))) &&
                   (((b += strlen(batteryStr)) - cp) < len)) {
            // NB: healthd is roughly 150us late, so we use it instead to
            //     trigger a check for ntp-induced or hardware clock drift.
            log_time real(CLOCK_REALTIME);
            log_time mono(CLOCK_MONOTONIC);
            correction = (real < mono) ? log_time::EPOCH : (real - mono);
        } else if (((b = android::strnstr(cp, len, suspendedStr))) &&
                   (((b += strlen(suspendStr)) - cp) < len)) {
            len -= b - cp;
            log_time real;
            char* endp;
            real.tv_sec = strtol(b, &endp, 10);
            if ((*endp == '.') && ((endp - b) < len)) {
                unsigned long multiplier = NS_PER_SEC;
                real.tv_nsec = 0;
                len -= endp - b;
                while (--len && isdigit(*++endp) && (multiplier /= 10)) {
                    real.tv_nsec += (*endp - '0') * multiplier;
                }
                if (reverse) {
                    if (real > correction) {
                        correction = log_time::EPOCH;
                    } else {
                        correction -= real;
                    }
                } else {
                    correction += real;
                }
            }
        }

        convertMonotonicToReal(now);
    } else {
        if (isMonotonic()) {
            now = log_time(CLOCK_MONOTONIC);
        } else {
            now = log_time(CLOCK_REALTIME);
        }
    }
}

pid_t LogKlog::sniffPid(const char*& buf, ssize_t len) {
    if (len <= 0) return 0;

    const char* cp = buf;
    // sscanf does a strlen, let's check if the string is not nul terminated.
    // pseudo out-of-bounds access since we always have an extra char on buffer.
    if (((ssize_t)strnlen(cp, len) == len) && cp[len]) {
        return 0;
    }
    // HTC kernels with modified printk "c0   1648 "
    if ((len > 9) && (cp[0] == 'c') && isdigit(cp[1]) &&
        (isdigit(cp[2]) || (cp[2] == ' ')) && (cp[3] == ' ')) {
        bool gotDigit = false;
        int i;
        for (i = 4; i < 9; ++i) {
            if (isdigit(cp[i])) {
                gotDigit = true;
            } else if (gotDigit || (cp[i] != ' ')) {
                break;
            }
        }
        if ((i == 9) && (cp[i] == ' ')) {
            int pid = 0;
            char dummy;
            if (sscanf(cp + 4, "%d%c", &pid, &dummy) == 2) {
                buf = cp + 10;  // skip-it-all
                return pid;
            }
        }
    }
    while (len) {
        // Mediatek kernels with modified printk
        if (*cp == '[') {
            int pid = 0;
            char dummy;
            if (sscanf(cp, "[%d:%*[a-z_./0-9:A-Z]]%c", &pid, &dummy) == 2) {
                return pid;
            }
            break;  // Only the first one
        }
        ++cp;
        --len;
    }
    return 0;
}

// kernel log prefix, convert to a kernel log priority number
static int parseKernelPrio(const char*& buf, ssize_t len) {
    int pri = LOG_USER | LOG_INFO;
    const char* cp = buf;
    if ((len > 0) && (*cp == '<')) {
        pri = 0;
        while (--len && isdigit(*++cp)) {
            pri = (pri * 10) + *cp - '0';
        }
        if ((len > 0) && (*cp == '>')) {
            ++cp;
        } else {
            cp = buf;
            pri = LOG_USER | LOG_INFO;
        }
        buf = cp;
    }
    return pri;
}

// Passed the entire SYSLOG_ACTION_READ_ALL buffer and interpret a
// compensated start time.
void LogKlog::synchronize(const char* buf, ssize_t len) {
    const char* cp = android::strnstr(buf, len, suspendStr);
    if (!cp) {
        cp = android::strnstr(buf, len, resumeStr);
        if (!cp) return;
    } else {
        const char* rp = android::strnstr(buf, len, resumeStr);
        if (rp && (rp < cp)) cp = rp;
    }

    do {
        --cp;
    } while ((cp > buf) && (*cp != '\n'));
    if (*cp == '\n') {
        ++cp;
    }
    parseKernelPrio(cp, len - (cp - buf));

    log_time now;
    sniffTime(now, cp, len - (cp - buf), true);

    const char* suspended = android::strnstr(buf, len, suspendedStr);
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
    parseKernelPrio(cp, len - (cp - buf));

    sniffTime(now, cp, len - (cp - buf), true);
}

// Convert kernel log priority number into an Android Logger priority number
static int convertKernelPrioToAndroidPrio(int pri) {
    switch (pri & LOG_PRIMASK) {
        case LOG_EMERG:
        case LOG_ALERT:
        case LOG_CRIT:
            return ANDROID_LOG_FATAL;

        case LOG_ERR:
            return ANDROID_LOG_ERROR;

        case LOG_WARNING:
            return ANDROID_LOG_WARN;

        default:
        case LOG_NOTICE:
        case LOG_INFO:
            break;

        case LOG_DEBUG:
            return ANDROID_LOG_DEBUG;
    }

    return ANDROID_LOG_INFO;
}

static const char* strnrchr(const char* s, ssize_t len, char c) {
    const char* save = nullptr;
    for (; len > 0; ++s, len--) {
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
int LogKlog::log(const char* buf, ssize_t len) {
    if (auditd && android::strnstr(buf, len, auditStr)) {
        return 0;
    }

    const char* p = buf;
    int pri = parseKernelPrio(p, len);

    log_time now;
    sniffTime(now, p, len - (p - buf), false);

    // sniff for start marker
    const char* start = android::strnstr(p, len - (p - buf), klogdStr);
    if (start) {
        uint64_t sig = strtoll(start + strlen(klogdStr), nullptr, 10);
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
    uid_t uid = AID_ROOT;
    if (pid) {
        logbuf->wrlock();
        uid = logbuf->pidToUid(pid);
        logbuf->unlock();
    }

    // Parse (rules at top) to pull out a tag from the incoming kernel message.
    // Some may view the following as an ugly heuristic, the desire is to
    // beautify the kernel logs into an Android Logging format; the goal is
    // admirable but costly.
    while ((p < &buf[len]) && (isspace(*p) || !*p)) {
        ++p;
    }
    if (p >= &buf[len]) {  // timestamp, no content
        return 0;
    }
    start = p;
    const char* tag = "";
    const char* etag = tag;
    ssize_t taglen = len - (p - buf);
    const char* bt = p;

    static const char infoBrace[] = "[INFO]";
    static const ssize_t infoBraceLen = strlen(infoBrace);
    if ((taglen >= infoBraceLen) &&
        !fastcmp<strncmp>(p, infoBrace, infoBraceLen)) {
        // <PRI>[<TIME>] "[INFO]"<tag> ":" message
        bt = p + infoBraceLen;
        taglen -= infoBraceLen;
    }

    const char* et;
    for (et = bt; (taglen > 0) && *et && (*et != ':') && !isspace(*et);
         ++et, --taglen) {
        // skip ':' within [ ... ]
        if (*et == '[') {
            while ((taglen > 0) && *et && *et != ']') {
                ++et;
                --taglen;
            }
            if (taglen <= 0) {
                break;
            }
        }
    }
    const char* cp;
    for (cp = et; (taglen > 0) && isspace(*cp); ++cp, --taglen) {
    }

    // Validate tag
    ssize_t size = et - bt;
    if ((taglen > 0) && (size > 0)) {
        if (*cp == ':') {
            // ToDo: handle case insensitive colon separated logging stutter:
            //       <tag> : <tag>: ...

            // One Word
            tag = bt;
            etag = et;
            p = cp + 1;
        } else if ((taglen > size) && (tolower(*bt) == tolower(*cp))) {
            // clean up any tag stutter
            if (!fastcmp<strncasecmp>(bt + 1, cp + 1, size - 1)) {  // no match
                // <PRI>[<TIME>] <tag> <tag> : message
                // <PRI>[<TIME>] <tag> <tag>: message
                // <PRI>[<TIME>] <tag> '<tag>.<num>' : message
                // <PRI>[<TIME>] <tag> '<tag><num>' : message
                // <PRI>[<TIME>] <tag> '<tag><stuff>' : message
                const char* b = cp;
                cp += size;
                taglen -= size;
                while ((--taglen > 0) && !isspace(*++cp) && (*cp != ':')) {
                }
                const char* e;
                for (e = cp; (taglen > 0) && isspace(*cp); ++cp, --taglen) {
                }
                if ((taglen > 0) && (*cp == ':')) {
                    tag = b;
                    etag = e;
                    p = cp + 1;
                }
            } else {
                // what about <PRI>[<TIME>] <tag>_host '<tag><stuff>' : message
                static const char host[] = "_host";
                static const ssize_t hostlen = strlen(host);
                if ((size > hostlen) &&
                    !fastcmp<strncmp>(bt + size - hostlen, host, hostlen) &&
                    !fastcmp<strncmp>(bt + 1, cp + 1, size - hostlen - 1)) {
                    const char* b = cp;
                    cp += size - hostlen;
                    taglen -= size - hostlen;
                    if (*cp == '.') {
                        while ((--taglen > 0) && !isspace(*++cp) &&
                               (*cp != ':')) {
                        }
                        const char* e;
                        for (e = cp; (taglen > 0) && isspace(*cp);
                             ++cp, --taglen) {
                        }
                        if ((taglen > 0) && (*cp == ':')) {
                            tag = b;
                            etag = e;
                            p = cp + 1;
                        }
                    }
                } else {
                    goto twoWord;
                }
            }
        } else {
        // <PRI>[<TIME>] <tag> <stuff>' : message
        twoWord:
            while ((--taglen > 0) && !isspace(*++cp) && (*cp != ':')) {
            }
            const char* e;
            for (e = cp; (taglen > 0) && isspace(*cp); ++cp, --taglen) {
            }
            // Two words
            if ((taglen > 0) && (*cp == ':')) {
                tag = bt;
                etag = e;
                p = cp + 1;
            }
        }
    }  // else no tag

    static const char cpu[] = "CPU";
    static const ssize_t cpuLen = strlen(cpu);
    static const char warning[] = "WARNING";
    static const ssize_t warningLen = strlen(warning);
    static const char error[] = "ERROR";
    static const ssize_t errorLen = strlen(error);
    static const char info[] = "INFO";
    static const ssize_t infoLen = strlen(info);

    size = etag - tag;
    if ((size <= 1) ||
        // register names like x9
        ((size == 2) && (isdigit(tag[0]) || isdigit(tag[1]))) ||
        // register names like x18 but not driver names like en0
        ((size == 3) && (isdigit(tag[1]) && isdigit(tag[2]))) ||
        // blacklist
        ((size == cpuLen) && !fastcmp<strncmp>(tag, cpu, cpuLen)) ||
        ((size == warningLen) &&
         !fastcmp<strncasecmp>(tag, warning, warningLen)) ||
        ((size == errorLen) && !fastcmp<strncasecmp>(tag, error, errorLen)) ||
        ((size == infoLen) && !fastcmp<strncasecmp>(tag, info, infoLen))) {
        p = start;
        etag = tag = "";
    }

    // Suppress additional stutter in tag:
    //   eg: [143:healthd]healthd -> [143:healthd]
    taglen = etag - tag;
    // Mediatek-special printk induced stutter
    const char* mp = strnrchr(tag, taglen, ']');
    if (mp && (++mp < etag)) {
        ssize_t s = etag - mp;
        if (((s + s) < taglen) && !fastcmp<memcmp>(mp, mp - 1 - s, s)) {
            taglen = mp - tag;
        }
    }
    // Deal with sloppy and simplistic harmless p = cp + 1 etc above.
    if (len < (p - buf)) {
        p = &buf[len];
    }
    // skip leading space
    while ((p < &buf[len]) && (isspace(*p) || !*p)) {
        ++p;
    }
    // truncate trailing space or nuls
    ssize_t b = len - (p - buf);
    while ((b > 0) && (isspace(p[b - 1]) || !p[b - 1])) {
        --b;
    }
    // trick ... allow tag with empty content to be logged. log() drops empty
    if ((b <= 0) && (taglen > 0)) {
        p = " ";
        b = 1;
    }
    // paranoid sanity check, can not happen ...
    if (b > LOGGER_ENTRY_MAX_PAYLOAD) {
        b = LOGGER_ENTRY_MAX_PAYLOAD;
    }
    if (taglen > LOGGER_ENTRY_MAX_PAYLOAD) {
        taglen = LOGGER_ENTRY_MAX_PAYLOAD;
    }
    // calculate buffer copy requirements
    ssize_t n = 1 + taglen + 1 + b + 1;
    // paranoid sanity check, first two just can not happen ...
    if ((taglen > n) || (b > n) || (n > (ssize_t)USHRT_MAX) || (n <= 0)) {
        return -EINVAL;
    }

    // Careful.
    // We are using the stack to house the log buffer for speed reasons.
    // If we malloc'd this buffer, we could get away without n's USHRT_MAX
    // test above, but we would then required a max(n, USHRT_MAX) as
    // truncating length argument to logbuf->log() below. Gain is protection
    // of stack sanity and speedup, loss is truncated long-line content.
    char newstr[n];
    char* np = newstr;

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

    if (!isMonotonic()) {
        // Watch out for singular race conditions with timezone causing near
        // integer quarter-hour jumps in the time and compensate accordingly.
        // Entries will be temporal within near_seconds * 2. b/21868540
        static uint32_t vote_time[3];
        vote_time[2] = vote_time[1];
        vote_time[1] = vote_time[0];
        vote_time[0] = now.tv_sec;

        if (vote_time[1] && vote_time[2]) {
            static const unsigned near_seconds = 10;
            static const unsigned timezones_seconds = 900;
            int diff0 = (vote_time[0] - vote_time[1]) / near_seconds;
            unsigned abs0 = (diff0 < 0) ? -diff0 : diff0;
            int diff1 = (vote_time[1] - vote_time[2]) / near_seconds;
            unsigned abs1 = (diff1 < 0) ? -diff1 : diff1;
            if ((abs1 <= 1) &&  // last two were in agreement on timezone
                ((abs0 + 1) % (timezones_seconds / near_seconds)) <= 2) {
                abs0 = (abs0 + 1) / (timezones_seconds / near_seconds) *
                       timezones_seconds;
                now.tv_sec -= (diff0 < 0) ? -abs0 : abs0;
            }
        }
    }

    // Log message
    int rc = logbuf->log(LOG_ID_KERNEL, now, uid, pid, tid, newstr, (uint16_t)n);

    // notify readers
    if (rc > 0) {
        reader->notifyNewLog(static_cast<log_mask_t>(1 << LOG_ID_KERNEL));
    }

    return rc;
}
