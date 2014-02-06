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

#include <stdarg.h>
#include <time.h>

#include <log/logger.h>
#include <private/android_filesystem_config.h>
#include <utils/String8.h>

#include "LogStatistics.h"

PidStatistics::PidStatistics(pid_t pid)
        : pid(pid)
        , mSizesTotal(0)
        , mElementsTotal(0)
        , mSizes(0)
        , mElements(0) { }

void PidStatistics::add(unsigned short size) {
    mSizesTotal += size;
    ++mElementsTotal;
    mSizes += size;
    ++mElements;
}

bool PidStatistics::subtract(unsigned short size) {
    mSizes -= size;
    --mElements;
    return mElements == 0 && kill(pid, 0);
}

void PidStatistics::addTotal(size_t size, size_t element) {
    if (pid == gone) {
        mSizesTotal += size;
        mElementsTotal += element;
    }
}

UidStatistics::UidStatistics(uid_t uid)
        : uid(uid) {
    Pids.clear();
}

UidStatistics::~UidStatistics() {
    PidStatisticsCollection::iterator it;
    for (it = begin(); it != end();) {
        delete (*it);
        it = Pids.erase(it);
    }
}

void UidStatistics::add(unsigned short size, pid_t pid) {
    PidStatistics *p;
    PidStatisticsCollection::iterator last;
    PidStatisticsCollection::iterator it;
    for (last = it = begin(); it != end(); last = it, ++it) {
        p = *it;
        if (pid == p->getPid()) {
            p->add(size);
            // poor-man sort, bubble upwards if bigger than last
            if ((last != it) && ((*last)->sizesTotal() < p->sizesTotal())) {
                Pids.erase(it);
                Pids.insert(last, p);
            }
            return;
        }
    }
    // poor-man sort, insert if bigger than last or last is the gone entry.
    bool insert = (last != it)
        && ((p->getPid() == p->gone)
            || ((*last)->sizesTotal() < (size_t) size));
    p = new PidStatistics(pid);
    if (insert) {
        Pids.insert(last, p);
    } else {
        Pids.push_back(p);
    }
    p->add(size);
}

void UidStatistics::subtract(unsigned short size, pid_t pid) {
    PidStatisticsCollection::iterator it;
    for (it = begin(); it != end(); ++it) {
        PidStatistics *p = *it;
        if (pid == p->getPid()) {
            if (p->subtract(size)) {
                size_t szsTotal = p->sizesTotal();
                size_t elsTotal = p->elementsTotal();
                delete p;
                Pids.erase(it);
                it = end();
                --it;
                if (it == end()) {
                    p = new PidStatistics(p->gone);
                    Pids.push_back(p);
                } else {
                    p = *it;
                    if (p->getPid() != p->gone) {
                        p = new PidStatistics(p->gone);
                        Pids.push_back(p);
                    }
                }
                p->addTotal(szsTotal, elsTotal);
            }
            return;
        }
    }
}

size_t UidStatistics::sizes(pid_t pid) {
    size_t sizes = 0;
    PidStatisticsCollection::iterator it;
    for (it = begin(); it != end(); ++it) {
        PidStatistics *p = *it;
        if ((pid == pid_all) || (pid == p->getPid())) {
            sizes += p->sizes();
        }
    }
    return sizes;
}

size_t UidStatistics::elements(pid_t pid) {
    size_t elements = 0;
    PidStatisticsCollection::iterator it;
    for (it = begin(); it != end(); ++it) {
        PidStatistics *p = *it;
        if ((pid == pid_all) || (pid == p->getPid())) {
            elements += p->elements();
        }
    }
    return elements;
}

size_t UidStatistics::sizesTotal(pid_t pid) {
    size_t sizes = 0;
    PidStatisticsCollection::iterator it;
    for (it = begin(); it != end(); ++it) {
        PidStatistics *p = *it;
        if ((pid == pid_all) || (pid == p->getPid())) {
            sizes += p->sizesTotal();
        }
    }
    return sizes;
}

size_t UidStatistics::elementsTotal(pid_t pid) {
    size_t elements = 0;
    PidStatisticsCollection::iterator it;
    for (it = begin(); it != end(); ++it) {
        PidStatistics *p = *it;
        if ((pid == pid_all) || (pid == p->getPid())) {
            elements += p->elementsTotal();
        }
    }
    return elements;
}

LidStatistics::LidStatistics() {
    Uids.clear();
}

LidStatistics::~LidStatistics() {
    UidStatisticsCollection::iterator it;
    for (it = begin(); it != end();) {
        delete (*it);
        it = Uids.erase(it);
    }
}

void LidStatistics::add(unsigned short size, uid_t uid, pid_t pid) {
    UidStatistics *u;
    UidStatisticsCollection::iterator it;
    UidStatisticsCollection::iterator last;

    if (uid == (uid_t) -1) { // init
        uid = (uid_t) AID_ROOT;
    }

    for (last = it = begin(); it != end(); last = it, ++it) {
        u = *it;
        if (uid == u->getUid()) {
            u->add(size, pid);
            if ((last != it) && ((*last)->sizesTotal() < u->sizesTotal())) {
                Uids.erase(it);
                Uids.insert(last, u);
            }
            return;
        }
    }
    u = new UidStatistics(uid);
    if ((last != it) && ((*last)->sizesTotal() < (size_t) size)) {
        Uids.insert(last, u);
    } else {
        Uids.push_back(u);
    }
    u->add(size, pid);
}

void LidStatistics::subtract(unsigned short size, uid_t uid, pid_t pid) {
    UidStatisticsCollection::iterator it;
    for (it = begin(); it != end(); ++it) {
        UidStatistics *u = *it;
        if (uid == u->getUid()) {
            u->subtract(size, pid);
            return;
        }
    }
}

size_t LidStatistics::sizes(uid_t uid, pid_t pid) {
    size_t sizes = 0;
    UidStatisticsCollection::iterator it;
    for (it = begin(); it != end(); ++it) {
        UidStatistics *u = *it;
        if ((uid == uid_all) || (uid == u->getUid())) {
            sizes += u->sizes(pid);
        }
    }
    return sizes;
}

size_t LidStatistics::elements(uid_t uid, pid_t pid) {
    size_t elements = 0;
    UidStatisticsCollection::iterator it;
    for (it = begin(); it != end(); ++it) {
        UidStatistics *u = *it;
        if ((uid == uid_all) || (uid == u->getUid())) {
            elements += u->elements(pid);
        }
    }
    return elements;
}

size_t LidStatistics::sizesTotal(uid_t uid, pid_t pid) {
    size_t sizes = 0;
    UidStatisticsCollection::iterator it;
    for (it = begin(); it != end(); ++it) {
        UidStatistics *u = *it;
        if ((uid == uid_all) || (uid == u->getUid())) {
            sizes += u->sizesTotal(pid);
        }
    }
    return sizes;
}

size_t LidStatistics::elementsTotal(uid_t uid, pid_t pid) {
    size_t elements = 0;
    UidStatisticsCollection::iterator it;
    for (it = begin(); it != end(); ++it) {
        UidStatistics *u = *it;
        if ((uid == uid_all) || (uid == u->getUid())) {
            elements += u->elementsTotal(pid);
        }
    }
    return elements;
}

LogStatistics::LogStatistics()
        : start(CLOCK_MONOTONIC) {
    log_id_for_each(i) {
        mSizes[i] = 0;
        mElements[i] = 0;
    }
}

void LogStatistics::add(unsigned short size,
                        log_id_t log_id, uid_t uid, pid_t pid) {
    mSizes[log_id] += size;
    ++mElements[log_id];
    id(log_id).add(size, uid, pid);
}

void LogStatistics::subtract(unsigned short size,
                             log_id_t log_id, uid_t uid, pid_t pid) {
    mSizes[log_id] -= size;
    --mElements[log_id];
    id(log_id).subtract(size, uid, pid);
}

size_t LogStatistics::sizes(log_id_t log_id, uid_t uid, pid_t pid) {
    if (log_id != log_id_all) {
        return id(log_id).sizes(uid, pid);
    }
    size_t sizes = 0;
    log_id_for_each(i) {
        sizes += id(i).sizes(uid, pid);
    }
    return sizes;
}

size_t LogStatistics::elements(log_id_t log_id, uid_t uid, pid_t pid) {
    if (log_id != log_id_all) {
        return id(log_id).elements(uid, pid);
    }
    size_t elements = 0;
    log_id_for_each(i) {
        elements += id(i).elements(uid, pid);
    }
    return elements;
}

size_t LogStatistics::sizesTotal(log_id_t log_id, uid_t uid, pid_t pid) {
    if (log_id != log_id_all) {
        return id(log_id).sizesTotal(uid, pid);
    }
    size_t sizes = 0;
    log_id_for_each(i) {
        sizes += id(i).sizesTotal(uid, pid);
    }
    return sizes;
}

size_t LogStatistics::elementsTotal(log_id_t log_id, uid_t uid, pid_t pid) {
    if (log_id != log_id_all) {
        return id(log_id).elementsTotal(uid, pid);
    }
    size_t elements = 0;
    log_id_for_each(i) {
        elements += id(i).elementsTotal(uid, pid);
    }
    return elements;
}

size_t LogStatistics::format(char **buf,
                             uid_t uid, unsigned int logMask, log_time oldest) {
    const unsigned short spaces_current = 13;
    const unsigned short spaces_total = 19;

    if (*buf) {
        free(buf);
        *buf = NULL;
    }

    android::String8 string("        span -> size/num");
    size_t oldLength;
    short spaces = 2;

    log_id_for_each(i) {
        if (logMask & (1 << i)) {
            oldLength = string.length();
            string.appendFormat("%*s%s", spaces, "", android_log_id_to_name(i));
            spaces += spaces_total + oldLength - string.length();
        }
    }

    spaces = 1;
    log_time t(CLOCK_MONOTONIC);
    unsigned long long d = t.nsec() - start.nsec();
    string.appendFormat("\nTotal%4llu:%02llu:%02llu.%09llu",
                  d / NS_PER_SEC / 60 / 60, (d / NS_PER_SEC / 60) % 60,
                  (d / NS_PER_SEC) % 60, d % NS_PER_SEC);

    log_id_for_each(i) {
        if (!(logMask & (1 << i))) {
            continue;
        }
        oldLength = string.length();
        string.appendFormat("%*s%zu/%zu", spaces, "",
                            sizesTotal(i), elementsTotal(i));
        spaces += spaces_total + oldLength - string.length();
    }

    spaces = 1;
    d = t.nsec() - oldest.nsec();
    string.appendFormat("\nNow%6llu:%02llu:%02llu.%09llu",
                  d / NS_PER_SEC / 60 / 60, (d / NS_PER_SEC / 60) % 60,
                  (d / NS_PER_SEC) % 60, d % NS_PER_SEC);

    log_id_for_each(i) {
        if (!(logMask & (1 << i))) {
            continue;
        }

        size_t els = elements(i);
        if (els) {
            oldLength = string.length();
            string.appendFormat("%*s%zu/%zu", spaces, "", sizes(i), els);
            spaces -= string.length() - oldLength;
        }
        spaces += spaces_total;
    }

    log_id_for_each(i) {
        if (!(logMask & (1 << i))) {
            continue;
        }

        bool header = false;
        bool first = true;

        UidStatisticsCollection::iterator ut;
        for(ut = id(i).begin(); ut != id(i).end(); ++ut) {
            UidStatistics *up = *ut;
            if ((uid != AID_ROOT) && (uid != up->getUid())) {
                continue;
            }

            PidStatisticsCollection::iterator pt = up->begin();
            if (pt == up->end()) {
                continue;
            }

            android::String8 intermediate;

            if (!header) {
                // header below tuned to match spaces_total and spaces_current
                spaces = 0;
                intermediate = string.format("%s: UID/PID Total size/num",
                                             android_log_id_to_name(i));
                string.appendFormat("\n\n%-31sNow          "
                                         "UID/PID[?]  Total              Now",
                                    intermediate.string());
                intermediate.clear();
                header = true;
            }

            bool oneline = ++pt == up->end();
            --pt;

            if (!oneline) {
                first = true;
            } else if (!first && spaces) {
                string.appendFormat("%*s", spaces, "");
            }
            spaces = 0;

            uid_t u = up->getUid();
            pid_t p = (*pt)->getPid();

            intermediate = string.format(oneline
                                             ? ((p == PidStatistics::gone)
                                                 ? "%d/?"
                                                 : "%d/%d")
                                             : "%d",
                                         u, p);
            string.appendFormat((first) ? "\n%-12s" : "%-12s",
                                intermediate.string());
            intermediate.clear();

            size_t elsTotal = up->elementsTotal();
            oldLength = string.length();
            string.appendFormat("%zu/%zu", up->sizesTotal(), elsTotal);
            spaces += spaces_total + oldLength - string.length();

            size_t els = up->elements();
            if (els == elsTotal) {
                string.appendFormat("%*s=", spaces, "");
                spaces = -1;
            } else if (els) {
                oldLength = string.length();
                string.appendFormat("%*s%zu/%zu", spaces, "", up->sizes(), els);
                spaces -= string.length() - oldLength;
            }
            spaces += spaces_current;

            first = !first;

            if (oneline) {
                continue;
            }

            size_t gone_szs = 0;
            size_t gone_els = 0;

            for(; pt != up->end(); ++pt) {
                PidStatistics *pp = *pt;
                pid_t p = pp->getPid();

                // If a PID no longer has any current logs, and is not
                // active anymore, skip & report totals for gone.
                elsTotal = pp->elementsTotal();
                size_t szsTotal = pp->sizesTotal();
                if (p == pp->gone) {
                    gone_szs += szsTotal;
                    gone_els += elsTotal;
                    continue;
                }
                els = pp->elements();
                bool gone = kill(p, 0);
                if (gone && (els == 0)) {
                    // ToDo: garbage collection: move this statistical bucket
                    //       from its current UID/PID to UID/? (races and
                    //       wrap around are our achilles heel). Below is
                    //       merely lipservice to catch PIDs that were still
                    //       around when the stats were pruned to zero.
                    gone_szs += szsTotal;
                    gone_els += elsTotal;
                    continue;
                }

                if (!first && spaces) {
                    string.appendFormat("%*s", spaces, "");
                }
                spaces = 0;

                intermediate = string.format((gone) ? "%d/%d?" : "%d/%d", u, p);
                string.appendFormat((first) ? "\n%-12s" : "%-12s",
                                    intermediate.string());
                intermediate.clear();

                oldLength = string.length();
                string.appendFormat("%zu/%zu", szsTotal, elsTotal);
                spaces += spaces_total + oldLength - string.length();

                if (els == elsTotal) {
                    string.appendFormat("%*s=", spaces, "");
                    spaces = -1;
                } else if (els) {
                    oldLength = string.length();
                    string.appendFormat("%*s%zu/%zu", spaces, "",
                                        pp->sizes(), els);
                    spaces -= string.length() - oldLength;
                }
                spaces += spaces_current;

                first = !first;
            }

            if (gone_els) {
                if (!first && spaces) {
                    string.appendFormat("%*s", spaces, "");
                }

                intermediate = string.format("%d/?", u);
                string.appendFormat((first) ? "\n%-12s" : "%-12s",
                                    intermediate.string());
                intermediate.clear();

                spaces = spaces_total + spaces_current;

                oldLength = string.length();
                string.appendFormat("%zu/%zu", gone_szs, gone_els);
                spaces -= string.length() - oldLength;

                first = !first;
            }
        }
    }

    // Calculate total buffer size prefix
    char re_fmt[32];
    size_t ret;
    for(size_t l = string.length(), y = 0, x = 6;
           y != x;
           y = x, x = strlen(re_fmt) - 2) {
       snprintf(re_fmt, sizeof(re_fmt), "%zu\n%%s\n\f", l + x);
       ret = l + x;
    }

    android::String8 intermediate = string.format(re_fmt, string.string());
    string.clear();

    *buf = strdup(intermediate.string());

    return ret;
}
