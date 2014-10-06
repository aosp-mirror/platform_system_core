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

#ifndef _LOGD_LOG_STATISTICS_H__
#define _LOGD_LOG_STATISTICS_H__

#include <sys/types.h>

#include <log/log.h>
#include <log/log_read.h>
#include <utils/List.h>

#define log_id_for_each(i) \
    for (log_id_t i = LOG_ID_MIN; i < LOG_ID_MAX; i = (log_id_t) (i + 1))

class PidStatistics {
    const pid_t pid;

    // Total
    size_t mSizesTotal;
    size_t mElementsTotal;
    // Current
    size_t mSizes;
    size_t mElements;

    char *name;
    bool mGone;

public:
    static const pid_t gone = (pid_t) -1;

    PidStatistics(pid_t pid, char *name = NULL);
    PidStatistics(const PidStatistics &copy);
    ~PidStatistics();

    pid_t getPid() const { return pid; }
    bool pidGone();
    char *getName() const { return name; }
    void setName(char *name);

    void add(unsigned short size);
    bool subtract(unsigned short size); // returns true if stats and PID gone
    void addTotal(size_t size, size_t element);

    size_t sizes() const { return mSizes; }
    size_t elements() const { return mElements; }

    size_t sizesTotal() const { return mSizesTotal; }
    size_t elementsTotal() const { return mElementsTotal; }

    // helper
    static char *pidToName(pid_t pid);
};

typedef android::List<PidStatistics *> PidStatisticsCollection;

class UidStatistics {
    const uid_t uid;

    PidStatisticsCollection Pids;

    void insert(PidStatisticsCollection::iterator i, PidStatistics *p)
        { Pids.insert(i, p); }
    void push_back(PidStatistics *p) { Pids.push_back(p); }

    size_t mSizes;
    size_t mElements;

public:
    UidStatistics(uid_t uid);
    ~UidStatistics();

    PidStatisticsCollection::iterator begin() { return Pids.begin(); }
    PidStatisticsCollection::iterator end() { return Pids.end(); }
    PidStatisticsCollection::iterator erase(PidStatisticsCollection::iterator i)
        { return Pids.erase(i); }

    uid_t getUid() { return uid; }

    void add(unsigned short size, pid_t pid);
    void subtract(unsigned short size, pid_t pid);
    void sort();

    static const pid_t pid_all = (pid_t) -1;

    // fast track current value
    size_t sizes() const { return mSizes; };
    size_t elements() const { return mElements; };

    // statistical track
    size_t sizes(pid_t pid);
    size_t elements(pid_t pid);

    size_t sizesTotal(pid_t pid = pid_all);
    size_t elementsTotal(pid_t pid = pid_all);

    // helper
    static char *pidToName(pid_t pid) { return PidStatistics::pidToName(pid); }
};

typedef android::List<UidStatistics *> UidStatisticsCollection;

class LidStatistics {
    UidStatisticsCollection Uids;

public:
    LidStatistics();
    ~LidStatistics();

    UidStatisticsCollection::iterator begin() { return Uids.begin(); }
    UidStatisticsCollection::iterator end() { return Uids.end(); }

    void add(unsigned short size, uid_t uid, pid_t pid);
    void subtract(unsigned short size, uid_t uid, pid_t pid);
    void sort();

    static const pid_t pid_all = (pid_t) -1;
    static const uid_t uid_all = (uid_t) -1;

    size_t sizes(uid_t uid = uid_all, pid_t pid = pid_all);
    size_t elements(uid_t uid = uid_all, pid_t pid = pid_all);

    size_t sizesTotal(uid_t uid = uid_all, pid_t pid = pid_all);
    size_t elementsTotal(uid_t uid = uid_all, pid_t pid = pid_all);
};

// Log Statistics
class LogStatistics {
    LidStatistics LogIds[LOG_ID_MAX];

    size_t mSizes[LOG_ID_MAX];
    size_t mElements[LOG_ID_MAX];

    bool mStatistics;
    bool dgramQlenStatistics;

    static const unsigned short mBuckets[14];
    log_time mMinimum[sizeof(mBuckets) / sizeof(mBuckets[0])];

public:
    const log_time start;

    LogStatistics();

    LidStatistics &id(log_id_t log_id) { return LogIds[log_id]; }

    void enableDgramQlenStatistics() { dgramQlenStatistics = true; }
    void enableStatistics() { mStatistics = true; }
    static unsigned short dgramQlen(unsigned short bucket);
    unsigned long long minimum(unsigned short bucket);
    void recordDiff(log_time diff, unsigned short bucket);

    void add(unsigned short size, log_id_t log_id, uid_t uid, pid_t pid);
    void subtract(unsigned short size, log_id_t log_id, uid_t uid, pid_t pid);
    void sort();

    // fast track current value by id only
    size_t sizes(log_id_t id) const { return mSizes[id]; }
    size_t elements(log_id_t id) const { return mElements[id]; }

    // statistical track
    static const log_id_t log_id_all = (log_id_t) -1;
    static const uid_t uid_all = (uid_t) -1;
    static const pid_t pid_all = (pid_t) -1;

    size_t sizes(log_id_t id, uid_t uid, pid_t pid = pid_all);
    size_t elements(log_id_t id, uid_t uid, pid_t pid = pid_all);
    size_t sizes() { return sizes(log_id_all, uid_all); }
    size_t elements() { return elements(log_id_all, uid_all); }

    size_t sizesTotal(log_id_t id = log_id_all,
                      uid_t uid = uid_all,
                      pid_t pid = pid_all);
    size_t elementsTotal(log_id_t id = log_id_all,
                         uid_t uid = uid_all,
                         pid_t pid = pid_all);

    // *strp = malloc, balance with free
    void format(char **strp, uid_t uid, unsigned int logMask, log_time oldest);

    // helper
    static char *pidToName(pid_t pid) { return PidStatistics::pidToName(pid); }
    uid_t pidToUid(pid_t pid);
};

#endif // _LOGD_LOG_STATISTICS_H__
