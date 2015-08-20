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

#ifndef _LOGD_LOG_WHITE_BLACK_LIST_H__
#define _LOGD_LOG_WHITE_BLACK_LIST_H__

#include <sys/types.h>

#include <list>

#include <LogBufferElement.h>

// White and Blacklist

class Prune {
    friend class PruneList;

    const uid_t mUid;
    const pid_t mPid;
    int cmp(uid_t uid, pid_t pid) const;

public:
    static const uid_t uid_all = (uid_t) -1;
    static const pid_t pid_all = (pid_t) -1;

    Prune(uid_t uid, pid_t pid);

    uid_t getUid() const { return mUid; }
    pid_t getPid() const { return mPid; }

    int cmp(LogBufferElement *e) const { return cmp(e->getUid(), e->getPid()); }

    // *strp is malloc'd, use free to release
    void format(char **strp);
};

typedef std::list<Prune> PruneCollection;

class PruneList {
    PruneCollection mNaughty;
    PruneCollection mNice;
    bool mWorstUidEnabled;

public:
    PruneList();
    ~PruneList();

    int init(char *str);

    bool naughty(LogBufferElement *element);
    bool naughty(void) { return !mNaughty.empty(); }
    bool nice(LogBufferElement *element);
    bool nice(void) { return !mNice.empty(); }
    bool worstUidEnabled() const { return mWorstUidEnabled; }

    // *strp is malloc'd, use free to release
    void format(char **strp);
};

#endif // _LOGD_LOG_WHITE_BLACK_LIST_H__
