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

#include <base/stringprintf.h>

#include "LogWhiteBlackList.h"

// White and Black list

Prune::Prune(uid_t uid, pid_t pid) : mUid(uid), mPid(pid) {
}

int Prune::cmp(uid_t uid, pid_t pid) const {
    if ((mUid == uid_all) || (mUid == uid)) {
        if (mPid == pid_all) {
            return 0;
        }
        return pid - mPid;
    }
    return uid - mUid;
}

std::string Prune::format() {
    if (mUid != uid_all) {
        if (mPid != pid_all) {
            return android::base::StringPrintf("%u/%u", mUid, mPid);
        }
        return android::base::StringPrintf("%u", mUid);
    }
    if (mPid != pid_all) {
        return android::base::StringPrintf("/%u", mPid);
    }
    // NB: mPid == pid_all can not happen if mUid == uid_all
    return std::string("/");
}

PruneList::PruneList() : mWorstUidEnabled(true) {
}

PruneList::~PruneList() {
    PruneCollection::iterator it;
    for (it = mNice.begin(); it != mNice.end();) {
        it = mNice.erase(it);
    }
    for (it = mNaughty.begin(); it != mNaughty.end();) {
        it = mNaughty.erase(it);
    }
}

int PruneList::init(const char *str) {
    mWorstUidEnabled = true;
    PruneCollection::iterator it;
    for (it = mNice.begin(); it != mNice.end();) {
        it = mNice.erase(it);
    }
    for (it = mNaughty.begin(); it != mNaughty.end();) {
        it = mNaughty.erase(it);
    }

    if (!str) {
        return 0;
    }

    mWorstUidEnabled = false;

    for(; *str; ++str) {
        if (isspace(*str)) {
            continue;
        }

        PruneCollection *list;
        if ((*str == '~') || (*str == '!')) { // ~ supported, ! undocumented
            ++str;
            // special case, translates to worst UID at priority in blacklist
            if (*str == '!') {
                mWorstUidEnabled = true;
                ++str;
                if (!*str) {
                    break;
                }
                if (!isspace(*str)) {
                    return 1;
                }
                continue;
            }
            if (!*str) {
                return 1;
            }
            list = &mNaughty;
        } else {
            list = &mNice;
        }

        uid_t uid = Prune::uid_all;
        if (isdigit(*str)) {
            uid = 0;
            do {
                uid = uid * 10 + *str++ - '0';
            } while (isdigit(*str));
        }

        pid_t pid = Prune::pid_all;
        if (*str == '/') {
            ++str;
            if (isdigit(*str)) {
                pid = 0;
                do {
                    pid = pid * 10 + *str++ - '0';
                } while (isdigit(*str));
            }
        }

        if ((uid == Prune::uid_all) && (pid == Prune::pid_all)) {
            return 1;
        }

        if (*str && !isspace(*str)) {
            return 1;
        }

        // insert sequentially into list
        PruneCollection::iterator it = list->begin();
        while (it != list->end()) {
            Prune &p = *it;
            int m = uid - p.mUid;
            if (m == 0) {
                if (p.mPid == p.pid_all) {
                    break;
                }
                if ((pid == p.pid_all) && (p.mPid != p.pid_all)) {
                    it = list->erase(it);
                    continue;
                }
                m = pid - p.mPid;
            }
            if (m <= 0) {
                if (m < 0) {
                    list->insert(it, Prune(uid,pid));
                }
                break;
            }
            ++it;
        }
        if (it == list->end()) {
            list->push_back(Prune(uid,pid));
        }
        if (!*str) {
            break;
        }
    }

    return 0;
}

std::string PruneList::format() {
    static const char nice_format[] = " %s";
    const char *fmt = nice_format + 1;

    std::string string;

    if (mWorstUidEnabled) {
        string = "~!";
        fmt = nice_format;
    }

    PruneCollection::iterator it;

    for (it = mNice.begin(); it != mNice.end(); ++it) {
        string += android::base::StringPrintf(fmt, (*it).format().c_str());
        fmt = nice_format;
    }

    static const char naughty_format[] = " ~%s";
    fmt = naughty_format + (*fmt != ' ');
    for (it = mNaughty.begin(); it != mNaughty.end(); ++it) {
        string += android::base::StringPrintf(fmt, (*it).format().c_str());
        fmt = naughty_format;
    }

    return string;
}

// ToDo: Lists are in sorted order, Prune->cmp() returns + or -
// If there is scaling issues, resort to a better algorithm than linear
// based on these assumptions.

bool PruneList::naughty(LogBufferElement *element) {
    PruneCollection::iterator it;
    for (it = mNaughty.begin(); it != mNaughty.end(); ++it) {
        if (!(*it).cmp(element)) {
            return true;
        }
    }
    return false;
}

bool PruneList::nice(LogBufferElement *element) {
    PruneCollection::iterator it;
    for (it = mNice.begin(); it != mNice.end(); ++it) {
        if (!(*it).cmp(element)) {
            return true;
        }
    }
    return false;
}
