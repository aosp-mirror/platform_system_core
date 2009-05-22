/*
 * Copyright (C) 2008 The Android Open Source Project
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

#include <stdlib.h>
#include <ctype.h>

#define LOG_TAG "ScanResult"
#include <cutils/log.h>

#include "ScanResult.h"

ScanResult::ScanResult() {
}

ScanResult::ScanResult(char *rawResult) {
    char *p = rawResult, *q = rawResult;
    char tmp[255];

    // BSSID
    for (q = p; *q != '\t'; ++q);
    strncpy(tmp, p, (q - p));
    tmp[q-p] = '\0';
    mBssid = strdup(tmp);
    ++q;

    // FREQ
    for (p = q; *q != '\t'; ++q);
    strncpy(tmp, p, (q - p));
    tmp[q-p] = '\0';
    mFreq = atoi(tmp);
    ++q;

    // LEVEL
    for (p = q; *q != '\t'; ++q);
    strncpy(tmp, p, (q - p));
    tmp[q-p] = '\0';
    mLevel = atoi(tmp);
    ++q;

    // FLAGS
    for (p = q; *q != '\t'; ++q);
    strncpy(tmp, p, (q - p));
    tmp[q-p] = '\0';
    mFlags = strdup(tmp);
    ++q;

    // XXX: For some reason Supplicant sometimes sends a double-tab here.
    // haven't had time to dig into it ...
    if (*q == '\t')
        q++;

    for (p = q; *q != '\t'; ++q) {
        if (*q == '\0')
            break;
    }

    strncpy(tmp, p, (q - p));
    tmp[q-p] = '\0';
    mSsid = strdup(tmp);
    ++q;

    return;
 out_bad:
    LOGW("Malformatted scan result (%s)", rawResult);
}

ScanResult::~ScanResult() {
    if (mBssid)
        free(mBssid);
    if (mFlags)
        free(mFlags);
    if (mSsid)
        free(mSsid);
}

ScanResult *ScanResult::clone() {
    ScanResult *r = new ScanResult();

    r->mBssid = strdup(mBssid);
    r->mFreq = mFreq;
    r->mLevel = mLevel;
    r->mFlags = strdup(mFlags);
    r->mSsid = strdup(mSsid);

    return r;
}
