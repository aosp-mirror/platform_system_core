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

#define LOG_TAG "ScanResult"
#include <cutils/log.h>

#include "ScanResult.h"

ScanResult::ScanResult() {
}

ScanResult::ScanResult(char *rawResult) {
    char *tok, *next = NULL;

    if (!(tok = strtok_r(rawResult, "\t", &next)))
        goto out_bad;
    mBssid = strdup(tok);

    if (!(tok = strtok_r(NULL, "\t", &next)))
        goto out_bad;
    mFreq = atoi(tok);

    if (!(tok = strtok_r(NULL, "\t", &next)))
        goto out_bad;
    mLevel = atoi(tok);

    if (!(tok = strtok_r(rawResult, "\t", &next)))
        goto out_bad;
    mFlags = strdup(tok);

    if (!(tok = strtok_r(rawResult, "\t", &next)))
        goto out_bad;
    mSsid = strdup(tok);

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
