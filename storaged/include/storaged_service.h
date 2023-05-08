/*
 * Copyright (C) 2016 The Android Open Source Project
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

#ifndef _STORAGED_SERVICE_H_
#define _STORAGED_SERVICE_H_

#include <vector>

#include <binder/BinderService.h>

#include "android/os/BnStoraged.h"
#include "android/os/storaged/BnStoragedPrivate.h"

using namespace std;
using namespace android::os;
using namespace android::os::storaged;

namespace android {
class StoragedService : public BinderService<StoragedService>, public BnStoraged {
private:
    void dumpUidRecordsDebug(int fd, const vector<struct uid_record>& entries);
    void dumpUidRecords(int fd, const vector<struct uid_record>& entries);
public:
    static status_t start();
    static char const* getServiceName() { return "storaged"; }
    virtual status_t dump(int fd, const Vector<String16> &args) override;

    binder::Status onUserStarted(int32_t userId);
    binder::Status onUserStopped(int32_t userId);
    binder::Status getRecentPerf(int32_t* _aidl_return);
};

class StoragedPrivateService : public BinderService<StoragedPrivateService>, public BnStoragedPrivate {
public:
    static status_t start();
    static char const* getServiceName() { return "storaged_pri"; }

    binder::Status dumpUids(vector<UidInfo>* _aidl_return);
    binder::Status dumpPerfHistory(vector<int32_t>* _aidl_return);
};

sp<IStoragedPrivate> get_storaged_pri_service();

}  // namespace android
#endif /* _STORAGED_SERVICE_H_ */