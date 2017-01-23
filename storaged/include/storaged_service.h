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

#include <binder/IInterface.h>
#include <binder/IBinder.h>

#include "storaged.h"

using namespace android;

// Interface
class IStoraged : public IInterface {
public:
    enum {
        DUMPUIDS  = IBinder::FIRST_CALL_TRANSACTION,
    };
    // Request the service to run the test function
    virtual std::vector<struct uid_info> dump_uids(const char* option) = 0;

    DECLARE_META_INTERFACE(Storaged);
};

// Client
class BpStoraged : public BpInterface<IStoraged> {
public:
    BpStoraged(const sp<IBinder>& impl) : BpInterface<IStoraged>(impl){};
    virtual std::vector<struct uid_info> dump_uids(const char* option);
};

// Server
class BnStoraged : public BnInterface<IStoraged> {
    virtual status_t onTransact(uint32_t code, const Parcel& data, Parcel* reply, uint32_t flags = 0);
};

class Storaged : public BnStoraged {
    virtual std::vector<struct uid_info> dump_uids(const char* option);
};

sp<IStoraged> get_storaged_service();

#endif /* _STORAGED_SERVICE_H_ */