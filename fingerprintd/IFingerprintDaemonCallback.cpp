/*
 * Copyright (C) 2015 The Android Open Source Project
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

#define LOG_TAG "IFingerprintDaemonCallback"
#include <stdint.h>
#include <sys/types.h>
#include <utils/Log.h>
#include <binder/Parcel.h>

#include "IFingerprintDaemonCallback.h"

namespace android {

class BpFingerprintDaemonCallback : public BpInterface<IFingerprintDaemonCallback>
{
public:
    BpFingerprintDaemonCallback(const sp<IBinder>& impl) :
            BpInterface<IFingerprintDaemonCallback>(impl) {
    }
    virtual status_t onEnrollResult(int64_t devId, int32_t fpId, int32_t gpId, int32_t rem) {
        Parcel data, reply;
        data.writeInterfaceToken(IFingerprintDaemonCallback::getInterfaceDescriptor());
        data.writeInt64(devId);
        data.writeInt32(fpId);
        data.writeInt32(gpId);
        data.writeInt32(rem);
        return remote()->transact(ON_ENROLL_RESULT, data, &reply, IBinder::FLAG_ONEWAY);
    }

    virtual status_t onAcquired(int64_t devId, int32_t acquiredInfo) {
        Parcel data, reply;
        data.writeInterfaceToken(IFingerprintDaemonCallback::getInterfaceDescriptor());
        data.writeInt64(devId);
        data.writeInt32(acquiredInfo);
        return remote()->transact(ON_ACQUIRED, data, &reply, IBinder::FLAG_ONEWAY);
    }

    virtual status_t onAuthenticated(int64_t devId, int32_t fpId, int32_t gpId) {
        Parcel data, reply;
        data.writeInterfaceToken(IFingerprintDaemonCallback::getInterfaceDescriptor());
        data.writeInt64(devId);
        data.writeInt32(fpId);
        data.writeInt32(gpId);
        return remote()->transact(ON_AUTHENTICATED, data, &reply, IBinder::FLAG_ONEWAY);
    }

    virtual status_t onError(int64_t devId, int32_t error) {
        Parcel data, reply;
        data.writeInterfaceToken(IFingerprintDaemonCallback::getInterfaceDescriptor());
        data.writeInt64(devId);
        data.writeInt32(error);
        return remote()->transact(ON_ERROR, data, &reply, IBinder::FLAG_ONEWAY);
    }

    virtual status_t onRemoved(int64_t devId, int32_t fpId, int32_t gpId) {
        Parcel data, reply;
        data.writeInterfaceToken(IFingerprintDaemonCallback::getInterfaceDescriptor());
        data.writeInt64(devId);
        data.writeInt32(fpId);
        data.writeInt32(gpId);
        return remote()->transact(ON_REMOVED, data, &reply, IBinder::FLAG_ONEWAY);
    }

    virtual status_t onEnumerate(int64_t devId, const int32_t* fpIds, const int32_t* gpIds,
            int32_t sz) {
        Parcel data, reply;
        data.writeInterfaceToken(IFingerprintDaemonCallback::getInterfaceDescriptor());
        data.writeInt64(devId);
        data.writeInt32Array(sz, fpIds);
        data.writeInt32Array(sz, gpIds);
        return remote()->transact(ON_ENUMERATE, data, &reply, IBinder::FLAG_ONEWAY);
    }
};

IMPLEMENT_META_INTERFACE(FingerprintDaemonCallback,
        "android.hardware.fingerprint.IFingerprintDaemonCallback");

}; // namespace android
