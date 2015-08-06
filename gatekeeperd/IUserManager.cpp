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

#define LOG_TAG "IUserManager"
#include <stdint.h>
#include <sys/types.h>
#include <utils/Log.h>
#include <binder/Parcel.h>

#include "IUserManager.h"

namespace android {

class BpUserManager : public BpInterface<IUserManager>
{
public:
    BpUserManager(const sp<IBinder>& impl) :
            BpInterface<IUserManager>(impl) {
    }
    virtual int32_t getCredentialOwnerProfile(int32_t user_id) {
        Parcel data, reply;
        data.writeInterfaceToken(IUserManager::getInterfaceDescriptor());
        data.writeInt32(user_id);
        status_t rc = remote()->transact(GET_CREDENTIAL_OWNER_PROFILE, data, &reply, 0);
        if (rc != NO_ERROR) {
            ALOGE("%s: failed (%d)\n", __func__, rc);
            return -1;
        }

        int32_t exception = reply.readExceptionCode();
        if (exception != 0) {
            ALOGE("%s: got exception (%d)\n", __func__, exception);
            return -1;
        }

        return reply.readInt32();
    }

};

IMPLEMENT_META_INTERFACE(UserManager, "android.os.IUserManager");

}; // namespace android

