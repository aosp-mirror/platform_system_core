/*
 * Copyright 2015, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

#define LOG_TAG "GateKeeperService"
#include <utils/Log.h>

#include "IGateKeeperService.h"

namespace android {

const android::String16 IGateKeeperService::descriptor("android.service.gatekeeper.IGateKeeperService");
const android::String16& IGateKeeperService::getInterfaceDescriptor() const {
    return IGateKeeperService::descriptor;
}

status_t BnGateKeeperService::onTransact(
    uint32_t code, const Parcel& data, Parcel* reply, uint32_t flags) {
    switch(code) {
        case ENROLL: {
            CHECK_INTERFACE(IGateKeeperService, data, reply);
            uint32_t uid = data.readInt32();

            ssize_t currentPasswordHandleSize = data.readInt32();
            const uint8_t *currentPasswordHandle =
                    static_cast<const uint8_t *>(data.readInplace(currentPasswordHandleSize));
            if (!currentPasswordHandle) currentPasswordHandleSize = 0;

            ssize_t currentPasswordSize = data.readInt32();
            const uint8_t *currentPassword =
                    static_cast<const uint8_t *>(data.readInplace(currentPasswordSize));
            if (!currentPassword) currentPasswordSize = 0;

            ssize_t desiredPasswordSize = data.readInt32();
            const uint8_t *desiredPassword =
                    static_cast<const uint8_t *>(data.readInplace(desiredPasswordSize));
            if (!desiredPassword) desiredPasswordSize = 0;

            uint8_t *out = NULL;
            uint32_t outSize = 0;
            status_t ret = enroll(uid, currentPasswordHandle, currentPasswordHandleSize,
                    currentPassword, currentPasswordSize, desiredPassword,
                    desiredPasswordSize, &out, &outSize);

            reply->writeNoException();
            if (ret == NO_ERROR && outSize > 0 && out != NULL) {
                reply->writeInt32(outSize);
                void *buf = reply->writeInplace(outSize);
                memcpy(buf, out, outSize);
                free(out);
            } else {
                reply->writeInt32(-1);
            }
            return NO_ERROR;
        }
        case VERIFY: {
            CHECK_INTERFACE(IGateKeeperService, data, reply);
            uint32_t uid = data.readInt32();
            ssize_t currentPasswordHandleSize = data.readInt32();
            const uint8_t *currentPasswordHandle =
                    static_cast<const uint8_t *>(data.readInplace(currentPasswordHandleSize));
            if (!currentPasswordHandle) currentPasswordHandleSize = 0;

            ssize_t currentPasswordSize = data.readInt32();
            const uint8_t *currentPassword =
                static_cast<const uint8_t *>(data.readInplace(currentPasswordSize));
            if (!currentPassword) currentPasswordSize = 0;

            status_t ret = verify(uid, (uint8_t *) currentPasswordHandle, currentPasswordHandleSize,
                    (uint8_t *) currentPassword, currentPasswordSize);
            reply->writeNoException();
            reply->writeInt32(ret == NO_ERROR ? 1 : 0);
            return NO_ERROR;
        }
        default:
            return BBinder::onTransact(code, data, reply, flags);
    }
};


}; // namespace android
