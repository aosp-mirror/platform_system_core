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
            int ret = enroll(uid, currentPasswordHandle, currentPasswordHandleSize,
                    currentPassword, currentPasswordSize, desiredPassword,
                    desiredPasswordSize, &out, &outSize);

            reply->writeNoException();
            reply->writeInt32(1);
            if (ret == 0 && outSize > 0 && out != NULL) {
                reply->writeInt32(GATEKEEPER_RESPONSE_OK);
                reply->writeInt32(0);
                reply->writeInt32(outSize);
                reply->writeInt32(outSize);
                void *buf = reply->writeInplace(outSize);
                memcpy(buf, out, outSize);
                delete[] out;
            } else if (ret > 0) {
                reply->writeInt32(GATEKEEPER_RESPONSE_RETRY);
                reply->writeInt32(ret);
            } else {
                reply->writeInt32(GATEKEEPER_RESPONSE_ERROR);
            }
            return OK;
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

            bool request_reenroll = false;
            int ret = verify(uid, (uint8_t *) currentPasswordHandle,
                    currentPasswordHandleSize, (uint8_t *) currentPassword, currentPasswordSize,
                    &request_reenroll);

            reply->writeNoException();
            reply->writeInt32(1);
            if (ret == 0) {
                reply->writeInt32(GATEKEEPER_RESPONSE_OK);
                reply->writeInt32(request_reenroll ? 1 : 0);
                reply->writeInt32(0); // no payload returned from this call
            } else if (ret > 0) {
                reply->writeInt32(GATEKEEPER_RESPONSE_RETRY);
                reply->writeInt32(ret);
            } else {
                reply->writeInt32(GATEKEEPER_RESPONSE_ERROR);
            }
            return OK;
        }
        case VERIFY_CHALLENGE: {
            CHECK_INTERFACE(IGateKeeperService, data, reply);
            uint32_t uid = data.readInt32();
            uint64_t challenge = data.readInt64();
            ssize_t currentPasswordHandleSize = data.readInt32();
            const uint8_t *currentPasswordHandle =
                    static_cast<const uint8_t *>(data.readInplace(currentPasswordHandleSize));
            if (!currentPasswordHandle) currentPasswordHandleSize = 0;

            ssize_t currentPasswordSize = data.readInt32();
            const uint8_t *currentPassword =
                static_cast<const uint8_t *>(data.readInplace(currentPasswordSize));
            if (!currentPassword) currentPasswordSize = 0;


            uint8_t *out = NULL;
            uint32_t outSize = 0;
            bool request_reenroll = false;
            int ret = verifyChallenge(uid, challenge, (uint8_t *) currentPasswordHandle,
                    currentPasswordHandleSize, (uint8_t *) currentPassword, currentPasswordSize,
                    &out, &outSize, &request_reenroll);
            reply->writeNoException();
            reply->writeInt32(1);
            if (ret == 0 && outSize > 0 && out != NULL) {
                reply->writeInt32(GATEKEEPER_RESPONSE_OK);
                reply->writeInt32(request_reenroll ? 1 : 0);
                reply->writeInt32(outSize);
                reply->writeInt32(outSize);
                void *buf = reply->writeInplace(outSize);
                memcpy(buf, out, outSize);
                delete[] out;
            } else if (ret > 0) {
                reply->writeInt32(GATEKEEPER_RESPONSE_RETRY);
                reply->writeInt32(ret);
            } else {
                reply->writeInt32(GATEKEEPER_RESPONSE_ERROR);
            }
            return OK;
        }
        case GET_SECURE_USER_ID: {
            CHECK_INTERFACE(IGateKeeperService, data, reply);
            uint32_t uid = data.readInt32();
            uint64_t sid = getSecureUserId(uid);
            reply->writeNoException();
            reply->writeInt64(sid);
            return OK;
        }
        case CLEAR_SECURE_USER_ID: {
            CHECK_INTERFACE(IGateKeeperService, data, reply);
            uint32_t uid = data.readInt32();
            clearSecureUserId(uid);
            reply->writeNoException();
            return OK;
        }
        case REPORT_DEVICE_SETUP_COMPLETE: {
            CHECK_INTERFACE(IGateKeeperService, data, reply);
            reportDeviceSetupComplete();
            reply->writeNoException();
            return OK;
        }
        default:
            return BBinder::onTransact(code, data, reply, flags);
    }
};


}; // namespace android
