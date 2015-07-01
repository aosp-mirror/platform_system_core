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

#ifndef IFINGERPRINT_DAEMON_H_
#define IFINGERPRINT_DAEMON_H_

#include <binder/IInterface.h>
#include <binder/Parcel.h>

namespace android {

class IFingerprintDaemonCallback;

/*
* Abstract base class for native implementation of FingerprintService.
*
* Note: This must be kept manually in sync with IFingerprintDaemon.aidl
*/
class IFingerprintDaemon : public IInterface, public IBinder::DeathRecipient {
    public:
        enum {
           AUTHENTICATE = IBinder::FIRST_CALL_TRANSACTION + 0,
           CANCEL_AUTHENTICATION = IBinder::FIRST_CALL_TRANSACTION + 1,
           ENROLL = IBinder::FIRST_CALL_TRANSACTION + 2,
           CANCEL_ENROLLMENT = IBinder::FIRST_CALL_TRANSACTION + 3,
           PRE_ENROLL = IBinder::FIRST_CALL_TRANSACTION + 4,
           REMOVE = IBinder::FIRST_CALL_TRANSACTION + 5,
           GET_AUTHENTICATOR_ID = IBinder::FIRST_CALL_TRANSACTION + 6,
           SET_ACTIVE_GROUP = IBinder::FIRST_CALL_TRANSACTION + 7,
           OPEN_HAL = IBinder::FIRST_CALL_TRANSACTION + 8,
           CLOSE_HAL = IBinder::FIRST_CALL_TRANSACTION + 9,
           INIT = IBinder::FIRST_CALL_TRANSACTION + 10,
           POST_ENROLL = IBinder::FIRST_CALL_TRANSACTION + 11,
        };

        IFingerprintDaemon() { }
        virtual ~IFingerprintDaemon() { }
        virtual const android::String16& getInterfaceDescriptor() const;

        // Binder interface methods
        virtual void init(const sp<IFingerprintDaemonCallback>& callback) = 0;
        virtual int32_t enroll(const uint8_t* token, ssize_t tokenLength, int32_t groupId,
                int32_t timeout) = 0;
        virtual uint64_t preEnroll() = 0;
        virtual int32_t postEnroll() = 0;
        virtual int32_t stopEnrollment() = 0;
        virtual int32_t authenticate(uint64_t sessionId, uint32_t groupId) = 0;
        virtual int32_t stopAuthentication() = 0;
        virtual int32_t remove(int32_t fingerId, int32_t groupId) = 0;
        virtual uint64_t getAuthenticatorId() = 0;
        virtual int32_t setActiveGroup(int32_t groupId, const uint8_t* path, ssize_t pathLen) = 0;
        virtual int64_t openHal() = 0;
        virtual int32_t closeHal() = 0;

        // DECLARE_META_INTERFACE - C++ client interface not needed
        static const android::String16 descriptor;
        static void hal_notify_callback(const fingerprint_msg_t *msg);
};

// ----------------------------------------------------------------------------

class BnFingerprintDaemon: public BnInterface<IFingerprintDaemon> {
    public:
       virtual status_t onTransact(uint32_t code, const Parcel& data, Parcel* reply,
               uint32_t flags = 0);
    private:
       bool checkPermission(const String16& permission);
};

} // namespace android

#endif // IFINGERPRINT_DAEMON_H_

