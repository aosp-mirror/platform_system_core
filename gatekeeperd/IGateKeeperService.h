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

#ifndef IGATEKEEPER_SERVICE_H_
#define IGATEKEEPER_SERVICE_H_

#include <binder/IInterface.h>
#include <binder/Parcel.h>

namespace android {

/*
 * This must be kept manually in sync with frameworks/base's IGateKeeperService.aidl
 */
class IGateKeeperService : public IInterface {
public:
    enum {
        ENROLL = IBinder::FIRST_CALL_TRANSACTION + 0,
        VERIFY = IBinder::FIRST_CALL_TRANSACTION + 1,
        VERIFY_CHALLENGE = IBinder::FIRST_CALL_TRANSACTION + 2,
        GET_SECURE_USER_ID = IBinder::FIRST_CALL_TRANSACTION + 3,
        CLEAR_SECURE_USER_ID = IBinder::FIRST_CALL_TRANSACTION + 4,
        REPORT_DEVICE_SETUP_COMPLETE = IBinder::FIRST_CALL_TRANSACTION + 5,
    };

    enum {
        GATEKEEPER_RESPONSE_OK = 0,
        GATEKEEPER_RESPONSE_RETRY = 1,
        GATEKEEPER_RESPONSE_ERROR = -1,
    };

    // DECLARE_META_INTERFACE - C++ client interface not needed
    static const android::String16 descriptor;
    virtual const android::String16& getInterfaceDescriptor() const;
    IGateKeeperService() {}
    virtual ~IGateKeeperService() {}

    /**
     * Enrolls a password with the GateKeeper. Returns 0 on success, negative on failure.
     * Returns:
     * - 0 on success
     * - A timestamp T > 0 if the call has failed due to throttling and should not
     *   be reattempted until T milliseconds have elapsed
     * - -1 on failure
     */
    virtual int enroll(uint32_t uid,
            const uint8_t *current_password_handle, uint32_t current_password_handle_length,
            const uint8_t *current_password, uint32_t current_password_length,
            const uint8_t *desired_password, uint32_t desired_password_length,
            uint8_t **enrolled_password_handle, uint32_t *enrolled_password_handle_length) = 0;

    /**
     * Verifies a password previously enrolled with the GateKeeper.
     * Returns:
     * - 0 on success
     * - A timestamp T > 0 if the call has failed due to throttling and should not
     *   be reattempted until T milliseconds have elapsed
     * - -1 on failure
     */
    virtual int verify(uint32_t uid, const uint8_t *enrolled_password_handle,
            uint32_t enrolled_password_handle_length,
            const uint8_t *provided_password, uint32_t provided_password_length,
            bool *request_reenroll) = 0;

    /**
     * Verifies a password previously enrolled with the GateKeeper.
     * Returns:
     * - 0 on success
     * - A timestamp T > 0 if the call has failed due to throttling and should not
     *   be reattempted until T milliseconds have elapsed
     * - -1 on failure
     */
    virtual int verifyChallenge(uint32_t uid, uint64_t challenge,
            const uint8_t *enrolled_password_handle, uint32_t enrolled_password_handle_length,
            const uint8_t *provided_password, uint32_t provided_password_length,
            uint8_t **auth_token, uint32_t *auth_token_length, bool *request_reenroll) = 0;
    /**
     * Returns the secure user ID for the provided android user
     */
    virtual uint64_t getSecureUserId(uint32_t uid) = 0;

    /**
     * Clears the secure user ID associated with the user.
     */
    virtual void clearSecureUserId(uint32_t uid) = 0;

    /**
     * Notifies gatekeeper that device setup has been completed and any potentially still existing
     * state from before a factory reset can be cleaned up (if it has not been already).
     */
    virtual void reportDeviceSetupComplete() = 0;
};

// ----------------------------------------------------------------------------

class BnGateKeeperService: public BnInterface<IGateKeeperService> {
public:
    virtual status_t onTransact(uint32_t code, const Parcel& data, Parcel* reply,
            uint32_t flags = 0);
};

} // namespace android

#endif

