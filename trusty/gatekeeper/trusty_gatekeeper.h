/*
 * Copyright (C) 2014 The Android Open Source Project
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

#ifndef TRUSTY_GATEKEEPER_H
#define TRUSTY_GATEKEEPER_H

#include <hardware/gatekeeper.h>
#include <gatekeeper/gatekeeper_messages.h>

#include "gatekeeper_ipc.h"

namespace gatekeeper {

class TrustyGateKeeperDevice {
    public:

    explicit TrustyGateKeeperDevice(const hw_module_t* module);
    ~TrustyGateKeeperDevice();

    hw_device_t* hw_device();

    /**
     * Enrolls password_payload, which should be derived from a user selected pin or password,
     * with the authentication factor private key used only for enrolling authentication
     * factor data.
     *
     * Returns: 0 on success or an error code less than 0 on error.
     * On error, enrolled_password will not be allocated.
     */
    int Enroll(uint32_t uid, const uint8_t *current_password_handle,
            uint32_t current_password_handle_length, const uint8_t *current_password,
            uint32_t current_password_length, const uint8_t *desired_password,
            uint32_t desired_password_length, uint8_t **enrolled_password_handle,
            uint32_t *enrolled_password_handle_length);

    /**
     * Verifies provided_password matches expected_password after enrolling
     * with the authentication factor private key.
     *
     * Implementations of this module may retain the result of this call
     * to attest to the recency of authentication.
     *
     * On success, writes the address of a verification token to verification_token,
     *
     * Returns: 0 on success or an error code less than 0 on error
     * On error, verification token will not be allocated
     */
    int Verify(uint32_t uid, uint64_t challenge, const uint8_t *enrolled_password_handle,
            uint32_t enrolled_password_handle_length, const uint8_t *provided_password,
            uint32_t provided_password_length, uint8_t **auth_token, uint32_t *auth_token_length,
            bool *request_reenroll);

    private:

    gatekeeper_error_t Send(uint32_t command, const GateKeeperMessage& request,
                           GateKeeperMessage* response);

    gatekeeper_error_t Send(const EnrollRequest& request, EnrollResponse *response) {
        return Send(GK_ENROLL, request, response);
    }

    gatekeeper_error_t Send(const VerifyRequest& request, VerifyResponse *response) {
        return Send(GK_VERIFY, request, response);
    }

    // Static methods interfacing the HAL API with the TrustyGateKeeper device

    /**
     * Enrolls desired_password, which should be derived from a user selected pin or password,
     * with the authentication factor private key used only for enrolling authentication
     * factor data.
     *
     * If there was already a password enrolled, it should be provided in
     * current_password_handle, along with the current password in current_password
     * that should validate against current_password_handle.
     *
     * Returns: 0 on success or an error code less than 0 on error.
     * On error, enrolled_password_handle will not be allocated.
     */
    static int enroll(const struct gatekeeper_device *dev, uint32_t uid,
            const uint8_t *current_password_handle, uint32_t current_password_handle_length,
            const uint8_t *current_password, uint32_t current_password_length,
            const uint8_t *desired_password, uint32_t desired_password_length,
            uint8_t **enrolled_password_handle, uint32_t *enrolled_password_handle_length);

    /**
     * Verifies provided_password matches enrolled_password_handle.
     *
     * Implementations of this module may retain the result of this call
     * to attest to the recency of authentication.
     *
     * On success, writes the address of a verification token to auth_token,
     * usable to attest password verification to other trusted services. Clients
     * may pass NULL for this value.
     *
     * Returns: 0 on success or an error code less than 0 on error
     * On error, verification token will not be allocated
     */
    static int verify(const struct gatekeeper_device *dev, uint32_t uid, uint64_t challenge,
            const uint8_t *enrolled_password_handle, uint32_t enrolled_password_handle_length,
            const uint8_t *provided_password, uint32_t provided_password_length,
            uint8_t **auth_token, uint32_t *auth_token_length, bool *request_reenroll);

    static int close_device(hw_device_t* dev);

    gatekeeper_device device_;
    int error_;

};
}

#endif

