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

#include <memory>

#include <aidl/android/hardware/gatekeeper/BnGatekeeper.h>

#include <gatekeeper/gatekeeper_messages.h>

#include "gatekeeper_ipc.h"

namespace aidl::android::hardware::gatekeeper {

using aidl::android::hardware::gatekeeper::GatekeeperEnrollResponse;
using aidl::android::hardware::gatekeeper::GatekeeperVerifyResponse;
using ::gatekeeper::DeleteAllUsersRequest;
using ::gatekeeper::DeleteAllUsersResponse;
using ::gatekeeper::DeleteUserRequest;
using ::gatekeeper::DeleteUserResponse;
using ::gatekeeper::EnrollRequest;
using ::gatekeeper::EnrollResponse;
using ::gatekeeper::gatekeeper_error_t;
using ::gatekeeper::GateKeeperMessage;
using ::gatekeeper::VerifyRequest;
using ::gatekeeper::VerifyResponse;

class TrustyGateKeeperDevice : public BnGatekeeper {
  public:
    explicit TrustyGateKeeperDevice();
    ~TrustyGateKeeperDevice();
    /**
     * Enrolls password_payload, which should be derived from a user selected pin or password,
     * with the authentication factor private key used only for enrolling authentication
     * factor data.
     *
     * Returns: 0 on success or an error code less than 0 on error.
     * On error, enrolled_password_handle will not be allocated.
     */
    ::ndk::ScopedAStatus enroll(int32_t uid, const std::vector<uint8_t>& currentPasswordHandle,
                                const std::vector<uint8_t>& currentPassword,
                                const std::vector<uint8_t>& desiredPassword,
                                GatekeeperEnrollResponse* _aidl_return) override;

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
    ::ndk::ScopedAStatus verify(int32_t uid, int64_t challenge,
                                const std::vector<uint8_t>& enrolledPasswordHandle,
                                const std::vector<uint8_t>& providedPassword,
                                GatekeeperVerifyResponse* _aidl_return) override;

    ::ndk::ScopedAStatus deleteAllUsers() override;

    ::ndk::ScopedAStatus deleteUser(int32_t uid) override;

  private:
    gatekeeper_error_t Send(uint32_t command, const GateKeeperMessage& request,
                           GateKeeperMessage* response);

    gatekeeper_error_t Send(const EnrollRequest& request, EnrollResponse* response) {
        return Send(GK_ENROLL, request, response);
    }

    gatekeeper_error_t Send(const VerifyRequest& request, VerifyResponse* response) {
        return Send(GK_VERIFY, request, response);
    }

    gatekeeper_error_t Send(const DeleteUserRequest& request, DeleteUserResponse* response) {
        return Send(GK_DELETE_USER, request, response);
    }

    gatekeeper_error_t Send(const DeleteAllUsersRequest& request,
                            DeleteAllUsersResponse* response) {
        return Send(GK_DELETE_ALL_USERS, request, response);
    }

    int error_;
};

}  // namespace aidl::android::hardware::gatekeeper

#endif
