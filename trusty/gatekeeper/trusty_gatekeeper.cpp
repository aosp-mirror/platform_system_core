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

#define LOG_TAG "TrustyGateKeeper"

#include <endian.h>
#include <limits>

#include <android-base/logging.h>
#include <gatekeeper/password_handle.h>
#include <hardware/hw_auth_token.h>

#include "gatekeeper_ipc.h"
#include "trusty_gatekeeper.h"
#include "trusty_gatekeeper_ipc.h"

namespace aidl::android::hardware::gatekeeper {

using ::gatekeeper::ERROR_INVALID;
using ::gatekeeper::ERROR_NONE;
using ::gatekeeper::ERROR_RETRY;
using ::gatekeeper::SizedBuffer;
using ::gatekeeper::VerifyRequest;
using ::gatekeeper::VerifyResponse;

constexpr const uint32_t SEND_BUF_SIZE = 8192;
constexpr const uint32_t RECV_BUF_SIZE = 8192;

TrustyGateKeeperDevice::TrustyGateKeeperDevice() {
    int rc = trusty_gatekeeper_connect();
    if (rc < 0) {
        LOG(ERROR) << "Error initializing trusty session: " << rc;
    }

    error_ = rc;
}

TrustyGateKeeperDevice::~TrustyGateKeeperDevice() {
    trusty_gatekeeper_disconnect();
}

SizedBuffer vec2sized_buffer(const std::vector<uint8_t>& vec) {
    if (vec.size() == 0 || vec.size() > std::numeric_limits<uint32_t>::max()) return {};
    auto buffer = new uint8_t[vec.size()];
    std::copy(vec.begin(), vec.end(), buffer);
    return {buffer, static_cast<uint32_t>(vec.size())};
}

void sizedBuffer2AidlHWToken(SizedBuffer& buffer,
                             android::hardware::security::keymint::HardwareAuthToken* aidlToken) {
    const hw_auth_token_t* authToken =
            reinterpret_cast<const hw_auth_token_t*>(buffer.Data<uint8_t>());
    aidlToken->challenge = authToken->challenge;
    aidlToken->userId = authToken->user_id;
    aidlToken->authenticatorId = authToken->authenticator_id;
    // these are in network order: translate to host
    aidlToken->authenticatorType =
            static_cast<android::hardware::security::keymint::HardwareAuthenticatorType>(
                    be32toh(authToken->authenticator_type));
    aidlToken->timestamp.milliSeconds = be64toh(authToken->timestamp);
    aidlToken->mac.insert(aidlToken->mac.begin(), std::begin(authToken->hmac),
                          std::end(authToken->hmac));
}

::ndk::ScopedAStatus TrustyGateKeeperDevice::enroll(
        int32_t uid, const std::vector<uint8_t>& currentPasswordHandle,
        const std::vector<uint8_t>& currentPassword, const std::vector<uint8_t>& desiredPassword,
        GatekeeperEnrollResponse* rsp) {
    if (error_ != 0) {
        return ndk::ScopedAStatus(AStatus_fromServiceSpecificError(ERROR_GENERAL_FAILURE));
    }

    if (desiredPassword.size() == 0) {
        return ndk::ScopedAStatus(AStatus_fromServiceSpecificError(ERROR_GENERAL_FAILURE));
    }

    EnrollRequest request(uid, vec2sized_buffer(currentPasswordHandle),
                          vec2sized_buffer(desiredPassword), vec2sized_buffer(currentPassword));
    EnrollResponse response;
    auto error = Send(request, &response);
    if (error != ERROR_NONE) {
        return ndk::ScopedAStatus(AStatus_fromServiceSpecificError(ERROR_GENERAL_FAILURE));
    } else if (response.error == ERROR_RETRY) {
        *rsp = {ERROR_RETRY_TIMEOUT, static_cast<int32_t>(response.retry_timeout), 0, {}};
        return ndk::ScopedAStatus::ok();
    } else if (response.error != ERROR_NONE) {
        return ndk::ScopedAStatus(AStatus_fromServiceSpecificError(ERROR_GENERAL_FAILURE));
    } else {
        const ::gatekeeper::password_handle_t* password_handle =
                response.enrolled_password_handle.Data<::gatekeeper::password_handle_t>();
        *rsp = {STATUS_OK,
                0,
                static_cast<int64_t>(password_handle->user_id),
                {response.enrolled_password_handle.Data<uint8_t>(),
                 (response.enrolled_password_handle.Data<uint8_t>() +
                  response.enrolled_password_handle.size())}};
    }
    return ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus TrustyGateKeeperDevice::verify(
        int32_t uid, int64_t challenge, const std::vector<uint8_t>& enrolledPasswordHandle,
        const std::vector<uint8_t>& providedPassword, GatekeeperVerifyResponse* rsp) {
    if (error_ != 0) {
        return ndk::ScopedAStatus(AStatus_fromServiceSpecificError(ERROR_GENERAL_FAILURE));
    }

    if (enrolledPasswordHandle.size() == 0) {
        return ndk::ScopedAStatus(AStatus_fromServiceSpecificError(ERROR_GENERAL_FAILURE));
    }

    VerifyRequest request(uid, challenge, vec2sized_buffer(enrolledPasswordHandle),
                          vec2sized_buffer(providedPassword));
    VerifyResponse response;

    auto error = Send(request, &response);
    if (error != ERROR_NONE) {
        return ndk::ScopedAStatus(AStatus_fromServiceSpecificError(ERROR_GENERAL_FAILURE));
    } else if (response.error == ERROR_RETRY) {
        *rsp = {ERROR_RETRY_TIMEOUT, static_cast<int32_t>(response.retry_timeout), {}};
        return ndk::ScopedAStatus::ok();
    } else if (response.error != ERROR_NONE) {
        return ndk::ScopedAStatus(AStatus_fromServiceSpecificError(ERROR_GENERAL_FAILURE));
    } else {
        // On Success, return GatekeeperVerifyResponse with Success Status, timeout{0} and
        // valid HardwareAuthToken.
        *rsp = {response.request_reenroll ? STATUS_REENROLL : STATUS_OK, 0, {}};
        // Convert the hw_auth_token_t to HardwareAuthToken in the response.
        sizedBuffer2AidlHWToken(response.auth_token, &rsp->hardwareAuthToken);
    }
    return ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus TrustyGateKeeperDevice::deleteUser(int32_t uid) {
    if (error_ != 0) {
        return ndk::ScopedAStatus(AStatus_fromServiceSpecificError(ERROR_GENERAL_FAILURE));
    }

    DeleteUserRequest request(uid);
    DeleteUserResponse response;
    auto error = Send(request, &response);

    if (error != ERROR_NONE) {
        return ndk::ScopedAStatus(AStatus_fromServiceSpecificError(ERROR_GENERAL_FAILURE));
    } else if (response.error == ERROR_NOT_IMPLEMENTED) {
        return ndk::ScopedAStatus(AStatus_fromServiceSpecificError(ERROR_NOT_IMPLEMENTED));
    } else if (response.error != ERROR_NONE) {
        return ndk::ScopedAStatus(AStatus_fromServiceSpecificError(ERROR_GENERAL_FAILURE));
    } else {
        return ndk::ScopedAStatus::ok();
    }
}

::ndk::ScopedAStatus TrustyGateKeeperDevice::deleteAllUsers() {
    if (error_ != 0) {
        return ndk::ScopedAStatus(AStatus_fromServiceSpecificError(ERROR_GENERAL_FAILURE));
    }

    DeleteAllUsersRequest request;
    DeleteAllUsersResponse response;
    auto error = Send(request, &response);

    if (error != ERROR_NONE) {
        return ndk::ScopedAStatus(AStatus_fromServiceSpecificError(ERROR_GENERAL_FAILURE));
    } else if (response.error == ERROR_NOT_IMPLEMENTED) {
        return ndk::ScopedAStatus(AStatus_fromServiceSpecificError(ERROR_NOT_IMPLEMENTED));
    } else if (response.error != ERROR_NONE) {
        return ndk::ScopedAStatus(AStatus_fromServiceSpecificError(ERROR_GENERAL_FAILURE));
    } else {
        return ndk::ScopedAStatus::ok();
    }
}

gatekeeper_error_t TrustyGateKeeperDevice::Send(uint32_t command, const GateKeeperMessage& request,
        GateKeeperMessage *response) {
    uint32_t request_size = request.GetSerializedSize();
    if (request_size > SEND_BUF_SIZE)
        return ERROR_INVALID;
    uint8_t send_buf[SEND_BUF_SIZE];
    request.Serialize(send_buf, send_buf + request_size);

    // Send it
    uint8_t recv_buf[RECV_BUF_SIZE];
    uint32_t response_size = RECV_BUF_SIZE;
    int rc = trusty_gatekeeper_call(command, send_buf, request_size, recv_buf, &response_size);
    if (rc < 0) {
        LOG(ERROR) << "error (" << rc << ") calling gatekeeper TA";
        return ERROR_INVALID;
    }

    const gatekeeper_message *msg = reinterpret_cast<gatekeeper_message *>(recv_buf);
    const uint8_t *payload = msg->payload;

    return response->Deserialize(payload, payload + response_size);
}

}  // namespace aidl::android::hardware::gatekeeper
