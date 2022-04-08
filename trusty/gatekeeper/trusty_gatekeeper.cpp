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

#include <android-base/logging.h>
#include <limits>

#include "trusty_gatekeeper.h"
#include "trusty_gatekeeper_ipc.h"
#include "gatekeeper_ipc.h"

using ::android::hardware::hidl_vec;
using ::android::hardware::Return;
using ::android::hardware::gatekeeper::V1_0::GatekeeperStatusCode;
using ::gatekeeper::EnrollRequest;
using ::gatekeeper::EnrollResponse;
using ::gatekeeper::ERROR_INVALID;
using ::gatekeeper::ERROR_MEMORY_ALLOCATION_FAILED;
using ::gatekeeper::ERROR_NONE;
using ::gatekeeper::ERROR_RETRY;
using ::gatekeeper::SizedBuffer;
using ::gatekeeper::VerifyRequest;
using ::gatekeeper::VerifyResponse;

namespace gatekeeper {

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

SizedBuffer hidl_vec2sized_buffer(const hidl_vec<uint8_t>& vec) {
    if (vec.size() == 0 || vec.size() > std::numeric_limits<uint32_t>::max()) return {};
    auto dummy = new uint8_t[vec.size()];
    std::copy(vec.begin(), vec.end(), dummy);
    return {dummy, static_cast<uint32_t>(vec.size())};
}

Return<void> TrustyGateKeeperDevice::enroll(uint32_t uid,
                                            const hidl_vec<uint8_t>& currentPasswordHandle,
                                            const hidl_vec<uint8_t>& currentPassword,
                                            const hidl_vec<uint8_t>& desiredPassword,
                                            enroll_cb _hidl_cb) {
    if (error_ != 0) {
        _hidl_cb({GatekeeperStatusCode::ERROR_GENERAL_FAILURE, 0, {}});
        return {};
    }

    if (desiredPassword.size() == 0) {
        _hidl_cb({GatekeeperStatusCode::ERROR_GENERAL_FAILURE, 0, {}});
        return {};
    }

    EnrollRequest request(uid, hidl_vec2sized_buffer(currentPasswordHandle),
                          hidl_vec2sized_buffer(desiredPassword),
                          hidl_vec2sized_buffer(currentPassword));
    EnrollResponse response;
    auto error = Send(request, &response);
    if (error != ERROR_NONE) {
        _hidl_cb({GatekeeperStatusCode::ERROR_GENERAL_FAILURE, 0, {}});
    } else if (response.error == ERROR_RETRY) {
        _hidl_cb({GatekeeperStatusCode::ERROR_RETRY_TIMEOUT, response.retry_timeout, {}});
    } else if (response.error != ERROR_NONE) {
        _hidl_cb({GatekeeperStatusCode::ERROR_GENERAL_FAILURE, 0, {}});
    } else {
        hidl_vec<uint8_t> new_handle(response.enrolled_password_handle.Data<uint8_t>(),
                                     response.enrolled_password_handle.Data<uint8_t>() +
                                             response.enrolled_password_handle.size());
        _hidl_cb({GatekeeperStatusCode::STATUS_OK, response.retry_timeout, new_handle});
    }
    return {};
}

Return<void> TrustyGateKeeperDevice::verify(
        uint32_t uid, uint64_t challenge,
        const ::android::hardware::hidl_vec<uint8_t>& enrolledPasswordHandle,
        const ::android::hardware::hidl_vec<uint8_t>& providedPassword, verify_cb _hidl_cb) {
    if (error_ != 0) {
        _hidl_cb({GatekeeperStatusCode::ERROR_GENERAL_FAILURE, 0, {}});
        return {};
    }

    if (enrolledPasswordHandle.size() == 0) {
        _hidl_cb({GatekeeperStatusCode::ERROR_GENERAL_FAILURE, 0, {}});
        return {};
    }

    VerifyRequest request(uid, challenge, hidl_vec2sized_buffer(enrolledPasswordHandle),
                          hidl_vec2sized_buffer(providedPassword));
    VerifyResponse response;

    auto error = Send(request, &response);
    if (error != ERROR_NONE) {
        _hidl_cb({GatekeeperStatusCode::ERROR_GENERAL_FAILURE, 0, {}});
    } else if (response.error == ERROR_RETRY) {
        _hidl_cb({GatekeeperStatusCode::ERROR_RETRY_TIMEOUT, response.retry_timeout, {}});
    } else if (response.error != ERROR_NONE) {
        _hidl_cb({GatekeeperStatusCode::ERROR_GENERAL_FAILURE, 0, {}});
    } else {
        hidl_vec<uint8_t> auth_token(
                response.auth_token.Data<uint8_t>(),
                response.auth_token.Data<uint8_t>() + response.auth_token.size());

        _hidl_cb({response.request_reenroll ? GatekeeperStatusCode::STATUS_REENROLL
                                            : GatekeeperStatusCode::STATUS_OK,
                  response.retry_timeout, auth_token});
    }
    return {};
}

Return<void> TrustyGateKeeperDevice::deleteUser(uint32_t /*uid*/, deleteUser_cb _hidl_cb) {
    _hidl_cb({GatekeeperStatusCode::ERROR_NOT_IMPLEMENTED, 0, {}});
    return {};
}

Return<void> TrustyGateKeeperDevice::deleteAllUsers(deleteAllUsers_cb _hidl_cb) {
    _hidl_cb({GatekeeperStatusCode::ERROR_NOT_IMPLEMENTED, 0, {}});
    return {};
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

};
