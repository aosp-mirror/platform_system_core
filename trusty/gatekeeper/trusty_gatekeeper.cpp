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

#include <assert.h>
#include <errno.h>
#include <stdio.h>

#include <type_traits>

#include <log/log.h>

#include "trusty_gatekeeper.h"
#include "trusty_gatekeeper_ipc.h"
#include "gatekeeper_ipc.h"

namespace gatekeeper {

const uint32_t SEND_BUF_SIZE = 8192;
const uint32_t RECV_BUF_SIZE = 8192;

TrustyGateKeeperDevice::TrustyGateKeeperDevice(const hw_module_t *module) {
#if __cplusplus >= 201103L || defined(__GXX_EXPERIMENTAL_CXX0X__)
    static_assert(std::is_standard_layout<TrustyGateKeeperDevice>::value,
                  "TrustyGateKeeperDevice must be standard layout");
    static_assert(offsetof(TrustyGateKeeperDevice, device_) == 0,
                  "device_ must be the first member of TrustyGateKeeperDevice");
    static_assert(offsetof(TrustyGateKeeperDevice, device_.common) == 0,
                  "common must be the first member of gatekeeper_device");
#else
    assert(reinterpret_cast<gatekeeper_device_t *>(this) == &device_);
    assert(reinterpret_cast<hw_device_t *>(this) == &(device_.common));
#endif

    memset(&device_, 0, sizeof(device_));
    device_.common.tag = HARDWARE_DEVICE_TAG;
    device_.common.version = 1;
    device_.common.module = const_cast<hw_module_t *>(module);
    device_.common.close = close_device;

    device_.enroll = enroll;
    device_.verify = verify;
    device_.delete_user = nullptr;
    device_.delete_all_users = nullptr;

    int rc = trusty_gatekeeper_connect();
    if (rc < 0) {
        ALOGE("Error initializing trusty session: %d", rc);
    }

    error_ = rc;

}

hw_device_t* TrustyGateKeeperDevice::hw_device() {
    return &device_.common;
}

int TrustyGateKeeperDevice::close_device(hw_device_t* dev) {
    delete reinterpret_cast<TrustyGateKeeperDevice *>(dev);
    return 0;
}

TrustyGateKeeperDevice::~TrustyGateKeeperDevice() {
    trusty_gatekeeper_disconnect();
}

int TrustyGateKeeperDevice::Enroll(uint32_t uid, const uint8_t *current_password_handle,
        uint32_t current_password_handle_length, const uint8_t *current_password,
        uint32_t current_password_length, const uint8_t *desired_password,
        uint32_t desired_password_length, uint8_t **enrolled_password_handle,
        uint32_t *enrolled_password_handle_length) {

    if (error_ != 0) {
        return error_;
    }

    SizedBuffer desired_password_buffer(desired_password_length);
    memcpy(desired_password_buffer.buffer.get(), desired_password, desired_password_length);

    SizedBuffer current_password_handle_buffer(current_password_handle_length);
    if (current_password_handle) {
        memcpy(current_password_handle_buffer.buffer.get(), current_password_handle,
                current_password_handle_length);
    }

    SizedBuffer current_password_buffer(current_password_length);
    if (current_password) {
        memcpy(current_password_buffer.buffer.get(), current_password, current_password_length);
    }

    EnrollRequest request(uid, &current_password_handle_buffer, &desired_password_buffer,
            &current_password_buffer);
    EnrollResponse response;

    gatekeeper_error_t error = Send(request, &response);

    if (error == ERROR_RETRY) {
        return response.retry_timeout;
    } else if (error != ERROR_NONE) {
        return -EINVAL;
    }

    *enrolled_password_handle = response.enrolled_password_handle.buffer.release();
    *enrolled_password_handle_length = response.enrolled_password_handle.length;


    return 0;
}

int TrustyGateKeeperDevice::Verify(uint32_t uid, uint64_t challenge,
        const uint8_t *enrolled_password_handle, uint32_t enrolled_password_handle_length,
        const uint8_t *provided_password, uint32_t provided_password_length,
        uint8_t **auth_token, uint32_t *auth_token_length, bool *request_reenroll) {
    if (error_ != 0) {
        return error_;
    }

    SizedBuffer password_handle_buffer(enrolled_password_handle_length);
    memcpy(password_handle_buffer.buffer.get(), enrolled_password_handle,
            enrolled_password_handle_length);
    SizedBuffer provided_password_buffer(provided_password_length);
    memcpy(provided_password_buffer.buffer.get(), provided_password, provided_password_length);

    VerifyRequest request(uid, challenge, &password_handle_buffer, &provided_password_buffer);
    VerifyResponse response;

    gatekeeper_error_t error = Send(request, &response);

    if (error == ERROR_RETRY) {
        return response.retry_timeout;
    } else if (error != ERROR_NONE) {
        return -EINVAL;
    }

    if (auth_token != NULL && auth_token_length != NULL) {
       *auth_token = response.auth_token.buffer.release();
       *auth_token_length = response.auth_token.length;
    }

    if (request_reenroll != NULL) {
        *request_reenroll = response.request_reenroll;
    }

    return 0;
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
        ALOGE("error (%d) calling gatekeeper TA", rc);
        return ERROR_INVALID;
    }

    const gatekeeper_message *msg = reinterpret_cast<gatekeeper_message *>(recv_buf);
    const uint8_t *payload = msg->payload;

    return response->Deserialize(payload, payload + response_size);
}

static inline TrustyGateKeeperDevice *convert_device(const gatekeeper_device *dev) {
    return reinterpret_cast<TrustyGateKeeperDevice *>(const_cast<gatekeeper_device *>(dev));
}

/* static */
int TrustyGateKeeperDevice::enroll(const struct gatekeeper_device *dev, uint32_t uid,
            const uint8_t *current_password_handle, uint32_t current_password_handle_length,
            const uint8_t *current_password, uint32_t current_password_length,
            const uint8_t *desired_password, uint32_t desired_password_length,
            uint8_t **enrolled_password_handle, uint32_t *enrolled_password_handle_length) {

    if (dev == NULL ||
            enrolled_password_handle == NULL || enrolled_password_handle_length == NULL ||
            desired_password == NULL || desired_password_length == 0)
        return -EINVAL;

    // Current password and current password handle go together
    if (current_password_handle == NULL || current_password_handle_length == 0 ||
            current_password == NULL || current_password_length == 0) {
        current_password_handle = NULL;
        current_password_handle_length = 0;
        current_password = NULL;
        current_password_length = 0;
    }

    return convert_device(dev)->Enroll(uid, current_password_handle, current_password_handle_length,
            current_password, current_password_length, desired_password, desired_password_length,
            enrolled_password_handle, enrolled_password_handle_length);

}

/* static */
int TrustyGateKeeperDevice::verify(const struct gatekeeper_device *dev, uint32_t uid,
        uint64_t challenge, const uint8_t *enrolled_password_handle,
        uint32_t enrolled_password_handle_length, const uint8_t *provided_password,
        uint32_t provided_password_length, uint8_t **auth_token, uint32_t *auth_token_length,
        bool *request_reenroll) {

    if (dev == NULL || enrolled_password_handle == NULL ||
            provided_password == NULL) {
        return -EINVAL;
    }

    return convert_device(dev)->Verify(uid, challenge, enrolled_password_handle,
            enrolled_password_handle_length, provided_password, provided_password_length,
            auth_token, auth_token_length, request_reenroll);
}
};
