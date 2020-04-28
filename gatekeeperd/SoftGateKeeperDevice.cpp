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
#include "SoftGateKeeper.h"
#include "SoftGateKeeperDevice.h"

namespace android {

int SoftGateKeeperDevice::enroll(uint32_t uid,
            const uint8_t *current_password_handle, uint32_t current_password_handle_length,
            const uint8_t *current_password, uint32_t current_password_length,
            const uint8_t *desired_password, uint32_t desired_password_length,
            uint8_t **enrolled_password_handle, uint32_t *enrolled_password_handle_length) {

    if (enrolled_password_handle == NULL || enrolled_password_handle_length == NULL ||
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

    impl_->Enroll(request, &response);

    if (response.error == ERROR_RETRY) {
        return response.retry_timeout;
    } else if (response.error != ERROR_NONE) {
        return -EINVAL;
    }

    *enrolled_password_handle = response.enrolled_password_handle.buffer.release();
    *enrolled_password_handle_length = response.enrolled_password_handle.length;
    return 0;
}

int SoftGateKeeperDevice::verify(uint32_t uid,
        uint64_t challenge, const uint8_t *enrolled_password_handle,
        uint32_t enrolled_password_handle_length, const uint8_t *provided_password,
        uint32_t provided_password_length, uint8_t **auth_token, uint32_t *auth_token_length,
        bool *request_reenroll) {

    if (enrolled_password_handle == NULL ||
            provided_password == NULL) {
        return -EINVAL;
    }

    SizedBuffer password_handle_buffer(enrolled_password_handle_length);
    memcpy(password_handle_buffer.buffer.get(), enrolled_password_handle,
            enrolled_password_handle_length);
    SizedBuffer provided_password_buffer(provided_password_length);
    memcpy(provided_password_buffer.buffer.get(), provided_password, provided_password_length);

    VerifyRequest request(uid, challenge, &password_handle_buffer, &provided_password_buffer);
    VerifyResponse response;

    impl_->Verify(request, &response);

    if (response.error == ERROR_RETRY) {
        return response.retry_timeout;
    } else if (response.error != ERROR_NONE) {
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
} // namespace android
