/*
 * Copyright 2015 The Android Open Source Project
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

#include <arpa/inet.h>
#include <iostream>

#include <gtest/gtest.h>
#include <UniquePtr.h>

#include <hardware/hw_auth_token.h>

#include "../SoftGateKeeper.h"

using ::gatekeeper::SizedBuffer;
using ::testing::Test;
using ::gatekeeper::EnrollRequest;
using ::gatekeeper::EnrollResponse;
using ::gatekeeper::VerifyRequest;
using ::gatekeeper::VerifyResponse;
using ::gatekeeper::SoftGateKeeper;
using ::gatekeeper::secure_id_t;

static void do_enroll(SoftGateKeeper &gatekeeper, EnrollResponse *response) {
    SizedBuffer password;

    password.buffer.reset(new uint8_t[16]);
    password.length = 16;
    memset(password.buffer.get(), 0, 16);
    EnrollRequest request(0, NULL, &password, NULL);

    gatekeeper.Enroll(request, response);
}

TEST(GateKeeperTest, EnrollSuccess) {
    SoftGateKeeper gatekeeper;
    EnrollResponse response;
    do_enroll(gatekeeper, &response);
    ASSERT_EQ(::gatekeeper::gatekeeper_error_t::ERROR_NONE, response.error);
}

TEST(GateKeeperTest, EnrollBogusData) {
    SoftGateKeeper gatekeeper;
    SizedBuffer password;
    EnrollResponse response;

    EnrollRequest request(0, NULL, &password, NULL);

    gatekeeper.Enroll(request, &response);

    ASSERT_EQ(::gatekeeper::gatekeeper_error_t::ERROR_INVALID, response.error);
}

TEST(GateKeeperTest, VerifySuccess) {
    SoftGateKeeper gatekeeper;
    SizedBuffer provided_password;
    EnrollResponse enroll_response;

    provided_password.buffer.reset(new uint8_t[16]);
    provided_password.length = 16;
    memset(provided_password.buffer.get(), 0, 16);

    do_enroll(gatekeeper, &enroll_response);
    ASSERT_EQ(::gatekeeper::gatekeeper_error_t::ERROR_NONE, enroll_response.error);
    VerifyRequest request(0, 1, &enroll_response.enrolled_password_handle,
            &provided_password);
    VerifyResponse response;

    gatekeeper.Verify(request, &response);

    ASSERT_EQ(::gatekeeper::gatekeeper_error_t::ERROR_NONE, response.error);

    hw_auth_token_t *auth_token =
        reinterpret_cast<hw_auth_token_t *>(response.auth_token.buffer.get());

    ASSERT_EQ((uint32_t) HW_AUTH_PASSWORD, ntohl(auth_token->authenticator_type));
    ASSERT_EQ((uint64_t) 1, auth_token->challenge);
    ASSERT_NE(~((uint32_t) 0), auth_token->timestamp);
    ASSERT_NE((uint64_t) 0, auth_token->user_id);
    ASSERT_NE((uint64_t) 0, auth_token->authenticator_id);
}

TEST(GateKeeperTest, TrustedReEnroll) {
    SoftGateKeeper gatekeeper;
    SizedBuffer provided_password;
    EnrollResponse enroll_response;
    SizedBuffer password_handle;

    // do_enroll enrolls an all 0 password
    provided_password.buffer.reset(new uint8_t[16]);
    provided_password.length = 16;
    memset(provided_password.buffer.get(), 0, 16);
    do_enroll(gatekeeper, &enroll_response);
    ASSERT_EQ(::gatekeeper::gatekeeper_error_t::ERROR_NONE, enroll_response.error);

    // keep a copy of the handle
    password_handle.buffer.reset(new uint8_t[enroll_response.enrolled_password_handle.length]);
    password_handle.length = enroll_response.enrolled_password_handle.length;
    memcpy(password_handle.buffer.get(), enroll_response.enrolled_password_handle.buffer.get(),
            password_handle.length);

    // verify first password
    VerifyRequest request(0, 0, &enroll_response.enrolled_password_handle,
            &provided_password);
    VerifyResponse response;
    gatekeeper.Verify(request, &response);
    ASSERT_EQ(::gatekeeper::gatekeeper_error_t::ERROR_NONE, response.error);
    hw_auth_token_t *auth_token =
        reinterpret_cast<hw_auth_token_t *>(response.auth_token.buffer.get());

    secure_id_t secure_id = auth_token->user_id;

    // enroll new password
    provided_password.buffer.reset(new uint8_t[16]);
    provided_password.length = 16;
    memset(provided_password.buffer.get(), 0, 16);
    SizedBuffer password;
    password.buffer.reset(new uint8_t[16]);
    memset(password.buffer.get(), 1, 16);
    password.length = 16;
    EnrollRequest enroll_request(0, &password_handle, &password, &provided_password);
    gatekeeper.Enroll(enroll_request, &enroll_response);
    ASSERT_EQ(::gatekeeper::gatekeeper_error_t::ERROR_NONE, enroll_response.error);

    // verify new password
    password.buffer.reset(new uint8_t[16]);
    memset(password.buffer.get(), 1, 16);
    password.length = 16;
    VerifyRequest new_request(0, 0, &enroll_response.enrolled_password_handle,
            &password);
    gatekeeper.Verify(new_request, &response);
    ASSERT_EQ(::gatekeeper::gatekeeper_error_t::ERROR_NONE, response.error);
    ASSERT_EQ(secure_id,
        reinterpret_cast<hw_auth_token_t *>(response.auth_token.buffer.get())->user_id);
}


TEST(GateKeeperTest, UntrustedReEnroll) {
    SoftGateKeeper gatekeeper;
    SizedBuffer provided_password;
    EnrollResponse enroll_response;

    // do_enroll enrolls an all 0 password
    provided_password.buffer.reset(new uint8_t[16]);
    provided_password.length = 16;
    memset(provided_password.buffer.get(), 0, 16);
    do_enroll(gatekeeper, &enroll_response);
    ASSERT_EQ(::gatekeeper::gatekeeper_error_t::ERROR_NONE, enroll_response.error);

    // verify first password
    VerifyRequest request(0, 0, &enroll_response.enrolled_password_handle,
            &provided_password);
    VerifyResponse response;
    gatekeeper.Verify(request, &response);
    ASSERT_EQ(::gatekeeper::gatekeeper_error_t::ERROR_NONE, response.error);
    hw_auth_token_t *auth_token =
        reinterpret_cast<hw_auth_token_t *>(response.auth_token.buffer.get());

    secure_id_t secure_id = auth_token->user_id;

    // enroll new password
    SizedBuffer password;
    password.buffer.reset(new uint8_t[16]);
    memset(password.buffer.get(), 1, 16);
    password.length = 16;
    EnrollRequest enroll_request(0, NULL, &password, NULL);
    gatekeeper.Enroll(enroll_request, &enroll_response);
    ASSERT_EQ(::gatekeeper::gatekeeper_error_t::ERROR_NONE, enroll_response.error);

    // verify new password
    password.buffer.reset(new uint8_t[16]);
    memset(password.buffer.get(), 1, 16);
    password.length = 16;
    VerifyRequest new_request(0, 0, &enroll_response.enrolled_password_handle,
            &password);
    gatekeeper.Verify(new_request, &response);
    ASSERT_EQ(::gatekeeper::gatekeeper_error_t::ERROR_NONE, response.error);
    ASSERT_NE(secure_id,
        reinterpret_cast<hw_auth_token_t *>(response.auth_token.buffer.get())->user_id);
}


TEST(GateKeeperTest, VerifyBogusData) {
    SoftGateKeeper gatekeeper;
    SizedBuffer provided_password;
    SizedBuffer password_handle;
    VerifyResponse response;

    VerifyRequest request(0, 0, &provided_password, &password_handle);

    gatekeeper.Verify(request, &response);

    ASSERT_EQ(::gatekeeper::gatekeeper_error_t::ERROR_INVALID, response.error);
}
