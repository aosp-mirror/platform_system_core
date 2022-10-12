/*
 * Copyright (C) 2012 The Android Open Source Project
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

#pragma once

// clang-format off

#define KEYMASTER_PORT "com.android.trusty.keymaster"
#define KEYMASTER_MAX_BUFFER_LENGTH 4096

// Commands
enum keymaster_command : uint32_t {
    KEYMASTER_RESP_BIT              = 1,
    KEYMASTER_STOP_BIT              = 2,
    KEYMASTER_REQ_SHIFT             = 2,

    KM_GENERATE_KEY                 = (0 << KEYMASTER_REQ_SHIFT),
    KM_BEGIN_OPERATION              = (1 << KEYMASTER_REQ_SHIFT),
    KM_UPDATE_OPERATION             = (2 << KEYMASTER_REQ_SHIFT),
    KM_FINISH_OPERATION             = (3 << KEYMASTER_REQ_SHIFT),
    KM_ABORT_OPERATION              = (4 << KEYMASTER_REQ_SHIFT),
    KM_IMPORT_KEY                   = (5 << KEYMASTER_REQ_SHIFT),
    KM_EXPORT_KEY                   = (6 << KEYMASTER_REQ_SHIFT),
    KM_GET_VERSION                  = (7 << KEYMASTER_REQ_SHIFT),
    KM_ADD_RNG_ENTROPY              = (8 << KEYMASTER_REQ_SHIFT),
    KM_GET_SUPPORTED_ALGORITHMS     = (9 << KEYMASTER_REQ_SHIFT),
    KM_GET_SUPPORTED_BLOCK_MODES    = (10 << KEYMASTER_REQ_SHIFT),
    KM_GET_SUPPORTED_PADDING_MODES  = (11 << KEYMASTER_REQ_SHIFT),
    KM_GET_SUPPORTED_DIGESTS        = (12 << KEYMASTER_REQ_SHIFT),
    KM_GET_SUPPORTED_IMPORT_FORMATS = (13 << KEYMASTER_REQ_SHIFT),
    KM_GET_SUPPORTED_EXPORT_FORMATS = (14 << KEYMASTER_REQ_SHIFT),
    KM_GET_KEY_CHARACTERISTICS      = (15 << KEYMASTER_REQ_SHIFT),
    KM_ATTEST_KEY                   = (16 << KEYMASTER_REQ_SHIFT),
    KM_UPGRADE_KEY                  = (17 << KEYMASTER_REQ_SHIFT),
    KM_CONFIGURE                    = (18 << KEYMASTER_REQ_SHIFT),
    KM_GET_HMAC_SHARING_PARAMETERS  = (19 << KEYMASTER_REQ_SHIFT),
    KM_COMPUTE_SHARED_HMAC          = (20 << KEYMASTER_REQ_SHIFT),
    KM_VERIFY_AUTHORIZATION         = (21 << KEYMASTER_REQ_SHIFT),
    KM_DELETE_KEY                   = (22 << KEYMASTER_REQ_SHIFT),
    KM_DELETE_ALL_KEYS              = (23 << KEYMASTER_REQ_SHIFT),
    KM_DESTROY_ATTESTATION_IDS      = (24 << KEYMASTER_REQ_SHIFT),
    KM_IMPORT_WRAPPED_KEY           = (25 << KEYMASTER_REQ_SHIFT),
    KM_GET_VERSION_2                = (28 << KEYMASTER_REQ_SHIFT),
    KM_EARLY_BOOT_ENDED             = (29 << KEYMASTER_REQ_SHIFT),
    KM_DEVICE_LOCKED                = (30 << KEYMASTER_REQ_SHIFT),
    KM_GENERATE_RKP_KEY             = (31 << KEYMASTER_REQ_SHIFT),
    KM_GENERATE_CSR                 = (32 << KEYMASTER_REQ_SHIFT),
    KM_CONFIGURE_VENDOR_PATCHLEVEL  = (33 << KEYMASTER_REQ_SHIFT),
    KM_GET_ROOT_OF_TRUST            = (34 << KEYMASTER_REQ_SHIFT),
    KM_GET_HW_INFO                  = (35 << KEYMASTER_REQ_SHIFT),

    // Bootloader/provisioning calls.
    KM_SET_BOOT_PARAMS = (0x1000 << KEYMASTER_REQ_SHIFT),
    KM_SET_ATTESTATION_KEY = (0x2000 << KEYMASTER_REQ_SHIFT),
    KM_APPEND_ATTESTATION_CERT_CHAIN = (0x3000 << KEYMASTER_REQ_SHIFT),
    KM_ATAP_GET_CA_REQUEST = (0x4000 << KEYMASTER_REQ_SHIFT),
    KM_ATAP_SET_CA_RESPONSE_BEGIN = (0x5000 << KEYMASTER_REQ_SHIFT),
    KM_ATAP_SET_CA_RESPONSE_UPDATE = (0x6000 << KEYMASTER_REQ_SHIFT),
    KM_ATAP_SET_CA_RESPONSE_FINISH = (0x7000 << KEYMASTER_REQ_SHIFT),
    KM_ATAP_READ_UUID = (0x8000 << KEYMASTER_REQ_SHIFT),
    KM_SET_PRODUCT_ID = (0x9000 << KEYMASTER_REQ_SHIFT),
    KM_CLEAR_ATTESTATION_CERT_CHAIN = (0xa000 << KEYMASTER_REQ_SHIFT),
    KM_SET_WRAPPED_ATTESTATION_KEY = (0xb000 << KEYMASTER_REQ_SHIFT),
    KM_SET_ATTESTATION_IDS = (0xc000 << KEYMASTER_REQ_SHIFT),
    KM_CONFIGURE_BOOT_PATCHLEVEL = (0xd000 << KEYMASTER_REQ_SHIFT),
};

#ifdef __ANDROID__

/**
 * keymaster_message - Serial header for communicating with KM server
 * @cmd: the command, one of keymaster_command.
 * @payload: start of the serialized command specific payload
 */
struct keymaster_message {
    uint32_t cmd;
    uint8_t payload[0];
};

#endif
