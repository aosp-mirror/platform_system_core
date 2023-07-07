/*
 * Copyright (C) 2021 The Android Open Source Project
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

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ACVP_PORT "com.android.trusty.acvp"

/*
 * Maximum number of arguments
 */
#define ACVP_MAX_NUM_ARGUMENTS 9

/*
 * Maximum length of an algorithm name
 */
#define ACVP_MAX_NAME_LENGTH 30

/*
 * Maximum length of an ACVP request message
 */
#define ACVP_MAX_MESSAGE_LENGTH sizeof(struct acvp_req)

/*
 * Minimum length of the shared memory buffer
 *
 * This must be at least as long as the longest reply from the ACVP service
 * (currently the reply from getConfig()).
 */
#define ACVP_MIN_SHARED_MEMORY 32768

/**
 * acvp_req - Request for the Trusty ACVP app
 * @num_args: Number of acvp_arg structures following this struct
 * @buffer_size: Total size of shared memory buffer
 * @lengths: Length of each argument in the shared memory buffer
 *
 * @num_args copies of the acvp_arg struct follow this structure.
 */
struct acvp_req {
    uint32_t num_args;
    uint32_t buffer_size;
    uint32_t lengths[ACVP_MAX_NUM_ARGUMENTS];
};

/**
 * acvp_resp - Response to a ACVP request
 *
 * @num_spans: Number of response sections
 * @lengths: Length of each response section
 */
struct acvp_resp {
    uint32_t num_spans;
    uint32_t lengths[ACVP_MAX_NUM_ARGUMENTS];
};

#ifdef __cplusplus
}  // extern "C"
#endif
