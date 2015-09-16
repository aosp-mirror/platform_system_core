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

#pragma once

#define GATEKEEPER_PORT "com.android.trusty.gatekeeper"
#define GATEKEEPER_MAX_BUFFER_LENGTH 1024

enum gatekeeper_command {
	GK_REQ_SHIFT = 1,
	GK_RESP_BIT  = 1,

	GK_ENROLL       = (0 << GK_REQ_SHIFT),
	GK_VERIFY       = (1 << GK_REQ_SHIFT),
};

/**
 * gatekeeper_message - Serial header for communicating with GK server
 * @cmd: the command, one of ENROLL, VERIFY. Payload must be a serialized
 *       buffer of the corresponding request object.
 * @payload: start of the serialized command specific payload
 */
struct gatekeeper_message {
    uint32_t cmd;
    uint8_t payload[0];
};

