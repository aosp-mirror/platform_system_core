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

/* This file is used to define the internal protocol for the Android Logger */

#ifndef _SYSTEM_CORE_INCLUDE_PRIVATE_ANDROID_LOGGER_H_
#define _SYSTEM_CORE_INCLUDE_PRIVATE_ANDROID_LOGGER_H_

#include <stdint.h>

#include <log/log.h>
#include <log/log_read.h>

/* Header Structure to logd */
typedef struct __attribute__((__packed__)) {
    typeof_log_id_t id;
    uint16_t tid;
    log_time realtime;
} android_log_header_t;

#endif
