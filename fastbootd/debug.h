/*
 * Copyright (C) 2013 The Android Open Source Project
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

#ifndef _FASTBOOTD_DEBUG_H_
#define _FASTBOOTD_DEBUG_H_

#include <stdio.h>

#include <cutils/klog.h>

#define ERR 0
#define WARN 1
#define INFO 2
#define VERBOSE 3
#define DEBUG 4

extern unsigned int debug_level;

//#define DLOG(fmt, ...) printf(fmt, ##__VA_ARGS__)
#define DLOG(fmt, ...) KLOG_INFO("fastbootd", fmt, ##__VA_ARGS__)

#define D(level, fmt, ...) \
    do { \
        if (debug_level == level || debug_level > level) { \
            DLOG("%s:%d " fmt "\n", __BASE_FILE__, __LINE__, ##__VA_ARGS__); \
        } \
    } while (0)

#endif
