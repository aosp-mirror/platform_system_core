/*
 * Copyright (C) 2016 The Android Open Source Project
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

#ifndef LIBMEMUNREACHABLE_LOG_H_
#define LIBMEMUNREACHABLE_LOG_H_

#define LOG_TAG "libmemunreachable"

#if defined(__ANDROID__)

#include <async_safe/log.h>

#define MEM_ALOGE(...) async_safe_format_log(ANDROID_LOG_ERROR, LOG_TAG, ##__VA_ARGS__)
#define MEM_ALOGW(...) async_safe_format_log(ANDROID_LOG_WARN, LOG_TAG, ##__VA_ARGS__)
#define MEM_ALOGI(...) async_safe_format_log(ANDROID_LOG_INFO, LOG_TAG, ##__VA_ARGS__)
#define MEM_ALOGV(...) async_safe_format_log(ANDROID_LOG_VERBOSE, LOG_TAG, ##__VA_ARGS__)

#define MEM_LOG_ALWAYS_FATAL(...) async_safe_fatal(__VA_ARGS__)

#define MEM_LOG_ALWAYS_FATAL_IF(cond, ...) \
  ((__predict_false(cond)) ? async_safe_fatal(__VA_ARGS__) : (void)0)

#else

#include <log/log.h>

#define MEM_ALOGW ALOGW
#define MEM_ALOGE ALOGE
#define MEM_ALOGV ALOGV
#define MEM_ALOGI ALOGI

#define MEM_LOG_ALWAYS_FATAL LOG_ALWAYS_FATAL
#define MEM_LOG_ALWAYS_FATAL_IF LOG_ALWAYS_FATAL_IF

#endif

#endif // LIBMEMUNREACHABLE_LOG_H_
