/*Special log.h file for VNDK linking modules*/
/*
 * Copyright (C) 2005-2017 The Android Open Source Project
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
#ifndef _LIBS_CUTIL_LOG_H
#define _LIBS_CUTIL_LOG_H

/* We do not know if developer wanted log/log.h or subset android/log.h */
#include <log/log.h>

#if defined(__GNUC__)
#if defined( __clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic warning "-W#warnings"
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wpedantic"
#elif (__GNUC__ > 4) || ((__GNUC__ == 4) && (__GNUC_MINOR > 9))
#pragma GCC diagnostic push
#pragma GCC diagnostic warning "-W#warnings"
#else
#pragma GCC diagnostic push
#pragma GCC diagnostic warning "-Wcpp"
#endif
#endif

#warning "Deprecated: don't include cutils/log.h, use either android/log.h or log/log.h"

#if defined(__GNUC__)
#if defined( __clang__)
#pragma clang diagnostic pop
#endif
#pragma GCC diagnostic pop
#endif

#endif /* _LIBS_CUTIL_LOG_H */
