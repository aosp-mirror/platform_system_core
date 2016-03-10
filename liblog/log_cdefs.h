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

#ifndef _LIBLOG_CDEFS_H__
#define _LIBLOG_CDEFS_H__

#include <sys/cdefs.h>

/* Declare this library function hidden and internal */
#if defined(_WIN32)
#define LIBLOG_HIDDEN
#else
#define LIBLOG_HIDDEN __attribute__((visibility("hidden")))
#endif

/* Declare this library function visible and external */
#if defined(_WIN32)
#define LIBLOG_ABI_PUBLIC
#else
#define LIBLOG_ABI_PUBLIC __attribute__((visibility("default")))
#endif

/* Declare this library function visible but private */
#define LIBLOG_ABI_PRIVATE LIBLOG_ABI_PUBLIC

/*
 * Declare this library function as reimplementation.
 * Prevent circular dependencies, but allow _real_ library to hijack
 */
#if defined(_WIN32)
#define LIBLOG_WEAK static /* Accept that it is totally private */
#else
#define LIBLOG_WEAK __attribute__((weak,visibility("default")))
#endif

/* Unused argument. For C code only, remove symbol name for C++ */
#ifndef __unused
#define __unused        __attribute__((__unused__))
#endif

#endif /* _LIBLOG_CDEFS_H__ */
