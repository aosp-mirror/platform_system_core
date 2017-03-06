/*
 * Copyright (C) 2017 The Android Open Source Project
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

#ifndef _LOG_GETOPT_H_
#define _LOG_GETOPT_H_

#ifndef __ANDROID_USE_LIBLOG_LOGCAT_INTERFACE
#ifndef __ANDROID_API__
#define __ANDROID_USE_LIBLOG_LOGCAT_INTERFACE 1
#elif __ANDROID_API__ > 24 /* > Nougat */
#define __ANDROID_USE_LIBLOG_LOGCAT_INTERFACE 1
#else
#define __ANDROID_USE_LIBLOG_LOGCAT_INTERFACE 0
#endif
#endif

#if __ANDROID_USE_LIBLOG_LOGCAT_INTERFACE

#include <getopt.h>
#include <sys/cdefs.h>

struct getopt_context {
    int opterr;
    int optind;
    int optopt;
    int optreset;
    const char* optarg;
    FILE* optstderr; /* NULL defaults to stderr */
    /* private */
    const char* place;
    int nonopt_start;
    int nonopt_end;
    int dash_prefix;
    /* expansion space */
    int __extra__;
    void* __stuff__;
};

#define EMSG ""
#define NO_PREFIX (-1)

#define INIT_GETOPT_CONTEXT(context) \
    context = { 1, 1, '?', 0, NULL, NULL, EMSG, -1, -1, NO_PREFIX, 0, NULL }

__BEGIN_DECLS
int getopt_long_r(int nargc, char* const* nargv, const char* options,
                  const struct option* long_options, int* idx,
                  struct getopt_context* context);

__END_DECLS

#endif /* __ANDROID_USE_LIBLOG_LOGCAT_INTERFACE */

#endif /* !_LOG_GETOPT_H_ */
