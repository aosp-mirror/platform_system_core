/*
 * Copyright (C) 2011 The Android Open Source Project
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

#define LOG_TAG "Corkscrew"
//#define LOG_NDEBUG 0

#include <corkscrew/demangle.h>

#include <cutils/log.h>

#ifdef CORKSCREW_HAVE_LIBIBERTY
// Defined in libiberty.a
extern char *cplus_demangle(const char *mangled, int options);
#endif

char* demangle_symbol_name(const char* name) {
#ifdef CORKSCREW_HAVE_LIBIBERTY
    return name ? cplus_demangle(name, 0) : NULL;
#else
    return NULL;
#endif
}
