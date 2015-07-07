/*
 * Copyright (C) 2007 The Android Open Source Project
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

#ifndef _INIT_PROPERTY_H
#define _INIT_PROPERTY_H

#include <stddef.h>
#include <sys/system_properties.h>

extern void property_init(void);
extern void property_load_boot_defaults(void);
extern void load_persist_props(void);
extern void load_all_props(void);
extern void start_property_service(void);
void get_property_workspace(int *fd, int *sz);
extern int __property_get(const char *name, char *value);
extern int property_set(const char *name, const char *value);
extern bool properties_initialized();

#ifndef __clang__
extern void __property_get_size_error()
    __attribute__((__error__("property_get called with too small buffer")));
#else
extern void __property_get_size_error();
#endif

static inline
__attribute__ ((always_inline))
__attribute__ ((gnu_inline))
#ifndef __clang__
__attribute__ ((artificial))
#endif
int property_get(const char *name, char *value)
{
    size_t value_len = __builtin_object_size(value, 0);
    if (value_len != PROP_VALUE_MAX)
        __property_get_size_error();

    return __property_get(name, value);
}

#endif	/* _INIT_PROPERTY_H */
