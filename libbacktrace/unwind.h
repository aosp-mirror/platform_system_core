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

#ifndef _UNWIND_H
#define _UNWIND_H

bool local_get_data(backtrace_t* backtrace);

void local_free_data(backtrace_t* backtrace);

char* local_get_proc_name(const backtrace_t* backtrace, uintptr_t pc,
                          uintptr_t* offset);

bool remote_get_data(backtrace_t* backtrace);

void remote_free_data(backtrace_t* backtrace);

char* remote_get_proc_name(const backtrace_t* backtrace, uintptr_t pc,
                           uintptr_t* offset);

#endif /* _UNWIND_H */
