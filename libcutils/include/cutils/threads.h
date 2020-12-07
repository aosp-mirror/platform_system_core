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

#pragma once

#include  <sys/types.h>

#if !defined(_WIN32)
#include <pthread.h>
#else
#include <windows.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(_WIN32)

typedef struct {
    pthread_mutex_t   lock;
    int               has_tls;
    pthread_key_t     tls;
} thread_store_t;

#define  THREAD_STORE_INITIALIZER  { PTHREAD_MUTEX_INITIALIZER, 0, 0 }

#endif

//
// Deprecated: use android::base::GetThreadId instead, which doesn't truncate on Mac/Windows.
//
extern pid_t gettid();

//
// Deprecated: use `_Thread_local` in C or `thread_local` in C++.
//
#if !defined(_WIN32)
typedef void (*thread_store_destruct_t)(void* x);
extern void* thread_store_get(thread_store_t* x)
        __attribute__((__deprecated__("use thread_local instead")));
extern void thread_store_set(thread_store_t* x, void* y, thread_store_destruct_t z)
        __attribute__((__deprecated__("use thread_local instead")));
#endif

#ifdef __cplusplus
}
#endif
