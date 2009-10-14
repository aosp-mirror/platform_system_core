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

#include <cutils/atomic.h>
#ifdef HAVE_WIN32_THREADS
#include <windows.h>
#else
#include <sched.h>
#endif

/*
 * Note :
 *
 * (1) SuperH does not have CMPXCHG.  It has only TAS for atomic
 *     operations.  It does not seem a good idea to implement CMPXCHG,
 *     with TAS.  So, we choose to implemnt these operations with
 *     posix mutexes.  Please be sure that this might cause performance
 *     problem for Android-SH. Using LL/SC instructions supported in SH-X3,
 *     best performnace would be realized.
 *
 * (2) Mutex initialization problem happens, which is commented for
 *     ARM implementation, in this file above.
 *     We follow the fact that the initializer for mutex is a simple zero
 *     value.
 */

#include <pthread.h>

#define  SWAP_LOCK_COUNT  32U
static pthread_mutex_t  _swap_locks[SWAP_LOCK_COUNT];

#define  SWAP_LOCK(addr)   \
   &_swap_locks[((unsigned)(void*)(addr) >> 3U) % SWAP_LOCK_COUNT]


void android_atomic_write(int32_t value, volatile int32_t* addr) {
    int32_t oldValue;
    do {
        oldValue = *addr;
    } while (android_atomic_cmpxchg(oldValue, value, addr));
}

int32_t android_atomic_inc(volatile int32_t* addr) {
    int32_t oldValue;
    do {
        oldValue = *addr;
    } while (android_atomic_cmpxchg(oldValue, oldValue+1, addr));
    return oldValue;
}

int32_t android_atomic_dec(volatile int32_t* addr) {
    int32_t oldValue;
    do {
        oldValue = *addr;
    } while (android_atomic_cmpxchg(oldValue, oldValue-1, addr));
    return oldValue;
}

int32_t android_atomic_add(int32_t value, volatile int32_t* addr) {
    int32_t oldValue;
    do {
        oldValue = *addr;
    } while (android_atomic_cmpxchg(oldValue, oldValue+value, addr));
    return oldValue;
}

int32_t android_atomic_and(int32_t value, volatile int32_t* addr) {
    int32_t oldValue;
    do {
        oldValue = *addr;
    } while (android_atomic_cmpxchg(oldValue, oldValue&value, addr));
    return oldValue;
}

int32_t android_atomic_or(int32_t value, volatile int32_t* addr) {
    int32_t oldValue;
    do {
        oldValue = *addr;
    } while (android_atomic_cmpxchg(oldValue, oldValue|value, addr));
    return oldValue;
}

int32_t android_atomic_swap(int32_t value, volatile int32_t* addr) {
    int32_t oldValue;
    do {
        oldValue = *addr;
    } while (android_atomic_cmpxchg(oldValue, value, addr));
    return oldValue;
}

int android_atomic_cmpxchg(int32_t oldvalue, int32_t newvalue,
                           volatile int32_t* addr) {
    int result;
    pthread_mutex_t*  lock = SWAP_LOCK(addr);

    pthread_mutex_lock(lock);

    if (*addr == oldvalue) {
        *addr  = newvalue;
        result = 0;
    } else {
        result = 1;
    }
    pthread_mutex_unlock(lock);
    return result;
}

int64_t android_quasiatomic_swap_64(int64_t value, volatile int64_t* addr) {
    int64_t oldValue;
    pthread_mutex_t*  lock = SWAP_LOCK(addr);

    pthread_mutex_lock(lock);

    oldValue = *addr;
    *addr    = value;

    pthread_mutex_unlock(lock);
    return oldValue;
}

int android_quasiatomic_cmpxchg_64(int64_t oldvalue, int64_t newvalue,
        volatile int64_t* addr) {
    int result;
    pthread_mutex_t*  lock = SWAP_LOCK(addr);

    pthread_mutex_lock(lock);

    if (*addr == oldvalue) {
        *addr  = newvalue;
        result = 0;
    } else {
        result = 1;
    }
    pthread_mutex_unlock(lock);
    return result;
}

int64_t android_quasiatomic_read_64(volatile int64_t* addr) {
    int64_t result;
    pthread_mutex_t*  lock = SWAP_LOCK(addr);

    pthread_mutex_lock(lock);
    result = *addr;
    pthread_mutex_unlock(lock);
    return result;
}
