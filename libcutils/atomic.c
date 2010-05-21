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
#include <cutils/atomic-inline.h>
#ifdef HAVE_WIN32_THREADS
#include <windows.h>
#else
#include <sched.h>
#endif

/*****************************************************************************/
#if defined(HAVE_MACOSX_IPC)

#include <libkern/OSAtomic.h>

void android_atomic_write(int32_t value, volatile int32_t* addr) {
    int32_t oldValue;
    do {
        oldValue = *addr;
    } while (OSAtomicCompareAndSwap32Barrier(oldValue, value, (int32_t*)addr) == 0);
}

int32_t android_atomic_inc(volatile int32_t* addr) {
    return OSAtomicIncrement32Barrier((int32_t*)addr)-1;
}

int32_t android_atomic_dec(volatile int32_t* addr) {
    return OSAtomicDecrement32Barrier((int32_t*)addr)+1;
}

int32_t android_atomic_add(int32_t value, volatile int32_t* addr) {
    return OSAtomicAdd32Barrier(value, (int32_t*)addr)-value;
}

int32_t android_atomic_and(int32_t value, volatile int32_t* addr) {
    int32_t oldValue;
    do {
        oldValue = *addr;
    } while (OSAtomicCompareAndSwap32Barrier(oldValue, oldValue&value, (int32_t*)addr) == 0);
    return oldValue;
}

int32_t android_atomic_or(int32_t value, volatile int32_t* addr) {
    int32_t oldValue;
    do {
        oldValue = *addr;
    } while (OSAtomicCompareAndSwap32Barrier(oldValue, oldValue|value, (int32_t*)addr) == 0);
    return oldValue;
}

int32_t android_atomic_swap(int32_t value, volatile int32_t* addr) {
    int32_t oldValue;
    do {
        oldValue = *addr;
    } while (android_atomic_cmpxchg(oldValue, value, addr));
    return oldValue;
}

int android_atomic_cmpxchg(int32_t oldvalue, int32_t newvalue, volatile int32_t* addr) {
    /* OS X CAS returns zero on failure; invert to return zero on success */
    return OSAtomicCompareAndSwap32Barrier(oldvalue, newvalue, (int32_t*)addr) == 0;
}

int android_atomic_acquire_cmpxchg(int32_t oldvalue, int32_t newvalue,
        volatile int32_t* addr) {
    int result = (OSAtomicCompareAndSwap32(oldvalue, newvalue, (int32_t*)addr) == 0);
    if (!result) {
        /* success, perform barrier */
        OSMemoryBarrier();
    }
}

/*****************************************************************************/
#elif defined(__i386__) || defined(__x86_64__)

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

int android_atomic_cmpxchg(int32_t oldvalue, int32_t newvalue, volatile int32_t* addr) {
    android_membar_full();
    int xchg;
    asm volatile
    (
    "   lock; cmpxchg %%ecx, (%%edx);"
    "   setne %%al;"
    "   andl $1, %%eax"
    : "=a" (xchg)
    : "a" (oldvalue), "c" (newvalue), "d" (addr)
    );
    return xchg;
}

int android_atomic_acquire_cmpxchg(int32_t oldvalue, int32_t newvalue,
        volatile int32_t* addr) {
    int xchg;
    asm volatile
    (
    "   lock; cmpxchg %%ecx, (%%edx);"
    "   setne %%al;"
    "   andl $1, %%eax"
    : "=a" (xchg)
    : "a" (oldvalue), "c" (newvalue), "d" (addr)
    );
    android_membar_full();
    return xchg;
}


/*****************************************************************************/
#elif __arm__
// implementation for ARM is in atomic-android-arm.s.

/*****************************************************************************/
#elif __sh__
// implementation for SuperH is in atomic-android-sh.c.

#else

#error "Unsupported atomic operations for this platform"

#endif

