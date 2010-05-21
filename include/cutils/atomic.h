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

#ifndef ANDROID_CUTILS_ATOMIC_H
#define ANDROID_CUTILS_ATOMIC_H

#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Unless otherwise noted, the operations below perform a full fence before
 * the atomic operation on SMP systems ("release" semantics).
 */

void android_atomic_write(int32_t value, volatile int32_t* addr);

/*
 * all these atomic operations return the previous value
 */

int32_t android_atomic_inc(volatile int32_t* addr);
int32_t android_atomic_dec(volatile int32_t* addr);

int32_t android_atomic_add(int32_t value, volatile int32_t* addr);
int32_t android_atomic_and(int32_t value, volatile int32_t* addr);
int32_t android_atomic_or(int32_t value, volatile int32_t* addr);

int32_t android_atomic_swap(int32_t value, volatile int32_t* addr);

/*
 * cmpxchg returns zero if the new value was successfully written.  This
 * will only happen when *addr == oldvalue.
 *
 * (The return value is inverted from implementations on other platforms, but
 * matches the ARM ldrex/strex sematics.  Note also this is a compare-and-set
 * operation, not a compare-and-exchange operation, since we don't return
 * the original value.)
 */
int android_atomic_cmpxchg(int32_t oldvalue, int32_t newvalue,
        volatile int32_t* addr);

/*
 * Same basic operation as android_atomic_cmpxchg, but with "acquire"
 * semantics.  The memory barrier, if required, is performed after the
 * new value is stored.  Useful for acquiring a spin lock.
 */
int android_atomic_acquire_cmpxchg(int32_t oldvalue, int32_t newvalue,
        volatile int32_t* addr);

/*
 * Perform an atomic store with "release" semantics.  The memory barrier,
 * if required, is performed before the store instruction.  Useful for
 * releasing a spin lock.
 */
#define android_atomic_release_store android_atomic_write

#ifdef __cplusplus
} // extern "C"
#endif

#endif // ANDROID_CUTILS_ATOMIC_H
