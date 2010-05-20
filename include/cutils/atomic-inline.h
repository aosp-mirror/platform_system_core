/*
 * Copyright (C) 2010 The Android Open Source Project
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

#ifndef ANDROID_CUTILS_ATOMIC_INLINE_H
#define ANDROID_CUTILS_ATOMIC_INLINE_H

/*
 * Inline declarations and macros for some special-purpose atomic
 * operations.  These are intended for rare circumstances where a
 * memory barrier needs to be issued inline rather than as a function
 * call.
 *
 * Most code should not use these.
 *
 * Anything that does include this file must set ANDROID_SMP to either
 * 0 or 1, indicating compilation for UP or SMP, respectively.
 */

#if !defined(ANDROID_SMP)
# error "Must define ANDROID_SMP before including atomic-inline.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Define the full memory barrier for an SMP system.  This is
 * platform-specific.
 */

#ifdef __arm__
#include <machine/cpu-features.h>

/*
 * For ARMv6K we need to issue a specific MCR instead of the DMB, since
 * that wasn't added until v7.  For anything older, SMP isn't relevant.
 * Since we don't have an ARMv6K to test with, we're not going to deal
 * with that now.
 *
 * The DMB instruction is found in the ARM and Thumb2 instruction sets.
 * This will fail on plain 16-bit Thumb.
 */
#if defined(__ARM_HAVE_DMB)
# define __android_membar_full_smp() \
    do { __asm__ __volatile__ ("dmb" ::: "memory"); } while (0)
#else
# define __android_membar_full_smp()  ARM_SMP_defined_but_no_DMB()
#endif

#elif defined(__i386__) || defined(__x86_64__)
/*
 * For recent x86, we can use the SSE2 mfence instruction.
 */
# define __android_membar_full_smp() \
    do { __asm__ __volatile__ ("mfence" ::: "memory"); } while (0)

#else
/*
 * Implementation not defined for this platform.  Hopefully we're building
 * in uniprocessor mode.
 */
# define __android_membar_full_smp()  SMP_barrier_not_defined_for_platform()
#endif


/*
 * Full barrier.  On uniprocessors this is just a compiler reorder barrier,
 * which ensures that the statements appearing above the barrier in the C/C++
 * code will be issued after the statements appearing below the barrier.
 *
 * For SMP this also includes a memory barrier instruction.  On an ARM
 * CPU this means that the current core will flush pending writes, wait
 * for pending reads to complete, and discard any cached reads that could
 * be stale.  Other CPUs may do less, but the end result is equivalent.
 */
#if ANDROID_SMP != 0
# define android_membar_full() __android_membar_full_smp()
#else
# define android_membar_full() \
    do { __asm__ __volatile__ ("" ::: "memory"); } while (0)
#endif

#ifdef __cplusplus
} // extern "C"
#endif

#endif // ANDROID_CUTILS_ATOMIC_INLINE_H
