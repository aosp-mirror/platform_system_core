/*
 * Copyright (C) 2005 The Android Open Source Project
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

#include <machine/cpu-features.h>

    .text
    .align

    .global android_atomic_acquire_load
    .type android_atomic_acquire_load, %function
    .global android_atomic_release_load
    .type android_atomic_release_load, %function

    .global android_atomic_acquire_store
    .type android_atomic_acquire_store, %function
    .global android_atomic_release_store
    .type android_atomic_release_store, %function

    .global android_atomic_inc
    .type android_atomic_inc, %function
    .global android_atomic_dec
    .type android_atomic_dec, %function

    .global android_atomic_add
    .type android_atomic_add, %function
    .global android_atomic_and
    .type android_atomic_and, %function
    .global android_atomic_or
    .type android_atomic_or, %function

    .global android_atomic_release_swap
    .type android_atomic_release_swap, %function
    .global android_atomic_acquire_swap
    .type android_atomic_acquire_swap, %function

    .global android_atomic_release_cas
    .type android_atomic_release_cas, %function
    .global android_atomic_acquire_cas
    .type android_atomic_acquire_cas, %function

/* must be on or off; cannot be left undefined */
#if !defined(ANDROID_SMP)
# error "ANDROID_SMP not defined"
#endif


#if defined(__ARM_HAVE_LDREX_STREX)
/*
 * ===========================================================================
 *      ARMv6+ implementation
 * ===========================================================================
 *
 * These functions use the LDREX/STREX instructions to perform atomic
 * operations ("LL/SC" approach).  On an SMP build they will include
 * an appropriate memory barrier.
 */

/* generate the memory barrier instruction when the build requires it */
#if ANDROID_SMP == 1
# if defined(__ARM_HAVE_DMB)
#  define SMP_DMB dmb
# else
   /* Data Memory Barrier operation, initated by writing a value into a
      specific register with the Move to Coprocessor instruction.  We
      arbitrarily use r0 here. */
#  define SMP_DMB mcr p15, 0, r0, c7, c10, 5
# endif
#else
# define SMP_DMB
#endif

/*
 * Sidebar: do we need to use the -EX instructions for atomic load/store?
 *
 * Consider the following situation (time advancing downward):
 *
 * P1                  P2
 *  val = LDREX(mem)
 *  val = val + 1
 *                      STR(mem, otherval)
 *  STREX(mem, val)
 *
 * If these instructions issue on separate cores, the STREX will correctly
 * fail because of the intervening store from the other core.  If this same
 * sequence of instructions executes in two threads on the same core, the
 * STREX will incorrectly succeed.
 *
 * There are two ways to fix this:
 * (1) Use LDREX/STREX for the atomic store operations.  This doesn't
 *   prevent the program from doing a non-exclusive store, but at least
 *   this way if they always use atomic ops to access the memory location
 *   there won't be any problems.
 * (2) Have the kernel clear the LDREX reservation on thread context switch.
 *  This will sometimes clear the reservation unnecessarily, but guarantees
 *  correct behavior.
 *
 * The Android kernel performs a CLREX (v7) or dummy STREX (pre-v7), so we
 * can get away with a non-exclusive store here.
 *
 * -----
 *
 * It's worth noting that using non-exclusive LDR and STR means the "load"
 * and "store" operations aren't quite the same as read-modify-write or
 * swap operations.  By definition those must read and write memory in a
 * in a way that is coherent across all cores, whereas our non-exclusive
 * load and store have no such requirement.
 *
 * In practice this doesn't matter, because the only guarantees we make
 * about who sees what when are tied to the acquire/release semantics.
 * Other cores may not see our atomic releasing store as soon as they would
 * if the code used LDREX/STREX, but a store-release operation doesn't make
 * any guarantees as to how soon the store will be visible.  It's allowable
 * for operations that happen later in program order to become visible
 * before the store.  For an acquring store we issue a full barrier after
 * the STREX, ensuring that other processors see events in the proper order.
 */

/*
 * android_atomic_acquire_load / android_atomic_release_load
 * input: r0 = address
 * output: r0 = value
 */
android_atomic_acquire_load:
    .fnstart
    ldr     r0, [r0]
    SMP_DMB
    bx      lr
    .fnend

android_atomic_release_load:
    .fnstart
    SMP_DMB
    ldr     r0, [r0]
    bx      lr
    .fnend


/*
 * android_atomic_acquire_store / android_atomic_release_store
 * input: r0 = value, r1 = address
 * output: void
 */
android_atomic_acquire_store:
    .fnstart
    str     r0, [r1]
    SMP_DMB
    bx      lr
    .fnend

android_atomic_release_store:
    .fnstart
    SMP_DMB
    str     r0, [r1]
    bx      lr
    .fnend

/*
 * Common sequence for read-modify-write operations.
 *
 * input: r1 = address
 * output: r0 = original value, returns to caller
 */
    .macro  RMWEX   op, arg
1:  ldrex   r0, [r1]                    @ load current value into r0
    \op     r2, r0, \arg                @ generate new value into r2
    strex   r3, r2, [r1]                @ try to store new value; result in r3
    cmp     r3, #0                      @ success?
    bxeq    lr                          @ yes, return
    b       1b                          @ no, retry
    .endm


/*
 * android_atomic_inc
 * input: r0 = address
 * output: r0 = old value
 */
android_atomic_inc:
    .fnstart
    SMP_DMB
    mov     r1, r0
    RMWEX   add, #1
    .fnend


/*
 * android_atomic_dec
 * input: r0 = address
 * output: r0 = old value
 */
android_atomic_dec:
    .fnstart
    SMP_DMB
    mov     r1, r0
    RMWEX   sub, #1
    .fnend


/*
 * android_atomic_add
 * input: r0 = value, r1 = address
 * output: r0 = old value
 */
android_atomic_add:
    .fnstart
    SMP_DMB
    mov     ip, r0
    RMWEX   add, ip
    .fnend


/*
 * android_atomic_and
 * input: r0 = value, r1 = address
 * output: r0 = old value
 */
android_atomic_and:
    .fnstart
    SMP_DMB
    mov     ip, r0
    RMWEX   and, ip
    .fnend


/*
 * android_atomic_or
 * input: r0 = value, r1 = address
 * output: r0 = old value
 */
android_atomic_or:
    .fnstart
    SMP_DMB
    mov     ip, r0
    RMWEX   orr, ip
    .fnend


/*
 * android_atomic_acquire_swap / android_atomic_release_swap
 * input: r0 = value, r1 = address
 * output: r0 = old value
 */
android_atomic_acquire_swap:
    .fnstart
1:  ldrex   r2, [r1]                    @ load current value into r2
    strex   r3, r0, [r1]                @ store new value
    teq     r3, #0                      @ strex success?
    bne     1b                          @ no, loop
    mov     r0, r2                      @ return old value
    SMP_DMB
    bx      lr
    .fnend

android_atomic_release_swap:
    .fnstart
    SMP_DMB
1:  ldrex   r2, [r1]
    strex   r3, r0, [r1]
    teq     r3, #0
    bne     1b
    mov     r0, r2
    bx      lr
    .fnend


/*
 * android_atomic_acquire_cas / android_atomic_release_cas
 * input: r0 = oldvalue, r1 = newvalue, r2 = address
 * output: r0 = 0 (xchg done) or non-zero (xchg not done)
 */
android_atomic_acquire_cas:
    .fnstart
1:  mov     ip, #2                      @ ip=2 means "new != old"
    ldrex   r3, [r2]                    @ load current value into r3
    teq     r0, r3                      @ new == old?
    strexeq ip, r1, [r2]                @ yes, try store, set ip to 0 or 1
    teq     ip, #1                      @ strex failure?
    beq     1b                          @ yes, retry
    mov     r0, ip                      @ return 0 on success, 2 on failure
    SMP_DMB
    bx      lr
    .fnend

android_atomic_release_cas:
    .fnstart
    SMP_DMB
1:  mov     ip, #2
    ldrex   r3, [r2]
    teq     r0, r3
    strexeq ip, r1, [r2]
    teq     ip, #1
    beq     1b
    mov     r0, ip
    bx      lr
    .fnend


#else /*not defined __ARM_HAVE_LDREX_STREX*/
/*
 * ===========================================================================
 *      Pre-ARMv6 implementation
 * ===========================================================================
 *
 * These functions call through the kernel cmpxchg facility, or use the
 * (now deprecated) SWP instruction.  They are not SMP-safe.
 */
#if ANDROID_SMP == 1
# error "SMP defined, but LDREX/STREX not available"
#endif

/*
 * int __kernel_cmpxchg(int oldval, int newval, int *ptr)
 * clobbered: r3, ip, flags
 * return 0 if a swap was made, non-zero otherwise.
 */ 
   .equ     kernel_cmpxchg, 0xFFFF0FC0
   .equ     kernel_atomic_base, 0xFFFF0FFF


/*
 * android_atomic_acquire_load / android_atomic_release_load
 * input: r0 = address
 * output: r0 = value
 */
android_atomic_acquire_load:
android_atomic_release_load:
    .fnstart
    ldr     r0, [r0]
    bx      lr
    .fnend


/*
 * android_atomic_acquire_store / android_atomic_release_store
 * input: r0 = value, r1 = address
 * output: void
 */
android_atomic_acquire_store:
android_atomic_release_store:
    .fnstart
    str     r0, [r1]
    bx      lr
    .fnend


/*
 * android_atomic_inc
 * input: r0 = address
 * output: r0 = old value
 */
android_atomic_inc:
    .fnstart
    .save {r4, lr}
    stmdb   sp!, {r4, lr}
    mov     r2, r0
1: @ android_atomic_inc
    ldr     r0, [r2]
    mov     r3, #kernel_atomic_base
#ifdef __ARM_HAVE_PC_INTERWORK
    add     lr, pc, #4
    add     r1, r0, #1
    add     pc, r3, #(kernel_cmpxchg - kernel_atomic_base)
#else
    add     r1, r0, #1
    add     r3, r3, #(kernel_cmpxchg - kernel_atomic_base)
    mov     lr, pc
    bx      r3
#endif
    bcc     1b
    sub     r0, r1, #1
    ldmia   sp!, {r4, lr}
    bx      lr
    .fnend


/*
 * android_atomic_dec
 * input: r0 = address
 * output: r0 = old value
 */
android_atomic_dec:
    .fnstart
    .save {r4, lr}
    stmdb   sp!, {r4, lr}
    mov     r2, r0
1: @ android_atomic_dec
    ldr     r0, [r2]
    mov     r3, #kernel_atomic_base
#ifdef __ARM_HAVE_PC_INTERWORK
    add     lr, pc, #4
    sub     r1, r0, #1
    add     pc, r3, #(kernel_cmpxchg - kernel_atomic_base)
#else
    sub     r1, r0, #1
    add     r3, r3, #(kernel_cmpxchg - kernel_atomic_base)
    mov     lr, pc
    bx      r3
#endif
    bcc     1b
    add     r0, r1, #1
    ldmia   sp!, {r4, lr}
    bx      lr
    .fnend


/*
 * android_atomic_add
 * input: r0 = value, r1 = address
 * output: r0 = old value
 */
android_atomic_add:
    .fnstart
    .save {r4, lr}
    stmdb   sp!, {r4, lr}
    mov     r2, r1
    mov     r4, r0
1: @ android_atomic_add
    ldr     r0, [r2]
    mov     r3, #kernel_atomic_base
#ifdef __ARM_HAVE_PC_INTERWORK
    add     lr, pc, #4
    add     r1, r0, r4
    add     pc, r3, #(kernel_cmpxchg - kernel_atomic_base)
#else
    add     r1, r0, r4
    add     r3, r3, #(kernel_cmpxchg - kernel_atomic_base)
    mov     lr, pc
    bx      r3
#endif
    bcc     1b
    sub     r0, r1, r4
    ldmia   sp!, {r4, lr}
    bx      lr
    .fnend


/*
 * android_atomic_and
 * input: r0 = value, r1 = address
 * output: r0 = old value
 */
android_atomic_and:
    .fnstart
    .save {r4, r5, ip, lr}      /* include ip for 64-bit stack alignment */
    stmdb   sp!, {r4, r5, ip, lr}
    mov     r2, r1              /* r2 = address */
    mov     r4, r0              /* r4 = the value */
1: @ android_atomic_and
    ldr     r0, [r2]            /* r0 = address[0] */
    mov     r3, #kernel_atomic_base
#ifdef __ARM_HAVE_PC_INTERWORK
    add     lr, pc, #8
    mov     r5, r0              /* r5 = save address[0] */
    and     r1, r0, r4          /* r1 = new value */
    add     pc, r3, #(kernel_cmpxchg - kernel_atomic_base)  /* call cmpxchg() */
#else
    mov     r5, r0              /* r5 = save address[0] */
    and     r1, r0, r4          /* r1 = new value */
    add     r3, r3, #(kernel_cmpxchg - kernel_atomic_base)  /* call cmpxchg() */
    mov     lr, pc
    bx      r3
#endif
    bcc     1b
    mov     r0, r5
    ldmia   sp!, {r4, r5, ip, lr}
    bx      lr
    .fnend


/*
 * android_atomic_or
 * input: r0 = value, r1 = address
 * output: r0 = old value
 */
android_atomic_or:
    .fnstart
    .save {r4, r5, ip, lr}      /* include ip for 64-bit stack alignment */
    stmdb   sp!, {r4, r5, ip, lr}
    mov     r2, r1              /* r2 = address */
    mov     r4, r0              /* r4 = the value */
1: @ android_atomic_or
    ldr     r0, [r2]            /* r0 = address[0] */
    mov     r3, #kernel_atomic_base
#ifdef __ARM_HAVE_PC_INTERWORK
    add     lr, pc, #8
    mov     r5, r0              /* r5 = save address[0] */
    orr     r1, r0, r4          /* r1 = new value */
    add     pc, r3, #(kernel_cmpxchg - kernel_atomic_base)  /* call cmpxchg() */
#else
    mov     r5, r0              /* r5 = save address[0] */
    orr     r1, r0, r4          /* r1 = new value */
    add     r3, r3, #(kernel_cmpxchg - kernel_atomic_base)  /* call cmpxchg() */
    mov     lr, pc
    bx      r3
#endif
    bcc     1b
    mov     r0, r5
    ldmia   sp!, {r4, r5, ip, lr}
    bx      lr
    .fnend


/*
 * android_atomic_acquire_swap / android_atomic_release_swap
 * input: r0 = value, r1 = address
 * output: r0 = old value
 */
android_atomic_acquire_swap:
android_atomic_release_swap:
    .fnstart
    swp     r0, r0, [r1]
    bx      lr
    .fnend


/*
 * android_atomic_acquire_cas / android_atomic_release_cas
 * input: r0 = oldvalue, r1 = newvalue, r2 = address
 * output: r0 = 0 (xchg done) or non-zero (xchg not done)
 */
android_atomic_acquire_cas:
android_atomic_release_cas:
    .fnstart
    .save {r4, lr}
    stmdb   sp!, {r4, lr}
    mov     r4, r0          /* r4 = save oldvalue */
1: @ android_atomic_cmpxchg
    mov     r3, #kernel_atomic_base
#ifdef __ARM_HAVE_PC_INTERWORK
    add     lr, pc, #4
    mov     r0, r4          /* r0 = oldvalue */
    add     pc, r3, #(kernel_cmpxchg - kernel_atomic_base)
#else
    mov     r0, r4          /* r0 = oldvalue */
    add     r3, r3, #(kernel_cmpxchg - kernel_atomic_base)
    mov     lr, pc
    bx      r3
#endif
    bcs     2f              /* swap was made. we're good, return. */
    ldr     r3, [r2]        /* swap not made, see if it's because *ptr!=oldvalue */
    cmp     r3, r4
    beq     1b
2: @ android_atomic_cmpxchg
    ldmia   sp!, {r4, lr}
    bx      lr
    .fnend

#endif /*not defined __ARM_HAVE_LDREX_STREX*/
