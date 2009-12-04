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

/*
 * NOTE: these atomic operations are SMP safe on all architectures. 
 */

	.text
	.align
	
    .global android_atomic_write
    .type android_atomic_write, %function

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
    
    .global android_atomic_swap
    .type android_atomic_swap, %function
	
	.global android_atomic_cmpxchg
	.type android_atomic_cmpxchg, %function

/*
 * ----------------------------------------------------------------------------
 * int __kernel_cmpxchg(int oldval, int newval, int *ptr)
 * clobbered: r3, ip, flags
 * return 0 if a swap was made, non-zero otherwise.
 */ 

   .equ     kernel_cmpxchg, 0xFFFF0FC0
   .equ     kernel_atomic_base, 0xFFFF0FFF

/*
 * ----------------------------------------------------------------------------
 * android_atomic_write
 * input: r0=value, r1=address
 * output: void
 */
 
android_atomic_write:
    str     r0, [r1]
    bx      lr;

/*
 * ----------------------------------------------------------------------------
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
 * ----------------------------------------------------------------------------
 * android_atomic_dec
 * input: r0=address
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
 * ----------------------------------------------------------------------------
 * android_atomic_add
 * input: r0=value, r1=address
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
 * ----------------------------------------------------------------------------
 * android_atomic_and
 * input: r0=value, r1=address
 * output: r0 = old value
 */

android_atomic_and:
    .fnstart
    .save {r4, r5, lr}
    stmdb   sp!, {r4, r5, lr}   
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
    ldmia   sp!, {r4, r5, lr}
    bx      lr
    .fnend
    
/*
 * ----------------------------------------------------------------------------
 * android_atomic_or
 * input: r0=value, r1=address
 * output: r0 = old value
 */

android_atomic_or:
    .fnstart
    .save {r4, r5, lr}
    stmdb   sp!, {r4, r5, lr}   
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
    ldmia   sp!, {r4, r5, lr}
    bx      lr
    .fnend

/*
 * ----------------------------------------------------------------------------
 * android_atomic_swap
 * input: r0=value, r1=address
 * output: r0 = old value
 */

/* replaced swp instruction with ldrex/strex for ARMv6 & ARMv7 */
android_atomic_swap:
#if defined (_ARM_HAVE_LDREX_STREX)
1:  ldrex   r2, [r1]
    strex   r3, r0, [r1]
    teq     r3, #0
    bne     1b
    mov     r0, r2
    mcr     p15, 0, r0, c7, c10, 5 /* or, use dmb */
#else
    swp     r0, r0, [r1]
#endif
    bx      lr

/*
 * ----------------------------------------------------------------------------
 * android_atomic_cmpxchg
 * input: r0=oldvalue, r1=newvalue, r2=address
 * output: r0 = 0 (xchg done) or non-zero (xchg not done)
 */

android_atomic_cmpxchg:
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

/*
 * ----------------------------------------------------------------------------
 * android_atomic_cmpxchg_64
 * input: r0-r1=oldvalue, r2-r3=newvalue, arg4 (on stack)=address
 * output: r0 = 0 (xchg done) or non-zero (xchg not done)
 */
/* TODO: NEED IMPLEMENTATION FOR THIS ARCHITECTURE */
