/*
 * Copyright (C) 2008 The Android Open Source Project
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


    .text
    .align
    
    .global android_atomic_write
    
    .global android_atomic_inc
    .global android_atomic_dec
    
    .global android_atomic_add
    .global android_atomic_and
    .global android_atomic_or
    
    .global android_atomic_swap
    
    .global android_atomic_cmpxchg
    


/* FIXME: On SMP systems memory barriers may be needed */
#warning  "this file is not safe with SMP systems"


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
    mov     r12, r0
1:  ldrex   r0, [r12]
    add     r2, r0, #1
    strex   r1, r2, [r12]
    cmp     r1, #0
    bxeq    lr
    b       1b

/*
 * ----------------------------------------------------------------------------
 * android_atomic_dec
 * input: r0=address
 * output: r0 = old value
 */
 
android_atomic_dec:
    mov     r12, r0
1:  ldrex   r0, [r12]
    sub     r2, r0, #1
    strex   r1, r2, [r12]
    cmp     r1, #0
    bxeq    lr
    b       1b

    
/*
 * ----------------------------------------------------------------------------
 * android_atomic_add
 * input: r0=value, r1=address
 * output: r0 = old value
 */

android_atomic_add:
    mov     r12, r0
1:  ldrex   r0, [r1]
    add     r2, r0, r12
    strex   r3, r2, [r1]
    cmp     r3, #0
    bxeq    lr
    b       1b
    
/*
 * ----------------------------------------------------------------------------
 * android_atomic_and
 * input: r0=value, r1=address
 * output: r0 = old value
 */

android_atomic_and:
    mov     r12, r0
1:  ldrex   r0, [r1]
    and     r2, r0, r12
    strex   r3, r2, [r1]
    cmp     r3, #0
    bxeq    lr
    b       1b

    
/*
 * ----------------------------------------------------------------------------
 * android_atomic_or
 * input: r0=value, r1=address
 * output: r0 = old value
 */

android_atomic_or:
    mov     r12, r0
1:  ldrex   r0, [r1]
    orr     r2, r0, r12
    strex   r3, r2, [r1]
    cmp     r3, #0
    bxeq    lr
    b       1b

/*
 * ----------------------------------------------------------------------------
 * android_atomic_swap
 * input: r0=value, r1=address
 * output: r0 = old value
 */

android_atomic_swap:
    swp     r0, r0, [r1]
    bx      lr

/*
 * ----------------------------------------------------------------------------
 * android_atomic_cmpxchg
 * input: r0=oldvalue, r1=newvalue, r2=address
 * output: r0 = 0 (xchg done) or non-zero (xchg not done)
 */

android_atomic_cmpxchg:
    mov     r12, r1
    ldrex   r3, [r2]
    eors    r0, r0, r3
    strexeq r0, r12, [r2]
    bx      lr



/*
 * ----------------------------------------------------------------------------
 * android_atomic_cmpxchg_64
 * input: r0-r1=oldvalue, r2-r3=newvalue, arg4 (on stack)=address
 * output: r0 = 0 (xchg done) or non-zero (xchg not done)
 */
/* TODO: NEED IMPLEMENTATION FOR THIS ARCHITECTURE */
