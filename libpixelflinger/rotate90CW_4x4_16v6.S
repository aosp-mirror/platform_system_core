/*
**
** Copyright 2006, The Android Open Source Project
**
** Licensed under the Apache License, Version 2.0 (the "License"); 
** you may not use this file except in compliance with the License. 
** You may obtain a copy of the License at 
**
**     http://www.apache.org/licenses/LICENSE-2.0 
**
** Unless required by applicable law or agreed to in writing, software 
** distributed under the License is distributed on an "AS IS" BASIS, 
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
** See the License for the specific language governing permissions and 
** limitations under the License.
*/


    .text
    .align
    
    .global rotate90CW_4x4_16v6

// Rotates 90deg CW a 4x4 block of 16bpp pixels using ARMv6
// src and dst must be 4 pixels-aligned (2-pixels aligned might
// actually work)
//
// The code below is complicated by ARM's little endianness. 

rotate90CW_4x4_16v6:
    // r0 = dst
    // r1 = src
    // r2 = dst stride in pixels
    // r3 = src stride in pixels

    stmfd   sp!, {r4,r5, r6,r7, r8,r9, r10,r11, lr}
    add     r14, r3, r3
    add     r12, r2, r2

    ldrd    r2, r3, [r1], r14
    ldrd    r4, r5, [r1], r14
    ldrd    r6, r7, [r1], r14
    ldrd    r8, r9, [r1]

    pkhbt   r10, r8, r6, lsl #16
    pkhbt   r11, r4, r2, lsl #16
    strd    r10, r11, [r0], r12  

    pkhtb   r10, r6, r8, asr #16
    pkhtb   r11, r2, r4, asr #16

    strd    r10, r11, [r0], r12  
    pkhbt   r10, r9, r7, lsl #16
    pkhbt   r11, r5, r3, lsl #16

    strd    r10, r11, [r0], r12  

    pkhtb   r10, r7, r9, asr #16
    pkhtb   r11, r3, r5, asr #16
    strd    r10, r11, [r0]

    ldmfd   sp!, {r4,r5, r6,r7, r8,r9, r10,r11, pc}
