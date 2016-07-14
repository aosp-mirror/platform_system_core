/* libs/pixelflinger/t32cb16blend.S
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
	.syntax unified
	.balign 4
	
	.global scanline_t32cb16blend_arm


/*
 * .macro pixel
 *
 * \DREG is a 32-bit register containing *two* original destination RGB565 
 *       pixels, with the even one in the low-16 bits, and the odd one in the
 *       high 16 bits.
 *
 * \SRC is a 32-bit 0xAABBGGRR pixel value, with pre-multiplied colors.
 *
 * \FB is a target register that will contain the blended pixel values.
 *
 * \ODD is either 0 or 1 and indicates if we're blending the lower or 
 *      upper 16-bit pixels in DREG into FB
 *
 *
 * clobbered: r6, r7, lr
 *
 */

.macro pixel,   DREG, SRC, FB, ODD

    // SRC = 0xAABBGGRR
    mov     r7, \SRC, lsr #24           // sA
    add     r7, r7, r7, lsr #7          // sA + (sA >> 7)
    rsb     r7, r7, #0x100              // sA = 0x100 - (sA+(sA>>7))

1:

.if \ODD

    // red
    mov     lr, \DREG, lsr #(16 + 11)
    smulbb  lr, r7, lr
    mov     r6, \SRC, lsr #3
    and     r6, r6, #0x1F
    add     lr, r6, lr, lsr #8
    cmp     lr, #0x1F
    orrhs   \FB, \FB, #(0x1F<<(16 + 11))
    orrlo   \FB, \FB, lr, lsl #(16 + 11)

        // green
        and     r6, \DREG, #(0x3F<<(16 + 5))
        smulbt  r6, r7, r6
        mov     lr, \SRC, lsr #(8+2)
        and     lr, lr, #0x3F
        add     r6, lr, r6, lsr #(5+8)
        cmp     r6, #0x3F
        orrhs   \FB, \FB, #(0x3F<<(16 + 5))
        orrlo   \FB, \FB, r6, lsl #(16 + 5)

            // blue
            and     lr, \DREG, #(0x1F << 16)
            smulbt  lr, r7, lr
            mov     r6, \SRC, lsr #(8+8+3)
            and     r6, r6, #0x1F
            add     lr, r6, lr, lsr #8
            cmp     lr, #0x1F
            orrhs   \FB, \FB, #(0x1F << 16)
            orrlo   \FB, \FB, lr, lsl #16

.else

    // red
    mov     lr, \DREG, lsr #11
    and     lr, lr, #0x1F
    smulbb  lr, r7, lr
    mov     r6, \SRC, lsr #3
    and     r6, r6, #0x1F
    add     lr, r6, lr, lsr #8
    cmp     lr, #0x1F
    movhs   \FB, #(0x1F<<11)
    movlo   \FB, lr, lsl #11


        // green
        and     r6, \DREG, #(0x3F<<5)
        smulbb  r6, r7, r6
        mov     lr, \SRC, lsr #(8+2)
        and     lr, lr, #0x3F
        add     r6, lr, r6, lsr #(5+8)
        cmp     r6, #0x3F
        orrhs   \FB, \FB, #(0x3F<<5)
        orrlo   \FB, \FB, r6, lsl #5

            // blue
            and     lr, \DREG, #0x1F
            smulbb  lr, r7, lr
            mov     r6, \SRC, lsr #(8+8+3)
            and     r6, r6, #0x1F
            add     lr, r6, lr, lsr #8
            cmp     lr, #0x1F
            orrhs   \FB, \FB, #0x1F
            orrlo   \FB, \FB, lr

.endif

    .endm
    

// r0:  dst ptr
// r1:  src ptr
// r2:  count
// r3:  d
// r4:  s0
// r5:  s1
// r6:  pixel
// r7:  pixel
// r8:  free
// r9:  free
// r10: free
// r11: free
// r12: scratch
// r14: pixel

scanline_t32cb16blend_arm:
    stmfd	sp!, {r4-r7, lr}

    pld     [r0]
    pld     [r1]

    // align DST to 32 bits
    tst     r0, #0x3
    beq     aligned
    subs    r2, r2, #1
    ldmfdlo sp!, {r4-r7, lr}        // return
    bxlo    lr

last:
    ldr     r4, [r1], #4
    ldrh    r3, [r0]
    pixel   r3, r4, r12, 0
    strh    r12, [r0], #2

aligned:
    subs    r2, r2, #2
    blo     9f

    // The main loop is unrolled twice and processes 4 pixels
8:  ldmia   r1!, {r4, r5}
    // stream the source
    pld     [r1, #32]
    add     r0, r0, #4
    // it's all zero, skip this pixel
    orrs    r3, r4, r5
    beq     7f
    
    // load the destination
    ldr     r3, [r0, #-4]
    // stream the destination
    pld     [r0, #32]
    pixel   r3, r4, r12, 0
    pixel   r3, r5, r12, 1
    // effectively, we're getting write-combining by virtue of the
    // cpu's write-back cache.
    str     r12, [r0, #-4]

    // 2nd iterration of the loop, don't stream anything
    subs    r2, r2, #2
    movlt   r4, r5
    blt     9f
    ldmia   r1!, {r4, r5}
    add     r0, r0, #4
    orrs    r3, r4, r5
    beq     7f
    ldr     r3, [r0, #-4]
    pixel   r3, r4, r12, 0
    pixel   r3, r5, r12, 16
    str     r12, [r0, #-4]

    
7:  subs    r2, r2, #2
    bhs     8b
    mov     r4, r5

9:  adds    r2, r2, #1
    ldmfdlo sp!, {r4-r7, lr}        // return
    bxlo    lr
    b       last
