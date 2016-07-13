/*
 * Copyright (C) 2013 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
    .text
    .balign 0

    .global scanline_t32cb16blend_arm64

/*
 * .macro pixel
 *
 *  This macro alpha blends RGB565 original pixel located in either
 *  top or bottom 16 bits of DREG register with SRC 32 bit pixel value
 *  and writes the result to FB register
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
 * clobbered: w6, w7, w16, w17, w18
 *
 */

.macro pixel,   DREG, SRC, FB, ODD

    // SRC = 0xAABBGGRR
    lsr     w7, \SRC, #24               // sA
    add     w7, w7, w7, lsr #7          // sA + (sA >> 7)
    mov     w6, #0x100
    sub     w7, w6, w7                  // sA = 0x100 - (sA+(sA>>7))

1:

.if \ODD //Blending odd pixel present in top 16 bits of DREG register

    // red
    lsr     w16, \DREG, #(16 + 11)
    mul     w16, w7, w16
    lsr     w6, \SRC, #3
    and     w6, w6, #0x1F
    add     w16, w6, w16, lsr #8
    cmp     w16, #0x1F
    orr     w17, \FB, #(0x1F<<(16 + 11))
    orr     w18, \FB, w16, lsl #(16 + 11)
    csel    \FB, w17, w18, hi
        // green
        and     w6, \DREG, #(0x3F<<(16 + 5))
        lsr     w17,w6,#(16+5)
        mul     w6, w7, w17
        lsr     w16, \SRC, #(8+2)
        and     w16, w16, #0x3F
        add     w6, w16, w6, lsr #8
        cmp     w6, #0x3F
        orr     w17, \FB, #(0x3F<<(16 + 5))
        orr     w18, \FB, w6, lsl #(16 + 5)
        csel    \FB, w17, w18, hi
            // blue
            and     w16, \DREG, #(0x1F << 16)
            lsr     w17,w16,#16
            mul     w16, w7, w17
            lsr     w6, \SRC, #(8+8+3)
            and     w6, w6, #0x1F
            add     w16, w6, w16, lsr #8
            cmp     w16, #0x1F
            orr     w17, \FB, #(0x1F << 16)
            orr     w18, \FB, w16, lsl #16
            csel    \FB, w17, w18, hi

.else //Blending even pixel present in bottom 16 bits of DREG register

    // red
    lsr     w16, \DREG, #11
    and     w16, w16, #0x1F
    mul     w16, w7, w16
    lsr     w6, \SRC, #3
    and     w6, w6, #0x1F
    add     w16, w6, w16, lsr #8
    cmp     w16, #0x1F
    mov     w17, #(0x1F<<11)
    lsl     w18, w16, #11
    csel    \FB, w17, w18, hi


        // green
        and     w6, \DREG, #(0x3F<<5)
        mul     w6, w7, w6
        lsr     w16, \SRC, #(8+2)
        and     w16, w16, #0x3F
        add     w6, w16, w6, lsr #(5+8)
        cmp     w6, #0x3F
        orr     w17, \FB, #(0x3F<<5)
        orr     w18, \FB, w6, lsl #5
        csel    \FB, w17, w18, hi

            // blue
            and     w16, \DREG, #0x1F
            mul     w16, w7, w16
            lsr     w6, \SRC, #(8+8+3)
            and     w6, w6, #0x1F
            add     w16, w6, w16, lsr #8
            cmp     w16, #0x1F
            orr     w17, \FB, #0x1F
            orr     w18, \FB, w16
            csel    \FB, w17, w18, hi

.endif // End of blending even pixel

.endm // End of pixel macro


// x0:  dst ptr
// x1:  src ptr
// w2:  count
// w3:  d
// w4:  s0
// w5:  s1
// w6:  pixel
// w7:  pixel
// w8:  free
// w9:  free
// w10: free
// w11: free
// w12: scratch
// w14: pixel

scanline_t32cb16blend_arm64:

    // align DST to 32 bits
    tst     x0, #0x3
    b.eq    aligned
    subs    w2, w2, #1
    b.lo    return

last:
    ldr     w4, [x1], #4
    ldrh    w3, [x0]
    pixel   w3, w4, w12, 0
    strh    w12, [x0], #2

aligned:
    subs    w2, w2, #2
    b.lo    9f

    // The main loop is unrolled twice and processes 4 pixels
8:
    ldp   w4,w5, [x1], #8
    add     x0, x0, #4
    // it's all zero, skip this pixel
    orr     w3, w4, w5
    cbz     w3, 7f

    // load the destination
    ldr     w3, [x0, #-4]
    // stream the destination
    pixel   w3, w4, w12, 0
    pixel   w3, w5, w12, 1
    str     w12, [x0, #-4]

    // 2nd iteration of the loop, don't stream anything
    subs    w2, w2, #2
    csel    w4, w5, w4, lt
    blt     9f
    ldp     w4,w5, [x1], #8
    add     x0, x0, #4
    orr     w3, w4, w5
    cbz     w3, 7f
    ldr     w3, [x0, #-4]
    pixel   w3, w4, w12, 0
    pixel   w3, w5, w12, 1
    str     w12, [x0, #-4]

7:  subs    w2, w2, #2
    bhs     8b
    mov     w4, w5

9:  adds    w2, w2, #1
    b.lo    return
    b       last

return:
    ret
