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
    .align

    .global scanline_col32cb16blend_arm64

//
// This function alpha blends a fixed color into a destination scanline, using
// the formula:
//
//     d = s + (((a + (a >> 7)) * d) >> 8)
//
// where d is the destination pixel,
//       s is the source color,
//       a is the alpha channel of the source color.
//

// x0 = destination buffer pointer
// w1 = color value
// w2 = count


scanline_col32cb16blend_arm64:

    lsr         w5, w1, #24                     // shift down alpha
    mov         w9, #0xff                       // create mask
    add         w5, w5, w5, lsr #7              // add in top bit
    mov         w4, #256                        // create #0x100
    sub         w5, w4, w5                      // invert alpha
    and         w10, w1, #0xff                  // extract red
    and         w12, w9, w1, lsr #8             // extract green
    and         w4,  w9, w1, lsr #16            // extract blue
    lsl         w10, w10, #5                    // prescale red
    lsl         w12, w12, #6                    // prescale green
    lsl         w4,  w4,  #5                    // prescale blue
    lsr         w9,  w9,  #2                    // create dest green mask

1:
    ldrh        w8, [x0]                        // load dest pixel
    subs        w2, w2, #1                      // decrement loop counter
    lsr         w6, w8, #11                     // extract dest red
    and         w7, w9, w8, lsr #5              // extract dest green
    and         w8, w8, #0x1f                   // extract dest blue

    madd        w6, w6, w5, w10                 // dest red * alpha + src red
    madd        w7, w7, w5, w12                 // dest green * alpha + src green
    madd        w8, w8, w5, w4                  // dest blue * alpha + src blue

    lsr         w6, w6, #8                      // shift down red
    lsr         w7, w7, #8                      // shift down green
    lsl         w6, w6, #11                     // shift red into 565
    orr         w6, w6, w7, lsl #5              // shift green into 565
    orr         w6, w6, w8, lsr #8              // shift blue into 565

    strh        w6, [x0], #2                    // store pixel to dest, update ptr
    b.ne        1b                              // if count != 0, loop

    ret



