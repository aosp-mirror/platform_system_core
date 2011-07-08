/* libs/pixelflinger/col32cb16blend.S
 *
 * Copyright (C) 2009 The Android Open Source Project
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

    .global scanline_col32cb16blend_arm

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

// r0 = destination buffer pointer
// r1 = color value
// r2 = count


scanline_col32cb16blend_arm:
    push        {r4-r10, lr}                    // stack ARM regs

    mov         r5, r1, lsr #24                 // shift down alpha
    mov         r9, #0xff                       // create mask
    add         r5, r5, r5, lsr #7              // add in top bit
    rsb         r5, r5, #256                    // invert alpha
    and         r10, r1, #0xff                  // extract red
    and         r12, r9, r1, lsr #8             // extract green
    and         r4, r9, r1, lsr #16             // extract blue
    mov         r10, r10, lsl #5                // prescale red
    mov         r12, r12, lsl #6                // prescale green
    mov         r4, r4, lsl #5                  // prescale blue
    mov         r9, r9, lsr #2                  // create dest green mask

1:
    ldrh        r8, [r0]                        // load dest pixel
    subs        r2, r2, #1                      // decrement loop counter
    mov         r6, r8, lsr #11                 // extract dest red
    and         r7, r9, r8, lsr #5              // extract dest green
    and         r8, r8, #0x1f                   // extract dest blue

    smlabb      r6, r6, r5, r10                 // dest red * alpha + src red
    smlabb      r7, r7, r5, r12                 // dest green * alpha + src green
    smlabb      r8, r8, r5, r4                  // dest blue * alpha + src blue

    mov         r6, r6, lsr #8                  // shift down red
    mov         r7, r7, lsr #8                  // shift down green
    mov         r6, r6, lsl #11                 // shift red into 565
    orr         r6, r7, lsl #5                  // shift green into 565
    orr         r6, r8, lsr #8                  // shift blue into 565

    strh        r6, [r0], #2                    // store pixel to dest, update ptr
    bne         1b                              // if count != 0, loop

    pop         {r4-r10, pc}                    // return



