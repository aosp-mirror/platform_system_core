/* libs/pixelflinger/col32cb16blend_neon.S
**
** (C) COPYRIGHT 2009 ARM Limited.
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
**
*/

    .text
    .align

    .global scanline_col32cb16blend_neon

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
// The NEON implementation processes 16 pixels per iteration. The remaining 0 - 15
// pixels are processed in ARM code.
//

// r0 = destination buffer pointer
// r1 = color pointer
// r2 = count


scanline_col32cb16blend_neon:
    push        {r4-r11, lr}                    // stack ARM regs

    vmov.u16    q15, #256                       // create alpha constant
    movs        r3, r2, lsr #4                  // calc. sixteens iterations
    vmov.u16    q14, #0x1f                      // create blue mask

    beq         2f                              // if r3 == 0, branch to singles

    vld4.8      {d0[], d2[], d4[], d6[]}, [r1]  // load color into four registers
                                                //  split and duplicate them, such that
                                                //  d0 = 8 equal red values
                                                //  d2 = 8 equal green values
                                                //  d4 = 8 equal blue values
                                                //  d6 = 8 equal alpha values
    vshll.u8    q0, d0, #5                      // shift up red and widen
    vshll.u8    q1, d2, #6                      // shift up green and widen
    vshll.u8    q2, d4, #5                      // shift up blue and widen

    vshr.u8     d7, d6, #7                      // extract top bit of alpha
    vaddl.u8    q3, d6, d7                      // add top bit into alpha
    vsub.u16    q3, q15, q3                     // invert alpha

1:
    // This loop processes 16 pixels per iteration. In the comments, references to
    // the first eight pixels are suffixed with "0" (red0, green0, blue0), 
    // the second eight are suffixed "1".
                                                // q8  = dst red0
                                                // q9  = dst green0
                                                // q10 = dst blue0
                                                // q13 = dst red1
                                                // q12 = dst green1
                                                // q11 = dst blue1

    vld1.16     {d20, d21, d22, d23}, [r0]      // load 16 dest pixels
    vshr.u16    q8, q10, #11                    // shift dst red0 to low 5 bits
    pld         [r0, #63]                       // preload next dest pixels
    vshl.u16    q9, q10, #5                     // shift dst green0 to top 6 bits
    vand        q10, q10, q14                   // extract dst blue0
    vshr.u16    q9, q9, #10                     // shift dst green0 to low 6 bits
    vmul.u16    q8, q8, q3                      // multiply dst red0 by src alpha
    vshl.u16    q12, q11, #5                    // shift dst green1 to top 6 bits
    vmul.u16    q9, q9, q3                      // multiply dst green0 by src alpha
    vshr.u16    q13, q11, #11                   // shift dst red1 to low 5 bits
    vmul.u16    q10, q10, q3                    // multiply dst blue0 by src alpha
    vshr.u16    q12, q12, #10                   // shift dst green1 to low 6 bits
    vand        q11, q11, q14                   // extract dst blue1
    vadd.u16    q8, q8, q0                      // add src red to dst red0
    vmul.u16    q13, q13, q3                    // multiply dst red1 by src alpha
    vadd.u16    q9, q9, q1                      // add src green to dst green0 
    vmul.u16    q12, q12, q3                    // multiply dst green1 by src alpha
    vadd.u16    q10, q10, q2                    // add src blue to dst blue0
    vmul.u16    q11, q11, q3                    // multiply dst blue1 by src alpha
    vshr.u16    q8, q8, #8                      // shift down red0
    vadd.u16    q13, q13, q0                    // add src red to dst red1
    vshr.u16    q9, q9, #8                      // shift down green0
    vadd.u16    q12, q12, q1                    // add src green to dst green1
    vshr.u16    q10, q10, #8                    // shift down blue0
    vadd.u16    q11, q11, q2                    // add src blue to dst blue1
    vsli.u16    q10, q9, #5                     // shift & insert green0 into blue0
    vshr.u16    q13, q13, #8                    // shift down red1
    vsli.u16    q10, q8, #11                    // shift & insert red0 into blue0    
    vshr.u16    q12, q12, #8                    // shift down green1
    vshr.u16    q11, q11, #8                    // shift down blue1
    subs        r3, r3, #1                      // decrement loop counter
    vsli.u16    q11, q12, #5                    // shift & insert green1 into blue1
    vsli.u16    q11, q13, #11                   // shift & insert red1 into blue1

    vst1.16     {d20, d21, d22, d23}, [r0]!     // write 16 pixels back to dst
    bne         1b                              // if count != 0, loop

2:
    ands        r3, r2, #15                     // calc. single iterations 
    beq         4f                              // if r3 == 0, exit

    ldr         r4, [r1]                        // load source color
    mov         r5, r4, lsr #24                 // shift down alpha
    add         r5, r5, r5, lsr #7              // add in top bit
    rsb         r5, r5, #256                    // invert alpha
    and         r11, r4, #0xff                  // extract red
    ubfx        r12, r4, #8, #8                 // extract green
    ubfx        r4, r4, #16, #8                 // extract blue
    mov         r11, r11, lsl #5                // prescale red
    mov         r12, r12, lsl #6                // prescale green
    mov         r4, r4, lsl #5                  // prescale blue

3:
    ldrh        r8, [r0]                        // load dest pixel
    subs        r3, r3, #1                      // decrement loop counter
    mov         r6, r8, lsr #11                 // extract dest red
    ubfx        r7, r8, #5, #6                  // extract dest green
    and         r8, r8, #0x1f                   // extract dest blue

    smlabb      r6, r6, r5, r11                 // dest red * alpha + src red
    smlabb      r7, r7, r5, r12                 // dest green * alpha + src green
    smlabb      r8, r8, r5, r4                  // dest blue * alpha + src blue

    mov         r6, r6, lsr #8                  // shift down red
    mov         r7, r7, lsr #8                  // shift down green
    mov         r6, r6, lsl #11                 // shift red into 565
    orr         r6, r7, lsl #5                  // shift green into 565
    orr         r6, r8, lsr #8                  // shift blue into 565

    strh        r6, [r0], #2                    // store pixel to dest, update ptr
    bne         3b                              // if count != 0, loop
4:

    pop         {r4-r11, pc}                    // return



