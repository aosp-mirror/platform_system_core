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

    .global asm_test_jacket

    // Set the register and flag values
    // Calls the asm function
    // Reads the register/flag values to output register

    // Parameters
    // X0 - Function to jump
    // X1 - register values array
    // X2 - flag values array
asm_test_jacket:
    // Save registers to stack
    stp    x29, x30, [sp,#-16]!
    stp    x27, x28, [sp,#-16]!

    mov x30, x0
    mov x28, x1
    mov x27, x2

    //Set the flags based on flag array
    //EQ
    ldr w0, [x27,#0]
    cmp w0, #1
    b.ne bt_aeq
    cmp w0,#1
    b bt_end
bt_aeq:

    //NE
    ldr w0, [x27,#4]
    cmp w0, #1
    b.ne bt_ane
    cmp w0,#2
    b bt_end
bt_ane:

    //CS
    ldr w0, [x27,#8]
    cmp w0, #1
    b.ne bt_acs
    cmp w0,#0
    b bt_end
bt_acs:

    //CC
    ldr w0, [x27,#12]
    cmp w0, #1
    b.ne bt_acc
    cmp w0,#2
    b bt_end
bt_acc:

    //MI
    ldr w0, [x27,#16]
    cmp w0, #1
    b.ne bt_ami
    subs w0,w0,#2
    b bt_end
bt_ami:

    //PL
    ldr w0, [x27,#20]
    cmp w0, #1
    b.ne bt_apl
    subs w0,w0,#0
    b bt_end
bt_apl:
    //HI - (C==1) && (Z==0)
    ldr w0, [x27,#32]
    cmp w0, #1
    b.ne bt_ahi
    cmp w0,#0
    b bt_end
bt_ahi:

    //LS - (C==0) || (Z==1)
    ldr w0, [x27,#36]
    cmp w0, #1
    b.ne bt_als
    cmp w0,#1
    b bt_end
bt_als:

    //GE
    ldr w0, [x27,#40]
    cmp w0, #1
    b.ne bt_age
    cmp w0,#0
    b bt_end
bt_age:

    //LT
    ldr w0, [x27,#44]
    cmp w0, #1
    b.ne bt_alt
    cmp w0,#2
    b bt_end
bt_alt:

    //GT
    ldr w0, [x27,#48]
    cmp w0, #1
    b.ne bt_agt
    cmp w0,#0
    b bt_end
bt_agt:

    //LE
    ldr w0, [x27,#52]
    cmp w0, #1
    b.ne bt_ale
    cmp w0,#2
    b bt_end
bt_ale:


bt_end:

    // Load the registers from reg array
    ldr x0, [x28,#0]
    ldr x1, [x28,#8]
    ldr x2, [x28,#16]
    ldr x3, [x28,#24]
    ldr x4, [x28,#32]
    ldr x5, [x28,#40]
    ldr x6, [x28,#48]
    ldr x7, [x28,#56]
    ldr x8, [x28,#64]
    ldr x9, [x28,#72]
    ldr x10, [x28,#80]
    ldr x11, [x28,#88]
    ldr x12, [x28,#96]
    ldr x14, [x28,#112]

    // Call the function
    blr X30

    // Save the registers to reg array
    str x0, [x28,#0]
    str x1, [x28,#8]
    str x2, [x28,#16]
    str x3, [x28,#24]
    str x4, [x28,#32]
    str x5, [x28,#40]
    str x6, [x28,#48]
    str x7, [x28,#56]
    str x8, [x28,#64]
    str x9, [x28,#72]
    str x10, [x28,#80]
    str x11, [x28,#88]
    str x12, [x28,#96]
    str x14, [x28,#112]

    //Set the flags array based on result flags
    movz w0, #0
    movz w1, #1
    csel w2, w1, w0, EQ
    str w2, [x27,#0]
    csel w2, w1, w0, NE
    str w2, [x27,#4]
    csel w2, w1, w0, CS
    str w2, [x27,#8]
    csel w2, w1, w0, CC
    str w2, [x27,#12]
    csel w2, w1, w0, MI
    str w2, [x27,#16]
    csel w2, w1, w0, PL
    str w2, [x27,#20]
    csel w2, w1, w0, VS
    str w2, [x27,#24]
    csel w2, w1, w0, VC
    str w2, [x27,#28]
    csel w2, w1, w0, HI
    str w2, [x27,#32]
    csel w2, w1, w0, LS
    str w2, [x27,#36]
    csel w2, w1, w0, GE
    str w2, [x27,#40]
    csel w2, w1, w0, LT
    str w2, [x27,#44]
    csel w2, w1, w0, GT
    str w2, [x27,#48]
    csel w2, w1, w0, LE
    str w2, [x27,#52]

    // Restore registers from stack
    ldp    x27, x28, [sp],#16
    ldp    x29, x30, [sp],#16
    ret

