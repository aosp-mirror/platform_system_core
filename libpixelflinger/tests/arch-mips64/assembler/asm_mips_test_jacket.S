# /*
#  * Copyright (C) 2015 The Android Open Source Project
#  * All rights reserved.
#  *
#  * Redistribution and use in source and binary forms, with or without
#  * modification, are permitted provided that the following conditions
#  * are met:
#  *  * Redistributions of source code must retain the above copyright
#  *    notice, this list of conditions and the following disclaimer.
#  *  * Redistributions in binary form must reproduce the above copyright
#  *    notice, this list of conditions and the following disclaimer in
#  *    the documentation and/or other materials provided with the
#  *    distribution.
#  *
#  * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#  * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#  * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
#  * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
#  * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
#  * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
#  * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
#  * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
#  * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
#  * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
#  * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
#  * SUCH DAMAGE.
#  */

    .text
    .balign 8

    .global asm_mips_test_jacket

    # // Set the register
    # // Calls the asm function
    # // Reads the register values to output register

    # // Parameters
    # // a0 - Function to jump
    # // a1 - register values array
    # // a2 - flag values array
asm_mips_test_jacket:
    # // Save registers to stack
    daddiu $sp, $sp, -96
    sd  $s0, 64($sp)
    sd  $s1, 72($sp)
    sd  $s2, 80($sp)
    sd  $ra, 88($sp)

    move $s0, $a0
    move $s1, $a1
    move $s2, $a2

    ld  $v0, 16($s1)
    ld  $v1, 24($s1)
    ld  $a0, 32($s1)
    ld  $a1, 40($s1)
    ld  $a2, 48($s1)
    ld  $a3, 56($s1)
    ld  $a4, 64($s1)
    ld  $a5, 72($s1)
    ld  $a6, 80($s1)
    ld  $a7, 88($s1)
    ld  $t0, 96($s1)
    ld  $t1, 104($s1)
    ld  $t2, 112($s1)
    ld  $t3, 120($s1)

    jal $s0

    sd  $v0, 16($s1)
    sd  $v1, 24($s1)
    sd  $a0, 32($s1)
    sd  $a1, 40($s1)
    sd  $a2, 48($s1)
    sd  $a3, 56($s1)
    sd  $a4, 64($s1)
    sd  $a5, 72($s1)
    sd  $a6, 80($s1)
    sd  $a7, 88($s1)
    sd  $t0, 96($s1)
    sd  $t1, 104($s1)
    sd  $t2, 112($s1)
    sd  $t3, 120($s1)

    ld  $s0, 64($sp)
    ld  $s1, 72($sp)
    ld  $s2, 80($sp)
    ld  $ra, 88($sp)

    daddiu $sp, $sp, 96

    j   $ra
