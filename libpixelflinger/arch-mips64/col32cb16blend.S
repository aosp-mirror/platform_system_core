/*
** Copyright 2015, The Android Open Source Project
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

    .macro pixel dreg src f sR sG sB shift

    /* extract red */
.if \shift < 32
    dext   $t0,\src,\shift+11,5
.else
    dextu  $t0,\src,\shift+11,5
.endif
    mul    $t0,$t0,\f

    /* extract green */
.if \shift < 32
    dext   $t1,\src,\shift+5,6
.else
    dextu  $t1,\src,\shift+5,6
.endif
    mul    $t1,$t1,\f

    /* extract blue */
.if \shift < 32
    dext   $t2,\src,\shift,5
.else
    dextu  $t2,\src,\shift,5
.endif
    mul    $t2,$t2,\f

    srl    $t0,$t0,8
    srl    $t1,$t1,8
    srl    $t2,$t2,8
    addu   $t0,$t0,\sR
    addu   $t1,$t1,\sG
    addu   \dreg,$t2,\sB
    sll    $t0,$t0,11
    sll    $t1,$t1,5
    or     \dreg,\dreg,$t0
    or     \dreg,\dreg,$t1
    .endm

    .text
    .balign 4

    .global scanline_col32cb16blend_mips64
    .ent    scanline_col32cb16blend_mips64
scanline_col32cb16blend_mips64:

    /* check if count is zero */
    srl     $v0,$a1,24 /* sA */
    beqz    $a2,done
    li      $t0, 0x100
    srl     $v1,$v0,7
    addu    $v0,$v1,$v0
    subu    $v0,$t0,$v0 /* f */
    ext     $a3,$a1,3,5 /* sR */
    ext     $a4,$a1,10,6 /* sG */
    ext     $a5,$a1,19,5 /* sB */

    /* check if cnt is at least 4 */
    addiu   $a2,$a2,-4
    bltz    $a2,tail

loop_4pixels:
    ld      $t3,0($a0)
    daddiu  $a0,$a0,8
    addiu   $a2,$a2,-4
    pixel   $a6 $t3 $v0 $a3 $a4 $a5 0
    pixel   $a7 $t3 $v0 $a3 $a4 $a5 16
    pixel   $t8 $t3 $v0 $a3 $a4 $a5 32
    pixel   $t9 $t3 $v0 $a3 $a4 $a5 48
    dins    $a6,$a7,16,16
    dinsu   $a6,$t8,32,16
    dinsu   $a6,$t9,48,16
    sd      $a6,-8($a0)
    bgez    $a2, loop_4pixels

tail:
    /* the pixel count underran, restore it now */
    addiu   $a2,$a2,4

    /* handle the last 0..3 pixels */
    beqz    $a2,done

loop_1pixel:
    lhu     $t3,0($a0)
    daddiu  $a0,$a0,2
    addiu   $a2,$a2,-1
    pixel   $a6 $t3 $v0 $a3 $a4 $a5 0
    sh      $a6, -2($a0)
    bnez    $a2,loop_1pixel

done:
    j       $ra
    .end    scanline_col32cb16blend_mips64
