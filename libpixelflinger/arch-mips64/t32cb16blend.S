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

#ifdef DEBUG
#define DBG
#else
#define DBG #
#endif

/*
 * blend one of 2 16bpp RGB pixels held in dreg selected by shift
 * with the 32bpp ABGR pixel held in src and store the result in fb
 *
 * Assumes that the dreg data is little endian and that
 * the the second pixel (shift==16) will be merged into
 * the fb result
 *
 * Uses $a4,$t2,$t3,$t8
 */

    .macro pixel dreg src fb shift
    /*
     * sA = s >> 24
     * f = 0x100 - (sA + (sA>>7))
     */
    srl     $t3,\src,24
    srl     $t2,$t3,7
    addu    $t3,$t2
    li      $t2,0x100
    subu    $t3,$t2,$t3

    /* red */
    ext     $t8,\dreg,\shift+6+5,5                  # dst[\shift:15..11]
    mul     $t2,$t8,$t3
    ext     $a4,\dreg,\shift+5,6                    # start green extraction dst[\shift:10..5]
    ext     $t8,\src,3,5                            # src[7..3]
    srl     $t2,8
    addu    $t8,$t2
.if \shift!=0
    sll     $t8,\shift+11                           # dst[\shift:15..11]
    or      \fb,$t8
.else
    sll     \fb,$t8,11
.endif

    /* green */
    mul     $t8,$a4,$t3
    ext     $a4,\dreg,\shift,5                      # start blue extraction dst[\shift:4..0]
    ext     $t2,\src,2+8,6                          # src[15..10]
    srl     $t8,8
    addu    $t8,$t2

    /* blue */
    mul     $a4,$a4,$t3
    sll     $t8, $t8, \shift+5                  # finish green insertion dst[\shift:10..5]
    or      \fb, \fb, $t8
    ext     $t2,\src,(3+8+8),5
    srl     $t8,$a4,8
    addu    $t8,$t2
    sll     $t8, $t8, \shift
    or      \fb, \fb, $t8
    .endm

    .text
    .balign 4

    .global scanline_t32cb16blend_mips64
    .ent    scanline_t32cb16blend_mips64
scanline_t32cb16blend_mips64:
    daddiu  $sp, $sp, -40
DBG li      $v0,0xffffffff
DBG li      $v1,0
    /* Align the destination if necessary */
    and     $a4,$a0,3
    beqz    $a4,aligned

    /* as long as there is at least one pixel */
    beqz    $a2,done

    lw      $t0,($a1)
    daddu   $a0,2
    daddu   $a1,4
    beqz    $t0,1f
    lhu     $a7,-2($a0)
    pixel   $a7,$t0,$a5,0
    sh      $a5,-2($a0)
1:  subu    $a2,1

aligned:
    /* Check to see if its worth unrolling the loop */
    subu    $a2,4
    bltz    $a2,tail

    /* Process 4 pixels at a time */
fourpixels:
    /* 1st pair of pixels */
    lw      $t0,0($a1)
    lw      $t1,4($a1)
    daddu   $a0,8
    daddu   $a1,16

    /* both are zero, skip this pair */
    or      $a7,$t0,$t1
    beqz    $a7,1f

    /* load the destination */
    lw      $a7,-8($a0)

    pixel   $a7,$t0,$a5,0
    andi    $a5, 0xFFFF
    pixel   $a7,$t1,$a5,16
    sw      $a5,-8($a0)

1:
    /* 2nd pair of pixels */
    lw      $t0,-8($a1)
    lw      $t1,-4($a1)

    /* both are zero, skip this pair */
    or      $a7,$t0,$t1
    beqz    $a7,1f

    /* load the destination */
    lw      $a7,-4($a0)

    pixel   $a7,$t0,$a5,0
    andi    $a5, 0xFFFF
    pixel   $a7,$t1,$a5,16
    sw      $a5,-4($a0)

1:  subu    $a2,4
    bgtz    $a2,fourpixels

tail:
    /* the pixel count underran, restore it now */
    addu    $a2,4

    /* handle the last 0..3 pixels */
    beqz    $a2,done
onepixel:
    lw      $t0,($a1)
    daddu   $a0,2
    daddu   $a1,4
    beqz    $t0,1f
    lhu     $a7,-2($a0)
    pixel   $a7,$t0,$a5,0
    sh      $a5,-2($a0)
1:  subu    $a2,1
    bnez    $a2,onepixel
done:
DBG .set    push
DBG .set    mips32r2
DBG rdhwr   $a0,$3
DBG mul     $v0,$a0
DBG mul     $v1,$a0
DBG .set    pop
    daddiu  $sp, $sp, 40
    j       $ra
    .end    scanline_t32cb16blend_mips64
