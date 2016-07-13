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

#if __mips==32 && __mips_isa_rev>=2
       /* extract red */
       ext $t4,\src,\shift+11,5
       mul $t4,$t4,\f

       /* extract green */
       ext $t5,\src,\shift+5,6
       mul $t5,$t5,\f

       /* extract blue */
       ext $t6,\src,\shift,5
       mul $t6,$t6,\f
#else
       /* extract red */
       srl $t4,\src,\shift+11
       andi $t4, 0x1f
       mul $t4,$t4,\f

       /* extract green */
       srl $t5,\src,\shift+5
       andi $t5, 0x3f
       mul $t5,$t5,\f

       /* extract blue */
       srl $t6,\src,\shift
       andi $t6, 0x1f
       mul $t6,$t6,\f
#endif

       srl $t4,$t4,8
       srl $t5,$t5,8
       srl $t6,$t6,8
       addu $t4,$t4,\sR
       addu $t5,$t5,\sG
       addu \dreg,$t6,\sB
       sll $t4,$t4,11
       sll $t5,$t5,5
       or \dreg,\dreg,$t4
       or \dreg,\dreg,$t5
       andi \dreg, 0xffff
       .endm

       .text
       .balign 4

       .global scanline_col32cb16blend_mips
       .ent    scanline_col32cb16blend_mips
scanline_col32cb16blend_mips:

       /* check if count is zero */
       srl     $v0,$a1,24 /* sA */
       beqz    $a2,done
       li      $t4, 0x100
       srl     $v1,$v0,7
       addu    $v0,$v1,$v0
       subu    $v0,$t4,$v0 /* f */
#if __mips==32 && __mips_isa_rev>=2
       ext     $a3,$a1,3,5 /* sR */
       ext     $t0,$a1,10,6 /* sG */
       ext     $t1,$a1,19,5 /* sB */
#else
       srl     $a3, $a1, 3
       andi    $a3, 0x1f    /* sR */
       srl     $t0, $a1, 10
       andi    $t0, 0x3f    /* sG */
       srl     $t1, $a1, 19
       andi    $t1, 0x1f    /* sB */
#endif

       /* check if cnt is at least 4 */
       addiu   $a2,$a2,-4
       bltz    $a2,tail

loop_4pixels:
       lw      $t7,0($a0)
       lw      $t8,4($a0)
       addiu   $a0,$a0,8
       addiu   $a2,$a2,-4
       pixel   $t2 $t7 $v0 $a3 $t0 $t1 0
       pixel   $t3 $t7 $v0 $a3 $t0 $t1 16
#if __mips==32 && __mips_isa_rev>=2
       ins     $t2,$t3,16,16
#else
       sll $t3, 16
       or  $t2, $t2, $t3
#endif
       pixel   $t7 $t8 $v0 $a3 $t0 $t1 0
       pixel   $t3 $t8 $v0 $a3 $t0 $t1 16
#if __mips==32 && __mips_isa_rev>=2
       ins     $t7,$t3,16,16
#else
       sll $t3, 16
       or  $t7, $t7, $t3
#endif
       sw      $t2,-8($a0)
       sw      $t7,-4($a0)
       bgez    $a2, loop_4pixels

tail:
       /* the pixel count underran, restore it now */
       addiu   $a2,$a2,4

       /* handle the last 0..3 pixels */
       beqz    $a2,done

loop_1pixel:
       lhu     $t7,0($a0)
       addiu   $a0,$a0,2
       addiu   $a2,$a2,-1
       pixel   $t2 $t7 $v0 $a3 $t0 $t1 0
       sh      $t2, -2($a0)
       bnez    $a2,loop_1pixel

done:
       j       $ra
       .end    scanline_col32cb16blend_mips
