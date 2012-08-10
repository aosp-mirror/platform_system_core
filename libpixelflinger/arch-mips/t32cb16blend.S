/* libs/pixelflinger/t32cb16blend.S
**
** Copyright 2010, The Android Open Source Project
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
 * Uses $t0,$t6,$t7,$t8
 */

#if __mips==32 && __mips_isa_rev>=2
	.macro pixel dreg src fb shift
	/*
	 * sA = s >> 24
	 * f = 0x100 - (sA + (sA>>7))
	 */
DBG	.set	noat
DBG	rdhwr	$at,$2
DBG	.set	at

	srl	$t7,\src,24
	srl	$t6,$t7,7
	addu	$t7,$t6
	li	$t6,0x100
	subu	$t7,$t6,$t7

	/* red */
	ext	$t8,\dreg,\shift+6+5,5			# dst[\shift:15..11]
	mul	$t6,$t8,$t7
	ext	$t0,\dreg,\shift+5,6			# start green extraction dst[\shift:10..5]
	ext	$t8,\src,3,5				# src[7..3]
	srl	$t6,8
	addu	$t8,$t6
	ins	\fb,$t8,\shift+6+5,5			# dst[\shift:15..11]

        /* green */
	mul	$t8,$t0,$t7
	ext	$t0,\dreg,\shift,5			# start blue extraction dst[\shift:4..0]
	ext	$t6,\src,2+8,6				# src[15..10]
	srl	$t8,8
        addu	$t8,$t6

	/* blue */
	mul	$t0,$t0,$t7
	ins	\fb,$t8,\shift+5,6			# finish green insertion dst[\shift:10..5]
	ext	$t6,\src,(3+8+8),5
	srl	$t8,$t0,8
	addu	$t8,$t6
	ins	\fb,$t8,\shift,5

DBG	.set	noat
DBG	rdhwr	$t8,$2
DBG	subu	$t8,$at
DBG	sltu	$at,$t8,$v0
DBG	movn	$v0,$t8,$at
DBG	sgtu	$at,$t8,$v1
DBG	movn	$v1,$t8,$at
DBG	.set	at
	.endm

#else

	.macro pixel dreg src fb shift
	/*
	 * sA = s >> 24
	 * f = 0x100 - (sA + (sA>>7))
	 */
DBG	.set	push
DBG	.set	noat
DBG	.set	mips32r2
DBG 	rdhwr	$at,$2
DBG	.set	pop

	srl	$t7,\src,24
	srl	$t6,$t7,7
	addu	$t7,$t6
	li	$t6,0x100
	subu	$t7,$t6,$t7

	/*
	 * red
	 * dR = (d >> (6 + 5)) & 0x1f;
	 * dR = (f*dR)>>8
	 * sR = (s >> (   3)) & 0x1f;
	 * sR += dR
	 * fb |= sR << 11
	 */
	srl	$t8,\dreg,\shift+6+5
.if \shift==0
	and     $t8,0x1f
.endif
	mul	$t8,$t8,$t7
	srl	$t6,\src,3
	and	$t6,0x1f
	srl	$t8,8
	addu	$t8,$t6
.if \shift!=0
	sll	$t8,\shift+11
	or	\fb,$t8
.else
	sll	\fb,$t8,11
.endif

        /*
	 * green
	 * dG = (d >> 5) & 0x3f
	 * dG = (f*dG) >> 8
	 * sG = (s >> ( 8+2))&0x3F;
	 */
	srl	$t8,\dreg,\shift+5
        and	$t8,0x3f
	mul	$t8,$t8,$t7
        srl	$t6,\src,8+2
        and     $t6,0x3f
	srl	$t8,8
        addu	$t8,$t6
	sll	$t8,\shift + 5
	or	\fb,$t8

	/* blue */
.if \shift!=0
	srl	$t8,\dreg,\shift
	and	$t8,0x1f
.else
	and	$t8,\dreg,0x1f
.endif
	mul	$t8,$t8,$t7
	srl	$t6,\src,(8+8+3)
	and	$t6,0x1f
	srl	$t8,8
	addu	$t8,$t6
.if \shift!=0
	sll	$t8,\shift
.endif
	or	\fb,$t8
DBG	.set	push
DBG	.set	noat
DBG	.set	mips32r2
DBG	rdhwr	$t8,$2
DBG	subu	$t8,$at
DBG	sltu	$at,$t8,$v0
DBG	movn	$v0,$t8,$at
DBG	sgtu	$at,$t8,$v1
DBG	movn	$v1,$t8,$at
DBG	.set	pop
	.endm
#endif

	.text
	.align

	.global scanline_t32cb16blend_mips
	.ent	scanline_t32cb16blend_mips
scanline_t32cb16blend_mips:
DBG	li	$v0,0xffffffff
DBG	li	$v1,0
	/* Align the destination if necessary */
	and	$t0,$a0,3
	beqz	$t0,aligned

	/* as long as there is at least one pixel */
	beqz	$a2,done

	lw	$t4,($a1)
	addu	$a0,2
	addu	$a1,4
	beqz	$t4,1f
	lhu	$t3,-2($a0)
	pixel   $t3,$t4,$t1,0
	sh	$t1,-2($a0)
1:	subu	$a2,1

aligned:
	/* Check to see if its worth unrolling the loop */
	subu	$a2,4
	bltz	$a2,tail

	/* Process 4 pixels at a time */
fourpixels:
	/* 1st pair of pixels */
	lw	$t4,0($a1)
	lw	$t5,4($a1)
	addu	$a0,8
	addu	$a1,16

	/* both are zero, skip this pair */
	or	$t3,$t4,$t5
	beqz	$t3,1f

	/* load the destination */
	lw	$t3,-8($a0)

	pixel	$t3,$t4,$t1,0
	pixel	$t3,$t5,$t1,16
	sw	$t1,-8($a0)

1:
	/* 2nd pair of pixels */
	lw	$t4,-8($a1)
	lw	$t5,-4($a1)

	/* both are zero, skip this pair */
	or	$t3,$t4,$t5
	beqz	$t3,1f

	/* load the destination */
	lw	$t3,-4($a0)

	pixel	$t3,$t4,$t1,0
	pixel	$t3,$t5,$t1,16
	sw	$t1,-4($a0)

1:	subu    $a2,4
	bgtz	$a2,fourpixels

tail:
	/* the pixel count underran, restore it now */
	addu	$a2,4

	/* handle the last 0..3 pixels */
	beqz	$a2,done
onepixel:
	lw	$t4,($a1)
	addu	$a0,2
	addu	$a1,4
	beqz	$t4,1f
	lhu	$t3,-2($a0)
	pixel   $t3,$t4,$t1,0
	sh	$t1,-2($a0)
1:	subu	$a2,1
	bnez	$a2,onepixel
done:
DBG	.set    push
DBG	.set    mips32r2
DBG 	rdhwr	$a0,$3
DBG 	mul	$v0,$a0
DBG 	mul	$v1,$a0
DBG	.set    pop
	j	$ra
	.end	scanline_t32cb16blend_mips
