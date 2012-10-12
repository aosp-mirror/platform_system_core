/*
 * Copyright (C) 2006 The android Open Source Project
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

#ifdef NDEBUG
#define DBG #
#else
#define DBG
#endif

	.text
	.align

        /*
         * Optimized memset16 for MIPS
         *
         * void android_memset16_test(uint16_t* dst, uint16_t value, size_t size);
         *
         */

	.global	android_memset16_test
	.type   android_memset16_test, @function
android_memset16_test:
        .ent	android_memset16_test
	.set	noreorder

	/* Check parameters */
DBG	andi	$t0,$a0,1	/* $a0 must be halfword aligned */
DBG	tne	$t0
DBG	lui	$t1,0xffff	/* $a1 must be 16bits */
DBG	and	$t1,$a1
DBG	tne	$t1
DBG	andi	$t2,$a2,1	/* $a2 must be even */
DBG	tne	$t2

#if (__mips==32) && (__mips_isa_rev>=2)
	ins	$a2,$0,0,1
#else
	li	$t0,~1
	and	$a2,$t0
#endif

	move	$t8,$ra
	blez	$a2,9f		/* Anything to do? */
	 andi	$t0,$a0,2	/* Check dst alignment */
	/* Expand value to 32 bits and check destination alignment */
#if (__mips==32) && (__mips_isa_rev>=2)
	beqz	$t0,.Laligned32	/* dst is 32 bit aligned */
	 ins	$a1,$a1,16,16
#else
	sll	$t2,$a1,16
	beqz	$t0,.Laligned32	/* dst is 32 bit aligned */
	 or	$a1,$t2
#endif
	sh	$a1,($a0)	/* do one halfword to get aligned */
	subu	$a2,2
	addu	$a0,2

.Laligned32:
	and	$t1,$a2,63	/* is there enough left to do a full 64 byte loop? */
	beq	$a2,$t1,1f
	 subu	$t2,$a2,$t1	/* $t2 is the number of bytes to do in loop64 */
	addu	$t3,$a0,$t2	/* $t3 is the end marker for loop64 */
	subu	$a2,$t2
.Lloop64:
	addu	$a0,64
	sw	$a1,-64($a0)
	sw	$a1,-60($a0)
	sw	$a1,-56($a0)
	sw	$a1,-52($a0)
	sw	$a1,-48($a0)
	sw	$a1,-44($a0)
	sw	$a1,-40($a0)
	sw	$a1,-36($a0)
	sw	$a1,-32($a0)
	sw	$a1,-28($a0)
	sw	$a1,-24($a0)
	sw	$a1,-20($a0)
	sw	$a1,-16($a0)
	sw	$a1,-12($a0)
	sw	$a1,-8($a0)
	bne	$a0,$t3,.Lloop64
	sw	$a1,-4($a0)

	/* Do the last 0..62 bytes */
1:	li	$t0,64+12
	andi	$t1,$a2,0x3c	/* $t1 how many bytes to store using sw */
	bal	1f
	 subu	$t0,$t1		/* 64+12-$t0 is offset to jump from 1f */
1:	addu	$ra,$t0
	j	$ra
	 subu	$a2,$t1
2:	sw	$a1,60($a0)
	sw	$a1,56($a0)
	sw	$a1,52($a0)
	sw	$a1,48($a0)
	sw	$a1,44($a0)
	sw	$a1,40($a0)
	sw	$a1,36($a0)
	sw	$a1,32($a0)
	sw	$a1,28($a0)
	sw	$a1,24($a0)
	sw	$a1,20($a0)
	sw	$a1,16($a0)
	sw	$a1,12($a0)
	sw	$a1,8($a0)
	sw	$a1,4($a0)
	sw	$a1,0($a0)

	beqz	$a2,9f
	 addu	$a0,$t1
	sh	$a1,($a0)

9:	j	$t8
	 nop
        .end	android_memset16_test
	.size	android_memset16_test,.-android_memset16_test

        /*
         * Optimized memset32 for MIPS
         *
         * void android_memset32_test(uint32_t* dst, uint32_t value, size_t size);
         *
         */
	.global android_memset32_test
	.type	android_memset32_test, @function
android_memset32_test:
        .ent	android_memset32_test
	.set	noreorder

	/* Check parameters */
DBG	andi	$t0,$a0,3	/* $a0 must be word aligned */
DBG	tne	$t0
DBG	andi	$t2,$a2,3	/* $a2 must be a multiple of 4 bytes */
DBG	tne	$t2

	b	.Laligned32
	 move	$t8,$ra
        .end	android_memset32_test
	.size	android_memset32_test,.-android_memset32_test
