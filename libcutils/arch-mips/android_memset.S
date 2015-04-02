/*
 * Copyright (c) 2009
 *      MIPS Technologies, Inc., California.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the MIPS Technologies, Inc., nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE MIPS TECHNOLOGIES, INC. ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE MIPS TECHNOLOGIES, INC. BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/************************************************************************
 *
 *  memset.S, version "64h" with 1 cache line horizon for "pref 30" and 14 nops
 *  Version: "043009"
 *
 ************************************************************************/


/************************************************************************
 *  Include files
 ************************************************************************/

#include <machine/asm.h>
#define END(f) .cfi_endproc; .size f, .-f; .end f

/*
 * This routine could be optimized for MIPS64. The current code only
 * uses MIPS32 instructions.
 */

#if defined(__MIPSEB__)
#  define SWHI	swl		/* high part is left in big-endian	*/
#  define SWLO	swr		/* low part is right in big-endian	*/
#endif

#if defined(__MIPSEL__)
#  define SWHI	swr		/* high part is right in little-endian	*/
#  define SWLO	swl		/* low part is left in little-endian	*/
#endif

#if !(defined(XGPROF) || defined(XPROF))
#undef SETUP_GP
#define SETUP_GP
#endif

#ifdef NDEBUG
#define DBG #
#else
#define DBG
#endif

/*
 * void android_memset16(uint16_t* dst, uint16_t value, size_t size);
 */

LEAF(android_memset16,0)
	.set noreorder
DBG	/* Check parameters */
DBG	andi	t0,a0,1			# a0 must be halfword aligned
DBG	tne	t0,zero
DBG	andi	t2,a2,1			# a2 must be even
DBG	tne	t2,zero

#ifdef FIXARGS
	# ensure count is even
#if (__mips==32) && (__mips_isa_rev>=2)
	ins	a2,zero,0,1
#else
	ori	a2,1
	xori	a2,1
#endif
#endif

#if (__mips==32) && (__mips_isa_rev>=2)
	ins	a1,a1,16,16
#else
	andi	a1,0xffff
	sll	t3,a1,16
	or	a1,t3
#endif

	beqz	a2,.Ldone
	 andi	t1,a0,2
	beqz	t1,.Lalignok
	 addu	t0,a0,a2		# t0 is the "past the end" address
	sh	a1,0(a0)		# store one halfword to get aligned
	addu	a0,2
	subu	a2,2
.Lalignok:
	slti	t1,a2,4			# .Laligned for 4 or more bytes
	beqz	t1,.Laligned
	 sne	t1,a2,2			# one more halfword?
	bnez	t1,.Ldone
	 nop
	sh	a1,0(a0)
.Ldone:
	j	ra
	 nop
	.set reorder
END(android_memset16)

/*
 * void android_memset32(uint32_t* dst, uint32_t value, size_t size);
 */

LEAF(android_memset32,0)
	.set noreorder
DBG	/* Check parameters */
DBG	andi	t0,a0,3			# a0 must be word aligned
DBG	tne	t0,zero
DBG	andi	t2,a2,3			# a2 must be a multiple of 4 bytes
DBG	tne	t2,zero

#ifdef FIXARGS
	# ensure count is a multiple of 4
#if (__mips==32) && (__mips_isa_rev>=2)
	ins	$a2,$0,0,2
#else
	ori	a2,3
	xori	a2,3
#endif
#endif

	bnez	a2,.Laligned		# any work to do?
	 addu	t0,a0,a2		# t0 is the "past the end" address

	j	ra
	 nop
	.set reorder
END(android_memset32)

LEAF(memset,0)

	.set	noreorder
	.set	noat

	addu	t0,a0,a2		# t0 is the "past the end" address
	slti	AT,a2,4			# is a2 less than 4?
	bne	AT,zero,.Llast4		# if yes, go to last4
	 move	v0,a0			# memset returns the dst pointer

	beq	a1,zero,.Lset0
	 subu	v1,zero,a0

	# smear byte into 32 bit word
#if (__mips==32) && (__mips_isa_rev>=2)
	ins     a1, a1, 8, 8        # Replicate fill byte into half-word.
	ins     a1, a1, 16, 16      # Replicate fill byte into word.
#else
	and	a1,0xff
	sll	AT,a1,8
	or	a1,AT
	sll	AT,a1,16
	or	a1,AT
#endif

.Lset0:
	andi	v1,v1,0x3		# word-unaligned address?
	beq	v1,zero,.Laligned	# v1 is the unalignment count
	 subu	a2,a2,v1
	SWHI	a1,0(a0)
	addu	a0,a0,v1

# Here we have the "word-aligned" a0 (until the "last4")
.Laligned:
	andi	t8,a2,0x3f	# any 64-byte chunks?
				# t8 is the byte count past 64-byte chunks
	beq	a2,t8,.Lchk8w	# when a2==t8, no 64-byte chunks
				# There will be at most 1 32-byte chunk then
	 subu	a3,a2,t8	# subtract from a2 the reminder
				# Here a3 counts bytes in 16w chunks
	addu	a3,a0,a3	# Now a3 is the final dst after 64-byte chunks

# Find out, if there are any 64-byte chunks after which will be still at least
# 96 bytes left. The value "96" is calculated as needed buffer for
# "pref 30,64(a0)" prefetch, which can be used as "pref 30,0(a0)" after
# incrementing "a0" by 64.
# For "a2" below 160 there will be no such "pref 30 safe" 64-byte chunk.
#
	sltiu	v1,a2,160
	bgtz	v1,.Lloop16w_nopref30	# skip "pref 30,0(a0)"
	 subu	t7,a2,96	# subtract "pref 30 unsafe" region
		# below we have at least 1 64-byte chunk which is "pref 30 safe"
	andi	t6,t7,0x3f	# t6 is past "64-byte safe chunks" reminder
	subu	t5,t7,t6	# subtract from t7 the reminder
				# Here t5 counts bytes in 16w "safe" chunks
	addu	t4,a0,t5	# Now t4 is the dst after 64-byte "safe" chunks

# Don't use "pref 30,0(a0)" for a0 in a "middle" of a cache line
#	pref	30,0(a0)
# Here we are in the region, where it is safe to use "pref 30,64(a0)"
.Lloop16w:
	addiu	a0,a0,64
	pref	30,-32(a0)	# continue setting up the dest, addr 64-32
	sw	a1,-64(a0)
	sw	a1,-60(a0)
	sw	a1,-56(a0)
	sw	a1,-52(a0)
	sw	a1,-48(a0)
	sw	a1,-44(a0)
	sw	a1,-40(a0)
	sw	a1,-36(a0)
	nop
	nop			# the extra nop instructions help to balance
	nop			# cycles needed for "store" + "fill" + "evict"
	nop			# For 64byte store there are needed 8 fill
	nop			# and 8 evict cycles, i.e. at least 32 instr.
	nop
	nop
	pref	30,0(a0)	# continue setting up the dest, addr 64-0
	sw	a1,-32(a0)
	sw	a1,-28(a0)
	sw	a1,-24(a0)
	sw	a1,-20(a0)
	sw	a1,-16(a0)
	sw	a1,-12(a0)
	sw	a1,-8(a0)
	sw	a1,-4(a0)
	nop
	nop
	nop
	nop			# NOTE: adding 14 nop-s instead of 12 nop-s
	nop			# gives better results for "fast" memory
	nop
	bne	a0,t4,.Lloop16w
	 nop

	beq	a0,a3,.Lchk8w	# maybe no more 64-byte chunks?
	 nop			# this "delayed slot" is useless ...

.Lloop16w_nopref30:	# there could be up to 3 "64-byte nopref30" chunks
	addiu	a0,a0,64
	sw	a1,-64(a0)
	sw	a1,-60(a0)
	sw	a1,-56(a0)
	sw	a1,-52(a0)
	sw	a1,-48(a0)
	sw	a1,-44(a0)
	sw	a1,-40(a0)
	sw	a1,-36(a0)
	sw	a1,-32(a0)
	sw	a1,-28(a0)
	sw	a1,-24(a0)
	sw	a1,-20(a0)
	sw	a1,-16(a0)
	sw	a1,-12(a0)
	sw	a1,-8(a0)
	bne	a0,a3,.Lloop16w_nopref30
	 sw	a1,-4(a0)

.Lchk8w:		# t8 here is the byte count past 64-byte chunks

	andi	t7,t8,0x1f	# is there a 32-byte chunk?
				# the t7 is the reminder count past 32-bytes
	beq	t8,t7,.Lchk1w	# when t8==t7, no 32-byte chunk
	 move	a2,t7

	sw	a1,0(a0)
	sw	a1,4(a0)
	sw	a1,8(a0)
	sw	a1,12(a0)
	sw	a1,16(a0)
	sw	a1,20(a0)
	sw	a1,24(a0)
	sw	a1,28(a0)
	addiu	a0,a0,32

.Lchk1w:
	andi	t8,a2,0x3	# now t8 is the reminder past 1w chunks
	beq	a2,t8,.Llast4aligned
	 subu	a3,a2,t8	# a3 is the count of bytes in 1w chunks
	addu	a3,a0,a3	# now a3 is the dst address past the 1w chunks

# copying in words (4-byte chunks)
.LwordCopy_loop:
	addiu	a0,a0,4
	bne	a0,a3,.LwordCopy_loop
	 sw	a1,-4(a0)

# store last 0-3 bytes
# this will repeat the last store if the memset finishes on a word boundary
.Llast4aligned:
	j	ra
	 SWLO	a1,-1(t0)

.Llast4:
	beq	a0,t0,.Llast4e
.Llast4l:
	 addiu	a0,a0,1
	bne	a0,t0,.Llast4l
	 sb	a1,-1(a0)
.Llast4e:
	j	ra
	 nop

	.set	at
	.set	reorder

END(memset)


/************************************************************************
 *  Implementation : Static functions
 ************************************************************************/
