.globl crash1
crash1:
	.cfi_startproc
	addi sp, sp, -16
	.cfi_def_cfa_offset 16
	sd ra, 8(sp)
	.cfi_offset ra, -8

	li	x0,0xdead0000+0
	li	x1,0xdead0000+1
	li	x2,0xdead0000+2
	li	x3,0xdead0000+3
	li	x4,0xdead0000+4
	li	x5,0xdead0000+5
	li	x6,0xdead0000+6
	li	x7,0xdead0000+7
	li	x8,0xdead0000+8
	li	x9,0xdead0000+9
	li	x10,0xdead0000+10
	li	x11,0xdead0000+11
	li	x12,0xdead0000+12
	li	x13,0xdead0000+13
	li	x14,0xdead0000+14
	li	x15,0xdead0000+15
	li	x16,0xdead0000+16
	li	x17,0xdead0000+17
	li	x18,0xdead0000+18
	li	x19,0xdead0000+19
	li	x20,0xdead0000+20
	li	x21,0xdead0000+21
	li	x22,0xdead0000+22
	li	x23,0xdead0000+23
	li	x24,0xdead0000+24
	li	x25,0xdead0000+25
	li	x26,0xdead0000+26
	li	x27,0xdead0000+27
	li	x28,0xdead0000+28
	# don't trash the stack otherwise the signal handler won't run
	#li	x29,0xdead0000+29
	li	x30,0xdead0000+30
	li	x31,0xdead0000+31

	li sp, 0
	ld t2, 0(zero)
	j .
	.cfi_endproc


.globl crashnostack
crashnostack:
	.cfi_startproc
	mv t1, sp
	.cfi_def_cfa_register t1
	li sp, 0
	ld t2, 0(zero)
	j .
	.cfi_endproc
