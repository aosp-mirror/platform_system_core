	.set	noat

	.globl crash1
	.globl crashnostack

crash1:
	li	$0,0xdead0000+0
	li	$1,0xdead0000+1
	li	$2,0xdead0000+2
	li	$3,0xdead0000+3
	li	$4,0xdead0000+4
	li	$5,0xdead0000+5
	li	$6,0xdead0000+6
	li	$7,0xdead0000+7
	li	$8,0xdead0000+8
	li	$9,0xdead0000+9
	li	$10,0xdead0000+10
	li	$11,0xdead0000+11
	li	$12,0xdead0000+12
	li	$13,0xdead0000+13
	li	$14,0xdead0000+14
	li	$15,0xdead0000+15
	li	$16,0xdead0000+16
	li	$17,0xdead0000+17
	li	$18,0xdead0000+18
	li	$19,0xdead0000+19
	li	$20,0xdead0000+20
	li	$21,0xdead0000+21
	li	$22,0xdead0000+22
	li	$23,0xdead0000+23
	li	$24,0xdead0000+24
	li	$25,0xdead0000+25
	li	$26,0xdead0000+26
	li	$27,0xdead0000+27
	li	$28,0xdead0000+28
	# don't trash the stack otherwise the signal handler won't run
	#li	$29,0xdead0000+29
	li	$30,0xdead0000+30
	li	$31,0xdead0000+31

	lw	$zero,($0)
	b .


crashnostack:
	li	$sp, 0
	lw	$zero,($0)
	b .
