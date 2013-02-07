	.global	android_memset16_dumb
	.type   android_memset16_dumb, @function
android_memset16_dumb:
        .ent	android_memset16_dumb

	.set	noreorder
	beqz	$a2,9f
	 srl	$a2,1

1:	sh	$a1,($a0)
	subu	$a2,1
	bnez	$a2,1b
	 addu	$a0,2
	.set reorder

9:	j	$ra
        .end	android_memset16_dumb
	.size	android_memset16_dumb,.-android_memset16_dumb

	.global android_memset32_dumb
	.type	android_memset32_dumb, @function
android_memset32_dumb:
        .ent	android_memset32_dumb
	.set	noreorder
	beqz	$a2,9f
	 srl	$a2,2

1:	sw	$a1,($a0)
	subu	$a2,1
	bnez	$a2,1b
	 addu	$a0,4
	.set reorder

9:	j	$ra
        .end	android_memset32_dumb
	.size	android_memset32_dumb,.-android_memset32_dumb
