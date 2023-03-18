.globl crash1
.type crash1, %function
crash1:
	.cfi_startproc
	push {lr}
	.cfi_def_cfa_offset 4
	.cfi_rel_offset lr, 0
	ldr r0, =0xa5a50000
	ldr r1, =0xa5a50001
	ldr r2, =0xa5a50002
	ldr r3, =0xa5a50003
	ldr r4, =0xa5a50004
	ldr r5, =0xa5a50005
	ldr r6, =0xa5a50006
	ldr r7, =0xa5a50007
	ldr r8, =0xa5a50008
	ldr r9, =0xa5a50009
	ldr r10, =0xa5a50010
	ldr r11, =0xa5a50011
	ldr r12, =0xa5a50012

	mov lr, #0
	ldr lr, [lr]
	b .
	.cfi_endproc

.globl crashnostack
.type crashnostack, %function
crashnostack:
	.cfi_startproc
	mov r1, sp
	.cfi_def_cfa_register r1
	mov sp, #0
	mov r0, #0
	ldr r0, [r0]
	b .
	.cfi_endproc
