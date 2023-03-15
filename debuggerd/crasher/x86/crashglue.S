.globl crash1
.globl crashnostack

crash1:
	movl $0xa5a50000, %eax
	movl $0xa5a50001, %ebx
	movl $0xa5a50002, %ecx

	movl $0, %edx
	jmp *%edx


crashnostack:
	.cfi_startproc
	movl %esp, %eax
	.cfi_def_cfa_register %eax
	movl $0, %esp
	movl (%esp), %ebx
	.cfi_endproc
