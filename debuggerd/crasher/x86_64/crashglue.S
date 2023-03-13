.globl crash1
.globl crashnostack

crash1:
	movl $0xa5a50000, %eax
	movl $0xa5a50001, %ebx
	movl $0xa5a50002, %ecx

	movl $0, %edx
	jmp *%rdx


crashnostack:
	.cfi_startproc
	movq %rsp, %rax
	.cfi_def_cfa_register %rax
	movq $0, %rsp
	movq (%rsp), %rbx
	.cfi_endproc
