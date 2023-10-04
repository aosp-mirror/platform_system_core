/*
 * Copyright 2010, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

.globl crash1
crash1:
	movl $0xa5a50000, %eax
	movl $0xa5a50001, %ebx
	movl $0xa5a50002, %ecx

	movl $0, %edx
	jmp *%edx
	.size crash1, .-crash1


.globl crash_no_stack
crash_no_stack:
	.cfi_startproc
	movl %esp, %eax
	.cfi_def_cfa_register %eax
	movl $0, %esp
	movl (%esp), %ebx
	.cfi_endproc
	.size crash_no_stack, .-crash_no_stack
