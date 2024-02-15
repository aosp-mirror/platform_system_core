/*
 * Copyright 2013, The Android Open Source Project
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
.type crash1, %function
crash1:
	.cfi_startproc
	stp x29, x30, [sp, -16]!
	.cfi_def_cfa_offset 16
	.cfi_rel_offset x29, 0
	.cfi_rel_offset x30, 8
	ldr x0, =0xa5a50000
	ldr x1, =0xa5a50001
	ldr x2, =0xa5a50002
	ldr x3, =0xa5a50003
	ldr x4, =0xa5a50004
	ldr x5, =0xa5a50005
	ldr x6, =0xa5a50006
	ldr x7, =0xa5a50007
	ldr x8, =0xa5a50008
	ldr x9, =0xa5a50009
	ldr x10, =0xa5a50010
	ldr x11, =0xa5a50011
	ldr x12, =0xa5a50012
	ldr x13, =0xa5a50013
	ldr x14, =0xa5a50014
	ldr x15, =0xa5a50015
	ldr x16, =0xa5a50016
	ldr x17, =0xa5a50017
	ldr x18, =0xa5a50018
	ldr x19, =0xa5a50019
	ldr x20, =0xa5a50020
	ldr x21, =0xa5a50021
	ldr x22, =0xa5a50022
	ldr x23, =0xa5a50023
	ldr x24, =0xa5a50024
	ldr x25, =0xa5a50025
	ldr x26, =0xa5a50026
	ldr x27, =0xa5a50027
	ldr x28, =0xa5a50028
	ldr x29, =0xa5a50029

	mov x30, xzr
	ldr x30, [x30]
	b .
	.cfi_endproc
	.size crash1, .-crash1


.globl crash_no_stack
.type crash_no_stack, %function
crash_no_stack:
	.cfi_startproc
	mov x1, sp
	.cfi_def_cfa_register x1
	mov x0, xzr
	add sp, x0, xzr
	ldr x0, [x0]
	b .
	.cfi_endproc
	.size crash_no_stack, .-crash_no_stack


.globl crash_bti
.type crash_bti, %function
crash_bti:
	.cfi_startproc
	adr x16, 1f
	br x16
1:	// Deliberatly not a bti instruction so we crash here.
	b .
	.cfi_endproc
	.size crash_bti, .-crash_bti


.globl crash_pac
.type crash_pac, %function
crash_pac:
	.cfi_startproc
	paciasp
	// Since sp is a pac input, this ensures a mismatch.
	sub sp, sp, #16
	autiasp
	b .
	.cfi_endproc
	.size crash_pac, .-crash_pac

// Set the PAC and BTI bits for this object file.
.section .note.gnu.property, "a"
.balign 8
.long 4
.long 0x10
.long 0x5
.asciz "GNU"
.long 0xc0000000
.long 4
.long 0x3
.long 0
