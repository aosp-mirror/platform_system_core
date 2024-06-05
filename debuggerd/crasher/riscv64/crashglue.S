/*
 * Copyright 2022, The Android Open Source Project
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
	.cfi_startproc
	addi sp, sp, -16
	.cfi_def_cfa_offset 16
	sd ra, 8(sp)
	.cfi_offset ra, -8

	li	x0,0xa5a50000
	li	x1,0xa5a50001
	li	x2,0xa5a50002
	li	x3,0xa5a50003
	li	x4,0xa5a50004
	li	x5,0xa5a50005
	li	x6,0xa5a50006
	li	x7,0xa5a50007
	li	x8,0xa5a50008
	li	x9,0xa5a50009
	li	x10,0xa5a50010
	li	x11,0xa5a50011
	li	x12,0xa5a50012
	li	x13,0xa5a50013
	li	x14,0xa5a50014
	li	x15,0xa5a50015
	li	x16,0xa5a50016
	li	x17,0xa5a50017
	li	x18,0xa5a50018
	li	x19,0xa5a50019
	li	x20,0xa5a50020
	li	x21,0xa5a50021
	li	x22,0xa5a50022
	li	x23,0xa5a50023
	li	x24,0xa5a50024
	li	x25,0xa5a50025
	li	x26,0xa5a50026
	li	x27,0xa5a50027
	li	x28,0xa5a50028
	li	x29,0xa5a50029
	li	x30,0xa5a50030
	li	x31,0xa5a50031

	li sp, 0
	ld t2, 0(zero)
	j .
	.cfi_endproc
	.size crash1, .-crash1


.globl crash_no_stack
crash_no_stack:
	.cfi_startproc
	mv t1, sp
	.cfi_def_cfa_register t1
	li sp, 0
	ld t2, 0(zero)
	j .
	.cfi_endproc
	.size crash_no_stack, .-crash_no_stack
