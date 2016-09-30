/*
 * Copyright (C) 2015 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <errno.h>
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include <android/log.h>
#include <cutils/ashmem.h>

#include "codeflinger/ARMAssemblerInterface.h"
#include "codeflinger/MIPS64Assembler.h"

using namespace android;

#define TESTS_DATAOP_ENABLE             1
#define TESTS_DATATRANSFER_ENABLE       1
#define ASSEMBLY_SCRATCH_SIZE           4096

void *instrMem;
uint32_t  instrMemSize = 128 * 1024;
char     dataMem[8192];

typedef void (*asm_function_t)();
extern "C" void asm_mips_test_jacket(asm_function_t function,
                                     int64_t regs[], int32_t flags[]);

#define MAX_32BIT (uint32_t)(((uint64_t)1 << 32) - 1)
#define MAX_64BIT ((uint64_t)0xFFFFFFFFFFFFFFFF)
const uint32_t NA = 0;
const uint32_t NUM_REGS = 32;
const uint32_t NUM_FLAGS = 16;

enum instr_t
{
    INSTR_ADD,
    INSTR_SUB,
    INSTR_AND,
    INSTR_ORR,
    INSTR_RSB,
    INSTR_BIC,
    INSTR_CMP,
    INSTR_MOV,
    INSTR_MVN,
    INSTR_MUL,
    INSTR_MLA,
    INSTR_SMULBB,
    INSTR_SMULBT,
    INSTR_SMULTB,
    INSTR_SMULTT,
    INSTR_SMULWB,
    INSTR_SMULWT,
    INSTR_SMLABB,
    INSTR_UXTB16,
    INSTR_UBFX,
    INSTR_ADDR_ADD,
    INSTR_ADDR_SUB,
    INSTR_LDR,
    INSTR_LDRB,
    INSTR_LDRH,
    INSTR_ADDR_LDR,
    INSTR_LDM,
    INSTR_STR,
    INSTR_STRB,
    INSTR_STRH,
    INSTR_ADDR_STR,
    INSTR_STM
};

enum shift_t
{
    SHIFT_LSL,
    SHIFT_LSR,
    SHIFT_ASR,
    SHIFT_ROR,
    SHIFT_NONE
};

enum offset_t
{
    REG_SCALE_OFFSET,
    REG_OFFSET,
    IMM8_OFFSET,
    IMM12_OFFSET,
    NO_OFFSET
};

enum cond_t
{
    EQ, NE, CS, CC, MI, PL, VS, VC, HI, LS, GE, LT, GT, LE, AL, NV,
    HS = CS,
    LO = CC
};

const char * cc_code[] =
{
    "EQ", "NE", "CS", "CC", "MI", "PL", "VS", "VC",
    "HI", "LS","GE","LT", "GT", "LE", "AL", "NV"
};

struct condTest_t
{
    int     mode;
    int32_t Rcond1;
    int32_t Rcond2;
    uint64_t Rcond1Value;
    uint64_t Rcond2Value;
};


struct dataOpTest_t
{
    uint32_t   id;
    instr_t    op;
    condTest_t preCond;
    cond_t     cond;
    bool       setFlags;
    uint64_t   RnValue;
    uint64_t   RsValue;
    bool       immediate;
    uint32_t   immValue;
    uint64_t   RmValue;
    uint32_t   shiftMode;
    uint32_t   shiftAmount;
    uint64_t   RdValue;
    bool       checkRd;
    uint64_t   postRdValue;
};

struct dataTransferTest_t
{
    uint32_t id;
    instr_t  op;
    uint32_t preFlag;
    cond_t   cond;
    bool     setMem;
    uint64_t memOffset;
    uint64_t memValue;
    uint64_t RnValue;
    offset_t offsetType;
    uint64_t RmValue;
    uint32_t immValue;
    bool     writeBack;
    bool     preIndex;
    bool     postIndex;
    uint64_t RdValue;
    uint64_t postRdValue;
    uint64_t postRnValue;
    bool     checkMem;
    uint64_t postMemOffset;
    uint32_t postMemLength;
    uint64_t postMemValue;
};


dataOpTest_t dataOpTests [] =
{
     {0xA000,INSTR_ADD,{0,0,0,0,0},AL,0,1,NA,1,MAX_32BIT,NA,NA,NA,NA,1,0},
     {0xA001,INSTR_ADD,{0,0,0,0,0},AL,0,1,NA,1,MAX_32BIT-1,NA,NA,NA,NA,1,MAX_64BIT},
     {0xA002,INSTR_ADD,{0,0,0,0,0},AL,0,1,NA,0,NA,MAX_32BIT,NA,NA,NA,1,0},
     {0xA003,INSTR_ADD,{0,0,0,0,0},AL,0,1,NA,0,NA,MAX_32BIT-1,NA,NA,NA,1,MAX_64BIT},
     {0xA004,INSTR_ADD,{0,0,0,0,0},AL,0,1,NA,0,0,MAX_32BIT,SHIFT_LSL, 0,NA,1,0},
     {0xA005,INSTR_ADD,{0,0,0,0,0},AL,0,1,NA,0,0,MAX_32BIT,SHIFT_LSL,31,NA,1,0xFFFFFFFF80000001},
     {0xA006,INSTR_ADD,{0,0,0,0,0},AL,0,1,NA,0,0,3,SHIFT_LSR,1,NA,1,2},
     {0xA007,INSTR_ADD,{0,0,0,0,0},AL,0,1,NA,0,0,MAX_32BIT,SHIFT_LSR,31,NA,1,2},
     {0xA008,INSTR_ADD,{0,0,0,0,0},AL,0,0,NA,0,0,3,SHIFT_ASR,1,NA,1,1},
     {0xA009,INSTR_ADD,{0,0,0,0,0},AL,0,1,NA,0,0,MAX_64BIT,SHIFT_ASR,31,NA,1,0},
     {0xA010,INSTR_AND,{0,0,0,0,0},AL,0,1,NA,1,MAX_32BIT,0,0,0,NA,1,1},
     {0xA011,INSTR_AND,{0,0,0,0,0},AL,0,1,NA,1,MAX_32BIT-1,0,0,0,NA,1,0},
     {0xA012,INSTR_AND,{0,0,0,0,0},AL,0,1,NA,0,0,MAX_32BIT,0,0,NA,1,1},
     {0xA013,INSTR_AND,{0,0,0,0,0},AL,0,1,NA,0,0,MAX_32BIT-1,0,0,NA,1,0},
     {0xA014,INSTR_AND,{0,0,0,0,0},AL,0,1,NA,0,0,MAX_32BIT,SHIFT_LSL,0,NA,1,1},
     {0xA015,INSTR_AND,{0,0,0,0,0},AL,0,1,NA,0,0,MAX_32BIT,SHIFT_LSL,31,NA,1,0},
     {0xA016,INSTR_AND,{0,0,0,0,0},AL,0,1,NA,0,0,3,SHIFT_LSR,1,NA,1,1},
     {0xA017,INSTR_AND,{0,0,0,0,0},AL,0,1,NA,0,0,MAX_32BIT,SHIFT_LSR,31,NA,1,1},
     {0xA018,INSTR_AND,{0,0,0,0,0},AL,0,0,NA,0,0,3,SHIFT_ASR,1,NA,1,0},
     {0xA019,INSTR_AND,{0,0,0,0,0},AL,0,1,NA,0,0,MAX_32BIT,SHIFT_ASR,31,NA,1,1},
     {0xA020,INSTR_ORR,{0,0,0,0,0},AL,0,3,NA,1,MAX_32BIT,0,0,0,NA,1,MAX_64BIT},
     {0xA021,INSTR_ORR,{0,0,0,0,0},AL,0,2,NA,1,MAX_32BIT-1,0,0,0,NA,1,MAX_64BIT-1},
     {0xA022,INSTR_ORR,{0,0,0,0,0},AL,0,3,NA,0,0,MAX_32BIT,0,0,NA,1,MAX_64BIT},
     {0xA023,INSTR_ORR,{0,0,0,0,0},AL,0,2,NA,0,0,MAX_32BIT-1,0,0,NA,1,MAX_64BIT-1},
     {0xA024,INSTR_ORR,{0,0,0,0,0},AL,0,1,NA,0,0,MAX_32BIT,SHIFT_LSL,0,NA,1,MAX_64BIT},
     {0xA025,INSTR_ORR,{0,0,0,0,0},AL,0,1,NA,0,0,MAX_32BIT,SHIFT_LSL,31,NA,1,0xFFFFFFFF80000001},
     {0xA026,INSTR_ORR,{0,0,0,0,0},AL,0,1,NA,0,0,3,SHIFT_LSR,1,NA,1,1},
     {0xA027,INSTR_ORR,{0,0,0,0,0},AL,0,0,NA,0,0,MAX_32BIT,SHIFT_LSR,31,NA,1,1},
     {0xA028,INSTR_ORR,{0,0,0,0,0},AL,0,0,NA,0,0,3,SHIFT_ASR,1,NA,1,1},
     {0xA029,INSTR_ORR,{0,0,0,0,0},AL,0,1,NA,0,0,MAX_64BIT,SHIFT_ASR,31,NA,1,MAX_64BIT},
     {0xA030,INSTR_CMP,{0,0,0,0,0},AL,1,0x10000,NA,1,0x10000,0,0,0,NA,0,0},
     {0xA031,INSTR_MUL,{0,0,0,0,0},AL,0,0,0x10000,0,0,0x10000,0,0,NA,1,0},
     {0xA032,INSTR_MUL,{0,0,0,0,0},AL,0,0,0x1000,0,0,0x10000,0,0,NA,1,0x10000000},
     {0xA033,INSTR_MUL,{0,0,0,0,0},AL,0,0,MAX_32BIT,0,0,1,0,0,NA,1,MAX_64BIT},
     {0xA034,INSTR_MLA,{0,0,0,0,0},AL,0,0x10000,0x10000,0,0,0x10000,0,0,NA,1,0x10000},
     {0xA035,INSTR_MLA,{0,0,0,0,0},AL,0,0x10000,0x1000,0,0,0x10000,0,0,NA,1,0x10010000},
     {0xA036,INSTR_SUB,{1,R_v1,R_a6,2,4},MI,0,2,NA,0,NA,1,NA,NA,2,1,1},
     {0xA037,INSTR_SUB,{2,R_v1,R_a6,2,0},MI,0,2,NA,0,NA,1,NA,NA,2,1,2},
     {0xA038,INSTR_SUB,{1,R_v1,R_a6,4,2},GE,0,2,NA,1,1,NA,NA,NA,2,1,1},
     {0xA039,INSTR_SUB,{1,R_a5,R_a6,2,7},GE,0,2,NA,1,1,NA,NA,NA,2,1,2},
     {0xA040,INSTR_SUB,{1,R_a5,R_a6,1,1},HS,0,2,NA,1,1,NA,NA,NA,2,1,1},
     {0xA041,INSTR_SUB,{1,R_a5,R_a6,0,1},HS,0,2,NA,1,1,NA,NA,NA,2,1,2},
     {0xA042,INSTR_SUB,{0,0,0,0,0},AL,0,1,NA,1,1<< 16,0,0,0,NA,1,UINT64_C(1) -(1<<16)},
     {0xA043,INSTR_SUB,{0,0,0,0,0},AL,0,MAX_32BIT,NA,1,1,0,0,0,NA,1,MAX_64BIT-1},
     {0xA044,INSTR_SUB,{0,0,0,0,0},AL,0,1,NA,1,1,0,0,0,NA,1,0},
     {0xA045,INSTR_SUB,{0,0,0,0,0},AL,0,1,NA,0,NA,1<<16,0,0,NA,1,UINT64_C(1) -(1<<16)},
     {0xA046,INSTR_SUB,{0,0,0,0,0},AL,0,MAX_32BIT,NA,0,NA,1,0,0,NA,1,MAX_64BIT-1},
     {0xA047,INSTR_SUB,{0,0,0,0,0},AL,0,1,NA,0,NA,1,0,0,NA,1,0},
     {0xA048,INSTR_SUB,{0,0,0,0,0},AL,0,1,NA,0,NA,1,SHIFT_LSL,16,NA,1,UINT64_C(1) -(1<<16)},
     {0xA049,INSTR_SUB,{0,0,0,0,0},AL,0,0x80000001,NA,0,NA,MAX_32BIT,SHIFT_LSL,31,NA,1,1},
     {0xA050,INSTR_SUB,{0,0,0,0,0},AL,0,1,NA,0,NA,3,SHIFT_LSR,1,NA,1,0},
     {0xA051,INSTR_SUB,{0,0,0,0,0},AL,0,1,NA,0,NA,MAX_32BIT,SHIFT_LSR,31,NA,1,0},
     {0xA052,INSTR_RSB,{1,R_a5,R_a6,4,1},GE,0,2,NA,1,0,NA,NA,NA,2,1,UINT64_C(-2)},
     {0xA053,INSTR_RSB,{1,R_a5,R_a6,UINT64_C(-1),1},GE,0,2,NA,1,0,NA,NA,NA,2,1,2},
     {0xA054,INSTR_RSB,{0,0,0,0,0},AL,0,1,NA,1,1<<16,NA,NA,NA,NA,1,(1<<16)-1},
     {0xA055,INSTR_RSB,{0,0,0,0,0},AL,0,MAX_32BIT,NA,1,1,NA,NA,NA,NA,1,UINT64_C(1)-MAX_64BIT},
     {0xA056,INSTR_RSB,{0,0,0,0,0},AL,0,1,NA,1,1,NA,NA,NA,NA,1,0},
     {0xA057,INSTR_RSB,{0,0,0,0,0},AL,0,1,NA,0,NA,1<<16,0,0,NA,1,(1<<16)-1},
     {0xA058,INSTR_RSB,{0,0,0,0,0},AL,0,MAX_32BIT,NA,0,NA,1,0,0,NA,1,UINT64_C(1)-MAX_64BIT},
     {0xA059,INSTR_RSB,{0,0,0,0,0},AL,0,1,NA,0,NA,1,0,0,NA,1,0},
     {0xA060,INSTR_RSB,{0,0,0,0,0},AL,0,1,NA,0,NA,1,SHIFT_LSL,16,NA,1,(1<<16)-1},
     {0xA061,INSTR_RSB,{0,0,0,0,0},AL,0,0x80000001,NA,0,NA,MAX_32BIT ,SHIFT_LSL,31,NA,1,UINT64_C(-1)},
     {0xA062,INSTR_RSB,{0,0,0,0,0},AL,0,1,NA,0,NA,3,SHIFT_LSR,1,NA,1,0},
     {0xA063,INSTR_RSB,{0,0,0,0,0},AL,0,1,NA,0,NA,MAX_32BIT,SHIFT_LSR,31,NA,1,0},
     {0xA064,INSTR_MOV,{0,0,0,0,0},AL,0,NA,NA,1,0x80000001,NA,NA,NA,NA,1,0xFFFFFFFF80000001},
     {0xA065,INSTR_MOV,{0,0,0,0,0},AL,0,NA,NA,0,0,0x80000001,0,0,NA,1,0xFFFFFFFF80000001},
     {0xA066,INSTR_MOV,{0,0,0,0,0},AL,0,NA,NA,0,0,MAX_32BIT,SHIFT_LSL,1,NA,1,MAX_64BIT-1},
     {0xA067,INSTR_MOV,{0,0,0,0,0},AL,0,NA,NA,0,0,MAX_32BIT,SHIFT_LSL,31,NA,1,0xFFFFFFFF80000000},
     {0xA068,INSTR_MOV,{0,0,0,0,0},AL,0,NA,NA,0,0,3,SHIFT_LSR,1,NA,1,1},
     {0xA069,INSTR_MOV,{0,0,0,0,0},AL,0,NA,NA,0,0,MAX_32BIT,SHIFT_LSR,31,NA,1,1},
     {0xA070,INSTR_MOV,{0,0,0,0,0},AL,0,NA,NA,0,0,3,SHIFT_ASR,1,NA,1,1},
     {0xA071,INSTR_MOV,{0,0,0,0,0},AL,0,NA,NA,0,0,MAX_64BIT ,SHIFT_ASR,31,NA,1,MAX_64BIT},
     {0xA072,INSTR_MOV,{0,0,0,0,0},AL,0,NA,NA,0,0,3,SHIFT_ROR,1,NA,1,0xFFFFFFFF80000001},
     {0xA073,INSTR_MOV,{0,0,0,0,0},AL,0,NA,NA,0,0,0x80000001,SHIFT_ROR,31,NA,1,3},
     {0xA074,INSTR_MOV,{0,0,0,0,0},AL,1,NA,NA,0,0,MAX_64BIT -1,SHIFT_ASR,1,NA,1,MAX_64BIT},
     {0xA075,INSTR_MOV,{0,0,0,0,0},AL,1,NA,NA,0,0,3,SHIFT_ASR,1,NA,1,1},
     {0xA076,INSTR_MOV,{2,R_a5,R_a6,6,8},MI,0,NA,NA,1,0x80000001,NA,NA,NA,2,1,2},
     {0xA077,INSTR_MOV,{2,R_a5,R_a6,UINT64_C(-4),UINT64_C(-8)},MI,0,NA,NA,0,0,0x80000001,0,0,2,1,0xFFFFFFFF80000001},
     {0xA078,INSTR_MOV,{1,R_a5,R_a6,UINT64_C(-1),UINT64_C(-1)},LT,0,NA,NA,1,0x80000001,NA,NA,NA,2,1,2},
     {0xA079,INSTR_MOV,{1,R_a5,R_a6,UINT64_C(-1),1},LT,0,NA,NA,1,0x80000001,NA,NA,NA,2,1,0xFFFFFFFF80000001},
     {0xA080,INSTR_MOV,{1,R_a5,R_a6,UINT64_C(-1),UINT64_C(-5)},GE,0,NA,NA,0,0,MAX_32BIT,SHIFT_LSL,1,2,1,MAX_64BIT-1},
     {0xA081,INSTR_MOV,{1,R_a5,R_a6,5,5},GE,0,NA,NA,0,0,MAX_32BIT,SHIFT_LSL,31,2,1,0xFFFFFFFF80000000},
     {0xA082,INSTR_MOV,{1,R_a5,R_a6,UINT64_C(-1),1},GE,0,NA,NA,0,0,MAX_32BIT,SHIFT_LSL,31,2,1,2},
     {0xA083,INSTR_MOV,{1,R_a5,R_a6,4,1},LE,0,NA,NA,0,0,MAX_32BIT,SHIFT_LSL,1,2,1,2},
     {0xA084,INSTR_MOV,{1,R_a5,R_a6,UINT64_C(-1),UINT64_C(-1)},LE,0,NA,NA,1,0x80000001,NA,NA,NA,2,1,0xFFFFFFFF80000001},
     {0xA085,INSTR_MOV,{1,R_a5,R_a6,UINT64_C(-1),1},LE,0,NA,NA,0,0,MAX_32BIT,SHIFT_LSL,31,2,1,0xFFFFFFFF80000000},
     {0xA086,INSTR_MOV,{1,R_a5,R_a6,1,1},GT,0,NA,NA,1,0x80000001,NA,NA,NA,2,1,2},
     {0xA087,INSTR_MOV,{1,R_a5,R_a6,UINT64_C(-1),UINT64_C(-3)},GT,0,NA,NA,1,0x80000001,NA,NA,NA,2,1,0xFFFFFFFF80000001},
     {0xA088,INSTR_MOV,{1,R_a5,R_a6,UINT64_C(-1),0},GT,0,NA,NA,1,0x80000001,NA,NA,NA,2,1,2},
     {0xA089,INSTR_MOV,{1,R_a5,R_a6,UINT64_C(-1),UINT64_C(-1)},GT,0,NA,NA,0,0,0x80000001,0,0,2,1,2},
     {0xA090,INSTR_MOV,{1,R_a5,R_a6,6,1},GT,0,NA,NA,0,0,0x80000001,0,0,2,1,0xFFFFFFFF80000001},
     {0xA091,INSTR_MOV,{1,R_a5,R_a6,UINT64_C(-1),1},GT,0,NA,NA,0,0,0x80000001,0,0,2,1,2},
     {0xA092,INSTR_MOV,{1,R_a5,R_a6,1,1},GT,0,NA,NA,0,0,MAX_32BIT,SHIFT_LSL,1,2,1,2},
     {0xA093,INSTR_MOV,{1,R_a5,R_a6,4,1},GT,0,NA,NA,0,0,MAX_32BIT,SHIFT_LSL,1,2,1,MAX_64BIT-1},
     {0xA094,INSTR_MOV,{1,R_a5,R_a6,UINT64_C(-1),1},GT,0,NA,NA,0,0,MAX_32BIT ,SHIFT_LSL,1,2,1,2},
     {0xA095,INSTR_MOV,{1,R_a5,R_a6,1,UINT64_C(-1)},HS,0,NA,NA,1,0x80000001,NA,NA,NA,2,1,2},
     {0xA096,INSTR_MOV,{1,R_a5,R_a6,UINT64_C(-1),1},HS,0,NA,NA,1,0x80000001,NA,NA,NA,2,1,0xFFFFFFFF80000001},
     {0xA097,INSTR_MVN,{1,R_a5,R_a6,1,4},HS,0,NA,NA,1,MAX_32BIT-1,NA,NA,NA,2,1,2},
     {0xA098,INSTR_MVN,{1,R_a5,R_a6,UINT64_C(-1),1},HS,0,NA,NA,1,MAX_32BIT-1,NA,NA,NA,2,1,1},
     {0xA099,INSTR_MVN,{0,0,0,0,0},AL,0,NA,NA,1,0,NA,NA,NA,2,1,MAX_64BIT},
     {0xA100,INSTR_MVN,{0,0,0,0,0},AL,0,NA,NA,0,NA,MAX_32BIT-1,NA,0,2,1,1},
     {0xA101,INSTR_MVN,{0,0,0,0,0},AL,0,NA,NA,0,NA,0x80000001,NA,0,2,1,0x7FFFFFFE},
     {0xA102,INSTR_BIC,{0,0,0,0,0},AL,0,1,NA,1,MAX_32BIT,NA,NA,NA,NA,1,0},
     {0xA103,INSTR_BIC,{0,0,0,0,0},AL,0,1,NA,1,MAX_32BIT-1,NA,NA,NA,NA,1,1},
     {0xA104,INSTR_BIC,{0,0,0,0,0},AL,0,1,NA,0,0,MAX_32BIT,0,0,NA,1,0},
     {0xA105,INSTR_BIC,{0,0,0,0,0},AL,0,1,NA,0,0,MAX_32BIT-1,0,0,NA,1,1},
     {0xA106,INSTR_BIC,{0,0,0,0,0},AL,0,0xF0,NA,0,0,3,SHIFT_ASR,1,NA,1,0xF0},
     {0xA107,INSTR_BIC,{0,0,0,0,0},AL,0,0xF0,NA,0,0,MAX_64BIT,SHIFT_ASR,31,NA,1,0},
     {0xA108,INSTR_SMULBB,{0,0,0,0,0},AL,0,NA,0xFFFFFFFFABCDFFFF,0,NA,0xFFFFFFFFABCD0001,NA,NA,NA,1,0xFFFFFFFFFFFFFFFF},
     {0xA109,INSTR_SMULBB,{0,0,0,0,0},AL,0,NA,0xFFFFFFFFABCD0001,0,NA,0xFFFFFFFFABCD0FFF,NA,NA,NA,1,0x00000FFF},
     {0xA110,INSTR_SMULBB,{0,0,0,0,0},AL,0,NA,0xFFFFFFFFABCD0001,0,NA,0xFFFFFFFFABCDFFFF,NA,NA,NA,1,0xFFFFFFFFFFFFFFFF},
     {0xA111,INSTR_SMULBB,{0,0,0,0,0},AL,0,NA,0xFFFFFFFFABCDFFFF,0,NA,0xFFFFFFFFABCDFFFF,NA,NA,NA,1,1},
     {0xA112,INSTR_SMULBT,{0,0,0,0,0},AL,0,NA,0xFFFFFFFFFFFFABCD,0,NA,0xFFFFFFFFABCD0001,NA,NA,NA,1,0xFFFFFFFFFFFFFFFF},
     {0xA113,INSTR_SMULBT,{0,0,0,0,0},AL,0,NA,0x000000000001ABCD,0,NA,0xFFFFFFFFABCD0FFF,NA,NA,NA,1,0x00000FFF},
     {0xA114,INSTR_SMULBT,{0,0,0,0,0},AL,0,NA,0x000000000001ABCD,0,NA,0xFFFFFFFFABCDFFFF,NA,NA,NA,1,0xFFFFFFFFFFFFFFFF},
     {0xA115,INSTR_SMULBT,{0,0,0,0,0},AL,0,NA,0xFFFFFFFFFFFFABCD,0,NA,0xFFFFFFFFABCDFFFF,NA,NA,NA,1,1},
     {0xA116,INSTR_SMULTB,{0,0,0,0,0},AL,0,NA,0xFFFFFFFFABCDFFFF,0,NA,0x000000000001ABCD,NA,NA,NA,1,0xFFFFFFFFFFFFFFFF},
     {0xA117,INSTR_SMULTB,{0,0,0,0,0},AL,0,NA,0xFFFFFFFFABCD0001,0,NA,0x000000000FFFABCD,NA,NA,NA,1,0x00000FFF},
     {0xA118,INSTR_SMULTB,{0,0,0,0,0},AL,0,NA,0xFFFFFFFFABCD0001,0,NA,0xFFFFFFFFFFFFABCD,NA,NA,NA,1,0xFFFFFFFFFFFFFFFF},
     {0xA119,INSTR_SMULTB,{0,0,0,0,0},AL,0,NA,0xFFFFFFFFABCDFFFF,0,NA,0xFFFFFFFFFFFFABCD,NA,NA,NA,1,1},
     {0xA120,INSTR_SMULTT,{0,0,0,0,0},AL,0,NA,0xFFFFFFFFFFFFABCD,0,NA,0x000000000001ABCD,NA,NA,NA,1,0xFFFFFFFFFFFFFFFF},
     {0xA121,INSTR_SMULTT,{0,0,0,0,0},AL,0,NA,0x000000000001ABCD,0,NA,0x000000000FFFABCD,NA,NA,NA,1,0x00000FFF},
     {0xA122,INSTR_SMULTT,{0,0,0,0,0},AL,0,NA,0x000000000001ABCD,0,NA,0xFFFFFFFFFFFFABCD,NA,NA,NA,1,0xFFFFFFFFFFFFFFFF},
     {0xA123,INSTR_SMULTT,{0,0,0,0,0},AL,0,NA,0xFFFFFFFFFFFFABCD,0,NA,0xFFFFFFFFFFFFABCD,NA,NA,NA,1,1},
     {0xA124,INSTR_SMULWB,{0,0,0,0,0},AL,0,NA,0xFFFFFFFFABCDFFFF,0,NA,0x000000000001ABCD,NA,NA,NA,1,0xFFFFFFFFFFFFFFFE},
     {0xA125,INSTR_SMULWB,{0,0,0,0,0},AL,0,NA,0xFFFFFFFFABCD0001,0,NA,0x000000000FFFABCD,NA,NA,NA,1,0x00000FFF},
     {0xA126,INSTR_SMULWB,{0,0,0,0,0},AL,0,NA,0xFFFFFFFFABCD0001,0,NA,0xFFFFFFFFFFFFABCD,NA,NA,NA,1,0xFFFFFFFFFFFFFFFF},
     {0xA127,INSTR_SMULWB,{0,0,0,0,0},AL,0,NA,0xFFFFFFFFABCDFFFF,0,NA,0xFFFFFFFFFFFFABCD,NA,NA,NA,1,0},
     {0xA128,INSTR_SMULWT,{0,0,0,0,0},AL,0,NA,0xFFFFFFFFFFFFABCD,0,NA,0x000000000001ABCD,NA,NA,NA,1,0xFFFFFFFFFFFFFFFE},
     {0xA129,INSTR_SMULWT,{0,0,0,0,0},AL,0,NA,0x000000000001ABCD,0,NA,0x000000000FFFABCD,NA,NA,NA,1,0x00000FFF},
     {0xA130,INSTR_SMULWT,{0,0,0,0,0},AL,0,NA,0x000000000001ABCD,0,NA,0xFFFFFFFFFFFFABCD,NA,NA,NA,1,0xFFFFFFFFFFFFFFFF},
     {0xA131,INSTR_SMULWT,{0,0,0,0,0},AL,0,NA,0xFFFFFFFFFFFFABCD,0,NA,0xFFFFFFFFFFFFABCD,NA,NA,NA,1,0},
     {0xA132,INSTR_SMLABB,{0,0,0,0,0},AL,0,1,0xFFFFFFFFABCDFFFF,0,NA,0xFFFFFFFFABCD0001,NA,NA,NA,1,0},
     {0xA133,INSTR_SMLABB,{0,0,0,0,0},AL,0,1,0xFFFFFFFFABCD0001,0,NA,0xFFFFFFFFABCD0FFF,NA,NA,NA,1,0x00001000},
     {0xA134,INSTR_SMLABB,{0,0,0,0,0},AL,0,0xFFFFFFFFFFFFFFFF,0xFFFFFFFFABCD0001,0,NA,0xABCDFFFF,NA,NA,NA,1,0xFFFFFFFFFFFFFFFE},
     {0xA135,INSTR_SMLABB,{0,0,0,0,0},AL,0,0xFFFFFFFFFFFFFFFF,0xFFFFFFFFABCDFFFF,0,NA,0xABCDFFFF,NA,NA,NA,1,0},
     {0xA136,INSTR_UXTB16,{0,0,0,0,0},AL,0,NA,NA,0,NA,0xABCDEF01,SHIFT_ROR,0,NA,1,0x00CD0001},
     {0xA137,INSTR_UXTB16,{0,0,0,0,0},AL,0,NA,NA,0,NA,0xABCDEF01,SHIFT_ROR,1,NA,1,0x00AB00EF},
     {0xA138,INSTR_UXTB16,{0,0,0,0,0},AL,0,NA,NA,0,NA,0xABCDEF01,SHIFT_ROR,2,NA,1,0x000100CD},
     {0xA139,INSTR_UXTB16,{0,0,0,0,0},AL,0,NA,NA,0,NA,0xABCDEF01,SHIFT_ROR,3,NA,1,0x00EF00AB},
     {0xA140,INSTR_ADDR_ADD,{0,0,0,0,0},AL,0,0xCFFFFFFFF,NA,0,NA,0x1,SHIFT_LSL,1,NA,1,0xD00000001},
     {0xA141,INSTR_ADDR_ADD,{0,0,0,0,0},AL,0,0x01,NA,0,NA,0x1,SHIFT_LSL,2,NA,1,0x5},
     {0xA142,INSTR_ADDR_ADD,{0,0,0,0,0},AL,0,0xCFFFFFFFF,NA,0,NA,0x1,NA,0,NA,1,0xD00000000},
     {0xA143,INSTR_ADDR_SUB,{0,0,0,0,0},AL,0,0xD00000001,NA,0,NA,0x010000,SHIFT_LSR,15,NA,1,0xCFFFFFFFF},
     {0xA144,INSTR_ADDR_SUB,{0,0,0,0,0},AL,0,0xCFFFFFFFF,NA,0,NA,0x020000,SHIFT_LSR,15,NA,1,0xCFFFFFFFB},
     {0xA145,INSTR_ADDR_SUB,{0,0,0,0,0},AL,0,3,NA,0,NA,0x010000,SHIFT_LSR,15,NA,1,1},
};

dataTransferTest_t dataTransferTests [] =
{
    {0xB000,INSTR_LDR,AL,AL,1,24,0xABCDEF0123456789,0,REG_SCALE_OFFSET,24,NA,NA,NA,NA,NA,0x23456789,0,0,NA,NA,NA},
    {0xB001,INSTR_LDR,AL,AL,1,0,0xABCDEF0123456789,0,IMM12_OFFSET,NA,4,1,0,1,NA,0x23456789,4,0,NA,NA,NA},
    {0xB002,INSTR_LDR,AL,AL,1,0,0xABCDEF0123456789,0,NO_OFFSET,NA,NA,0,0,0,NA,0x23456789,0,0,NA,NA,NA},
    {0xB003,INSTR_LDRB,AL,AL,1,4064,0xABCDEF0123456789,0,REG_SCALE_OFFSET,4064,NA,NA,NA,NA,NA,0x89,0,0,NA,NA,NA},
    {0xB004,INSTR_LDRB,AL,AL,1,4064,0xABCDEF0123456789,4065,IMM12_OFFSET,NA,0,0,1,0,NA,0x67,4065,0,NA,NA,NA},
    {0xB005,INSTR_LDRB,AL,AL,1,4064,0xABCDEF0123456789,4065,IMM12_OFFSET,NA,1,0,1,0,NA,0x45,4065,0,NA,NA,NA},
    {0xB006,INSTR_LDRB,AL,AL,1,4064,0xABCDEF0123456789,4065,IMM12_OFFSET,NA,2,0,1,0,NA,0x23,4065,0,NA,NA,NA},
    {0xB007,INSTR_LDRB,AL,AL,1,4064,0xABCDEF0123456789,4065,IMM12_OFFSET,NA,1,1,0,1,NA,0x67,4066,0,NA,NA,NA},
    {0xB008,INSTR_LDRB,AL,AL,1,4064,0xABCDEF0123456789,0,NO_OFFSET,NA,NA,0,0,0,NA,0x89,0,0,NA,NA,NA},
    {0xB009,INSTR_LDRH,AL,AL,1,0,0xABCDEF0123456789,0,IMM8_OFFSET,NA,2,1,0,1,NA,0x6789,2,0,NA,NA,NA},
    {0xB010,INSTR_LDRH,AL,AL,1,4064,0xABCDEF0123456789,0,REG_OFFSET,4064,0,0,1,0,NA,0x6789,0,0,NA,NA,NA},
    {0xB011,INSTR_LDRH,AL,AL,1,4064,0xABCDEF0123456789,0,REG_OFFSET,4066,0,0,1,0,NA,0x2345,0,0,NA,NA,NA},
    {0xB012,INSTR_LDRH,AL,AL,1,0,0xABCDEF0123456789,0,NO_OFFSET,NA,0,0,0,0,NA,0x6789,0,0,NA,NA,NA},
    {0xB013,INSTR_LDRH,AL,AL,1,0,0xABCDEF0123456789,2,NO_OFFSET,NA,0,0,0,0,NA,0x2345,2,0,NA,NA,NA},
    {0xB014,INSTR_STR,AL,AL,1,2,0xDEADBEEFDEADBEEF,4,IMM12_OFFSET,NA,4,1,0,1,0xABCDEF0123456789,0xABCDEF0123456789,8,1,2,8,0xDEAD23456789BEEF},
    {0xB015,INSTR_STR,AL,AL,1,2,0xDEADBEEFDEADBEEF,4,NO_OFFSET,NA,NA,0,0,0,0xABCDEF0123456789,0xABCDEF0123456789,4,1,2,8,0xDEAD23456789BEEF},
    {0xB016,INSTR_STRB,AL,AL,1,0,0xDEADBEEFDEADBEEF,1,IMM12_OFFSET,NA,0,0,1,0,0xABCDEF0123456789,0xABCDEF0123456789,1,1,0,8,0xDEADBEEFDEAD89EF},
    {0xB017,INSTR_STRB,AL,AL,1,0,0xDEADBEEFDEADBEEF,1,IMM12_OFFSET,NA,1,0,1,0,0xABCDEF0123456789,0xABCDEF0123456789,1,1,0,8,0xDEADBEEFDE89BEEF},
    {0xB018,INSTR_STRB,AL,AL,1,0,0xDEADBEEFDEADBEEF,1,IMM12_OFFSET,NA,2,0,1,0,0xABCDEF0123456789,0xABCDEF0123456789,1,1,0,8,0xDEADBEEF89ADBEEF},
    {0xB019,INSTR_STRB,AL,AL,1,0,0xDEADBEEFDEADBEEF,1,IMM12_OFFSET,NA,4,1,0,1,0xABCDEF0123456789,0xABCDEF0123456789,5,1,0,8,0xDEADBEEFDEAD89EF},
    {0xB020,INSTR_STRB,AL,AL,1,0,0xDEADBEEFDEADBEEF,1,NO_OFFSET,NA,NA,0,0,0,0xABCDEF0123456789,0xABCDEF0123456789,1,1,0,8,0xDEADBEEFDEAD89EF},
    {0xB021,INSTR_STRH,AL,AL,1,4066,0xDEADBEEFDEADBEEF,4070,IMM8_OFFSET,NA,2,1,0,1,0xABCDEF0123456789,0xABCDEF0123456789,4072,1,4066,8,0xDEAD6789DEADBEEF},
    {0xB022,INSTR_STRH,AL,AL,1,4066,0xDEADBEEFDEADBEEF,4070,NO_OFFSET,NA,NA,0,0,0,0xABCDEF0123456789,0xABCDEF0123456789,4070,1,4066,8,0xDEAD6789DEADBEEF},
};


void flushcache()
{
    const long base = long(instrMem);
    const long curr = base + long(instrMemSize);
    __builtin___clear_cache((char*)base, (char*)curr);
}

void dataOpTest(dataOpTest_t test, ArmToMips64Assembler *a64asm, uint32_t Rd = R_v1,
                uint32_t Rn = R_t0, uint32_t Rm = R_t1, uint32_t Rs = R_t2)
{
    int64_t  regs[NUM_REGS] = {0};
    int32_t  flags[NUM_FLAGS] = {0};
    int64_t  savedRegs[NUM_REGS] = {0};
    uint32_t i;
    uint32_t op2;

    for(i = 0; i < NUM_REGS; ++i)
    {
        regs[i] = i;
    }

    regs[Rd] = test.RdValue;
    regs[Rn] = test.RnValue;
    regs[Rs] = test.RsValue;
    a64asm->reset();
    if (test.preCond.mode) {
        a64asm->set_condition(test.preCond.mode, test.preCond.Rcond1, test.preCond.Rcond2);
        regs[test.preCond.Rcond1] = test.preCond.Rcond1Value;
        regs[test.preCond.Rcond2] = test.preCond.Rcond2Value;
    }
    a64asm->prolog();
    if(test.immediate == true)
    {
        op2 = a64asm->imm(test.immValue);
    }
    else if(test.immediate == false && test.shiftAmount == 0)
    {
        op2 = Rm;
        regs[Rm] = (int64_t)((int32_t)(test.RmValue));
    }
    else
    {
        op2 = a64asm->reg_imm(Rm, test.shiftMode, test.shiftAmount);
        regs[Rm] = (int64_t)((int32_t)(test.RmValue));
    }
    switch(test.op)
    {
    case INSTR_ADD: a64asm->ADD(test.cond, test.setFlags, Rd,Rn,op2); break;
    case INSTR_SUB: a64asm->SUB(test.cond, test.setFlags, Rd,Rn,op2); break;
    case INSTR_RSB: a64asm->RSB(test.cond, test.setFlags, Rd,Rn,op2); break;
    case INSTR_AND: a64asm->AND(test.cond, test.setFlags, Rd,Rn,op2); break;
    case INSTR_ORR: a64asm->ORR(test.cond, test.setFlags, Rd,Rn,op2); break;
    case INSTR_BIC: a64asm->BIC(test.cond, test.setFlags, Rd,Rn,op2); break;
    case INSTR_MUL: a64asm->MUL(test.cond, test.setFlags, Rd,Rm,Rs); break;
    case INSTR_MLA: a64asm->MLA(test.cond, test.setFlags, Rd,Rm,Rs,Rn); break;
    case INSTR_CMP: a64asm->CMP(test.cond, Rn,op2); break;
    case INSTR_MOV: a64asm->MOV(test.cond, test.setFlags,Rd,op2); break;
    case INSTR_MVN: a64asm->MVN(test.cond, test.setFlags,Rd,op2); break;
    case INSTR_SMULBB:a64asm->SMULBB(test.cond, Rd,Rm,Rs); break;
    case INSTR_SMULBT:a64asm->SMULBT(test.cond, Rd,Rm,Rs); break;
    case INSTR_SMULTB:a64asm->SMULTB(test.cond, Rd,Rm,Rs); break;
    case INSTR_SMULTT:a64asm->SMULTT(test.cond, Rd,Rm,Rs); break;
    case INSTR_SMULWB:a64asm->SMULWB(test.cond, Rd,Rm,Rs); break;
    case INSTR_SMULWT:a64asm->SMULWT(test.cond, Rd,Rm,Rs); break;
    case INSTR_SMLABB:a64asm->SMLABB(test.cond, Rd,Rm,Rs,Rn); break;
    case INSTR_UXTB16:a64asm->UXTB16(test.cond, Rd,Rm,test.shiftAmount); break;
    case INSTR_ADDR_ADD: a64asm->ADDR_ADD(test.cond, test.setFlags, Rd,Rn,op2); break;
    case INSTR_ADDR_SUB: a64asm->ADDR_SUB(test.cond, test.setFlags, Rd,Rn,op2); break;
    default: printf("Error"); return;
    }
    a64asm->epilog(0);
    a64asm->fix_branches();
    flushcache();

    asm_function_t asm_function = (asm_function_t)(instrMem);

    for(i = 0; i < NUM_REGS; ++i)
        savedRegs[i] = regs[i];

    asm_mips_test_jacket(asm_function, regs, flags);

    /* Check if all regs except Rd is same */
    for(i = 0; i < NUM_REGS; ++i)
    {
        if((i == Rd) || i == 2) continue;
        if(regs[i] != savedRegs[i])
        {
            printf("Test %x failed Reg(%d) tampered Expected(0x%" PRIx64 "),"
                   "Actual(0x%" PRIx64 ") t\n", test.id, i, savedRegs[i],
                   regs[i]);
            exit(0);
            return;
        }
    }

    if(test.checkRd == 1 && regs[Rd] != test.postRdValue)
    {
        printf("Test %x failed, Expected(%" PRIx64 "), Actual(%" PRIx64 ")\n",
               test.id, test.postRdValue, regs[Rd]);
        exit(0);
    }
    else
    {
        printf("Test %x passed\n", test.id);
    }
}


void dataTransferTest(dataTransferTest_t test, ARMAssemblerInterface *a64asm,
                      uint32_t Rd = R_v1, uint32_t Rn = R_t0,uint32_t Rm = R_t1)
{
    int64_t regs[NUM_REGS] = {0};
    int64_t savedRegs[NUM_REGS] = {0};
    int32_t flags[NUM_FLAGS] = {0};
    uint32_t i;
    for(i = 0; i < NUM_REGS; ++i)
    {
        regs[i] = i;
    }

    uint32_t op2;

    regs[Rd] = test.RdValue;
    regs[Rn] = (uint64_t)(&dataMem[test.RnValue]);
    regs[Rm] = test.RmValue;
    flags[test.preFlag] = 1;

    if(test.setMem == true)
    {
        unsigned char *mem = (unsigned char *)&dataMem[test.memOffset];
        uint64_t value = test.memValue;
        for(int j = 0; j < 8; ++j)
        {
            mem[j] = value & 0x00FF;
            value >>= 8;
        }
    }
    a64asm->reset();
    a64asm->prolog();
    if(test.offsetType == REG_SCALE_OFFSET)
    {
        op2 = a64asm->reg_scale_pre(Rm);
    }
    else if(test.offsetType == REG_OFFSET)
    {
        op2 = a64asm->reg_pre(Rm);
    }
    else if(test.offsetType == IMM12_OFFSET && test.preIndex == true)
    {
        op2 = a64asm->immed12_pre(test.immValue, test.writeBack);
    }
    else if(test.offsetType == IMM12_OFFSET && test.postIndex == true)
    {
        op2 = a64asm->immed12_post(test.immValue);
    }
    else if(test.offsetType == IMM8_OFFSET && test.preIndex == true)
    {
        op2 = a64asm->immed8_pre(test.immValue, test.writeBack);
    }
    else if(test.offsetType == IMM8_OFFSET && test.postIndex == true)
    {
        op2 = a64asm->immed8_post(test.immValue);
    }
    else if(test.offsetType == NO_OFFSET)
    {
        op2 = a64asm->__immed12_pre(0);
    }
    else
    {
        printf("Error - Unknown offset\n"); return;
    }

    switch(test.op)
    {
    case INSTR_LDR:  a64asm->LDR(test.cond, Rd,Rn,op2); break;
    case INSTR_LDRB: a64asm->LDRB(test.cond, Rd,Rn,op2); break;
    case INSTR_LDRH: a64asm->LDRH(test.cond, Rd,Rn,op2); break;
    case INSTR_ADDR_LDR: a64asm->ADDR_LDR(test.cond, Rd,Rn,op2); break;
    case INSTR_STR:  a64asm->STR(test.cond, Rd,Rn,op2); break;
    case INSTR_STRB: a64asm->STRB(test.cond, Rd,Rn,op2); break;
    case INSTR_STRH: a64asm->STRH(test.cond, Rd,Rn,op2); break;
    case INSTR_ADDR_STR: a64asm->ADDR_STR(test.cond, Rd,Rn,op2); break;
    default: printf("Error"); return;
    }
    a64asm->epilog(0);
    flushcache();

    asm_function_t asm_function = (asm_function_t)(instrMem);

    for(i = 0; i < NUM_REGS; ++i)
        savedRegs[i] = regs[i];

    asm_mips_test_jacket(asm_function, regs, flags);

    /* Check if all regs except Rd/Rn are same */
    for(i = 0; i < NUM_REGS; ++i)
    {
        if(i == Rd || i == Rn || i == R_v0) continue;

        if(regs[i] != savedRegs[i])
        {
            printf("Test %x failed Reg(%d) tampered"
                   " Expected(0x%" PRIx64 "), Actual(0x%" PRIx64 ") t\n",
                   test.id, i, savedRegs[i], regs[i]);
            return;
        }
    }

    if((uint64_t)regs[Rd] != test.postRdValue)
    {
        printf("Test %x failed, "
               "Expected in Rd(0x%" PRIx64 "), Actual(0x%" PRIx64 ")\n",
               test.id, test.postRdValue, regs[Rd]);
    }
    else if((uint64_t)regs[Rn] != (uint64_t)(&dataMem[test.postRnValue]))
    {
        printf("Test %x failed, "
               "Expected in Rn(0x%" PRIx64 "), Actual(0x%" PRIx64 ")\n",
               test.id, test.postRnValue, regs[Rn] - (uint64_t)dataMem);
    }
    else if(test.checkMem == true)
    {
        unsigned char *addr = (unsigned char *)&dataMem[test.postMemOffset];
        uint64_t value;
        value = 0;
        for(uint32_t j = 0; j < test.postMemLength; ++j)
            value = (value << 8) | addr[test.postMemLength-j-1];
        if(value != test.postMemValue)
        {
            printf("Test %x failed, "
                   "Expected in Mem(0x%" PRIx64 "), Actual(0x%" PRIx64 ")\n",
                   test.id, test.postMemValue, value);
        }
        else
        {
            printf("Test %x passed\n", test.id);
        }
    }
    else
    {
        printf("Test %x passed\n", test.id);
    }
}

int main(void)
{
    uint32_t i;

    /* Allocate memory to store instructions generated by ArmToArm64Assembler */
    {
        int fd = ashmem_create_region("code cache", instrMemSize);
        if(fd < 0) {
            printf("IF < 0\n");
            printf("Creating code cache, ashmem_create_region "
                                "failed with error '%s'", strerror(errno));
        }
        instrMem = mmap(NULL, instrMemSize,
                                    PROT_READ | PROT_WRITE | PROT_EXEC,
                                MAP_PRIVATE, fd, 0);
    }

    ArmToMips64Assembler a64asm(instrMem);

    if(TESTS_DATAOP_ENABLE)
    {
        printf("Running data processing tests\n");
        for(i = 0; i < sizeof(dataOpTests)/sizeof(dataOpTest_t); ++i) {
            dataOpTest(dataOpTests[i], &a64asm);
        }
    }

    if(TESTS_DATATRANSFER_ENABLE)
    {
        printf("Running data transfer tests\n");
        for(i = 0; i < sizeof(dataTransferTests)/sizeof(dataTransferTest_t); ++i)
            dataTransferTest(dataTransferTests[i], &a64asm);
    }

    return 0;
}
