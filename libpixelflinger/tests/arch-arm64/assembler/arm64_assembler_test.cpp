/*
 * Copyright (C) 2013 The Android Open Source Project
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <sys/mman.h>
#include <cutils/ashmem.h>

#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#include "codeflinger/ARMAssemblerInterface.h"
#include "codeflinger/Arm64Assembler.h"
using namespace android;

#define TESTS_DATAOP_ENABLE             1
#define TESTS_DATATRANSFER_ENABLE       1
#define TESTS_LDMSTM_ENABLE             1
#define TESTS_REG_CORRUPTION_ENABLE     0

void *instrMem;
uint32_t  instrMemSize = 128 * 1024;
char     dataMem[8192];

typedef void (*asm_function_t)();
extern "C" void asm_test_jacket(asm_function_t function,
                                int64_t regs[], int32_t flags[]);

#define MAX_32BIT (uint32_t)(((uint64_t)1 << 32) - 1)
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


struct dataOpTest_t
{
    uint32_t id;
    instr_t  op;
    uint32_t preFlag;
    cond_t   cond;
    bool     setFlags;
    uint64_t RnValue;
    uint64_t RsValue;
    bool     immediate;
    uint32_t immValue;
    uint64_t RmValue;
    uint32_t shiftMode;
    uint32_t shiftAmount;
    uint64_t RdValue;
    bool     checkRd;
    uint64_t postRdValue;
    bool     checkFlag;
    uint32_t postFlag;
};

struct dataTransferTest_t
{
    uint32_t id;
    instr_t op;
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
     {0xA000,INSTR_ADD,AL,AL,0,1,NA,1,MAX_32BIT ,NA,NA,NA,NA,1,0,0,0},
     {0xA001,INSTR_ADD,AL,AL,0,1,NA,1,MAX_32BIT -1,NA,NA,NA,NA,1,MAX_32BIT,0,0},
     {0xA002,INSTR_ADD,AL,AL,0,1,NA,0,NA,MAX_32BIT ,NA,NA,NA,1,0,0,0},
     {0xA003,INSTR_ADD,AL,AL,0,1,NA,0,NA,MAX_32BIT -1,NA,NA,NA,1,MAX_32BIT,0,0},
     {0xA004,INSTR_ADD,AL,AL,0,1,NA,0,0,MAX_32BIT ,SHIFT_LSL,0,NA,1,0,0,0},
     {0xA005,INSTR_ADD,AL,AL,0,1,NA,0,0,MAX_32BIT ,SHIFT_LSL,31,NA,1,0x80000001,0,0},
     {0xA006,INSTR_ADD,AL,AL,0,1,NA,0,0,3,SHIFT_LSR,1,NA,1,2,0,0},
     {0xA007,INSTR_ADD,AL,AL,0,1,NA,0,0,MAX_32BIT ,SHIFT_LSR,31,NA,1,2,0,0},
     {0xA008,INSTR_ADD,AL,AL,0,0,NA,0,0,3,SHIFT_ASR,1,NA,1,1,0,0},
     {0xA009,INSTR_ADD,AL,AL,0,1,NA,0,0,MAX_32BIT ,SHIFT_ASR,31,NA,1,0,0,0},
     {0xA010,INSTR_AND,AL,AL,0,1,NA,1,MAX_32BIT ,0,0,0,NA,1,1,0,0},
     {0xA011,INSTR_AND,AL,AL,0,1,NA,1,MAX_32BIT -1,0,0,0,NA,1,0,0,0},
     {0xA012,INSTR_AND,AL,AL,0,1,NA,0,0,MAX_32BIT ,0,0,NA,1,1,0,0},
     {0xA013,INSTR_AND,AL,AL,0,1,NA,0,0,MAX_32BIT -1,0,0,NA,1,0,0,0},
     {0xA014,INSTR_AND,AL,AL,0,1,NA,0,0,MAX_32BIT ,SHIFT_LSL,0,NA,1,1,0,0},
     {0xA015,INSTR_AND,AL,AL,0,1,NA,0,0,MAX_32BIT ,SHIFT_LSL,31,NA,1,0,0,0},
     {0xA016,INSTR_AND,AL,AL,0,1,NA,0,0,3,SHIFT_LSR,1,NA,1,1,0,0},
     {0xA017,INSTR_AND,AL,AL,0,1,NA,0,0,MAX_32BIT ,SHIFT_LSR,31,NA,1,1,0,0},
     {0xA018,INSTR_AND,AL,AL,0,0,NA,0,0,3,SHIFT_ASR,1,NA,1,0,0,0},
     {0xA019,INSTR_AND,AL,AL,0,1,NA,0,0,MAX_32BIT ,SHIFT_ASR,31,NA,1,1,0,0},
     {0xA020,INSTR_ORR,AL,AL,0,3,NA,1,MAX_32BIT ,0,0,0,NA,1,MAX_32BIT,0,0},
     {0xA021,INSTR_ORR,AL,AL,0,2,NA,1,MAX_32BIT -1,0,0,0,NA,1,MAX_32BIT-1,0,0},
     {0xA022,INSTR_ORR,AL,AL,0,3,NA,0,0,MAX_32BIT ,0,0,NA,1,MAX_32BIT,0,0},
     {0xA023,INSTR_ORR,AL,AL,0,2,NA,0,0,MAX_32BIT -1,0,0,NA,1,MAX_32BIT-1,0,0},
     {0xA024,INSTR_ORR,AL,AL,0,1,NA,0,0,MAX_32BIT ,SHIFT_LSL,0,NA,1,MAX_32BIT,0,0},
     {0xA025,INSTR_ORR,AL,AL,0,1,NA,0,0,MAX_32BIT ,SHIFT_LSL,31,NA,1,0x80000001,0,0},
     {0xA026,INSTR_ORR,AL,AL,0,1,NA,0,0,3,SHIFT_LSR,1,NA,1,1,0,0},
     {0xA027,INSTR_ORR,AL,AL,0,0,NA,0,0,MAX_32BIT ,SHIFT_LSR,31,NA,1,1,0,0},
     {0xA028,INSTR_ORR,AL,AL,0,0,NA,0,0,3,SHIFT_ASR,1,NA,1,1,0,0},
     {0xA029,INSTR_ORR,AL,AL,0,1,NA,0,0,MAX_32BIT ,SHIFT_ASR,31,NA,1,MAX_32BIT ,0,0},
     {0xA030,INSTR_CMP,AL,AL,1,0x10000,NA,1,0x10000,0,0,0,NA,0,0,1,HS},
     {0xA031,INSTR_CMP,AL,AL,1,0x00000,NA,1,0x10000,0,0,0,NA,0,0,1,CC},
     {0xA032,INSTR_CMP,AL,AL,1,0x00000,NA,0,0,0x10000,0,0,NA,0,0,1,LT},
     {0xA033,INSTR_CMP,AL,AL,1,0x10000,NA,0,0,0x10000,0,0,NA,0,0,1,EQ},
     {0xA034,INSTR_CMP,AL,AL,1,0x00000,NA,0,0,0x10000,0,0,NA,0,0,1,LS},
     {0xA035,INSTR_CMP,AL,AL,1,0x10000,NA,0,0,0x10000,0,0,NA,0,0,1,LS},
     {0xA036,INSTR_CMP,AL,AL,1,0x10000,NA,0,0,0x00000,0,0,NA,0,0,1,HI},
     {0xA037,INSTR_CMP,AL,AL,1,0x10000,NA,0,0,0x10000,0,0,NA,0,0,1,HS},
     {0xA038,INSTR_CMP,AL,AL,1,0x10000,NA,0,0,0x00000,0,0,NA,0,0,1,HS},
     {0xA039,INSTR_CMP,AL,AL,1,0x10000,NA,0,0,0x00000,0,0,NA,0,0,1,NE},
     {0xA040,INSTR_CMP,AL,AL,1,0,NA,0,0,MAX_32BIT ,SHIFT_LSR,1,NA,0,0,1,LT},
     {0xA041,INSTR_CMP,AL,AL,1,1,NA,0,0,MAX_32BIT ,SHIFT_LSR,31,NA,0,0,1,EQ},
     {0xA042,INSTR_CMP,AL,AL,1,0,NA,0,0,0x10000,SHIFT_LSR,31,NA,0,0,1,LS},
     {0xA043,INSTR_CMP,AL,AL,1,0x10000,NA,0,0,0x30000,SHIFT_LSR,1,NA,0,0,1,LS},
     {0xA044,INSTR_CMP,AL,AL,1,0x10000,NA,0,0,0x00000,SHIFT_LSR,31,NA,0,0,1,HI},
     {0xA045,INSTR_CMP,AL,AL,1,1,NA,0,0,MAX_32BIT ,SHIFT_LSR,31,NA,0,0,1,HS},
     {0xA046,INSTR_CMP,AL,AL,1,0x10000,NA,0,0,0x2000,SHIFT_LSR,1,NA,0,0,1,HS},
     {0xA047,INSTR_CMP,AL,AL,1,0,NA,0,0,MAX_32BIT ,SHIFT_LSR,1,NA,0,0,1,NE},
     {0xA048,INSTR_CMP,AL,AL,1,0,NA,0,0,0x10000,SHIFT_ASR,2,NA,0,0,1,LT},
     {0xA049,INSTR_CMP,AL,AL,1,MAX_32BIT ,NA,0,0,MAX_32BIT ,SHIFT_ASR,1,NA,0,0,1,EQ},
     {0xA050,INSTR_CMP,AL,AL,1,MAX_32BIT ,NA,0,0,MAX_32BIT ,SHIFT_ASR,31,NA,0,0,1,LS},
     {0xA051,INSTR_CMP,AL,AL,1,0,NA,0,0,0x10000,SHIFT_ASR,1,NA,0,0,1,LS},
     {0xA052,INSTR_CMP,AL,AL,1,0x10000,NA,0,0,0x10000,SHIFT_ASR,1,NA,0,0,1,HI},
     {0xA053,INSTR_CMP,AL,AL,1,1,NA,0,0,0x10000,SHIFT_ASR,31,NA,0,0,1,HS},
     {0xA054,INSTR_CMP,AL,AL,1,1,NA,0,0,0x10000,SHIFT_ASR,16,NA,0,0,1,HS},
     {0xA055,INSTR_CMP,AL,AL,1,1,NA,0,0,MAX_32BIT ,SHIFT_ASR,1,NA,0,0,1,NE},
     {0xA056,INSTR_MUL,AL,AL,0,0,0x10000,0,0,0x10000,0,0,NA,1,0,0,0},
     {0xA057,INSTR_MUL,AL,AL,0,0,0x1000,0,0,0x10000,0,0,NA,1,0x10000000,0,0},
     {0xA058,INSTR_MUL,AL,AL,0,0,MAX_32BIT ,0,0,1,0,0,NA,1,MAX_32BIT ,0,0},
     {0xA059,INSTR_MLA,AL,AL,0,0x10000,0x10000,0,0,0x10000,0,0,NA,1,0x10000,0,0},
     {0xA060,INSTR_MLA,AL,AL,0,0x10000,0x1000,0,0,0x10000,0,0,NA,1,0x10010000,0,0},
     {0xA061,INSTR_MLA,AL,AL,1,1,MAX_32BIT ,0,0,1,0,0,NA,1,0,1,PL},
     {0xA062,INSTR_MLA,AL,AL,1,0,MAX_32BIT ,0,0,1,0,0,NA,1,MAX_32BIT ,1,MI},
     {0xA063,INSTR_SUB,AL,AL,1,1 << 16,NA,1,1 << 16,NA,NA,NA,NA,1,0,1,PL},
     {0xA064,INSTR_SUB,AL,AL,1,(1 << 16) + 1,NA,1,1 << 16,NA,NA,NA,NA,1,1,1,PL},
     {0xA065,INSTR_SUB,AL,AL,1,0,NA,1,1 << 16,NA,NA,NA,NA,1,(uint32_t)(0 - (1<<16)),1,MI},
     {0xA066,INSTR_SUB,MI,MI,0,2,NA,0,NA,1,NA,NA,2,1,1,0,NA},
     {0xA067,INSTR_SUB,EQ,MI,0,2,NA,0,NA,1,NA,NA,2,1,2,0,NA},
     {0xA068,INSTR_SUB,GT,GE,0,2,NA,1,1,NA,NA,NA,2,1,1,0,NA},
     {0xA069,INSTR_SUB,LT,GE,0,2,NA,1,1,NA,NA,NA,2,1,2,0,NA},
     {0xA070,INSTR_SUB,CS,HS,0,2,NA,1,1,NA,NA,NA,2,1,1,0,NA},
     {0xA071,INSTR_SUB,CC,HS,0,2,NA,1,1,NA,NA,NA,2,1,2,0,NA},
     {0xA072,INSTR_SUB,AL,AL,0,1,NA,1,1 << 16,0,0,0,NA,1,(uint32_t)(1 - (1 << 16)),0,NA},
     {0xA073,INSTR_SUB,AL,AL,0,MAX_32BIT,NA,1,1,0,0,0,NA,1,MAX_32BIT  - 1,0,NA},
     {0xA074,INSTR_SUB,AL,AL,0,1,NA,1,1,0,0,0,NA,1,0,0,NA},
     {0xA075,INSTR_SUB,AL,AL,0,1,NA,0,NA,1 << 16,0,0,NA,1,(uint32_t)(1 - (1 << 16)),0,NA},
     {0xA076,INSTR_SUB,AL,AL,0,MAX_32BIT,NA,0,NA,1,0,0,NA,1,MAX_32BIT  - 1,0,NA},
     {0xA077,INSTR_SUB,AL,AL,0,1,NA,0,NA,1,0,0,NA,1,0,0,NA},
     {0xA078,INSTR_SUB,AL,AL,0,1,NA,0,NA,1,SHIFT_LSL,16,NA,1,(uint32_t)(1 - (1 << 16)),0,NA},
     {0xA079,INSTR_SUB,AL,AL,0,0x80000001,NA,0,NA,MAX_32BIT ,SHIFT_LSL,31,NA,1,1,0,NA},
     {0xA080,INSTR_SUB,AL,AL,0,1,NA,0,NA,3,SHIFT_LSR,1,NA,1,0,0,NA},
     {0xA081,INSTR_SUB,AL,AL,0,1,NA,0,NA,MAX_32BIT ,SHIFT_LSR,31,NA,1,0,0,NA},
     {0xA082,INSTR_RSB,GT,GE,0,2,NA,1,0,NA,NA,NA,2,1,(uint32_t)-2,0,NA},
     {0xA083,INSTR_RSB,LT,GE,0,2,NA,1,0,NA,NA,NA,2,1,2,0,NA},
     {0xA084,INSTR_RSB,AL,AL,0,1,NA,1,1 << 16,NA,NA,NA,NA,1,(1 << 16) - 1,0,NA},
     {0xA085,INSTR_RSB,AL,AL,0,MAX_32BIT,NA,1,1,NA,NA,NA,NA,1,(uint32_t) (1 - MAX_32BIT),0,NA},
     {0xA086,INSTR_RSB,AL,AL,0,1,NA,1,1,NA,NA,NA,NA,1,0,0,NA},
     {0xA087,INSTR_RSB,AL,AL,0,1,NA,0,NA,1 << 16,0,0,NA,1,(1 << 16) - 1,0,NA},
     {0xA088,INSTR_RSB,AL,AL,0,MAX_32BIT,NA,0,NA,1,0,0,NA,1,(uint32_t) (1 - MAX_32BIT),0,NA},
     {0xA089,INSTR_RSB,AL,AL,0,1,NA,0,NA,1,0,0,NA,1,0,0,NA},
     {0xA090,INSTR_RSB,AL,AL,0,1,NA,0,NA,1,SHIFT_LSL,16,NA,1,(1 << 16) - 1,0,NA},
     {0xA091,INSTR_RSB,AL,AL,0,0x80000001,NA,0,NA,MAX_32BIT ,SHIFT_LSL,31,NA,1,(uint32_t)-1,0,NA},
     {0xA092,INSTR_RSB,AL,AL,0,1,NA,0,NA,3,SHIFT_LSR,1,NA,1,0,0,NA},
     {0xA093,INSTR_RSB,AL,AL,0,1,NA,0,NA,MAX_32BIT ,SHIFT_LSR,31,NA,1,0,0,NA},
     {0xA094,INSTR_MOV,AL,AL,0,NA,NA,1,0x80000001,NA,NA,NA,NA,1,0x80000001,0,0},
     {0xA095,INSTR_MOV,AL,AL,0,NA,NA,0,0,0x80000001,0,0,NA,1,0x80000001,0,0},
     {0xA096,INSTR_MOV,AL,AL,0,NA,NA,0,0,MAX_32BIT ,SHIFT_LSL,1,NA,1,MAX_32BIT -1,0,0},
     {0xA097,INSTR_MOV,AL,AL,0,NA,NA,0,0,MAX_32BIT ,SHIFT_LSL,31,NA,1,0x80000000,0,0},
     {0xA098,INSTR_MOV,AL,AL,0,NA,NA,0,0,3,SHIFT_LSR,1,NA,1,1,0,0},
     {0xA099,INSTR_MOV,AL,AL,0,NA,NA,0,0,MAX_32BIT ,SHIFT_LSR,31,NA,1,1,0,0},
     {0xA100,INSTR_MOV,AL,AL,0,NA,NA,0,0,3,SHIFT_ASR,1,NA,1,1,0,0},
     {0xA101,INSTR_MOV,AL,AL,0,NA,NA,0,0,MAX_32BIT ,SHIFT_ASR,31,NA,1,MAX_32BIT ,0,0},
     {0xA102,INSTR_MOV,AL,AL,0,NA,NA,0,0,3,SHIFT_ROR,1,NA,1,0x80000001,0,0},
     {0xA103,INSTR_MOV,AL,AL,0,NA,NA,0,0,0x80000001,SHIFT_ROR,31,NA,1,3,0,0},
     {0xA104,INSTR_MOV,AL,AL,1,NA,NA,0,0,MAX_32BIT -1,SHIFT_ASR,1,NA,1,MAX_32BIT,1,MI},
     {0xA105,INSTR_MOV,AL,AL,1,NA,NA,0,0,3,SHIFT_ASR,1,NA,1,1,1,PL},
     {0xA106,INSTR_MOV,PL,MI,0,NA,NA,1,0x80000001,NA,NA,NA,2,1,2,0,0},
     {0xA107,INSTR_MOV,MI,MI,0,NA,NA,0,0,0x80000001,0,0,2,1,0x80000001,0,0},
     {0xA108,INSTR_MOV,EQ,LT,0,NA,NA,1,0x80000001,NA,NA,NA,2,1,2,0,0},
     {0xA109,INSTR_MOV,LT,LT,0,NA,NA,1,0x80000001,NA,NA,NA,2,1,0x80000001,0,0},
     {0xA110,INSTR_MOV,GT,GE,0,NA,NA,0,0,MAX_32BIT ,SHIFT_LSL,1,2,1,MAX_32BIT -1,0,0},
     {0xA111,INSTR_MOV,EQ,GE,0,NA,NA,0,0,MAX_32BIT ,SHIFT_LSL,31,2,1,0x80000000,0,0},
     {0xA112,INSTR_MOV,LT,GE,0,NA,NA,0,0,MAX_32BIT ,SHIFT_LSL,31,2,1,2,0,0},
     {0xA113,INSTR_MOV,GT,LE,0,NA,NA,0,0,MAX_32BIT ,SHIFT_LSL,1,2,1,2,0,0},
     {0xA114,INSTR_MOV,EQ,LE,0,NA,NA,1,0x80000001,NA,NA,NA,2,1,0x80000001,0,0},
     {0xA115,INSTR_MOV,LT,LE,0,NA,NA,0,0,MAX_32BIT ,SHIFT_LSL,31,2,1,0x80000000,0,0},
     {0xA116,INSTR_MOV,EQ,GT,0,NA,NA,1,0x80000001,NA,NA,NA,2,1,2,0,0},
     {0xA117,INSTR_MOV,GT,GT,0,NA,NA,1,0x80000001,NA,NA,NA,2,1,0x80000001,0,0},
     {0xA118,INSTR_MOV,LE,GT,0,NA,NA,1,0x80000001,NA,NA,NA,2,1,2,0,0},
     {0xA119,INSTR_MOV,EQ,GT,0,NA,NA,0,0,0x80000001,0,0,2,1,2,0,0},
     {0xA120,INSTR_MOV,GT,GT,0,NA,NA,0,0,0x80000001,0,0,2,1,0x80000001,0,0},
     {0xA121,INSTR_MOV,LE,GT,0,NA,NA,0,0,0x80000001,0,0,2,1,2,0,0},
     {0xA122,INSTR_MOV,EQ,GT,0,NA,NA,0,0,MAX_32BIT ,SHIFT_LSL,1,2,1,2,0,0},
     {0xA123,INSTR_MOV,GT,GT,0,NA,NA,0,0,MAX_32BIT ,SHIFT_LSL,1,2,1,MAX_32BIT -1,0,0},
     {0xA124,INSTR_MOV,LE,GT,0,NA,NA,0,0,MAX_32BIT ,SHIFT_LSL,1,2,1,2,0,0},
     {0xA125,INSTR_MOV,LO,HS,0,NA,NA,1,0x80000001,NA,NA,NA,2,1,2,0,0},
     {0xA126,INSTR_MOV,HS,HS,0,NA,NA,1,0x80000001,NA,NA,NA,2,1,0x80000001,0,0},
     {0xA127,INSTR_MVN,LO,HS,0,NA,NA,1,MAX_32BIT -1,NA,NA,NA,2,1,2,0,0},
     {0xA128,INSTR_MVN,HS,HS,0,NA,NA,1,MAX_32BIT -1,NA,NA,NA,2,1,1,0,0},
     {0xA129,INSTR_MVN,AL,AL,0,NA,NA,1,0,NA,NA,NA,2,1,MAX_32BIT,0,NA},
     {0xA130,INSTR_MVN,AL,AL,0,NA,NA,0,NA,MAX_32BIT -1,NA,0,2,1,1,0,NA},
     {0xA131,INSTR_MVN,AL,AL,0,NA,NA,0,NA,0x80000001,NA,0,2,1,0x7FFFFFFE,0,NA},
     {0xA132,INSTR_BIC,AL,AL,0,1,NA,1,MAX_32BIT ,NA,NA,NA,NA,1,0,0,0},
     {0xA133,INSTR_BIC,AL,AL,0,1,NA,1,MAX_32BIT -1,NA,NA,NA,NA,1,1,0,0},
     {0xA134,INSTR_BIC,AL,AL,0,1,NA,0,0,MAX_32BIT ,0,0,NA,1,0,0,0},
     {0xA135,INSTR_BIC,AL,AL,0,1,NA,0,0,MAX_32BIT -1,0,0,NA,1,1,0,0},
     {0xA136,INSTR_BIC,AL,AL,0,0xF0,NA,0,0,3,SHIFT_ASR,1,NA,1,0xF0,0,0},
     {0xA137,INSTR_BIC,AL,AL,0,0xF0,NA,0,0,MAX_32BIT ,SHIFT_ASR,31,NA,1,0,0,0},
     {0xA138,INSTR_SMULBB,AL,AL,0,NA,0xABCDFFFF,0,NA,0xABCD0001,NA,NA,NA,1,0xFFFFFFFF,0,0},
     {0xA139,INSTR_SMULBB,AL,AL,0,NA,0xABCD0001,0,NA,0xABCD0FFF,NA,NA,NA,1,0x00000FFF,0,0},
     {0xA140,INSTR_SMULBB,AL,AL,0,NA,0xABCD0001,0,NA,0xABCDFFFF,NA,NA,NA,1,0xFFFFFFFF,0,0},
     {0xA141,INSTR_SMULBB,AL,AL,0,NA,0xABCDFFFF,0,NA,0xABCDFFFF,NA,NA,NA,1,1,0,0},
     {0xA142,INSTR_SMULBT,AL,AL,0,NA,0xFFFFABCD,0,NA,0xABCD0001,NA,NA,NA,1,0xFFFFFFFF,0,0},
     {0xA143,INSTR_SMULBT,AL,AL,0,NA,0x0001ABCD,0,NA,0xABCD0FFF,NA,NA,NA,1,0x00000FFF,0,0},
     {0xA144,INSTR_SMULBT,AL,AL,0,NA,0x0001ABCD,0,NA,0xABCDFFFF,NA,NA,NA,1,0xFFFFFFFF,0,0},
     {0xA145,INSTR_SMULBT,AL,AL,0,NA,0xFFFFABCD,0,NA,0xABCDFFFF,NA,NA,NA,1,1,0,0},
     {0xA146,INSTR_SMULTB,AL,AL,0,NA,0xABCDFFFF,0,NA,0x0001ABCD,NA,NA,NA,1,0xFFFFFFFF,0,0},
     {0xA147,INSTR_SMULTB,AL,AL,0,NA,0xABCD0001,0,NA,0x0FFFABCD,NA,NA,NA,1,0x00000FFF,0,0},
     {0xA148,INSTR_SMULTB,AL,AL,0,NA,0xABCD0001,0,NA,0xFFFFABCD,NA,NA,NA,1,0xFFFFFFFF,0,0},
     {0xA149,INSTR_SMULTB,AL,AL,0,NA,0xABCDFFFF,0,NA,0xFFFFABCD,NA,NA,NA,1,1,0,0},
     {0xA150,INSTR_SMULTT,AL,AL,0,NA,0xFFFFABCD,0,NA,0x0001ABCD,NA,NA,NA,1,0xFFFFFFFF,0,0},
     {0xA151,INSTR_SMULTT,AL,AL,0,NA,0x0001ABCD,0,NA,0x0FFFABCD,NA,NA,NA,1,0x00000FFF,0,0},
     {0xA152,INSTR_SMULTT,AL,AL,0,NA,0x0001ABCD,0,NA,0xFFFFABCD,NA,NA,NA,1,0xFFFFFFFF,0,0},
     {0xA153,INSTR_SMULTT,AL,AL,0,NA,0xFFFFABCD,0,NA,0xFFFFABCD,NA,NA,NA,1,1,0,0},
     {0xA154,INSTR_SMULWB,AL,AL,0,NA,0xABCDFFFF,0,NA,0x0001ABCD,NA,NA,NA,1,0xFFFFFFFE,0,0},
     {0xA155,INSTR_SMULWB,AL,AL,0,NA,0xABCD0001,0,NA,0x0FFFABCD,NA,NA,NA,1,0x00000FFF,0,0},
     {0xA156,INSTR_SMULWB,AL,AL,0,NA,0xABCD0001,0,NA,0xFFFFABCD,NA,NA,NA,1,0xFFFFFFFF,0,0},
     {0xA157,INSTR_SMULWB,AL,AL,0,NA,0xABCDFFFF,0,NA,0xFFFFABCD,NA,NA,NA,1,0,0,0},
     {0xA158,INSTR_SMULWT,AL,AL,0,NA,0xFFFFABCD,0,NA,0x0001ABCD,NA,NA,NA,1,0xFFFFFFFE,0,0},
     {0xA159,INSTR_SMULWT,AL,AL,0,NA,0x0001ABCD,0,NA,0x0FFFABCD,NA,NA,NA,1,0x00000FFF,0,0},
     {0xA160,INSTR_SMULWT,AL,AL,0,NA,0x0001ABCD,0,NA,0xFFFFABCD,NA,NA,NA,1,0xFFFFFFFF,0,0},
     {0xA161,INSTR_SMULWT,AL,AL,0,NA,0xFFFFABCD,0,NA,0xFFFFABCD,NA,NA,NA,1,0,0,0},
     {0xA162,INSTR_SMLABB,AL,AL,0,1,0xABCDFFFF,0,NA,0xABCD0001,NA,NA,NA,1,0,0,0},
     {0xA163,INSTR_SMLABB,AL,AL,0,1,0xABCD0001,0,NA,0xABCD0FFF,NA,NA,NA,1,0x00001000,0,0},
     {0xA164,INSTR_SMLABB,AL,AL,0,0xFFFFFFFF,0xABCD0001,0,NA,0xABCDFFFF,NA,NA,NA,1,0xFFFFFFFE,0,0},
     {0xA165,INSTR_SMLABB,AL,AL,0,0xFFFFFFFF,0xABCDFFFF,0,NA,0xABCDFFFF,NA,NA,NA,1,0,0,0},
     {0xA166,INSTR_UXTB16,AL,AL,0,NA,NA,0,NA,0xABCDEF01,SHIFT_ROR,0,NA,1,0x00CD0001,0,0},
     {0xA167,INSTR_UXTB16,AL,AL,0,NA,NA,0,NA,0xABCDEF01,SHIFT_ROR,1,NA,1,0x00AB00EF,0,0},
     {0xA168,INSTR_UXTB16,AL,AL,0,NA,NA,0,NA,0xABCDEF01,SHIFT_ROR,2,NA,1,0x000100CD,0,0},
     {0xA169,INSTR_UXTB16,AL,AL,0,NA,NA,0,NA,0xABCDEF01,SHIFT_ROR,3,NA,1,0x00EF00AB,0,0},
     {0xA170,INSTR_UBFX,AL,AL,0,0xABCDEF01,4,0,NA,24,NA,NA,NA,1,0x00BCDEF0,0,0},
     {0xA171,INSTR_UBFX,AL,AL,0,0xABCDEF01,1,0,NA,2,NA,NA,NA,1,0,0,0},
     {0xA172,INSTR_UBFX,AL,AL,0,0xABCDEF01,16,0,NA,8,NA,NA,NA,1,0xCD,0,0},
     {0xA173,INSTR_UBFX,AL,AL,0,0xABCDEF01,31,0,NA,1,NA,NA,NA,1,1,0,0},
     {0xA174,INSTR_ADDR_ADD,AL,AL,0,0xCFFFFFFFF,NA,0,NA,0x1,SHIFT_LSL,1,NA,1,0xD00000001,0,0},
     {0xA175,INSTR_ADDR_ADD,AL,AL,0,0x01,NA,0,NA,0x1,SHIFT_LSL,2,NA,1,0x5,0,0},
     {0xA176,INSTR_ADDR_ADD,AL,AL,0,0xCFFFFFFFF,NA,0,NA,0x1,NA,0,NA,1,0xD00000000,0,0},
     {0xA177,INSTR_ADDR_SUB,AL,AL,0,0xD00000001,NA,0,NA,0x010000,SHIFT_LSR,15,NA,1,0xCFFFFFFFF,0,0},
     {0xA178,INSTR_ADDR_SUB,AL,AL,0,0xCFFFFFFFF,NA,0,NA,0x020000,SHIFT_LSR,15,NA,1,0xCFFFFFFFB,0,0},
     {0xA179,INSTR_ADDR_SUB,AL,AL,0,3,NA,0,NA,0x010000,SHIFT_LSR,15,NA,1,1,0,0},
};

dataTransferTest_t dataTransferTests [] =
{
    {0xB000,INSTR_LDR,AL,AL,1,24,0xABCDEF0123456789,0,REG_SCALE_OFFSET,24,NA,NA,NA,NA,NA,0x23456789,0,0,NA,NA,NA},
    {0xB001,INSTR_LDR,AL,AL,1,4064,0xABCDEF0123456789,0,IMM12_OFFSET,NA,4068,0,1,0,NA,0xABCDEF01,0,0,NA,NA,NA},
    {0xB002,INSTR_LDR,AL,AL,1,0,0xABCDEF0123456789,0,IMM12_OFFSET,NA,4,1,0,1,NA,0x23456789,4,0,NA,NA,NA},
    {0xB003,INSTR_LDR,AL,AL,1,0,0xABCDEF0123456789,0,NO_OFFSET,NA,NA,0,0,0,NA,0x23456789,0,0,NA,NA,NA},
    {0xB004,INSTR_LDRB,AL,AL,1,4064,0xABCDEF0123456789,0,REG_SCALE_OFFSET,4064,NA,NA,NA,NA,NA,0x89,0,0,NA,NA,NA},
    {0xB005,INSTR_LDRB,AL,AL,1,4064,0xABCDEF0123456789,0,IMM12_OFFSET,NA,4065,0,1,0,NA,0x67,0,0,NA,NA,NA},
    {0xB006,INSTR_LDRB,AL,AL,1,4064,0xABCDEF0123456789,4065,IMM12_OFFSET,NA,0,0,1,0,NA,0x67,4065,0,NA,NA,NA},
    {0xB007,INSTR_LDRB,AL,AL,1,4064,0xABCDEF0123456789,4065,IMM12_OFFSET,NA,1,0,1,0,NA,0x45,4065,0,NA,NA,NA},
    {0xB008,INSTR_LDRB,AL,AL,1,4064,0xABCDEF0123456789,4065,IMM12_OFFSET,NA,2,0,1,0,NA,0x23,4065,0,NA,NA,NA},
    {0xB009,INSTR_LDRB,AL,AL,1,4064,0xABCDEF0123456789,4065,IMM12_OFFSET,NA,1,1,0,1,NA,0x67,4066,0,NA,NA,NA},
    {0xB010,INSTR_LDRB,AL,AL,1,4064,0xABCDEF0123456789,0,NO_OFFSET,NA,NA,0,0,0,NA,0x89,0,0,NA,NA,NA},
    {0xB011,INSTR_LDRH,AL,AL,1,0,0xABCDEF0123456789,0,IMM8_OFFSET,NA,2,1,0,1,NA,0x6789,2,0,NA,NA,NA},
    {0xB012,INSTR_LDRH,AL,AL,1,4064,0xABCDEF0123456789,0,REG_OFFSET,4064,0,0,1,0,NA,0x6789,0,0,NA,NA,NA},
    {0xB013,INSTR_LDRH,AL,AL,1,4064,0xABCDEF0123456789,0,REG_OFFSET,4066,0,0,1,0,NA,0x2345,0,0,NA,NA,NA},
    {0xB014,INSTR_LDRH,AL,AL,1,0,0xABCDEF0123456789,0,NO_OFFSET,NA,0,0,0,0,NA,0x6789,0,0,NA,NA,NA},
    {0xB015,INSTR_LDRH,AL,AL,1,0,0xABCDEF0123456789,2,NO_OFFSET,NA,0,0,0,0,NA,0x2345,2,0,NA,NA,NA},
    {0xB016,INSTR_ADDR_LDR,AL,AL,1,4064,0xABCDEF0123456789,0,IMM12_OFFSET,NA,4064,0,1,0,NA,0xABCDEF0123456789,0,0,NA,NA,NA},
    {0xB017,INSTR_STR,AL,AL,1,2,0xDEADBEEFDEADBEEF,4,IMM12_OFFSET,NA,4,1,0,1,0xABCDEF0123456789,0xABCDEF0123456789,8,1,2,8,0xDEAD23456789BEEF},
    {0xB018,INSTR_STR,AL,AL,1,2,0xDEADBEEFDEADBEEF,4,NO_OFFSET,NA,NA,0,0,0,0xABCDEF0123456789,0xABCDEF0123456789,4,1,2,8,0xDEAD23456789BEEF},
    {0xB019,INSTR_STR,AL,AL,1,4066,0xDEADBEEFDEADBEEF,4,IMM12_OFFSET,NA,4064,0,1,0,0xABCDEF0123456789,0xABCDEF0123456789,4,1,4066,8,0xDEAD23456789BEEF},
    {0xB020,INSTR_STRB,AL,AL,1,0,0xDEADBEEFDEADBEEF,1,IMM12_OFFSET,NA,0,0,1,0,0xABCDEF0123456789,0xABCDEF0123456789,1,1,0,8,0xDEADBEEFDEAD89EF},
    {0xB021,INSTR_STRB,AL,AL,1,0,0xDEADBEEFDEADBEEF,1,IMM12_OFFSET,NA,1,0,1,0,0xABCDEF0123456789,0xABCDEF0123456789,1,1,0,8,0xDEADBEEFDE89BEEF},
    {0xB022,INSTR_STRB,AL,AL,1,0,0xDEADBEEFDEADBEEF,1,IMM12_OFFSET,NA,2,0,1,0,0xABCDEF0123456789,0xABCDEF0123456789,1,1,0,8,0xDEADBEEF89ADBEEF},
    {0xB023,INSTR_STRB,AL,AL,1,0,0xDEADBEEFDEADBEEF,1,IMM12_OFFSET,NA,4,1,0,1,0xABCDEF0123456789,0xABCDEF0123456789,5,1,0,8,0xDEADBEEFDEAD89EF},
    {0xB024,INSTR_STRB,AL,AL,1,0,0xDEADBEEFDEADBEEF,1,NO_OFFSET,NA,NA,0,0,0,0xABCDEF0123456789,0xABCDEF0123456789,1,1,0,8,0xDEADBEEFDEAD89EF},
    {0xB025,INSTR_STRH,AL,AL,1,4066,0xDEADBEEFDEADBEEF,4070,IMM12_OFFSET,NA,2,1,0,1,0xABCDEF0123456789,0xABCDEF0123456789,4072,1,4066,8,0xDEAD6789DEADBEEF},
    {0xB026,INSTR_STRH,AL,AL,1,4066,0xDEADBEEFDEADBEEF,4070,NO_OFFSET,NA,NA,0,0,0,0xABCDEF0123456789,0xABCDEF0123456789,4070,1,4066,8,0xDEAD6789DEADBEEF},
    {0xB027,INSTR_STRH,EQ,NE,1,4066,0xDEADBEEFDEADBEEF,4070,NO_OFFSET,NA,NA,0,0,0,0xABCDEF0123456789,0xABCDEF0123456789,4070,1,4066,8,0xDEADBEEFDEADBEEF},
    {0xB028,INSTR_STRH,NE,NE,1,4066,0xDEADBEEFDEADBEEF,4070,NO_OFFSET,NA,NA,0,0,0,0xABCDEF0123456789,0xABCDEF0123456789,4070,1,4066,8,0xDEAD6789DEADBEEF},
    {0xB029,INSTR_STRH,NE,EQ,1,4066,0xDEADBEEFDEADBEEF,4070,NO_OFFSET,NA,NA,0,0,0,0xABCDEF0123456789,0xABCDEF0123456789,4070,1,4066,8,0xDEADBEEFDEADBEEF},
    {0xB030,INSTR_STRH,EQ,EQ,1,4066,0xDEADBEEFDEADBEEF,4070,NO_OFFSET,NA,NA,0,0,0,0xABCDEF0123456789,0xABCDEF0123456789,4070,1,4066,8,0xDEAD6789DEADBEEF},
    {0xB031,INSTR_STRH,HI,LS,1,4066,0xDEADBEEFDEADBEEF,4070,NO_OFFSET,NA,NA,0,0,0,0xABCDEF0123456789,0xABCDEF0123456789,4070,1,4066,8,0xDEADBEEFDEADBEEF},
    {0xB032,INSTR_STRH,LS,LS,1,4066,0xDEADBEEFDEADBEEF,4070,NO_OFFSET,NA,NA,0,0,0,0xABCDEF0123456789,0xABCDEF0123456789,4070,1,4066,8,0xDEAD6789DEADBEEF},
    {0xB033,INSTR_STRH,LS,HI,1,4066,0xDEADBEEFDEADBEEF,4070,NO_OFFSET,NA,NA,0,0,0,0xABCDEF0123456789,0xABCDEF0123456789,4070,1,4066,8,0xDEADBEEFDEADBEEF},
    {0xB034,INSTR_STRH,HI,HI,1,4066,0xDEADBEEFDEADBEEF,4070,NO_OFFSET,NA,NA,0,0,0,0xABCDEF0123456789,0xABCDEF0123456789,4070,1,4066,8,0xDEAD6789DEADBEEF},
    {0xB035,INSTR_STRH,CC,HS,1,4066,0xDEADBEEFDEADBEEF,4070,NO_OFFSET,NA,NA,0,0,0,0xABCDEF0123456789,0xABCDEF0123456789,4070,1,4066,8,0xDEADBEEFDEADBEEF},
    {0xB036,INSTR_STRH,CS,HS,1,4066,0xDEADBEEFDEADBEEF,4070,NO_OFFSET,NA,NA,0,0,0,0xABCDEF0123456789,0xABCDEF0123456789,4070,1,4066,8,0xDEAD6789DEADBEEF},
    {0xB037,INSTR_STRH,GE,LT,1,4066,0xDEADBEEFDEADBEEF,4070,NO_OFFSET,NA,NA,0,0,0,0xABCDEF0123456789,0xABCDEF0123456789,4070,1,4066,8,0xDEADBEEFDEADBEEF},
    {0xB038,INSTR_STRH,LT,LT,1,4066,0xDEADBEEFDEADBEEF,4070,NO_OFFSET,NA,NA,0,0,0,0xABCDEF0123456789,0xABCDEF0123456789,4070,1,4066,8,0xDEAD6789DEADBEEF},
    {0xB039,INSTR_ADDR_STR,AL,AL,1,4064,0xDEADBEEFDEADBEEF,4,IMM12_OFFSET,NA,4060,0,1,0,0xABCDEF0123456789,0xABCDEF0123456789,4,1,4064,8,0xABCDEF0123456789},
};


void flushcache()
{
    const long base = long(instrMem);
    const long curr = base + long(instrMemSize);
    __builtin___clear_cache((char*)base, (char*)curr);
}
void dataOpTest(dataOpTest_t test, ARMAssemblerInterface *a64asm, uint32_t Rd = 0,
                uint32_t Rn = 1, uint32_t Rm = 2, uint32_t Rs = 3)
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
    flags[test.preFlag] = 1;
    a64asm->reset();
    a64asm->prolog();
    if(test.immediate == true)
    {
        op2 = a64asm->imm(test.immValue);
    }
    else if(test.immediate == false && test.shiftAmount == 0)
    {
        op2 = Rm;
        regs[Rm] = test.RmValue;
    }
    else
    {
        op2 = a64asm->reg_imm(Rm, test.shiftMode, test.shiftAmount);
        regs[Rm] = test.RmValue;
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
    case INSTR_UBFX:
    {
        int32_t lsb   = test.RsValue;
        int32_t width = test.RmValue;
        a64asm->UBFX(test.cond, Rd,Rn,lsb, width);
        break;
    }
    case INSTR_ADDR_ADD: a64asm->ADDR_ADD(test.cond, test.setFlags, Rd,Rn,op2); break;
    case INSTR_ADDR_SUB: a64asm->ADDR_SUB(test.cond, test.setFlags, Rd,Rn,op2); break;
    default: printf("Error"); return;
    }
    a64asm->epilog(0);
    flushcache();

    asm_function_t asm_function = (asm_function_t)(instrMem);

    for(i = 0; i < NUM_REGS; ++i)
        savedRegs[i] = regs[i];

    asm_test_jacket(asm_function, regs, flags);

    /* Check if all regs except Rd is same */
    for(i = 0; i < NUM_REGS; ++i)
    {
        if(i == Rd) continue;
        if(regs[i] != savedRegs[i])
        {
            printf("Test %x failed Reg(%d) tampered Expected(0x%" PRIx64 "),"
                   "Actual(0x%" PRIx64 ") t\n", test.id, i, savedRegs[i],
                   regs[i]);
            return;
        }
    }

    if(test.checkRd == 1 && (uint64_t)regs[Rd] != test.postRdValue)
    {
        printf("Test %x failed, Expected(%" PRIx64 "), Actual(%" PRIx64 ")\n",
               test.id, test.postRdValue, regs[Rd]);
    }
    else if(test.checkFlag == 1 && flags[test.postFlag] == 0)
    {
        printf("Test %x failed Flag(%s) NOT set\n",
                test.id,cc_code[test.postFlag]);
    }
    else
    {
        printf("Test %x passed\n", test.id);
    }
}


void dataTransferTest(dataTransferTest_t test, ARMAssemblerInterface *a64asm,
                      uint32_t Rd = 0, uint32_t Rn = 1,uint32_t Rm = 2)
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


    asm_test_jacket(asm_function, regs, flags);

    /* Check if all regs except Rd/Rn are same */
    for(i = 0; i < NUM_REGS; ++i)
    {
        if(i == Rd || i == Rn) continue;
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

void dataTransferLDMSTM(ARMAssemblerInterface *a64asm)
{
    int64_t regs[NUM_REGS] = {0};
    int32_t flags[NUM_FLAGS] = {0};
    const uint32_t numArmv7Regs = 16;

    uint32_t Rn = ARMAssemblerInterface::SP;

    uint32_t patterns[] =
    {
        0x5A03,
        0x4CF0,
        0x1EA6,
        0x0DBF,
    };

    uint32_t i, j;
    for(i = 0; i < sizeof(patterns)/sizeof(uint32_t); ++i)
    {
        for(j = 0; j < NUM_REGS; ++j)
        {
            regs[j] = j;
        }
        a64asm->reset();
        a64asm->prolog();
        a64asm->STM(AL,ARMAssemblerInterface::DB,Rn,1,patterns[i]);
        for(j = 0; j < numArmv7Regs; ++j)
        {
            uint32_t op2 = a64asm->imm(0x31);
            a64asm->MOV(AL, 0,j,op2);
        }
        a64asm->LDM(AL,ARMAssemblerInterface::IA,Rn,1,patterns[i]);
        a64asm->epilog(0);
        flushcache();

        asm_function_t asm_function = (asm_function_t)(instrMem);
        asm_test_jacket(asm_function, regs, flags);

        for(j = 0; j < numArmv7Regs; ++j)
        {
            if((1 << j) & patterns[i])
            {
                if(regs[j] != j)
                {
                    printf("LDM/STM Test %x failed "
                           "Reg%d expected(0x%x) Actual(0x%" PRIx64 ") \n",
                           patterns[i], j, j, regs[j]);
                    break;
                }
            }
        }
        if(j == numArmv7Regs)
            printf("LDM/STM Test %x passed\n", patterns[i]);
    }
}

int main(void)
{
    uint32_t i;

    /* Allocate memory to store instructions generated by ArmToArm64Assembler */
    {
        int fd = ashmem_create_region("code cache", instrMemSize);
        if(fd < 0)
            printf("Creating code cache, ashmem_create_region "
                                "failed with error '%s'", strerror(errno));
        instrMem = mmap(NULL, instrMemSize,
                                    PROT_READ | PROT_WRITE | PROT_EXEC,
                                MAP_PRIVATE, fd, 0);
    }

    ArmToArm64Assembler a64asm(instrMem);

    if(TESTS_DATAOP_ENABLE)
    {
        printf("Running data processing tests\n");
        for(i = 0; i < sizeof(dataOpTests)/sizeof(dataOpTest_t); ++i)
            dataOpTest(dataOpTests[i], &a64asm);
    }

    if(TESTS_DATATRANSFER_ENABLE)
    {
        printf("Running data transfer tests\n");
        for(i = 0; i < sizeof(dataTransferTests)/sizeof(dataTransferTest_t); ++i)
            dataTransferTest(dataTransferTests[i], &a64asm);
    }

    if(TESTS_LDMSTM_ENABLE)
    {
        printf("Running LDM/STM tests\n");
        dataTransferLDMSTM(&a64asm);
    }


    if(TESTS_REG_CORRUPTION_ENABLE)
    {
        uint32_t reg_list[] = {0,1,12,14};
        uint32_t Rd, Rm, Rs, Rn;
        uint32_t i;
        uint32_t numRegs = sizeof(reg_list)/sizeof(uint32_t);

        printf("Running Register corruption tests\n");
        for(i = 0; i < sizeof(dataOpTests)/sizeof(dataOpTest_t); ++i)
        {
            for(Rd = 0; Rd < numRegs; ++Rd)
            {
                for(Rn = 0; Rn < numRegs; ++Rn)
                {
                    for(Rm = 0; Rm < numRegs; ++Rm)
                    {
                        for(Rs = 0; Rs < numRegs;++Rs)
                        {
                            if(Rd == Rn || Rd == Rm || Rd == Rs) continue;
                            if(Rn == Rm || Rn == Rs) continue;
                            if(Rm == Rs) continue;
                            printf("Testing combination Rd(%d), Rn(%d),"
                                   " Rm(%d), Rs(%d): ",
                                   reg_list[Rd], reg_list[Rn], reg_list[Rm], reg_list[Rs]);
                            dataOpTest(dataOpTests[i], &a64asm, reg_list[Rd],
                                       reg_list[Rn], reg_list[Rm], reg_list[Rs]);
                        }
                    }
                }
            }
        }
    }
    return 0;
}
