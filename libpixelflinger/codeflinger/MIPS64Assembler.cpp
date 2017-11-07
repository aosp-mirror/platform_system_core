/* libs/pixelflinger/codeflinger/MIPS64Assembler.cpp
**
** Copyright 2015, The Android Open Source Project
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/


/* MIPS64 assembler and ARM->MIPS64 assembly translator
**
** The approach is utilize MIPSAssembler generator, using inherited MIPS64Assembler
** that overrides just the specific MIPS64r6 instructions.
** For now ArmToMips64Assembler is copied over from ArmToMipsAssembler class,
** changing some MIPS64r6 related stuff.
**
*/

#define LOG_TAG "MIPS64Assembler"

#include <stdio.h>
#include <stdlib.h>

#include <cutils/properties.h>
#include <log/log.h>
#include <private/pixelflinger/ggl_context.h>

#include "MIPS64Assembler.h"
#include "CodeCache.h"
#include "mips64_disassem.h"

#define NOT_IMPLEMENTED()  LOG_ALWAYS_FATAL("Arm instruction %s not yet implemented\n", __func__)
#define __unused __attribute__((__unused__))

// ----------------------------------------------------------------------------

namespace android {

// ----------------------------------------------------------------------------
#if 0
#pragma mark -
#pragma mark ArmToMips64Assembler...
#endif

ArmToMips64Assembler::ArmToMips64Assembler(const sp<Assembly>& assembly,
                                           char *abuf, int linesz, int instr_count)
    :   ARMAssemblerInterface(),
        mArmDisassemblyBuffer(abuf),
        mArmLineLength(linesz),
        mArmInstrCount(instr_count),
        mInum(0),
        mAssembly(assembly)
{
    mMips = new MIPS64Assembler(assembly, this);
    mArmPC = (uint32_t **) malloc(ARM_MAX_INSTUCTIONS * sizeof(uint32_t *));
    init_conditional_labels();
}

ArmToMips64Assembler::ArmToMips64Assembler(void* assembly)
    :   ARMAssemblerInterface(),
        mArmDisassemblyBuffer(NULL),
        mInum(0),
        mAssembly(NULL)
{
    mMips = new MIPS64Assembler(assembly, this);
    mArmPC = (uint32_t **) malloc(ARM_MAX_INSTUCTIONS * sizeof(uint32_t *));
    init_conditional_labels();
}

ArmToMips64Assembler::~ArmToMips64Assembler()
{
    delete mMips;
    free((void *) mArmPC);
}

uint32_t* ArmToMips64Assembler::pc() const
{
    return mMips->pc();
}

uint32_t* ArmToMips64Assembler::base() const
{
    return mMips->base();
}

void ArmToMips64Assembler::reset()
{
    cond.labelnum = 0;
    mInum = 0;
    mMips->reset();
}

int ArmToMips64Assembler::getCodegenArch()
{
    return CODEGEN_ARCH_MIPS64;
}

void ArmToMips64Assembler::comment(const char* string)
{
    mMips->comment(string);
}

void ArmToMips64Assembler::label(const char* theLabel)
{
    mMips->label(theLabel);
}

void ArmToMips64Assembler::disassemble(const char* name)
{
    mMips->disassemble(name);
}

void ArmToMips64Assembler::init_conditional_labels()
{
    int i;
    for (i=0;i<99; ++i) {
        sprintf(cond.label[i], "cond_%d", i);
    }
}



#if 0
#pragma mark -
#pragma mark Prolog/Epilog & Generate...
#endif

void ArmToMips64Assembler::prolog()
{
    mArmPC[mInum++] = pc();  // save starting PC for this instr

    mMips->DADDIU(R_sp, R_sp, -(5 * 8));
    mMips->SD(R_s0, R_sp, 0);
    mMips->SD(R_s1, R_sp, 8);
    mMips->SD(R_s2, R_sp, 16);
    mMips->SD(R_s3, R_sp, 24);
    mMips->SD(R_s4, R_sp, 32);
    mMips->MOVE(R_v0, R_a0);    // move context * passed in a0 to v0 (arm r0)
}

void ArmToMips64Assembler::epilog(uint32_t touched __unused)
{
    mArmPC[mInum++] = pc();  // save starting PC for this instr

    mMips->LD(R_s0, R_sp, 0);
    mMips->LD(R_s1, R_sp, 8);
    mMips->LD(R_s2, R_sp, 16);
    mMips->LD(R_s3, R_sp, 24);
    mMips->LD(R_s4, R_sp, 32);
    mMips->DADDIU(R_sp, R_sp, (5 * 8));
    mMips->JR(R_ra);

}

int ArmToMips64Assembler::generate(const char* name)
{
    return mMips->generate(name);
}

void ArmToMips64Assembler::fix_branches()
{
    mMips->fix_branches();
}

uint32_t* ArmToMips64Assembler::pcForLabel(const char* label)
{
    return mMips->pcForLabel(label);
}

void ArmToMips64Assembler::set_condition(int mode, int R1, int R2) {
    if (mode == 2) {
        cond.type = SBIT_COND;
    } else {
        cond.type = CMP_COND;
    }
    cond.r1 = R1;
    cond.r2 = R2;
}

//----------------------------------------------------------

#if 0
#pragma mark -
#pragma mark Addressing modes & shifters...
#endif


// do not need this for MIPS, but it is in the Interface (virtual)
int ArmToMips64Assembler::buildImmediate(
        uint32_t immediate, uint32_t& rot, uint32_t& imm)
{
    // for MIPS, any 32-bit immediate is OK
    rot = 0;
    imm = immediate;
    return 0;
}

// shifters...

bool ArmToMips64Assembler::isValidImmediate(uint32_t immediate __unused)
{
    // for MIPS, any 32-bit immediate is OK
    return true;
}

uint32_t ArmToMips64Assembler::imm(uint32_t immediate)
{
    amode.value = immediate;
    return AMODE_IMM;
}

uint32_t ArmToMips64Assembler::reg_imm(int Rm, int type, uint32_t shift)
{
    amode.reg = Rm;
    amode.stype = type;
    amode.value = shift;
    return AMODE_REG_IMM;
}

uint32_t ArmToMips64Assembler::reg_rrx(int Rm __unused)
{
    // reg_rrx mode is not used in the GLLAssember code at this time
    return AMODE_UNSUPPORTED;
}

uint32_t ArmToMips64Assembler::reg_reg(int Rm __unused, int type __unused,
                                       int Rs __unused)
{
    // reg_reg mode is not used in the GLLAssember code at this time
    return AMODE_UNSUPPORTED;
}


// addressing modes...
// LDR(B)/STR(B)/PLD (immediate and Rm can be negative, which indicate U=0)
uint32_t ArmToMips64Assembler::immed12_pre(int32_t immed12, int W)
{
    LOG_ALWAYS_FATAL_IF(abs(immed12) >= 0x800,
                        "LDR(B)/STR(B)/PLD immediate too big (%08x)",
                        immed12);
    amode.value = immed12;
    amode.writeback = W;
    return AMODE_IMM_12_PRE;
}

uint32_t ArmToMips64Assembler::immed12_post(int32_t immed12)
{
    LOG_ALWAYS_FATAL_IF(abs(immed12) >= 0x800,
                        "LDR(B)/STR(B)/PLD immediate too big (%08x)",
                        immed12);

    amode.value = immed12;
    return AMODE_IMM_12_POST;
}

uint32_t ArmToMips64Assembler::reg_scale_pre(int Rm, int type,
        uint32_t shift, int W)
{
    LOG_ALWAYS_FATAL_IF(W | type | shift, "reg_scale_pre adv modes not yet implemented");

    amode.reg = Rm;
    // amode.stype = type;      // more advanced modes not used in GGLAssembler yet
    // amode.value = shift;
    // amode.writeback = W;
    return AMODE_REG_SCALE_PRE;
}

uint32_t ArmToMips64Assembler::reg_scale_post(int Rm __unused, int type __unused,
                                              uint32_t shift __unused)
{
    LOG_ALWAYS_FATAL("adr mode reg_scale_post not yet implemented\n");
    return AMODE_UNSUPPORTED;
}

// LDRH/LDRSB/LDRSH/STRH (immediate and Rm can be negative, which indicate U=0)
uint32_t ArmToMips64Assembler::immed8_pre(int32_t immed8, int W __unused)
{
    LOG_ALWAYS_FATAL("adr mode immed8_pre not yet implemented\n");

    LOG_ALWAYS_FATAL_IF(abs(immed8) >= 0x100,
                        "LDRH/LDRSB/LDRSH/STRH immediate too big (%08x)",
                        immed8);
    return AMODE_IMM_8_PRE;
}

uint32_t ArmToMips64Assembler::immed8_post(int32_t immed8)
{
    LOG_ALWAYS_FATAL_IF(abs(immed8) >= 0x100,
                        "LDRH/LDRSB/LDRSH/STRH immediate too big (%08x)",
                        immed8);
    amode.value = immed8;
    return AMODE_IMM_8_POST;
}

uint32_t ArmToMips64Assembler::reg_pre(int Rm, int W)
{
    LOG_ALWAYS_FATAL_IF(W, "reg_pre writeback not yet implemented");
    amode.reg = Rm;
    return AMODE_REG_PRE;
}

uint32_t ArmToMips64Assembler::reg_post(int Rm __unused)
{
    LOG_ALWAYS_FATAL("adr mode reg_post not yet implemented\n");
    return AMODE_UNSUPPORTED;
}



// ----------------------------------------------------------------------------

#if 0
#pragma mark -
#pragma mark Data Processing...
#endif

// check if the operand registers from a previous CMP or S-bit instruction
// would be overwritten by this instruction. If so, move the value to a
// safe register.
// Note that we cannot tell at _this_ instruction time if a future (conditional)
// instruction will _also_ use this value (a defect of the simple 1-pass, one-
// instruction-at-a-time translation). Therefore we must be conservative and
// save the value before it is overwritten. This costs an extra MOVE instr.

void ArmToMips64Assembler::protectConditionalOperands(int Rd)
{
    if (Rd == cond.r1) {
        mMips->MOVE(R_cmp, cond.r1);
        cond.r1 = R_cmp;
    }
    if (cond.type == CMP_COND && Rd == cond.r2) {
        mMips->MOVE(R_cmp2, cond.r2);
        cond.r2 = R_cmp2;
    }
}


// interprets the addressing mode, and generates the common code
// used by the majority of data-processing ops. Many MIPS instructions
// have a register-based form and a different immediate form. See
// opAND below for an example. (this could be inlined)
//
// this works with the imm(), reg_imm() methods above, which are directly
// called by the GLLAssembler.
// note: _signed parameter defaults to false (un-signed)
// note: tmpReg parameter defaults to 1, MIPS register AT
int ArmToMips64Assembler::dataProcAdrModes(int op, int& source, bool _signed, int tmpReg)
{
    if (op < AMODE_REG) {
        source = op;
        return SRC_REG;
    } else if (op == AMODE_IMM) {
        if ((!_signed && amode.value > 0xffff)
                || (_signed && ((int)amode.value < -32768 || (int)amode.value > 32767) )) {
            mMips->LUI(tmpReg, (amode.value >> 16));
            if (amode.value & 0x0000ffff) {
                mMips->ORI(tmpReg, tmpReg, (amode.value & 0x0000ffff));
            }
            source = tmpReg;
            return SRC_REG;
        } else {
            source = amode.value;
            return SRC_IMM;
        }
    } else if (op == AMODE_REG_IMM) {
        switch (amode.stype) {
            case LSL: mMips->SLL(tmpReg, amode.reg, amode.value); break;
            case LSR: mMips->SRL(tmpReg, amode.reg, amode.value); break;
            case ASR: mMips->SRA(tmpReg, amode.reg, amode.value); break;
            case ROR: mMips->ROTR(tmpReg, amode.reg, amode.value); break;
        }
        source = tmpReg;
        return SRC_REG;
    } else {  // adr mode RRX is not used in GGL Assembler at this time
        // we are screwed, this should be exception, assert-fail or something
        LOG_ALWAYS_FATAL("adr mode reg_rrx not yet implemented\n");
        return SRC_ERROR;
    }
}


void ArmToMips64Assembler::dataProcessing(int opcode, int cc,
        int s, int Rd, int Rn, uint32_t Op2)
{
    int src;    // src is modified by dataProcAdrModes() - passed as int&

    if (cc != AL) {
        protectConditionalOperands(Rd);
        // the branch tests register(s) set by prev CMP or instr with 'S' bit set
        // inverse the condition to jump past this conditional instruction
        ArmToMips64Assembler::B(cc^1, cond.label[++cond.labelnum]);
    } else {
        mArmPC[mInum++] = pc();  // save starting PC for this instr
    }

    switch (opcode) {
    case opAND:
        if (dataProcAdrModes(Op2, src) == SRC_REG) {
            mMips->AND(Rd, Rn, src);
        } else {                        // adr mode was SRC_IMM
            mMips->ANDI(Rd, Rn, src);
        }
        break;

    case opADD:
        // set "signed" to true for adr modes
        if (dataProcAdrModes(Op2, src, true) == SRC_REG) {
            mMips->ADDU(Rd, Rn, src);
        } else {                        // adr mode was SRC_IMM
            mMips->ADDIU(Rd, Rn, src);
        }
        break;

    case opSUB:
        // set "signed" to true for adr modes
        if (dataProcAdrModes(Op2, src, true) == SRC_REG) {
            mMips->SUBU(Rd, Rn, src);
        } else {                        // adr mode was SRC_IMM
            mMips->SUBIU(Rd, Rn, src);
        }
        break;

    case opADD64:
        // set "signed" to true for adr modes
        if (dataProcAdrModes(Op2, src, true) == SRC_REG) {
            mMips->DADDU(Rd, Rn, src);
        } else {                        // adr mode was SRC_IMM
            mMips->DADDIU(Rd, Rn, src);
        }
        break;

    case opSUB64:
        // set "signed" to true for adr modes
        if (dataProcAdrModes(Op2, src, true) == SRC_REG) {
            mMips->DSUBU(Rd, Rn, src);
        } else {                        // adr mode was SRC_IMM
            mMips->DSUBIU(Rd, Rn, src);
        }
        break;

    case opEOR:
        if (dataProcAdrModes(Op2, src) == SRC_REG) {
            mMips->XOR(Rd, Rn, src);
        } else {                        // adr mode was SRC_IMM
            mMips->XORI(Rd, Rn, src);
        }
        break;

    case opORR:
        if (dataProcAdrModes(Op2, src) == SRC_REG) {
            mMips->OR(Rd, Rn, src);
        } else {                        // adr mode was SRC_IMM
            mMips->ORI(Rd, Rn, src);
        }
        break;

    case opBIC:
        if (dataProcAdrModes(Op2, src) == SRC_IMM) {
            // if we are 16-bit imnmediate, load to AT reg
            mMips->ORI(R_at, 0, src);
            src = R_at;
        }
        mMips->NOT(R_at, src);
        mMips->AND(Rd, Rn, R_at);
        break;

    case opRSB:
        if (dataProcAdrModes(Op2, src) == SRC_IMM) {
            // if we are 16-bit imnmediate, load to AT reg
            mMips->ORI(R_at, 0, src);
            src = R_at;
        }
        mMips->SUBU(Rd, src, Rn);   // subu with the parameters reversed
        break;

    case opMOV:
        if (Op2 < AMODE_REG) {  // op2 is reg # in this case
            mMips->MOVE(Rd, Op2);
        } else if (Op2 == AMODE_IMM) {
            if (amode.value > 0xffff) {
                mMips->LUI(Rd, (amode.value >> 16));
                if (amode.value & 0x0000ffff) {
                    mMips->ORI(Rd, Rd, (amode.value & 0x0000ffff));
                }
             } else {
                mMips->ORI(Rd, 0, amode.value);
            }
        } else if (Op2 == AMODE_REG_IMM) {
            switch (amode.stype) {
            case LSL: mMips->SLL(Rd, amode.reg, amode.value); break;
            case LSR: mMips->SRL(Rd, amode.reg, amode.value); break;
            case ASR: mMips->SRA(Rd, amode.reg, amode.value); break;
            case ROR: mMips->ROTR(Rd, amode.reg, amode.value); break;
            }
        }
        else {
            // adr mode RRX is not used in GGL Assembler at this time
            mMips->UNIMPL();
        }
        break;

    case opMVN:     // this is a 1's complement: NOT
        if (Op2 < AMODE_REG) {  // op2 is reg # in this case
            mMips->NOR(Rd, Op2, 0);     // NOT is NOR with 0
            break;
        } else if (Op2 == AMODE_IMM) {
            if (amode.value > 0xffff) {
                mMips->LUI(Rd, (amode.value >> 16));
                if (amode.value & 0x0000ffff) {
                    mMips->ORI(Rd, Rd, (amode.value & 0x0000ffff));
                }
             } else {
                mMips->ORI(Rd, 0, amode.value);
             }
        } else if (Op2 == AMODE_REG_IMM) {
            switch (amode.stype) {
            case LSL: mMips->SLL(Rd, amode.reg, amode.value); break;
            case LSR: mMips->SRL(Rd, amode.reg, amode.value); break;
            case ASR: mMips->SRA(Rd, amode.reg, amode.value); break;
            case ROR: mMips->ROTR(Rd, amode.reg, amode.value); break;
            }
        }
        else {
            // adr mode RRX is not used in GGL Assembler at this time
            mMips->UNIMPL();
        }
        mMips->NOR(Rd, Rd, 0);     // NOT is NOR with 0
        break;

    case opCMP:
        // Either operand of a CMP instr could get overwritten by a subsequent
        // conditional instruction, which is ok, _UNLESS_ there is a _second_
        // conditional instruction. Under MIPS, this requires doing the comparison
        // again (SLT), and the original operands must be available. (and this
        // pattern of multiple conditional instructions from same CMP _is_ used
        // in GGL-Assembler)
        //
        // For now, if a conditional instr overwrites the operands, we will
        // move them to dedicated temp regs. This is ugly, and inefficient,
        // and should be optimized.
        //
        // WARNING: making an _Assumption_ that CMP operand regs will NOT be
        // trashed by intervening NON-conditional instructions. In the general
        // case this is legal, but it is NOT currently done in GGL-Assembler.

        cond.type = CMP_COND;
        cond.r1 = Rn;
        if (dataProcAdrModes(Op2, src, false, R_cmp2) == SRC_REG) {
            cond.r2 = src;
        } else {                        // adr mode was SRC_IMM
            mMips->ORI(R_cmp2, R_zero, src);
            cond.r2 = R_cmp2;
        }

        break;


    case opTST:
    case opTEQ:
    case opCMN:
    case opADC:
    case opSBC:
    case opRSC:
        mMips->UNIMPL(); // currently unused in GGL Assembler code
        break;
    }

    if (cc != AL) {
        mMips->label(cond.label[cond.labelnum]);
    }
    if (s && opcode != opCMP) {
        cond.type = SBIT_COND;
        cond.r1 = Rd;
    }
}



#if 0
#pragma mark -
#pragma mark Multiply...
#endif

// multiply, accumulate
void ArmToMips64Assembler::MLA(int cc __unused, int s,
        int Rd, int Rm, int Rs, int Rn) {

    //ALOGW("MLA");
    mArmPC[mInum++] = pc();  // save starting PC for this instr

    mMips->MUL(R_at, Rm, Rs);
    mMips->ADDU(Rd, R_at, Rn);
    if (s) {
        cond.type = SBIT_COND;
        cond.r1 = Rd;
    }
}

void ArmToMips64Assembler::MUL(int cc __unused, int s,
        int Rd, int Rm, int Rs) {
    mArmPC[mInum++] = pc();
    mMips->MUL(Rd, Rm, Rs);
    if (s) {
        cond.type = SBIT_COND;
        cond.r1 = Rd;
    }
}

void ArmToMips64Assembler::UMULL(int cc __unused, int s,
        int RdLo, int RdHi, int Rm, int Rs) {
    mArmPC[mInum++] = pc();
    mMips->MUH(RdHi, Rm, Rs);
    mMips->MUL(RdLo, Rm, Rs);

    if (s) {
        cond.type = SBIT_COND;
        cond.r1 = RdHi;     // BUG...
        LOG_ALWAYS_FATAL("Condition on UMULL must be on 64-bit result\n");
    }
}

void ArmToMips64Assembler::UMUAL(int cc __unused, int s,
        int RdLo __unused, int RdHi, int Rm __unused, int Rs __unused) {
    LOG_FATAL_IF(RdLo==Rm || RdHi==Rm || RdLo==RdHi,
                        "UMUAL(r%u,r%u,r%u,r%u)", RdLo,RdHi,Rm,Rs);
    // *mPC++ =    (cc<<28) | (1<<23) | (1<<21) | (s<<20) |
    //             (RdHi<<16) | (RdLo<<12) | (Rs<<8) | 0x90 | Rm;
    mArmPC[mInum++] = pc();
    mMips->NOP2();
    NOT_IMPLEMENTED();
    if (s) {
        cond.type = SBIT_COND;
        cond.r1 = RdHi;     // BUG...
        LOG_ALWAYS_FATAL("Condition on UMULL must be on 64-bit result\n");
    }
}

void ArmToMips64Assembler::SMULL(int cc __unused, int s,
        int RdLo __unused, int RdHi, int Rm __unused, int Rs __unused) {
    LOG_FATAL_IF(RdLo==Rm || RdHi==Rm || RdLo==RdHi,
                        "SMULL(r%u,r%u,r%u,r%u)", RdLo,RdHi,Rm,Rs);
    // *mPC++ =    (cc<<28) | (1<<23) | (1<<22) | (s<<20) |
    //             (RdHi<<16) | (RdLo<<12) | (Rs<<8) | 0x90 | Rm;
    mArmPC[mInum++] = pc();
    mMips->NOP2();
    NOT_IMPLEMENTED();
    if (s) {
        cond.type = SBIT_COND;
        cond.r1 = RdHi;     // BUG...
        LOG_ALWAYS_FATAL("Condition on SMULL must be on 64-bit result\n");
    }
}
void ArmToMips64Assembler::SMUAL(int cc __unused, int s,
        int RdLo __unused, int RdHi, int Rm __unused, int Rs __unused) {
    LOG_FATAL_IF(RdLo==Rm || RdHi==Rm || RdLo==RdHi,
                        "SMUAL(r%u,r%u,r%u,r%u)", RdLo,RdHi,Rm,Rs);
    // *mPC++ =    (cc<<28) | (1<<23) | (1<<22) | (1<<21) | (s<<20) |
    //             (RdHi<<16) | (RdLo<<12) | (Rs<<8) | 0x90 | Rm;
    mArmPC[mInum++] = pc();
    mMips->NOP2();
    NOT_IMPLEMENTED();
    if (s) {
        cond.type = SBIT_COND;
        cond.r1 = RdHi;     // BUG...
        LOG_ALWAYS_FATAL("Condition on SMUAL must be on 64-bit result\n");
    }
}



#if 0
#pragma mark -
#pragma mark Branches...
#endif

// branches...

void ArmToMips64Assembler::B(int cc, const char* label)
{
    mArmPC[mInum++] = pc();
    if (cond.type == SBIT_COND) { cond.r2 = R_zero; }

    switch(cc) {
        case EQ: mMips->BEQ(cond.r1, cond.r2, label); break;
        case NE: mMips->BNE(cond.r1, cond.r2, label); break;
        case HS: mMips->BGEU(cond.r1, cond.r2, label); break;
        case LO: mMips->BLTU(cond.r1, cond.r2, label); break;
        case MI: mMips->BLT(cond.r1, cond.r2, label); break;
        case PL: mMips->BGE(cond.r1, cond.r2, label); break;

        case HI: mMips->BGTU(cond.r1, cond.r2, label); break;
        case LS: mMips->BLEU(cond.r1, cond.r2, label); break;
        case GE: mMips->BGE(cond.r1, cond.r2, label); break;
        case LT: mMips->BLT(cond.r1, cond.r2, label); break;
        case GT: mMips->BGT(cond.r1, cond.r2, label); break;
        case LE: mMips->BLE(cond.r1, cond.r2, label); break;
        case AL: mMips->B(label); break;
        case NV: /* B Never - no instruction */ break;

        case VS:
        case VC:
        default:
            LOG_ALWAYS_FATAL("Unsupported cc: %02x\n", cc);
            break;
    }
}

void ArmToMips64Assembler::BL(int cc __unused, const char* label __unused)
{
    LOG_ALWAYS_FATAL("branch-and-link not supported yet\n");
    mArmPC[mInum++] = pc();
}

// no use for Branches with integer PC, but they're in the Interface class ....
void ArmToMips64Assembler::B(int cc __unused, uint32_t* to_pc __unused)
{
    LOG_ALWAYS_FATAL("branch to absolute PC not supported, use Label\n");
    mArmPC[mInum++] = pc();
}

void ArmToMips64Assembler::BL(int cc __unused, uint32_t* to_pc __unused)
{
    LOG_ALWAYS_FATAL("branch to absolute PC not supported, use Label\n");
    mArmPC[mInum++] = pc();
}

void ArmToMips64Assembler::BX(int cc __unused, int Rn __unused)
{
    LOG_ALWAYS_FATAL("branch to absolute PC not supported, use Label\n");
    mArmPC[mInum++] = pc();
}



#if 0
#pragma mark -
#pragma mark Data Transfer...
#endif

// data transfer...
void ArmToMips64Assembler::LDR(int cc __unused, int Rd, int Rn, uint32_t offset)
{
    mArmPC[mInum++] = pc();
    // work-around for ARM default address mode of immed12_pre(0)
    if (offset > AMODE_UNSUPPORTED) offset = 0;
    switch (offset) {
        case 0:
            amode.value = 0;
            amode.writeback = 0;
            // fall thru to next case ....
        case AMODE_IMM_12_PRE:
            if (Rn == ARMAssemblerInterface::SP) {
                Rn = R_sp;      // convert LDR via Arm SP to LW via Mips SP
            }
            mMips->LW(Rd, Rn, amode.value);
            if (amode.writeback) {      // OPTIONAL writeback on pre-index mode
                mMips->DADDIU(Rn, Rn, amode.value);
            }
            break;
        case AMODE_IMM_12_POST:
            if (Rn == ARMAssemblerInterface::SP) {
                Rn = R_sp;      // convert STR thru Arm SP to STR thru Mips SP
            }
            mMips->LW(Rd, Rn, 0);
            mMips->DADDIU(Rn, Rn, amode.value);
            break;
        case AMODE_REG_SCALE_PRE:
            // we only support simple base + index, no advanced modes for this one yet
            mMips->DADDU(R_at, Rn, amode.reg);
            mMips->LW(Rd, R_at, 0);
            break;
    }
}

void ArmToMips64Assembler::LDRB(int cc __unused, int Rd, int Rn, uint32_t offset)
{
    mArmPC[mInum++] = pc();
    // work-around for ARM default address mode of immed12_pre(0)
    if (offset > AMODE_UNSUPPORTED) offset = 0;
    switch (offset) {
        case 0:
            amode.value = 0;
            amode.writeback = 0;
            // fall thru to next case ....
        case AMODE_IMM_12_PRE:
            mMips->LBU(Rd, Rn, amode.value);
            if (amode.writeback) {      // OPTIONAL writeback on pre-index mode
                mMips->DADDIU(Rn, Rn, amode.value);
            }
            break;
        case AMODE_IMM_12_POST:
            mMips->LBU(Rd, Rn, 0);
            mMips->DADDIU(Rn, Rn, amode.value);
            break;
        case AMODE_REG_SCALE_PRE:
            // we only support simple base + index, no advanced modes for this one yet
            mMips->DADDU(R_at, Rn, amode.reg);
            mMips->LBU(Rd, R_at, 0);
            break;
    }

}

void ArmToMips64Assembler::STR(int cc __unused, int Rd, int Rn, uint32_t offset)
{
    mArmPC[mInum++] = pc();
    // work-around for ARM default address mode of immed12_pre(0)
    if (offset > AMODE_UNSUPPORTED) offset = 0;
    switch (offset) {
        case 0:
            amode.value = 0;
            amode.writeback = 0;
            // fall thru to next case ....
        case AMODE_IMM_12_PRE:
            if (Rn == ARMAssemblerInterface::SP) {
                Rn = R_sp;  // convert STR thru Arm SP to SW thru Mips SP
            }
            if (amode.writeback) {      // OPTIONAL writeback on pre-index mode
                // If we will writeback, then update the index reg, then store.
                // This correctly handles stack-push case.
                mMips->DADDIU(Rn, Rn, amode.value);
                mMips->SW(Rd, Rn, 0);
            } else {
                // No writeback so store offset by value
                mMips->SW(Rd, Rn, amode.value);
            }
            break;
        case AMODE_IMM_12_POST:
            mMips->SW(Rd, Rn, 0);
            mMips->DADDIU(Rn, Rn, amode.value);  // post index always writes back
            break;
        case AMODE_REG_SCALE_PRE:
            // we only support simple base + index, no advanced modes for this one yet
            mMips->DADDU(R_at, Rn, amode.reg);
            mMips->SW(Rd, R_at, 0);
            break;
    }
}

void ArmToMips64Assembler::STRB(int cc __unused, int Rd, int Rn, uint32_t offset)
{
    mArmPC[mInum++] = pc();
    // work-around for ARM default address mode of immed12_pre(0)
    if (offset > AMODE_UNSUPPORTED) offset = 0;
    switch (offset) {
        case 0:
            amode.value = 0;
            amode.writeback = 0;
            // fall thru to next case ....
        case AMODE_IMM_12_PRE:
            mMips->SB(Rd, Rn, amode.value);
            if (amode.writeback) {      // OPTIONAL writeback on pre-index mode
                mMips->DADDIU(Rn, Rn, amode.value);
            }
            break;
        case AMODE_IMM_12_POST:
            mMips->SB(Rd, Rn, 0);
            mMips->DADDIU(Rn, Rn, amode.value);
            break;
        case AMODE_REG_SCALE_PRE:
            // we only support simple base + index, no advanced modes for this one yet
            mMips->DADDU(R_at, Rn, amode.reg);
            mMips->SB(Rd, R_at, 0);
            break;
    }
}

void ArmToMips64Assembler::LDRH(int cc __unused, int Rd, int Rn, uint32_t offset)
{
    mArmPC[mInum++] = pc();
    // work-around for ARM default address mode of immed8_pre(0)
    if (offset > AMODE_UNSUPPORTED) offset = 0;
    switch (offset) {
        case 0:
            amode.value = 0;
            // fall thru to next case ....
        case AMODE_IMM_8_PRE:      // no support yet for writeback
            mMips->LHU(Rd, Rn, amode.value);
            break;
        case AMODE_IMM_8_POST:
            mMips->LHU(Rd, Rn, 0);
            mMips->DADDIU(Rn, Rn, amode.value);
            break;
        case AMODE_REG_PRE:
            // we only support simple base +/- index
            if (amode.reg >= 0) {
                mMips->DADDU(R_at, Rn, amode.reg);
            } else {
                mMips->DSUBU(R_at, Rn, abs(amode.reg));
            }
            mMips->LHU(Rd, R_at, 0);
            break;
    }
}

void ArmToMips64Assembler::LDRSB(int cc __unused, int Rd __unused,
                                 int Rn __unused, uint32_t offset __unused)
{
    mArmPC[mInum++] = pc();
    mMips->NOP2();
    NOT_IMPLEMENTED();
}

void ArmToMips64Assembler::LDRSH(int cc __unused, int Rd __unused,
                                 int Rn __unused, uint32_t offset __unused)
{
    mArmPC[mInum++] = pc();
    mMips->NOP2();
    NOT_IMPLEMENTED();
}

void ArmToMips64Assembler::STRH(int cc __unused, int Rd, int Rn, uint32_t offset)
{
    mArmPC[mInum++] = pc();
    // work-around for ARM default address mode of immed8_pre(0)
    if (offset > AMODE_UNSUPPORTED) offset = 0;
    switch (offset) {
        case 0:
            amode.value = 0;
            // fall thru to next case ....
        case AMODE_IMM_8_PRE:      // no support yet for writeback
            mMips->SH(Rd, Rn, amode.value);
            break;
        case AMODE_IMM_8_POST:
            mMips->SH(Rd, Rn, 0);
            mMips->DADDIU(Rn, Rn, amode.value);
            break;
        case AMODE_REG_PRE:
            // we only support simple base +/- index
            if (amode.reg >= 0) {
                mMips->DADDU(R_at, Rn, amode.reg);
            } else {
                mMips->DSUBU(R_at, Rn, abs(amode.reg));
            }
            mMips->SH(Rd, R_at, 0);
            break;
    }
}



#if 0
#pragma mark -
#pragma mark Block Data Transfer...
#endif

// block data transfer...
void ArmToMips64Assembler::LDM(int cc __unused, int dir __unused,
        int Rn __unused, int W __unused, uint32_t reg_list __unused)
{   //                        ED FD EA FA      IB IA DB DA
    // const uint8_t P[8] = { 1, 0, 1, 0,      1, 0, 1, 0 };
    // const uint8_t U[8] = { 1, 1, 0, 0,      1, 1, 0, 0 };
    // *mPC++ = (cc<<28) | (4<<25) | (uint32_t(P[dir])<<24) |
    //         (uint32_t(U[dir])<<23) | (1<<20) | (W<<21) | (Rn<<16) | reg_list;
    mArmPC[mInum++] = pc();
    mMips->NOP2();
    NOT_IMPLEMENTED();
}

void ArmToMips64Assembler::STM(int cc __unused, int dir __unused,
        int Rn __unused, int W __unused, uint32_t reg_list __unused)
{   //                        FA EA FD ED      IB IA DB DA
    // const uint8_t P[8] = { 0, 1, 0, 1,      1, 0, 1, 0 };
    // const uint8_t U[8] = { 0, 0, 1, 1,      1, 1, 0, 0 };
    // *mPC++ = (cc<<28) | (4<<25) | (uint32_t(P[dir])<<24) |
    //         (uint32_t(U[dir])<<23) | (0<<20) | (W<<21) | (Rn<<16) | reg_list;
    mArmPC[mInum++] = pc();
    mMips->NOP2();
    NOT_IMPLEMENTED();
}



#if 0
#pragma mark -
#pragma mark Special...
#endif

// special...
void ArmToMips64Assembler::SWP(int cc __unused, int Rn __unused,
                               int Rd __unused, int Rm __unused) {
    // *mPC++ = (cc<<28) | (2<<23) | (Rn<<16) | (Rd << 12) | 0x90 | Rm;
    mArmPC[mInum++] = pc();
    mMips->NOP2();
    NOT_IMPLEMENTED();
}

void ArmToMips64Assembler::SWPB(int cc __unused, int Rn __unused,
                                int Rd __unused, int Rm __unused) {
    // *mPC++ = (cc<<28) | (2<<23) | (1<<22) | (Rn<<16) | (Rd << 12) | 0x90 | Rm;
    mArmPC[mInum++] = pc();
    mMips->NOP2();
    NOT_IMPLEMENTED();
}

void ArmToMips64Assembler::SWI(int cc __unused, uint32_t comment __unused) {
    // *mPC++ = (cc<<28) | (0xF<<24) | comment;
    mArmPC[mInum++] = pc();
    mMips->NOP2();
    NOT_IMPLEMENTED();
}


#if 0
#pragma mark -
#pragma mark DSP instructions...
#endif

// DSP instructions...
void ArmToMips64Assembler::PLD(int Rn __unused, uint32_t offset) {
    LOG_ALWAYS_FATAL_IF(!((offset&(1<<24)) && !(offset&(1<<21))),
                        "PLD only P=1, W=0");
    // *mPC++ = 0xF550F000 | (Rn<<16) | offset;
    mArmPC[mInum++] = pc();
    mMips->NOP2();
    NOT_IMPLEMENTED();
}

void ArmToMips64Assembler::CLZ(int cc __unused, int Rd, int Rm)
{
    mArmPC[mInum++] = pc();
    mMips->CLZ(Rd, Rm);
}

void ArmToMips64Assembler::QADD(int cc __unused, int Rd __unused,
                                int Rm __unused, int Rn __unused)
{
    // *mPC++ = (cc<<28) | 0x1000050 | (Rn<<16) | (Rd<<12) | Rm;
    mArmPC[mInum++] = pc();
    mMips->NOP2();
    NOT_IMPLEMENTED();
}

void ArmToMips64Assembler::QDADD(int cc __unused, int Rd __unused,
                                 int Rm __unused, int Rn __unused)
{
    // *mPC++ = (cc<<28) | 0x1400050 | (Rn<<16) | (Rd<<12) | Rm;
    mArmPC[mInum++] = pc();
    mMips->NOP2();
    NOT_IMPLEMENTED();
}

void ArmToMips64Assembler::QSUB(int cc __unused, int Rd __unused,
                                int Rm __unused, int Rn __unused)
{
    // *mPC++ = (cc<<28) | 0x1200050 | (Rn<<16) | (Rd<<12) | Rm;
    mArmPC[mInum++] = pc();
    mMips->NOP2();
    NOT_IMPLEMENTED();
}

void ArmToMips64Assembler::QDSUB(int cc __unused, int Rd __unused,
                                 int Rm __unused, int Rn __unused)
{
    // *mPC++ = (cc<<28) | 0x1600050 | (Rn<<16) | (Rd<<12) | Rm;
    mArmPC[mInum++] = pc();
    mMips->NOP2();
    NOT_IMPLEMENTED();
}

// 16 x 16 signed multiply (like SMLAxx without the accumulate)
void ArmToMips64Assembler::SMUL(int cc __unused, int xy,
                int Rd, int Rm, int Rs)
{
    mArmPC[mInum++] = pc();

    // the 16 bits may be in the top or bottom half of 32-bit source reg,
    // as defined by the codes BB, BT, TB, TT (compressed param xy)
    // where x corresponds to Rm and y to Rs

    // select half-reg for Rm
    if (xy & xyTB) {
        // use top 16-bits
        mMips->SRA(R_at, Rm, 16);
    } else {
        // use bottom 16, but sign-extend to 32
        mMips->SEH(R_at, Rm);
    }
    // select half-reg for Rs
    if (xy & xyBT) {
        // use top 16-bits
        mMips->SRA(R_at2, Rs, 16);
    } else {
        // use bottom 16, but sign-extend to 32
        mMips->SEH(R_at2, Rs);
    }
    mMips->MUL(Rd, R_at, R_at2);
}

// signed 32b x 16b multiple, save top 32-bits of 48-bit result
void ArmToMips64Assembler::SMULW(int cc __unused, int y,
                int Rd, int Rm, int Rs)
{
    mArmPC[mInum++] = pc();

    // the selector yT or yB refers to reg Rs
    if (y & yT) {
        // zero the bottom 16-bits, with 2 shifts, it can affect result
        mMips->SRL(R_at, Rs, 16);
        mMips->SLL(R_at, R_at, 16);

    } else {
        // move low 16-bit half, to high half
        mMips->SLL(R_at, Rs, 16);
    }
    mMips->MUH(Rd, Rm, R_at);
}

// 16 x 16 signed multiply, accumulate: Rd = Rm{16} * Rs{16} + Rn
void ArmToMips64Assembler::SMLA(int cc __unused, int xy,
                int Rd, int Rm, int Rs, int Rn)
{
    mArmPC[mInum++] = pc();

    // the 16 bits may be in the top or bottom half of 32-bit source reg,
    // as defined by the codes BB, BT, TB, TT (compressed param xy)
    // where x corresponds to Rm and y to Rs

    // select half-reg for Rm
    if (xy & xyTB) {
        // use top 16-bits
        mMips->SRA(R_at, Rm, 16);
    } else {
        // use bottom 16, but sign-extend to 32
        mMips->SEH(R_at, Rm);
    }
    // select half-reg for Rs
    if (xy & xyBT) {
        // use top 16-bits
        mMips->SRA(R_at2, Rs, 16);
    } else {
        // use bottom 16, but sign-extend to 32
        mMips->SEH(R_at2, Rs);
    }

    mMips->MUL(R_at, R_at, R_at2);
    mMips->ADDU(Rd, R_at, Rn);
}

void ArmToMips64Assembler::SMLAL(int cc __unused, int xy __unused,
                                 int RdHi __unused, int RdLo __unused,
                                 int Rs __unused, int Rm __unused)
{
    // *mPC++ = (cc<<28) | 0x1400080 | (RdHi<<16) | (RdLo<<12) | (Rs<<8) | (xy<<4) | Rm;
    mArmPC[mInum++] = pc();
    mMips->NOP2();
    NOT_IMPLEMENTED();
}

void ArmToMips64Assembler::SMLAW(int cc __unused, int y __unused,
                                 int Rd __unused, int Rm __unused,
                                 int Rs __unused, int Rn __unused)
{
    // *mPC++ = (cc<<28) | 0x1200080 | (Rd<<16) | (Rn<<12) | (Rs<<8) | (y<<4) | Rm;
    mArmPC[mInum++] = pc();
    mMips->NOP2();
    NOT_IMPLEMENTED();
}

// used by ARMv6 version of GGLAssembler::filter32
void ArmToMips64Assembler::UXTB16(int cc __unused, int Rd, int Rm, int rotate)
{
    mArmPC[mInum++] = pc();

    //Rd[31:16] := ZeroExtend((Rm ROR (8 * sh))[23:16]),
    //Rd[15:0] := ZeroExtend((Rm ROR (8 * sh))[7:0]). sh 0-3.

    mMips->ROTR(R_at2, Rm, rotate * 8);
    mMips->LUI(R_at, 0xFF);
    mMips->ORI(R_at, R_at, 0xFF);
    mMips->AND(Rd, R_at2, R_at);
}

void ArmToMips64Assembler::UBFX(int cc __unused, int Rd __unused, int Rn __unused,
                                int lsb __unused, int width __unused)
{
     /* Placeholder for UBFX */
     mArmPC[mInum++] = pc();

     mMips->NOP2();
     NOT_IMPLEMENTED();
}

// ----------------------------------------------------------------------------
// Address Processing...
// ----------------------------------------------------------------------------

void ArmToMips64Assembler::ADDR_ADD(int cc,
        int s, int Rd, int Rn, uint32_t Op2)
{
//    if(cc != AL){ NOT_IMPLEMENTED(); return;} //Not required
//    if(s  != 0) { NOT_IMPLEMENTED(); return;} //Not required
    dataProcessing(opADD64, cc, s, Rd, Rn, Op2);
}

void ArmToMips64Assembler::ADDR_SUB(int cc,
        int s, int Rd, int Rn, uint32_t Op2)
{
//    if(cc != AL){ NOT_IMPLEMENTED(); return;} //Not required
//    if(s  != 0) { NOT_IMPLEMENTED(); return;} //Not required
    dataProcessing(opSUB64, cc, s, Rd, Rn, Op2);
}

void ArmToMips64Assembler::ADDR_LDR(int cc __unused, int Rd,
                                    int Rn, uint32_t offset) {
    mArmPC[mInum++] = pc();
    // work-around for ARM default address mode of immed12_pre(0)
    if (offset > AMODE_UNSUPPORTED) offset = 0;
    switch (offset) {
        case 0:
            amode.value = 0;
            amode.writeback = 0;
            // fall thru to next case ....
        case AMODE_IMM_12_PRE:
            if (Rn == ARMAssemblerInterface::SP) {
                Rn = R_sp;      // convert LDR via Arm SP to LW via Mips SP
            }
            mMips->LD(Rd, Rn, amode.value);
            if (amode.writeback) {      // OPTIONAL writeback on pre-index mode
                mMips->DADDIU(Rn, Rn, amode.value);
            }
            break;
        case AMODE_IMM_12_POST:
            if (Rn == ARMAssemblerInterface::SP) {
                Rn = R_sp;      // convert STR thru Arm SP to STR thru Mips SP
            }
            mMips->LD(Rd, Rn, 0);
            mMips->DADDIU(Rn, Rn, amode.value);
            break;
        case AMODE_REG_SCALE_PRE:
            // we only support simple base + index, no advanced modes for this one yet
            mMips->DADDU(R_at, Rn, amode.reg);
            mMips->LD(Rd, R_at, 0);
            break;
    }
}

void ArmToMips64Assembler::ADDR_STR(int cc __unused, int Rd,
                                    int Rn, uint32_t offset) {
    mArmPC[mInum++] = pc();
    // work-around for ARM default address mode of immed12_pre(0)
    if (offset > AMODE_UNSUPPORTED) offset = 0;
    switch (offset) {
        case 0:
            amode.value = 0;
            amode.writeback = 0;
            // fall thru to next case ....
        case AMODE_IMM_12_PRE:
            if (Rn == ARMAssemblerInterface::SP) {
                Rn = R_sp;  // convert STR thru Arm SP to SW thru Mips SP
            }
            if (amode.writeback) {      // OPTIONAL writeback on pre-index mode
                // If we will writeback, then update the index reg, then store.
                // This correctly handles stack-push case.
                mMips->DADDIU(Rn, Rn, amode.value);
                mMips->SD(Rd, Rn, 0);
            } else {
                // No writeback so store offset by value
                mMips->SD(Rd, Rn, amode.value);
            }
            break;
        case AMODE_IMM_12_POST:
            mMips->SD(Rd, Rn, 0);
            mMips->DADDIU(Rn, Rn, amode.value);  // post index always writes back
            break;
        case AMODE_REG_SCALE_PRE:
            // we only support simple base + index, no advanced modes for this one yet
            mMips->DADDU(R_at, Rn, amode.reg);
            mMips->SD(Rd, R_at, 0);
            break;
    }
}

#if 0
#pragma mark -
#pragma mark MIPS Assembler...
#endif


//**************************************************************************
//**************************************************************************
//**************************************************************************


/* MIPS64 assembler
** this is a subset of mips64r6, targeted specifically at ARM instruction
** replacement in the pixelflinger/codeflinger code.
**
** This class is extended from MIPSAssembler class and overrides only
** MIPS64r6 specific stuff.
*/

MIPS64Assembler::MIPS64Assembler(const sp<Assembly>& assembly, ArmToMips64Assembler *parent)
    : MIPSAssembler::MIPSAssembler(assembly, NULL), mParent(parent)
{
}

MIPS64Assembler::MIPS64Assembler(void* assembly, ArmToMips64Assembler *parent)
    : MIPSAssembler::MIPSAssembler(assembly), mParent(parent)
{
}

MIPS64Assembler::~MIPS64Assembler()
{
}

void MIPS64Assembler::reset()
{
    if (mAssembly != NULL) {
        mBase = mPC = (uint32_t *)mAssembly->base();
    } else {
        mPC = mBase = base();
    }
    mBranchTargets.clear();
    mLabels.clear();
    mLabelsInverseMapping.clear();
    mComments.clear();
}


void MIPS64Assembler::disassemble(const char* name __unused)
{
    char di_buf[140];

    bool arm_disasm_fmt = (mParent->mArmDisassemblyBuffer == NULL) ? false : true;

    typedef char dstr[40];
    dstr *lines = (dstr *)mParent->mArmDisassemblyBuffer;

    if (mParent->mArmDisassemblyBuffer != NULL) {
        for (int i=0; i<mParent->mArmInstrCount; ++i) {
            string_detab(lines[i]);
        }
    }

    size_t count = pc()-base();
    uint32_t* mipsPC = base();

    while (count--) {
        ssize_t label = mLabelsInverseMapping.indexOfKey(mipsPC);
        if (label >= 0) {
            ALOGW("%s:\n", mLabelsInverseMapping.valueAt(label));
        }
        ssize_t comment = mComments.indexOfKey(mipsPC);
        if (comment >= 0) {
            ALOGW("; %s\n", mComments.valueAt(comment));
        }
        ::mips_disassem(mipsPC, di_buf, arm_disasm_fmt);
        string_detab(di_buf);
        string_pad(di_buf, 30);
        ALOGW("%08lx:    %08x    %s", uintptr_t(mipsPC), uint32_t(*mipsPC), di_buf);
        mipsPC++;
    }
}

void MIPS64Assembler::fix_branches()
{
    // fixup all the branches
    size_t count = mBranchTargets.size();
    while (count--) {
        const branch_target_t& bt = mBranchTargets[count];
        uint32_t* target_pc = mLabels.valueFor(bt.label);
        LOG_ALWAYS_FATAL_IF(!target_pc,
                "error resolving branch targets, target_pc is null");
        int32_t offset = int32_t(target_pc - (bt.pc+1));
        *bt.pc |= offset & 0x00FFFF;
    }
}

void MIPS64Assembler::DADDU(int Rd, int Rs, int Rt)
{
    *mPC++ = (spec_op<<OP_SHF) | (daddu_fn<<FUNC_SHF)
                    | (Rs<<RS_SHF) | (Rt<<RT_SHF) | (Rd<<RD_SHF);
}

void MIPS64Assembler::DADDIU(int Rt, int Rs, int16_t imm)
{
    *mPC++ = (daddiu_op<<OP_SHF) | (Rt<<RT_SHF) | (Rs<<RS_SHF) | (imm & MSK_16);
}

void MIPS64Assembler::DSUBU(int Rd, int Rs, int Rt)
{
    *mPC++ = (spec_op<<OP_SHF) | (dsubu_fn<<FUNC_SHF) |
                        (Rs<<RS_SHF) | (Rt<<RT_SHF) | (Rd<<RD_SHF) ;
}

void MIPS64Assembler::DSUBIU(int Rt, int Rs, int16_t imm)   // really addiu(d, s, -j)
{
    *mPC++ = (daddiu_op<<OP_SHF) | (Rt<<RT_SHF) | (Rs<<RS_SHF) | ((-imm) & MSK_16);
}

void MIPS64Assembler::MUL(int Rd, int Rs, int Rt)
{
    *mPC++ = (spec_op<<OP_SHF) | (mul_fn<<RE_SHF) | (sop30_fn<<FUNC_SHF) |
                        (Rs<<RS_SHF) | (Rt<<RT_SHF) | (Rd<<RD_SHF) ;
}

void MIPS64Assembler::MUH(int Rd, int Rs, int Rt)
{
    *mPC++ = (spec_op<<OP_SHF) | (muh_fn<<RE_SHF) | (sop30_fn<<FUNC_SHF) |
                        (Rs<<RS_SHF) | (Rt<<RT_SHF) | (Rd<<RD_SHF) ;
}

void MIPS64Assembler::CLO(int Rd, int Rs)
{
    *mPC++ = (spec_op<<OP_SHF) | (17<<FUNC_SHF) |
                        (Rd<<RD_SHF) | (Rs<<RS_SHF) | (1<<RE_SHF);
}

void MIPS64Assembler::CLZ(int Rd, int Rs)
{
    *mPC++ = (spec_op<<OP_SHF) | (16<<FUNC_SHF) |
                        (Rd<<RD_SHF) | (Rs<<RS_SHF) | (1<<RE_SHF);
}

void MIPS64Assembler::LD(int Rt, int Rbase, int16_t offset)
{
    *mPC++ = (ld_op<<OP_SHF) | (Rbase<<RS_SHF) | (Rt<<RT_SHF) | (offset & MSK_16);
}

void MIPS64Assembler::SD(int Rt, int Rbase, int16_t offset)
{
    *mPC++ = (sd_op<<OP_SHF) | (Rbase<<RS_SHF) | (Rt<<RT_SHF) | (offset & MSK_16);
}

void MIPS64Assembler::LUI(int Rt, int16_t offset)
{
    *mPC++ = (aui_op<<OP_SHF) | (Rt<<RT_SHF) | (offset & MSK_16);
}


void MIPS64Assembler::JR(int Rs)
{
        *mPC++ = (spec_op<<OP_SHF) | (Rs<<RS_SHF) | (jalr_fn << FUNC_SHF);
        MIPS64Assembler::NOP();
}

}; // namespace android:
