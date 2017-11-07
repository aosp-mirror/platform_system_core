/* libs/pixelflinger/codeflinger/MIPSAssembler.cpp
**
** Copyright 2012, The Android Open Source Project
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


/* MIPS assembler and ARM->MIPS assembly translator
**
** The approach is to leave the GGLAssembler and associated files largely
** un-changed, still utilizing all Arm instruction generation. Via the
** ArmToMipsAssembler (subclassed from ArmAssemblerInterface) each Arm
** instruction is translated to one or more Mips instructions as necessary. This
** is clearly less efficient than a direct implementation within the
** GGLAssembler, but is far cleaner, more maintainable, and has yielded very
** significant performance gains on Mips compared to the generic pixel pipeline.
**
**
** GGLAssembler changes
**
** - The register allocator has been modified to re-map Arm registers 0-15 to mips
** registers 2-17. Mips register 0 cannot be used as general-purpose register,
** and register 1 has traditional uses as a short-term temporary.
**
** - Added some early bailouts for OUT_OF_REGISTERS in texturing.cpp and
** GGLAssembler.cpp, since this is not fatal, and can be retried at lower
** optimization level.
**
**
** ARMAssembler and ARMAssemblerInterface changes
**
** Refactored ARM address-mode static functions (imm(), reg_imm(), imm12_pre(), etc.)
** to virtual, so they can be overridden in MIPSAssembler. The implementation of these
** functions on ARM is moved from ARMAssemblerInterface.cpp to ARMAssembler.cpp, and
** is unchanged from the original. (This required duplicating 2 of these as static
** functions in ARMAssemblerInterface.cpp so they could be used as static initializers).
*/

#define LOG_TAG "MIPSAssembler"

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

#include <cutils/properties.h>
#include <log/log.h>
#include <private/pixelflinger/ggl_context.h>

#include "CodeCache.h"
#include "MIPSAssembler.h"
#include "mips_disassem.h"

#define __unused __attribute__((__unused__))

// Choose MIPS arch variant following gcc flags
#if defined(__mips__) && __mips==32 && __mips_isa_rev>=2
#define mips32r2 1
#else
#define mips32r2 0
#endif


#define NOT_IMPLEMENTED()  LOG_ALWAYS_FATAL("Arm instruction %s not yet implemented\n", __func__)



// ----------------------------------------------------------------------------

namespace android {

// ----------------------------------------------------------------------------
#if 0
#pragma mark -
#pragma mark ArmToMipsAssembler...
#endif

ArmToMipsAssembler::ArmToMipsAssembler(const sp<Assembly>& assembly,
                                       char *abuf, int linesz, int instr_count)
    :   ARMAssemblerInterface(),
        mArmDisassemblyBuffer(abuf),
        mArmLineLength(linesz),
        mArmInstrCount(instr_count),
        mInum(0),
        mAssembly(assembly)
{
    mMips = new MIPSAssembler(assembly, this);
    mArmPC = (uint32_t **) malloc(ARM_MAX_INSTUCTIONS * sizeof(uint32_t *));
    init_conditional_labels();
}

ArmToMipsAssembler::~ArmToMipsAssembler()
{
    delete mMips;
    free((void *) mArmPC);
}

uint32_t* ArmToMipsAssembler::pc() const
{
    return mMips->pc();
}

uint32_t* ArmToMipsAssembler::base() const
{
    return mMips->base();
}

void ArmToMipsAssembler::reset()
{
    cond.labelnum = 0;
    mInum = 0;
    mMips->reset();
}

int ArmToMipsAssembler::getCodegenArch()
{
    return CODEGEN_ARCH_MIPS;
}

void ArmToMipsAssembler::comment(const char* string)
{
    mMips->comment(string);
}

void ArmToMipsAssembler::label(const char* theLabel)
{
    mMips->label(theLabel);
}

void ArmToMipsAssembler::disassemble(const char* name)
{
    mMips->disassemble(name);
}

void ArmToMipsAssembler::init_conditional_labels()
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

void ArmToMipsAssembler::prolog()
{
    mArmPC[mInum++] = pc();  // save starting PC for this instr

    mMips->ADDIU(R_sp, R_sp, -(5 * 4));
    mMips->SW(R_s0, R_sp, 0);
    mMips->SW(R_s1, R_sp, 4);
    mMips->SW(R_s2, R_sp, 8);
    mMips->SW(R_s3, R_sp, 12);
    mMips->SW(R_s4, R_sp, 16);
    mMips->MOVE(R_v0, R_a0);    // move context * passed in a0 to v0 (arm r0)
}

void ArmToMipsAssembler::epilog(uint32_t touched __unused)
{
    mArmPC[mInum++] = pc();  // save starting PC for this instr

    mMips->LW(R_s0, R_sp, 0);
    mMips->LW(R_s1, R_sp, 4);
    mMips->LW(R_s2, R_sp, 8);
    mMips->LW(R_s3, R_sp, 12);
    mMips->LW(R_s4, R_sp, 16);
    mMips->ADDIU(R_sp, R_sp, (5 * 4));
    mMips->JR(R_ra);

}

int ArmToMipsAssembler::generate(const char* name)
{
    return mMips->generate(name);
}

uint32_t* ArmToMipsAssembler::pcForLabel(const char* label)
{
    return mMips->pcForLabel(label);
}



//----------------------------------------------------------

#if 0
#pragma mark -
#pragma mark Addressing modes & shifters...
#endif


// do not need this for MIPS, but it is in the Interface (virtual)
int ArmToMipsAssembler::buildImmediate(
        uint32_t immediate, uint32_t& rot, uint32_t& imm)
{
    // for MIPS, any 32-bit immediate is OK
    rot = 0;
    imm = immediate;
    return 0;
}

// shifters...

bool ArmToMipsAssembler::isValidImmediate(uint32_t immediate __unused)
{
    // for MIPS, any 32-bit immediate is OK
    return true;
}

uint32_t ArmToMipsAssembler::imm(uint32_t immediate)
{
    // ALOGW("immediate value %08x at pc %08x\n", immediate, (int)pc());
    amode.value = immediate;
    return AMODE_IMM;
}

uint32_t ArmToMipsAssembler::reg_imm(int Rm, int type, uint32_t shift)
{
    amode.reg = Rm;
    amode.stype = type;
    amode.value = shift;
    return AMODE_REG_IMM;
}

uint32_t ArmToMipsAssembler::reg_rrx(int Rm __unused)
{
    // reg_rrx mode is not used in the GLLAssember code at this time
    return AMODE_UNSUPPORTED;
}

uint32_t ArmToMipsAssembler::reg_reg(int Rm __unused, int type __unused,
                                     int Rs __unused)
{
    // reg_reg mode is not used in the GLLAssember code at this time
    return AMODE_UNSUPPORTED;
}


// addressing modes...
// LDR(B)/STR(B)/PLD (immediate and Rm can be negative, which indicate U=0)
uint32_t ArmToMipsAssembler::immed12_pre(int32_t immed12, int W)
{
    LOG_ALWAYS_FATAL_IF(abs(immed12) >= 0x800,
                        "LDR(B)/STR(B)/PLD immediate too big (%08x)",
                        immed12);
    amode.value = immed12;
    amode.writeback = W;
    return AMODE_IMM_12_PRE;
}

uint32_t ArmToMipsAssembler::immed12_post(int32_t immed12)
{
    LOG_ALWAYS_FATAL_IF(abs(immed12) >= 0x800,
                        "LDR(B)/STR(B)/PLD immediate too big (%08x)",
                        immed12);

    amode.value = immed12;
    return AMODE_IMM_12_POST;
}

uint32_t ArmToMipsAssembler::reg_scale_pre(int Rm, int type,
        uint32_t shift, int W)
{
    LOG_ALWAYS_FATAL_IF(W | type | shift, "reg_scale_pre adv modes not yet implemented");

    amode.reg = Rm;
    // amode.stype = type;      // more advanced modes not used in GGLAssembler yet
    // amode.value = shift;
    // amode.writeback = W;
    return AMODE_REG_SCALE_PRE;
}

uint32_t ArmToMipsAssembler::reg_scale_post(int Rm __unused, int type __unused,
                                            uint32_t shift __unused)
{
    LOG_ALWAYS_FATAL("adr mode reg_scale_post not yet implemented\n");
    return AMODE_UNSUPPORTED;
}

// LDRH/LDRSB/LDRSH/STRH (immediate and Rm can be negative, which indicate U=0)
uint32_t ArmToMipsAssembler::immed8_pre(int32_t immed8, int W __unused)
{
    // uint32_t offset = abs(immed8);

    LOG_ALWAYS_FATAL("adr mode immed8_pre not yet implemented\n");

    LOG_ALWAYS_FATAL_IF(abs(immed8) >= 0x100,
                        "LDRH/LDRSB/LDRSH/STRH immediate too big (%08x)",
                        immed8);
    return AMODE_IMM_8_PRE;
}

uint32_t ArmToMipsAssembler::immed8_post(int32_t immed8)
{
    // uint32_t offset = abs(immed8);

    LOG_ALWAYS_FATAL_IF(abs(immed8) >= 0x100,
                        "LDRH/LDRSB/LDRSH/STRH immediate too big (%08x)",
                        immed8);
    amode.value = immed8;
    return AMODE_IMM_8_POST;
}

uint32_t ArmToMipsAssembler::reg_pre(int Rm, int W)
{
    LOG_ALWAYS_FATAL_IF(W, "reg_pre writeback not yet implemented");
    amode.reg = Rm;
    return AMODE_REG_PRE;
}

uint32_t ArmToMipsAssembler::reg_post(int Rm __unused)
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

void ArmToMipsAssembler::protectConditionalOperands(int Rd)
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
int ArmToMipsAssembler::dataProcAdrModes(int op, int& source, bool _signed, int tmpReg)
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
            case ROR: if (mips32r2) {
                          mMips->ROTR(tmpReg, amode.reg, amode.value);
                      } else {
                          mMips->RORIsyn(tmpReg, amode.reg, amode.value);
                      }
                      break;
        }
        source = tmpReg;
        return SRC_REG;
    } else {  // adr mode RRX is not used in GGL Assembler at this time
        // we are screwed, this should be exception, assert-fail or something
        LOG_ALWAYS_FATAL("adr mode reg_rrx not yet implemented\n");
        return SRC_ERROR;
    }
}


void ArmToMipsAssembler::dataProcessing(int opcode, int cc,
        int s, int Rd, int Rn, uint32_t Op2)
{
    int src;    // src is modified by dataProcAdrModes() - passed as int&


    if (cc != AL) {
        protectConditionalOperands(Rd);
        // the branch tests register(s) set by prev CMP or instr with 'S' bit set
        // inverse the condition to jump past this conditional instruction
        ArmToMipsAssembler::B(cc^1, cond.label[++cond.labelnum]);
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
            case ROR: if (mips32r2) {
                          mMips->ROTR(Rd, amode.reg, amode.value);
                      } else {
                          mMips->RORIsyn(Rd, amode.reg, amode.value);
                      }
                      break;
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
            case ROR: if (mips32r2) {
                          mMips->ROTR(Rd, amode.reg, amode.value);
                      } else {
                          mMips->RORIsyn(Rd, amode.reg, amode.value);
                      }
                      break;
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
void ArmToMipsAssembler::MLA(int cc __unused, int s,
        int Rd, int Rm, int Rs, int Rn) {

    mArmPC[mInum++] = pc();  // save starting PC for this instr

    mMips->MUL(R_at, Rm, Rs);
    mMips->ADDU(Rd, R_at, Rn);
    if (s) {
        cond.type = SBIT_COND;
        cond.r1 = Rd;
    }
}

void ArmToMipsAssembler::MUL(int cc __unused, int s,
        int Rd, int Rm, int Rs) {
    mArmPC[mInum++] = pc();
    mMips->MUL(Rd, Rm, Rs);
    if (s) {
        cond.type = SBIT_COND;
        cond.r1 = Rd;
    }
}

void ArmToMipsAssembler::UMULL(int cc __unused, int s,
        int RdLo, int RdHi, int Rm, int Rs) {
    mArmPC[mInum++] = pc();
    mMips->MULT(Rm, Rs);
    mMips->MFHI(RdHi);
    mMips->MFLO(RdLo);
    if (s) {
        cond.type = SBIT_COND;
        cond.r1 = RdHi;     // BUG...
        LOG_ALWAYS_FATAL("Condition on UMULL must be on 64-bit result\n");
    }
}

void ArmToMipsAssembler::UMUAL(int cc __unused, int s,
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

void ArmToMipsAssembler::SMULL(int cc __unused, int s,
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
void ArmToMipsAssembler::SMUAL(int cc __unused, int s,
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

void ArmToMipsAssembler::B(int cc, const char* label)
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

void ArmToMipsAssembler::BL(int cc __unused, const char* label __unused)
{
    LOG_ALWAYS_FATAL("branch-and-link not supported yet\n");
    mArmPC[mInum++] = pc();
}

// no use for Branches with integer PC, but they're in the Interface class ....
void ArmToMipsAssembler::B(int cc __unused, uint32_t* to_pc __unused)
{
    LOG_ALWAYS_FATAL("branch to absolute PC not supported, use Label\n");
    mArmPC[mInum++] = pc();
}

void ArmToMipsAssembler::BL(int cc __unused, uint32_t* to_pc __unused)
{
    LOG_ALWAYS_FATAL("branch to absolute PC not supported, use Label\n");
    mArmPC[mInum++] = pc();
}

void ArmToMipsAssembler::BX(int cc __unused, int Rn __unused)
{
    LOG_ALWAYS_FATAL("branch to absolute PC not supported, use Label\n");
    mArmPC[mInum++] = pc();
}



#if 0
#pragma mark -
#pragma mark Data Transfer...
#endif

// data transfer...
void ArmToMipsAssembler::LDR(int cc __unused, int Rd, int Rn, uint32_t offset)
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
                mMips->ADDIU(Rn, Rn, amode.value);
            }
            break;
        case AMODE_IMM_12_POST:
            if (Rn == ARMAssemblerInterface::SP) {
                Rn = R_sp;      // convert STR thru Arm SP to STR thru Mips SP
            }
            mMips->LW(Rd, Rn, 0);
            mMips->ADDIU(Rn, Rn, amode.value);
            break;
        case AMODE_REG_SCALE_PRE:
            // we only support simple base + index, no advanced modes for this one yet
            mMips->ADDU(R_at, Rn, amode.reg);
            mMips->LW(Rd, R_at, 0);
            break;
    }
}

void ArmToMipsAssembler::LDRB(int cc __unused, int Rd, int Rn, uint32_t offset)
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
                mMips->ADDIU(Rn, Rn, amode.value);
            }
            break;
        case AMODE_IMM_12_POST:
            mMips->LBU(Rd, Rn, 0);
            mMips->ADDIU(Rn, Rn, amode.value);
            break;
        case AMODE_REG_SCALE_PRE:
            // we only support simple base + index, no advanced modes for this one yet
            mMips->ADDU(R_at, Rn, amode.reg);
            mMips->LBU(Rd, R_at, 0);
            break;
    }

}

void ArmToMipsAssembler::STR(int cc __unused, int Rd, int Rn, uint32_t offset)
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
                mMips->ADDIU(Rn, Rn, amode.value);
                mMips->SW(Rd, Rn, 0);
            } else {
                // No writeback so store offset by value
                mMips->SW(Rd, Rn, amode.value);
            }
            break;
        case AMODE_IMM_12_POST:
            mMips->SW(Rd, Rn, 0);
            mMips->ADDIU(Rn, Rn, amode.value);  // post index always writes back
            break;
        case AMODE_REG_SCALE_PRE:
            // we only support simple base + index, no advanced modes for this one yet
            mMips->ADDU(R_at, Rn, amode.reg);
            mMips->SW(Rd, R_at, 0);
            break;
    }
}

void ArmToMipsAssembler::STRB(int cc __unused, int Rd, int Rn, uint32_t offset)
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
                mMips->ADDIU(Rn, Rn, amode.value);
            }
            break;
        case AMODE_IMM_12_POST:
            mMips->SB(Rd, Rn, 0);
            mMips->ADDIU(Rn, Rn, amode.value);
            break;
        case AMODE_REG_SCALE_PRE:
            // we only support simple base + index, no advanced modes for this one yet
            mMips->ADDU(R_at, Rn, amode.reg);
            mMips->SB(Rd, R_at, 0);
            break;
    }
}

void ArmToMipsAssembler::LDRH(int cc __unused, int Rd, int Rn, uint32_t offset)
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
            mMips->ADDIU(Rn, Rn, amode.value);
            break;
        case AMODE_REG_PRE:
            // we only support simple base +/- index
            if (amode.reg >= 0) {
                mMips->ADDU(R_at, Rn, amode.reg);
            } else {
                mMips->SUBU(R_at, Rn, abs(amode.reg));
            }
            mMips->LHU(Rd, R_at, 0);
            break;
    }
}

void ArmToMipsAssembler::LDRSB(int cc __unused, int Rd __unused,
                               int Rn __unused, uint32_t offset __unused)
{
    mArmPC[mInum++] = pc();
    mMips->NOP2();
    NOT_IMPLEMENTED();
}

void ArmToMipsAssembler::LDRSH(int cc __unused, int Rd __unused,
                               int Rn __unused, uint32_t offset __unused)
{
    mArmPC[mInum++] = pc();
    mMips->NOP2();
    NOT_IMPLEMENTED();
}

void ArmToMipsAssembler::STRH(int cc __unused, int Rd, int Rn, uint32_t offset)
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
            mMips->ADDIU(Rn, Rn, amode.value);
            break;
        case AMODE_REG_PRE:
            // we only support simple base +/- index
            if (amode.reg >= 0) {
                mMips->ADDU(R_at, Rn, amode.reg);
            } else {
                mMips->SUBU(R_at, Rn, abs(amode.reg));
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
void ArmToMipsAssembler::LDM(int cc __unused, int dir __unused,
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

void ArmToMipsAssembler::STM(int cc __unused, int dir __unused,
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
void ArmToMipsAssembler::SWP(int cc __unused, int Rn __unused,
                             int Rd __unused, int Rm __unused) {
    // *mPC++ = (cc<<28) | (2<<23) | (Rn<<16) | (Rd << 12) | 0x90 | Rm;
    mArmPC[mInum++] = pc();
    mMips->NOP2();
    NOT_IMPLEMENTED();
}

void ArmToMipsAssembler::SWPB(int cc __unused, int Rn __unused,
                              int Rd __unused, int Rm __unused) {
    // *mPC++ = (cc<<28) | (2<<23) | (1<<22) | (Rn<<16) | (Rd << 12) | 0x90 | Rm;
    mArmPC[mInum++] = pc();
    mMips->NOP2();
    NOT_IMPLEMENTED();
}

void ArmToMipsAssembler::SWI(int cc __unused, uint32_t comment __unused) {
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
void ArmToMipsAssembler::PLD(int Rn __unused, uint32_t offset) {
    LOG_ALWAYS_FATAL_IF(!((offset&(1<<24)) && !(offset&(1<<21))),
                        "PLD only P=1, W=0");
    // *mPC++ = 0xF550F000 | (Rn<<16) | offset;
    mArmPC[mInum++] = pc();
    mMips->NOP2();
    NOT_IMPLEMENTED();
}

void ArmToMipsAssembler::CLZ(int cc __unused, int Rd, int Rm)
{
    mArmPC[mInum++] = pc();
    mMips->CLZ(Rd, Rm);
}

void ArmToMipsAssembler::QADD(int cc __unused,  int Rd __unused,
                              int Rm __unused, int Rn __unused)
{
    // *mPC++ = (cc<<28) | 0x1000050 | (Rn<<16) | (Rd<<12) | Rm;
    mArmPC[mInum++] = pc();
    mMips->NOP2();
    NOT_IMPLEMENTED();
}

void ArmToMipsAssembler::QDADD(int cc __unused,  int Rd __unused,
                               int Rm __unused, int Rn __unused)
{
    // *mPC++ = (cc<<28) | 0x1400050 | (Rn<<16) | (Rd<<12) | Rm;
    mArmPC[mInum++] = pc();
    mMips->NOP2();
    NOT_IMPLEMENTED();
}

void ArmToMipsAssembler::QSUB(int cc __unused,  int Rd __unused,
                              int Rm __unused, int Rn __unused)
{
    // *mPC++ = (cc<<28) | 0x1200050 | (Rn<<16) | (Rd<<12) | Rm;
    mArmPC[mInum++] = pc();
    mMips->NOP2();
    NOT_IMPLEMENTED();
}

void ArmToMipsAssembler::QDSUB(int cc __unused,  int Rd __unused,
                               int Rm __unused, int Rn __unused)
{
    // *mPC++ = (cc<<28) | 0x1600050 | (Rn<<16) | (Rd<<12) | Rm;
    mArmPC[mInum++] = pc();
    mMips->NOP2();
    NOT_IMPLEMENTED();
}

// 16 x 16 signed multiply (like SMLAxx without the accumulate)
void ArmToMipsAssembler::SMUL(int cc __unused, int xy,
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
        if (mips32r2) {
            mMips->SEH(R_at, Rm);
        } else {
            mMips->SLL(R_at, Rm, 16);
            mMips->SRA(R_at, R_at, 16);
        }
    }
    // select half-reg for Rs
    if (xy & xyBT) {
        // use top 16-bits
        mMips->SRA(R_at2, Rs, 16);
    } else {
        // use bottom 16, but sign-extend to 32
        if (mips32r2) {
            mMips->SEH(R_at2, Rs);
        } else {
            mMips->SLL(R_at2, Rs, 16);
            mMips->SRA(R_at2, R_at2, 16);
        }
    }
    mMips->MUL(Rd, R_at, R_at2);
}

// signed 32b x 16b multiple, save top 32-bits of 48-bit result
void ArmToMipsAssembler::SMULW(int cc __unused, int y,
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
    mMips->MULT(Rm, R_at);
    mMips->MFHI(Rd);
}

// 16 x 16 signed multiply, accumulate: Rd = Rm{16} * Rs{16} + Rn
void ArmToMipsAssembler::SMLA(int cc __unused, int xy,
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
        if (mips32r2) {
            mMips->SEH(R_at, Rm);
        } else {
            mMips->SLL(R_at, Rm, 16);
            mMips->SRA(R_at, R_at, 16);
        }
    }
    // select half-reg for Rs
    if (xy & xyBT) {
        // use top 16-bits
        mMips->SRA(R_at2, Rs, 16);
    } else {
        // use bottom 16, but sign-extend to 32
        if (mips32r2) {
            mMips->SEH(R_at2, Rs);
        } else {
            mMips->SLL(R_at2, Rs, 16);
            mMips->SRA(R_at2, R_at2, 16);
        }
    }

    mMips->MUL(R_at, R_at, R_at2);
    mMips->ADDU(Rd, R_at, Rn);
}

void ArmToMipsAssembler::SMLAL(int cc __unused, int xy __unused,
                               int RdHi __unused, int RdLo __unused,
                               int Rs __unused, int Rm __unused)
{
    // *mPC++ = (cc<<28) | 0x1400080 | (RdHi<<16) | (RdLo<<12) | (Rs<<8) | (xy<<4) | Rm;
    mArmPC[mInum++] = pc();
    mMips->NOP2();
    NOT_IMPLEMENTED();
}

void ArmToMipsAssembler::SMLAW(int cc __unused, int y __unused,
                               int Rd __unused, int Rm __unused,
                               int Rs __unused, int Rn __unused)
{
    // *mPC++ = (cc<<28) | 0x1200080 | (Rd<<16) | (Rn<<12) | (Rs<<8) | (y<<4) | Rm;
    mArmPC[mInum++] = pc();
    mMips->NOP2();
    NOT_IMPLEMENTED();
}

// used by ARMv6 version of GGLAssembler::filter32
void ArmToMipsAssembler::UXTB16(int cc __unused, int Rd, int Rm, int rotate)
{
    mArmPC[mInum++] = pc();

    //Rd[31:16] := ZeroExtend((Rm ROR (8 * sh))[23:16]),
    //Rd[15:0] := ZeroExtend((Rm ROR (8 * sh))[7:0]). sh 0-3.

    mMips->ROTR(Rm, Rm, rotate * 8);
    mMips->AND(Rd, Rm, 0x00FF00FF);
}

void ArmToMipsAssembler::UBFX(int cc __unused, int Rd __unused,
                              int Rn __unused, int lsb __unused,
                              int width __unused)
{
     /* Placeholder for UBFX */
     mArmPC[mInum++] = pc();

     mMips->NOP2();
     NOT_IMPLEMENTED();
}





#if 0
#pragma mark -
#pragma mark MIPS Assembler...
#endif


//**************************************************************************
//**************************************************************************
//**************************************************************************


/* mips assembler
** this is a subset of mips32r2, targeted specifically at ARM instruction
** replacement in the pixelflinger/codeflinger code.
**
** To that end, there is no need for floating point, or priviledged
** instructions. This all runs in user space, no float.
**
** The syntax makes no attempt to be as complete as the assember, with
** synthetic instructions, and automatic recognition of immedate operands
** (use the immediate form of the instruction), etc.
**
** We start with mips32r1, and may add r2 and dsp extensions if cpu
** supports. Decision will be made at compile time, based on gcc
** options. (makes sense since android will be built for a a specific
** device)
*/

MIPSAssembler::MIPSAssembler(const sp<Assembly>& assembly, ArmToMipsAssembler *parent)
    : mParent(parent),
    mAssembly(assembly)
{
    mBase = mPC = (uint32_t *)assembly->base();
    mDuration = ggl_system_time();
}

MIPSAssembler::MIPSAssembler(void* assembly)
    : mParent(NULL), mAssembly(NULL)
{
    mBase = mPC = (uint32_t *)assembly;
}

MIPSAssembler::~MIPSAssembler()
{
}


uint32_t* MIPSAssembler::pc() const
{
    return mPC;
}

uint32_t* MIPSAssembler::base() const
{
    return mBase;
}

void MIPSAssembler::reset()
{
    mBase = mPC = (uint32_t *)mAssembly->base();
    mBranchTargets.clear();
    mLabels.clear();
    mLabelsInverseMapping.clear();
    mComments.clear();
}


// convert tabs to spaces, and remove any newline
// works with strings of limited size (makes a temp copy)
#define TABSTOP 8
void MIPSAssembler::string_detab(char *s)
{
    char *os = s;
    char temp[100];
    char *t = temp;
    int len = 99;
    int i = TABSTOP;

    while (*s && len-- > 0) {
        if (*s == '\n') { s++; continue; }
        if (*s == '\t') {
            s++;
            for ( ; i>0; i--) {*t++ = ' '; len--; }
        } else {
            *t++ = *s++;
        }
        if (i <= 0) i = TABSTOP;
        i--;
    }
    *t = '\0';
    strcpy(os, temp);
}

void MIPSAssembler::string_pad(char *s, int padded_len)
{
    int len = strlen(s);
    s += len;
    for (int i = padded_len - len; i > 0; --i) {
        *s++ = ' ';
    }
    *s = '\0';
}

// ----------------------------------------------------------------------------

void MIPSAssembler::disassemble(const char* name)
{
    char di_buf[140];

    if (name) {
        ALOGW("%s:\n", name);
    }

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
        // ALOGW("%08x:    %08x    ", int(i), int(i[0]));
        ::mips_disassem(mipsPC, di_buf, arm_disasm_fmt);
        string_detab(di_buf);
        string_pad(di_buf, 30);
        ALOGW("0x%p:    %08x    %s", mipsPC, uint32_t(*mipsPC), di_buf);
        mipsPC++;
    }
}

void MIPSAssembler::comment(const char* string)
{
    mComments.add(pc(), string);
}

void MIPSAssembler::label(const char* theLabel)
{
    mLabels.add(theLabel, pc());
    mLabelsInverseMapping.add(pc(), theLabel);
}


void MIPSAssembler::prolog()
{
    // empty - done in ArmToMipsAssembler
}

void MIPSAssembler::epilog(uint32_t touched __unused)
{
    // empty - done in ArmToMipsAssembler
}

int MIPSAssembler::generate(const char* name)
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

    mAssembly->resize( int(pc()-base())*4 );

    // the instruction & data caches are flushed by CodeCache
    const int64_t duration = ggl_system_time() - mDuration;
    const char * const format = "generated %s (%d ins) at [%p:%p] in %" PRId64 " ns\n";
    ALOGI(format, name, int(pc()-base()), base(), pc(), duration);

    char value[PROPERTY_VALUE_MAX];
    value[0] = '\0';

    property_get("debug.pf.disasm", value, "0");

    if (atoi(value) != 0) {
        disassemble(name);
    }

    return NO_ERROR;
}

uint32_t* MIPSAssembler::pcForLabel(const char* label)
{
    return mLabels.valueFor(label);
}



#if 0
#pragma mark -
#pragma mark Arithmetic...
#endif

void MIPSAssembler::ADDU(int Rd, int Rs, int Rt)
{
    *mPC++ = (spec_op<<OP_SHF) | (addu_fn<<FUNC_SHF)
                    | (Rs<<RS_SHF) | (Rt<<RT_SHF) | (Rd<<RD_SHF);
}

// MD00086 pdf says this is: ADDIU rt, rs, imm -- they do not use Rd
void MIPSAssembler::ADDIU(int Rt, int Rs, int16_t imm)
{
    *mPC++ = (addiu_op<<OP_SHF) | (Rt<<RT_SHF) | (Rs<<RS_SHF) | (imm & MSK_16);
}


void MIPSAssembler::SUBU(int Rd, int Rs, int Rt)
{
    *mPC++ = (spec_op<<OP_SHF) | (subu_fn<<FUNC_SHF) |
                        (Rs<<RS_SHF) | (Rt<<RT_SHF) | (Rd<<RD_SHF) ;
}


void MIPSAssembler::SUBIU(int Rt, int Rs, int16_t imm)   // really addiu(d, s, -j)
{
    *mPC++ = (addiu_op<<OP_SHF) | (Rt<<RT_SHF) | (Rs<<RS_SHF) | ((-imm) & MSK_16);
}


void MIPSAssembler::NEGU(int Rd, int Rs)    // really subu(d, zero, s)
{
    MIPSAssembler::SUBU(Rd, 0, Rs);
}

void MIPSAssembler::MUL(int Rd, int Rs, int Rt)
{
    *mPC++ = (spec2_op<<OP_SHF) | (mul_fn<<FUNC_SHF) |
                        (Rs<<RS_SHF) | (Rt<<RT_SHF) | (Rd<<RD_SHF) ;
}

void MIPSAssembler::MULT(int Rs, int Rt)    // dest is hi,lo
{
    *mPC++ = (spec_op<<OP_SHF) | (mult_fn<<FUNC_SHF) | (Rt<<RT_SHF) | (Rs<<RS_SHF);
}

void MIPSAssembler::MULTU(int Rs, int Rt)    // dest is hi,lo
{
    *mPC++ = (spec_op<<OP_SHF) | (multu_fn<<FUNC_SHF) | (Rt<<RT_SHF) | (Rs<<RS_SHF);
}

void MIPSAssembler::MADD(int Rs, int Rt)    // hi,lo = hi,lo + Rs * Rt
{
    *mPC++ = (spec2_op<<OP_SHF) | (madd_fn<<FUNC_SHF) | (Rt<<RT_SHF) | (Rs<<RS_SHF);
}

void MIPSAssembler::MADDU(int Rs, int Rt)    // hi,lo = hi,lo + Rs * Rt
{
    *mPC++ = (spec2_op<<OP_SHF) | (maddu_fn<<FUNC_SHF) | (Rt<<RT_SHF) | (Rs<<RS_SHF);
}


void MIPSAssembler::MSUB(int Rs, int Rt)    // hi,lo = hi,lo - Rs * Rt
{
    *mPC++ = (spec2_op<<OP_SHF) | (msub_fn<<FUNC_SHF) | (Rt<<RT_SHF) | (Rs<<RS_SHF);
}

void MIPSAssembler::MSUBU(int Rs, int Rt)    // hi,lo = hi,lo - Rs * Rt
{
    *mPC++ = (spec2_op<<OP_SHF) | (msubu_fn<<FUNC_SHF) | (Rt<<RT_SHF) | (Rs<<RS_SHF);
}


void MIPSAssembler::SEB(int Rd, int Rt)    // sign-extend byte (mips32r2)
{
    *mPC++ = (spec3_op<<OP_SHF) | (bshfl_fn<<FUNC_SHF) | (seb_fn << SA_SHF) |
                    (Rt<<RT_SHF) | (Rd<<RD_SHF);
}

void MIPSAssembler::SEH(int Rd, int Rt)    // sign-extend half-word (mips32r2)
{
    *mPC++ = (spec3_op<<OP_SHF) | (bshfl_fn<<FUNC_SHF) | (seh_fn << SA_SHF) |
                    (Rt<<RT_SHF) | (Rd<<RD_SHF);
}



#if 0
#pragma mark -
#pragma mark Comparisons...
#endif

void MIPSAssembler::SLT(int Rd, int Rs, int Rt)
{
    *mPC++ = (spec_op<<OP_SHF) | (slt_fn<<FUNC_SHF) |
                        (Rd<<RD_SHF) | (Rs<<RS_SHF) | (Rt<<RT_SHF);
}

void MIPSAssembler::SLTI(int Rt, int Rs, int16_t imm)
{
    *mPC++ = (slti_op<<OP_SHF) | (Rt<<RT_SHF) | (Rs<<RS_SHF) | (imm & MSK_16);
}


void MIPSAssembler::SLTU(int Rd, int Rs, int Rt)
{
    *mPC++ = (spec_op<<OP_SHF) | (sltu_fn<<FUNC_SHF) |
                        (Rd<<RD_SHF) | (Rs<<RS_SHF) | (Rt<<RT_SHF);
}

void MIPSAssembler::SLTIU(int Rt, int Rs, int16_t imm)
{
    *mPC++ = (sltiu_op<<OP_SHF) | (Rt<<RT_SHF) | (Rs<<RS_SHF) | (imm & MSK_16);
}



#if 0
#pragma mark -
#pragma mark Logical...
#endif

void MIPSAssembler::AND(int Rd, int Rs, int Rt)
{
    *mPC++ = (spec_op<<OP_SHF) | (and_fn<<FUNC_SHF) |
                        (Rd<<RD_SHF) | (Rs<<RS_SHF) | (Rt<<RT_SHF);
}

void MIPSAssembler::ANDI(int Rt, int Rs, uint16_t imm)      // todo: support larger immediate
{
    *mPC++ = (andi_op<<OP_SHF) | (Rt<<RT_SHF) | (Rs<<RS_SHF) | (imm & MSK_16);
}


void MIPSAssembler::OR(int Rd, int Rs, int Rt)
{
    *mPC++ = (spec_op<<OP_SHF) | (or_fn<<FUNC_SHF) |
                        (Rd<<RD_SHF) | (Rs<<RS_SHF) | (Rt<<RT_SHF);
}

void MIPSAssembler::ORI(int Rt, int Rs, uint16_t imm)
{
    *mPC++ = (ori_op<<OP_SHF) | (Rt<<RT_SHF) | (Rs<<RS_SHF) | (imm & MSK_16);
}

void MIPSAssembler::NOR(int Rd, int Rs, int Rt)
{
    *mPC++ = (spec_op<<OP_SHF) | (nor_fn<<FUNC_SHF) |
                        (Rd<<RD_SHF) | (Rs<<RS_SHF) | (Rt<<RT_SHF);
}

void MIPSAssembler::NOT(int Rd, int Rs)
{
    MIPSAssembler::NOR(Rd, Rs, 0);  // NOT(d,s) = NOR(d,s,zero)
}

void MIPSAssembler::XOR(int Rd, int Rs, int Rt)
{
    *mPC++ = (spec_op<<OP_SHF) | (xor_fn<<FUNC_SHF) |
                        (Rd<<RD_SHF) | (Rs<<RS_SHF) | (Rt<<RT_SHF);
}

void MIPSAssembler::XORI(int Rt, int Rs, uint16_t imm)  // todo: support larger immediate
{
    *mPC++ = (xori_op<<OP_SHF) | (Rt<<RT_SHF) | (Rs<<RS_SHF) | (imm & MSK_16);
}

void MIPSAssembler::SLL(int Rd, int Rt, int shft)
{
    *mPC++ = (spec_op<<OP_SHF) | (sll_fn<<FUNC_SHF) |
                        (Rd<<RD_SHF) | (Rt<<RT_SHF) | (shft<<RE_SHF);
}

void MIPSAssembler::SLLV(int Rd, int Rt, int Rs)
{
    *mPC++ = (spec_op<<OP_SHF) | (sllv_fn<<FUNC_SHF) |
                        (Rd<<RD_SHF) | (Rs<<RS_SHF) | (Rt<<RT_SHF);
}

void MIPSAssembler::SRL(int Rd, int Rt, int shft)
{
    *mPC++ = (spec_op<<OP_SHF) | (srl_fn<<FUNC_SHF) |
                        (Rd<<RD_SHF) | (Rt<<RT_SHF) | (shft<<RE_SHF);
}

void MIPSAssembler::SRLV(int Rd, int Rt, int Rs)
{
    *mPC++ = (spec_op<<OP_SHF) | (srlv_fn<<FUNC_SHF) |
                        (Rd<<RD_SHF) | (Rs<<RS_SHF) | (Rt<<RT_SHF);
}

void MIPSAssembler::SRA(int Rd, int Rt, int shft)
{
    *mPC++ = (spec_op<<OP_SHF) | (sra_fn<<FUNC_SHF) |
                        (Rd<<RD_SHF) | (Rt<<RT_SHF) | (shft<<RE_SHF);
}

void MIPSAssembler::SRAV(int Rd, int Rt, int Rs)
{
    *mPC++ = (spec_op<<OP_SHF) | (srav_fn<<FUNC_SHF) |
                        (Rd<<RD_SHF) | (Rs<<RS_SHF) | (Rt<<RT_SHF);
}

void MIPSAssembler::ROTR(int Rd, int Rt, int shft)      // mips32r2
{
    // note weird encoding (SRL + 1)
    *mPC++ = (spec_op<<OP_SHF) | (srl_fn<<FUNC_SHF) |
                        (1<<RS_SHF) | (Rd<<RD_SHF) | (Rt<<RT_SHF) | (shft<<RE_SHF);
}

void MIPSAssembler::ROTRV(int Rd, int Rt, int Rs)       // mips32r2
{
    // note weird encoding (SRLV + 1)
    *mPC++ = (spec_op<<OP_SHF) | (srlv_fn<<FUNC_SHF) |
                        (Rd<<RD_SHF) | (Rs<<RS_SHF) | (Rt<<RT_SHF) | (1<<RE_SHF);
}

// uses at2 register (mapped to some appropriate mips reg)
void MIPSAssembler::RORsyn(int Rd, int Rt, int Rs)
{
    // synthetic: d = t rotated by s
    MIPSAssembler::NEGU(R_at2, Rs);
    MIPSAssembler::SLLV(R_at2, Rt, R_at2);
    MIPSAssembler::SRLV(Rd, Rt, Rs);
    MIPSAssembler::OR(Rd, Rd, R_at2);
}

// immediate version - uses at2 register (mapped to some appropriate mips reg)
void MIPSAssembler::RORIsyn(int Rd, int Rt, int rot)
{
    // synthetic: d = t rotated by immed rot
    // d = s >> rot | s << (32-rot)
    MIPSAssembler::SLL(R_at2, Rt, 32-rot);
    MIPSAssembler::SRL(Rd, Rt, rot);
    MIPSAssembler::OR(Rd, Rd, R_at2);
}

void MIPSAssembler::CLO(int Rd, int Rs)
{
    // Rt field must have same gpr # as Rd
    *mPC++ = (spec2_op<<OP_SHF) | (clo_fn<<FUNC_SHF) |
                        (Rd<<RD_SHF) | (Rs<<RS_SHF) | (Rd<<RT_SHF);
}

void MIPSAssembler::CLZ(int Rd, int Rs)
{
    // Rt field must have same gpr # as Rd
    *mPC++ = (spec2_op<<OP_SHF) | (clz_fn<<FUNC_SHF) |
                        (Rd<<RD_SHF) | (Rs<<RS_SHF) | (Rd<<RT_SHF);
}

void MIPSAssembler::WSBH(int Rd, int Rt)      // mips32r2
{
    *mPC++ = (spec3_op<<OP_SHF) | (bshfl_fn<<FUNC_SHF) | (wsbh_fn << SA_SHF) |
                        (Rt<<RT_SHF) | (Rd<<RD_SHF);
}



#if 0
#pragma mark -
#pragma mark Load/store...
#endif

void MIPSAssembler::LW(int Rt, int Rbase, int16_t offset)
{
    *mPC++ = (lw_op<<OP_SHF) | (Rbase<<RS_SHF) | (Rt<<RT_SHF) | (offset & MSK_16);
}

void MIPSAssembler::SW(int Rt, int Rbase, int16_t offset)
{
    *mPC++ = (sw_op<<OP_SHF) | (Rbase<<RS_SHF) | (Rt<<RT_SHF) | (offset & MSK_16);
}

// lb is sign-extended
void MIPSAssembler::LB(int Rt, int Rbase, int16_t offset)
{
    *mPC++ = (lb_op<<OP_SHF) | (Rbase<<RS_SHF) | (Rt<<RT_SHF) | (offset & MSK_16);
}

void MIPSAssembler::LBU(int Rt, int Rbase, int16_t offset)
{
    *mPC++ = (lbu_op<<OP_SHF) | (Rbase<<RS_SHF) | (Rt<<RT_SHF) | (offset & MSK_16);
}

void MIPSAssembler::SB(int Rt, int Rbase, int16_t offset)
{
    *mPC++ = (sb_op<<OP_SHF) | (Rbase<<RS_SHF) | (Rt<<RT_SHF) | (offset & MSK_16);
}

// lh is sign-extended
void MIPSAssembler::LH(int Rt, int Rbase, int16_t offset)
{
    *mPC++ = (lh_op<<OP_SHF) | (Rbase<<RS_SHF) | (Rt<<RT_SHF) | (offset & MSK_16);
}

void MIPSAssembler::LHU(int Rt, int Rbase, int16_t offset)
{
    *mPC++ = (lhu_op<<OP_SHF) | (Rbase<<RS_SHF) | (Rt<<RT_SHF) | (offset & MSK_16);
}

void MIPSAssembler::SH(int Rt, int Rbase, int16_t offset)
{
    *mPC++ = (sh_op<<OP_SHF) | (Rbase<<RS_SHF) | (Rt<<RT_SHF) | (offset & MSK_16);
}

void MIPSAssembler::LUI(int Rt, int16_t offset)
{
    *mPC++ = (lui_op<<OP_SHF) | (Rt<<RT_SHF) | (offset & MSK_16);
}



#if 0
#pragma mark -
#pragma mark Register move...
#endif

void MIPSAssembler::MOVE(int Rd, int Rs)
{
    // encoded as "or rd, rs, zero"
    *mPC++ = (spec_op<<OP_SHF) | (or_fn<<FUNC_SHF) |
                        (Rd<<RD_SHF) | (Rs<<RS_SHF) | (0<<RT_SHF);
}

void MIPSAssembler::MOVN(int Rd, int Rs, int Rt)
{
    *mPC++ = (spec_op<<OP_SHF) | (movn_fn<<FUNC_SHF) |
                        (Rd<<RD_SHF) | (Rs<<RS_SHF) | (Rt<<RT_SHF);
}

void MIPSAssembler::MOVZ(int Rd, int Rs, int Rt)
{
    *mPC++ = (spec_op<<OP_SHF) | (movz_fn<<FUNC_SHF) |
                        (Rd<<RD_SHF) | (Rs<<RS_SHF) | (Rt<<RT_SHF);
}

void MIPSAssembler::MFHI(int Rd)
{
    *mPC++ = (spec_op<<OP_SHF) | (mfhi_fn<<FUNC_SHF) | (Rd<<RD_SHF);
}

void MIPSAssembler::MFLO(int Rd)
{
    *mPC++ = (spec_op<<OP_SHF) | (mflo_fn<<FUNC_SHF) | (Rd<<RD_SHF);
}

void MIPSAssembler::MTHI(int Rs)
{
    *mPC++ = (spec_op<<OP_SHF) | (mthi_fn<<FUNC_SHF) | (Rs<<RS_SHF);
}

void MIPSAssembler::MTLO(int Rs)
{
    *mPC++ = (spec_op<<OP_SHF) | (mtlo_fn<<FUNC_SHF) | (Rs<<RS_SHF);
}



#if 0
#pragma mark -
#pragma mark Branch...
#endif

// temporarily forcing a NOP into branch-delay slot, just to be safe
// todo: remove NOP, optimze use of delay slots
void MIPSAssembler::B(const char* label)
{
    mBranchTargets.add(branch_target_t(label, mPC));

    // encoded as BEQ zero, zero, offset
    *mPC++ = (beq_op<<OP_SHF) | (0<<RT_SHF)
                        | (0<<RS_SHF) | 0;  // offset filled in later

    MIPSAssembler::NOP();
}

void MIPSAssembler::BEQ(int Rs, int Rt, const char* label)
{
    mBranchTargets.add(branch_target_t(label, mPC));
    *mPC++ = (beq_op<<OP_SHF) | (Rt<<RT_SHF) | (Rs<<RS_SHF) | 0;
    MIPSAssembler::NOP();
}

void MIPSAssembler::BNE(int Rs, int Rt, const char* label)
{
    mBranchTargets.add(branch_target_t(label, mPC));
    *mPC++ = (bne_op<<OP_SHF) | (Rt<<RT_SHF) | (Rs<<RS_SHF) | 0;
    MIPSAssembler::NOP();
}

void MIPSAssembler::BLEZ(int Rs, const char* label)
{
    mBranchTargets.add(branch_target_t(label, mPC));
    *mPC++ = (blez_op<<OP_SHF) | (0<<RT_SHF) | (Rs<<RS_SHF) | 0;
    MIPSAssembler::NOP();
}

void MIPSAssembler::BLTZ(int Rs, const char* label)
{
    mBranchTargets.add(branch_target_t(label, mPC));
    *mPC++ = (regimm_op<<OP_SHF) | (bltz_fn<<RT_SHF) | (Rs<<RS_SHF) | 0;
    MIPSAssembler::NOP();
}

void MIPSAssembler::BGTZ(int Rs, const char* label)
{
    mBranchTargets.add(branch_target_t(label, mPC));
    *mPC++ = (bgtz_op<<OP_SHF) | (0<<RT_SHF) | (Rs<<RS_SHF) | 0;
    MIPSAssembler::NOP();
}


void MIPSAssembler::BGEZ(int Rs, const char* label)
{
    mBranchTargets.add(branch_target_t(label, mPC));
    *mPC++ = (regimm_op<<OP_SHF) | (bgez_fn<<RT_SHF) | (Rs<<RS_SHF) | 0;
    MIPSAssembler::NOP();
}

void MIPSAssembler::JR(int Rs)
{
    *mPC++ = (spec_op<<OP_SHF) | (Rs<<RS_SHF) | (jr_fn << FUNC_SHF);
    MIPSAssembler::NOP();
}


#if 0
#pragma mark -
#pragma mark Synthesized Branch...
#endif

// synthetic variants of branches (using slt & friends)
void MIPSAssembler::BEQZ(int Rs, const char* label)
{
    BEQ(Rs, R_zero, label);
}

void MIPSAssembler::BNEZ(int Rs __unused, const char* label)
{
    BNE(R_at, R_zero, label);
}

void MIPSAssembler::BGE(int Rs, int Rt, const char* label)
{
    SLT(R_at, Rs, Rt);
    BEQ(R_at, R_zero, label);
}

void MIPSAssembler::BGEU(int Rs, int Rt, const char* label)
{
    SLTU(R_at, Rs, Rt);
    BEQ(R_at, R_zero, label);
}

void MIPSAssembler::BGT(int Rs, int Rt, const char* label)
{
    SLT(R_at, Rt, Rs);   // rev
    BNE(R_at, R_zero, label);
}

void MIPSAssembler::BGTU(int Rs, int Rt, const char* label)
{
    SLTU(R_at, Rt, Rs);   // rev
    BNE(R_at, R_zero, label);
}

void MIPSAssembler::BLE(int Rs, int Rt, const char* label)
{
    SLT(R_at, Rt, Rs);   // rev
    BEQ(R_at, R_zero, label);
}

void MIPSAssembler::BLEU(int Rs, int Rt, const char* label)
{
    SLTU(R_at, Rt, Rs);  // rev
    BEQ(R_at, R_zero, label);
}

void MIPSAssembler::BLT(int Rs, int Rt, const char* label)
{
    SLT(R_at, Rs, Rt);
    BNE(R_at, R_zero, label);
}

void MIPSAssembler::BLTU(int Rs, int Rt, const char* label)
{
    SLTU(R_at, Rs, Rt);
    BNE(R_at, R_zero, label);
}




#if 0
#pragma mark -
#pragma mark Misc...
#endif

void MIPSAssembler::NOP(void)
{
    // encoded as "sll zero, zero, 0", which is all zero
    *mPC++ = (spec_op<<OP_SHF) | (sll_fn<<FUNC_SHF);
}

// using this as special opcode for not-yet-implemented ARM instruction
void MIPSAssembler::NOP2(void)
{
    // encoded as "sll zero, zero, 2", still a nop, but a unique code
    *mPC++ = (spec_op<<OP_SHF) | (sll_fn<<FUNC_SHF) | (2 << RE_SHF);
}

// using this as special opcode for purposefully NOT implemented ARM instruction
void MIPSAssembler::UNIMPL(void)
{
    // encoded as "sll zero, zero, 3", still a nop, but a unique code
    *mPC++ = (spec_op<<OP_SHF) | (sll_fn<<FUNC_SHF) | (3 << RE_SHF);
}


}; // namespace android:


