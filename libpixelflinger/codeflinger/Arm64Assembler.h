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

#ifndef ANDROID_ARMTOARM64ASSEMBLER_H
#define ANDROID_ARMTOARM64ASSEMBLER_H

#include <stdint.h>
#include <sys/types.h>

#include "tinyutils/smartpointer.h"
#include "utils/Vector.h"
#include "utils/KeyedVector.h"

#include "tinyutils/smartpointer.h"
#include "codeflinger/ARMAssemblerInterface.h"
#include "codeflinger/CodeCache.h"

namespace android {

// ----------------------------------------------------------------------------

class ArmToArm64Assembler : public ARMAssemblerInterface
{
public:
    explicit    ArmToArm64Assembler(const sp<Assembly>& assembly);
    explicit    ArmToArm64Assembler(void *base);
    virtual     ~ArmToArm64Assembler();

    uint32_t*   base() const;
    uint32_t*   pc() const;


    void        disassemble(const char* name);

    // ------------------------------------------------------------------------
    // ARMAssemblerInterface...
    // ------------------------------------------------------------------------

    virtual void    reset();

    virtual int     generate(const char* name);
    virtual int     getCodegenArch();

    virtual void    prolog();
    virtual void    epilog(uint32_t touched);
    virtual void    comment(const char* string);


    // -----------------------------------------------------------------------
    // shifters and addressing modes
    // -----------------------------------------------------------------------

    // shifters...
    virtual bool        isValidImmediate(uint32_t immed);
    virtual int         buildImmediate(uint32_t i, uint32_t& rot, uint32_t& imm);

    virtual uint32_t    imm(uint32_t immediate);
    virtual uint32_t    reg_imm(int Rm, int type, uint32_t shift);
    virtual uint32_t    reg_rrx(int Rm);
    virtual uint32_t    reg_reg(int Rm, int type, int Rs);

    // addressing modes...
    virtual uint32_t    immed12_pre(int32_t immed12, int W=0);
    virtual uint32_t    immed12_post(int32_t immed12);
    virtual uint32_t    reg_scale_pre(int Rm, int type=0, uint32_t shift=0, int W=0);
    virtual uint32_t    reg_scale_post(int Rm, int type=0, uint32_t shift=0);
    virtual uint32_t    immed8_pre(int32_t immed8, int W=0);
    virtual uint32_t    immed8_post(int32_t immed8);
    virtual uint32_t    reg_pre(int Rm, int W=0);
    virtual uint32_t    reg_post(int Rm);


    virtual void    dataProcessing(int opcode, int cc, int s,
                                int Rd, int Rn,
                                uint32_t Op2);
    virtual void MLA(int cc, int s,
                int Rd, int Rm, int Rs, int Rn);
    virtual void MUL(int cc, int s,
                int Rd, int Rm, int Rs);
    virtual void UMULL(int cc, int s,
                int RdLo, int RdHi, int Rm, int Rs);
    virtual void UMUAL(int cc, int s,
                int RdLo, int RdHi, int Rm, int Rs);
    virtual void SMULL(int cc, int s,
                int RdLo, int RdHi, int Rm, int Rs);
    virtual void SMUAL(int cc, int s,
                int RdLo, int RdHi, int Rm, int Rs);

    virtual void B(int cc, uint32_t* pc);
    virtual void BL(int cc, uint32_t* pc);
    virtual void BX(int cc, int Rn);
    virtual void label(const char* theLabel);
    virtual void B(int cc, const char* label);
    virtual void BL(int cc, const char* label);

    virtual uint32_t* pcForLabel(const char* label);

    virtual void ADDR_LDR(int cc, int Rd,
                int Rn, uint32_t offset = 0);
    virtual void ADDR_ADD(int cc, int s, int Rd,
                int Rn, uint32_t Op2);
    virtual void ADDR_SUB(int cc, int s, int Rd,
                int Rn, uint32_t Op2);
    virtual void ADDR_STR (int cc, int Rd,
                int Rn, uint32_t offset = 0);

    virtual void LDR (int cc, int Rd,
                int Rn, uint32_t offset = 0);
    virtual void LDRB(int cc, int Rd,
                int Rn, uint32_t offset = 0);
    virtual void STR (int cc, int Rd,
                int Rn, uint32_t offset = 0);
    virtual void STRB(int cc, int Rd,
                int Rn, uint32_t offset = 0);
    virtual void LDRH (int cc, int Rd,
                int Rn, uint32_t offset = 0);
    virtual void LDRSB(int cc, int Rd,
                int Rn, uint32_t offset = 0);
    virtual void LDRSH(int cc, int Rd,
                int Rn, uint32_t offset = 0);
    virtual void STRH (int cc, int Rd,
                int Rn, uint32_t offset = 0);


    virtual void LDM(int cc, int dir,
                int Rn, int W, uint32_t reg_list);
    virtual void STM(int cc, int dir,
                int Rn, int W, uint32_t reg_list);

    virtual void SWP(int cc, int Rn, int Rd, int Rm);
    virtual void SWPB(int cc, int Rn, int Rd, int Rm);
    virtual void SWI(int cc, uint32_t comment);

    virtual void PLD(int Rn, uint32_t offset);
    virtual void CLZ(int cc, int Rd, int Rm);
    virtual void QADD(int cc, int Rd, int Rm, int Rn);
    virtual void QDADD(int cc, int Rd, int Rm, int Rn);
    virtual void QSUB(int cc, int Rd, int Rm, int Rn);
    virtual void QDSUB(int cc, int Rd, int Rm, int Rn);
    virtual void SMUL(int cc, int xy,
                int Rd, int Rm, int Rs);
    virtual void SMULW(int cc, int y,
                int Rd, int Rm, int Rs);
    virtual void SMLA(int cc, int xy,
                int Rd, int Rm, int Rs, int Rn);
    virtual void SMLAL(int cc, int xy,
                int RdHi, int RdLo, int Rs, int Rm);
    virtual void SMLAW(int cc, int y,
                int Rd, int Rm, int Rs, int Rn);
    virtual void UXTB16(int cc, int Rd, int Rm, int rotate);
    virtual void UBFX(int cc, int Rd, int Rn, int lsb, int width);

private:
    ArmToArm64Assembler(const ArmToArm64Assembler& rhs);
    ArmToArm64Assembler& operator = (const ArmToArm64Assembler& rhs);

    // -----------------------------------------------------------------------
    // helper functions
    // -----------------------------------------------------------------------

    void dataTransfer(int operation, int cc, int Rd, int Rn,
                      uint32_t operand_type, uint32_t size = 32);
    void dataProcessingCommon(int opcode, int s,
                      int Rd, int Rn, uint32_t Op2);

    // -----------------------------------------------------------------------
    // Arm64 instructions
    // -----------------------------------------------------------------------
    uint32_t A64_B_COND(uint32_t cc, uint32_t offset);
    uint32_t A64_RET(uint32_t Rn);

    uint32_t A64_LDRSTR_Wm_SXTW_0(uint32_t operation,
                                uint32_t size, uint32_t Rt,
                                uint32_t Rn, uint32_t Rm);

    uint32_t A64_STR_IMM_PreIndex(uint32_t Rt, uint32_t Rn, int32_t simm);
    uint32_t A64_LDR_IMM_PostIndex(uint32_t Rt,uint32_t Rn, int32_t simm);

    uint32_t A64_ADD_X_Wm_SXTW(uint32_t Rd, uint32_t Rn, uint32_t Rm,
                               uint32_t amount);
    uint32_t A64_SUB_X_Wm_SXTW(uint32_t Rd, uint32_t Rn, uint32_t Rm,
                               uint32_t amount);

    uint32_t A64_ADD_IMM_X(uint32_t Rd, uint32_t Rn,
                           uint32_t imm, uint32_t shift = 0);
    uint32_t A64_SUB_IMM_X(uint32_t Rd, uint32_t Rn,
                           uint32_t imm, uint32_t shift = 0);

    uint32_t A64_ADD_X(uint32_t Rd, uint32_t Rn,
                       uint32_t Rm, uint32_t shift = 0, uint32_t amount = 0);
    uint32_t A64_ADD_W(uint32_t Rd, uint32_t Rn, uint32_t Rm,
                       uint32_t shift = 0, uint32_t amount = 0);
    uint32_t A64_SUB_W(uint32_t Rd, uint32_t Rn, uint32_t Rm,
                       uint32_t shift = 0, uint32_t amount = 0,
                       uint32_t setflag = 0);
    uint32_t A64_AND_W(uint32_t Rd, uint32_t Rn,
                       uint32_t Rm, uint32_t shift = 0, uint32_t amount = 0);
    uint32_t A64_ORR_W(uint32_t Rd, uint32_t Rn,
                       uint32_t Rm, uint32_t shift = 0, uint32_t amount = 0);
    uint32_t A64_ORN_W(uint32_t Rd, uint32_t Rn,
                       uint32_t Rm, uint32_t shift = 0, uint32_t amount = 0);

    uint32_t A64_MOVZ_W(uint32_t Rd, uint32_t imm, uint32_t shift);
    uint32_t A64_MOVZ_X(uint32_t Rd, uint32_t imm, uint32_t shift);
    uint32_t A64_MOVK_W(uint32_t Rd, uint32_t imm, uint32_t shift);

    uint32_t A64_SMADDL(uint32_t Rd, uint32_t Rn, uint32_t Rm, uint32_t Ra);
    uint32_t A64_MADD_W(uint32_t Rd, uint32_t Rn, uint32_t Rm, uint32_t Ra);

    uint32_t A64_SBFM_W(uint32_t Rd, uint32_t Rn,
                        uint32_t immr, uint32_t imms);
    uint32_t A64_UBFM_W(uint32_t Rd, uint32_t Rn,
                        uint32_t immr, uint32_t imms);
    uint32_t A64_UBFM_X(uint32_t Rd, uint32_t Rn,
                        uint32_t immr, uint32_t imms);

    uint32_t A64_EXTR_W(uint32_t Rd, uint32_t Rn, uint32_t Rm, uint32_t lsb);
    uint32_t A64_CSEL_X(uint32_t Rd, uint32_t Rn, uint32_t Rm, uint32_t cond);
    uint32_t A64_CSEL_W(uint32_t Rd, uint32_t Rn, uint32_t Rm, uint32_t cond);

    uint32_t*       mBase;
    uint32_t*       mPC;
    uint32_t*       mPrologPC;
    int64_t         mDuration;
    uint32_t        mTmpReg1, mTmpReg2, mTmpReg3, mZeroReg;

    struct branch_target_t {
        inline branch_target_t() : label(0), pc(0) { }
        inline branch_target_t(const char* l, uint32_t* p)
            : label(l), pc(p) { }
        const char* label;
        uint32_t*   pc;
    };

    sp<Assembly>    mAssembly;
    Vector<branch_target_t>                 mBranchTargets;
    KeyedVector< const char*, uint32_t* >   mLabels;
    KeyedVector< uint32_t*, const char* >   mLabelsInverseMapping;
    KeyedVector< uint32_t*, const char* >   mComments;

    enum operand_type_t
    {
        OPERAND_REG = 0x20,
        OPERAND_IMM,
        OPERAND_REG_IMM,
        OPERAND_REG_OFFSET,
        OPERAND_UNSUPPORTED
    };

    struct addr_mode_t {
        int32_t         immediate;
        bool            writeback;
        bool            preindex;
        bool            postindex;
        int32_t         reg_imm_Rm;
        int32_t         reg_imm_type;
        uint32_t        reg_imm_shift;
        int32_t         reg_offset;
    } mAddrMode;

};

}; // namespace android

#endif //ANDROID_ARM64ASSEMBLER_H
