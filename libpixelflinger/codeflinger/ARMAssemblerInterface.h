/* libs/pixelflinger/codeflinger/ARMAssemblerInterface.h
**
** Copyright 2006, The Android Open Source Project
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


#ifndef ANDROID_ARMASSEMBLER_INTERFACE_H
#define ANDROID_ARMASSEMBLER_INTERFACE_H

#include <stdint.h>
#include <sys/types.h>

namespace android {

// ----------------------------------------------------------------------------

class ARMAssemblerInterface
{
public:
    virtual ~ARMAssemblerInterface();

    enum {
        EQ, NE, CS, CC, MI, PL, VS, VC, HI, LS, GE, LT, GT, LE, AL, NV,
        HS = CS,
        LO = CC
    };
    enum {
        S = 1
    };
    enum {
        LSL, LSR, ASR, ROR
    };
    enum {
        ED, FD, EA, FA,
        IB, IA, DB, DA
    };
    enum {
        R0, R1, R2, R3, R4, R5, R6, R7, R8, R9, R10, R11, R12, R13, R14, R15,
        SP = R13,
        LR = R14,
        PC = R15
    };
    enum {
        #define LIST(rr) L##rr=1<<rr
        LIST(R0), LIST(R1), LIST(R2), LIST(R3), LIST(R4), LIST(R5), LIST(R6),
        LIST(R7), LIST(R8), LIST(R9), LIST(R10), LIST(R11), LIST(R12),
        LIST(R13), LIST(R14), LIST(R15),
        LIST(SP), LIST(LR), LIST(PC),
        #undef LIST
        LSAVED = LR4|LR5|LR6|LR7|LR8|LR9|LR10|LR11 | LLR
    };

    // -----------------------------------------------------------------------
    // shifters and addressing modes
    // -----------------------------------------------------------------------

    // shifters...
    static bool        isValidImmediate(uint32_t immed);
    static int         buildImmediate(uint32_t i, uint32_t& rot, uint32_t& imm);

    static uint32_t    imm(uint32_t immediate);
    static uint32_t    reg_imm(int Rm, int type, uint32_t shift);
    static uint32_t    reg_rrx(int Rm);
    static uint32_t    reg_reg(int Rm, int type, int Rs);

    // addressing modes... 
    // LDR(B)/STR(B)/PLD
    // (immediate and Rm can be negative, which indicates U=0)
    static uint32_t    immed12_pre(int32_t immed12, int W=0);
    static uint32_t    immed12_post(int32_t immed12);
    static uint32_t    reg_scale_pre(int Rm, int type=0, uint32_t shift=0, int W=0);
    static uint32_t    reg_scale_post(int Rm, int type=0, uint32_t shift=0);

    // LDRH/LDRSB/LDRSH/STRH
    // (immediate and Rm can be negative, which indicates U=0)
    static uint32_t    immed8_pre(int32_t immed8, int W=0);
    static uint32_t    immed8_post(int32_t immed8);
    static uint32_t    reg_pre(int Rm, int W=0);
    static uint32_t    reg_post(int Rm);

    // -----------------------------------------------------------------------
    // basic instructions & code generation
    // -----------------------------------------------------------------------

    // generate the code
    virtual void reset() = 0;
    virtual int  generate(const char* name) = 0;
    virtual void disassemble(const char* name) = 0;
    
    // construct prolog and epilog
    virtual void prolog() = 0;
    virtual void epilog(uint32_t touched) = 0;
    virtual void comment(const char* string) = 0;

    // data processing...
    enum {
        opAND, opEOR, opSUB, opRSB, opADD, opADC, opSBC, opRSC, 
        opTST, opTEQ, opCMP, opCMN, opORR, opMOV, opBIC, opMVN
    };

    virtual void
            dataProcessing( int opcode, int cc, int s,
                            int Rd, int Rn,
                            uint32_t Op2) = 0;
    
    // multiply...
    virtual void MLA(int cc, int s,
                int Rd, int Rm, int Rs, int Rn) = 0;
    virtual void MUL(int cc, int s,
                int Rd, int Rm, int Rs) = 0;
    virtual void UMULL(int cc, int s,
                int RdLo, int RdHi, int Rm, int Rs) = 0;
    virtual void UMUAL(int cc, int s,
                int RdLo, int RdHi, int Rm, int Rs) = 0;
    virtual void SMULL(int cc, int s,
                int RdLo, int RdHi, int Rm, int Rs) = 0;
    virtual void SMUAL(int cc, int s,
                int RdLo, int RdHi, int Rm, int Rs) = 0;

    // branches...
    virtual void B(int cc, uint32_t* pc) = 0;
    virtual void BL(int cc, uint32_t* pc) = 0;
    virtual void BX(int cc, int Rn) = 0;

    virtual void label(const char* theLabel) = 0;
    virtual void B(int cc, const char* label) = 0;
    virtual void BL(int cc, const char* label) = 0;

    // valid only after generate() has been called
    virtual uint32_t* pcForLabel(const char* label) = 0;

    // data transfer...
    virtual void LDR (int cc, int Rd,
                int Rn, uint32_t offset = immed12_pre(0)) = 0;
    virtual void LDRB(int cc, int Rd,
                int Rn, uint32_t offset = immed12_pre(0)) = 0;
    virtual void STR (int cc, int Rd,
                int Rn, uint32_t offset = immed12_pre(0)) = 0;
    virtual void STRB(int cc, int Rd,
                int Rn, uint32_t offset = immed12_pre(0)) = 0;

    virtual void LDRH (int cc, int Rd,
                int Rn, uint32_t offset = immed8_pre(0)) = 0;
    virtual void LDRSB(int cc, int Rd, 
                int Rn, uint32_t offset = immed8_pre(0)) = 0;
    virtual void LDRSH(int cc, int Rd,
                int Rn, uint32_t offset = immed8_pre(0)) = 0;
    virtual void STRH (int cc, int Rd,
                int Rn, uint32_t offset = immed8_pre(0)) = 0;

    // block data transfer...
    virtual void LDM(int cc, int dir,
                int Rn, int W, uint32_t reg_list) = 0;
    virtual void STM(int cc, int dir,
                int Rn, int W, uint32_t reg_list) = 0;

    // special...
    virtual void SWP(int cc, int Rn, int Rd, int Rm) = 0;
    virtual void SWPB(int cc, int Rn, int Rd, int Rm) = 0;
    virtual void SWI(int cc, uint32_t comment) = 0;

    // DSP instructions...
    enum {
        // B=0, T=1
        //     yx
        xyBB = 0, // 0000,
        xyTB = 2, // 0010,
        xyBT = 4, // 0100,
        xyTT = 6, // 0110,
        yB   = 0, // 0000,
        yT   = 4, // 0100
    };

    virtual void PLD(int Rn, uint32_t offset) = 0;

    virtual void CLZ(int cc, int Rd, int Rm) = 0;
    
    virtual void QADD(int cc, int Rd, int Rm, int Rn) = 0;
    virtual void QDADD(int cc, int Rd, int Rm, int Rn) = 0;
    virtual void QSUB(int cc, int Rd, int Rm, int Rn) = 0;
    virtual void QDSUB(int cc, int Rd, int Rm, int Rn) = 0;
    
    virtual void SMUL(int cc, int xy,
                int Rd, int Rm, int Rs) = 0;
    virtual void SMULW(int cc, int y,
                int Rd, int Rm, int Rs) = 0;
    virtual void SMLA(int cc, int xy,
                int Rd, int Rm, int Rs, int Rn) = 0;
    virtual void SMLAL(int cc, int xy,
                int RdHi, int RdLo, int Rs, int Rm) = 0;
    virtual void SMLAW(int cc, int y,
                int Rd, int Rm, int Rs, int Rn) = 0;

    // byte/half word extract...
    virtual void UXTB16(int cc, int Rd, int Rm, int rotate) = 0;

    // bit manipulation...
    virtual void UBFX(int cc, int Rd, int Rn, int lsb, int width) = 0;

    // -----------------------------------------------------------------------
    // convenience...
    // -----------------------------------------------------------------------
    inline void
    ADC(int cc, int s, int Rd, int Rn, uint32_t Op2) {
        dataProcessing(opADC, cc, s, Rd, Rn, Op2);
    }
    inline void
    ADD(int cc, int s, int Rd, int Rn, uint32_t Op2) {
        dataProcessing(opADD, cc, s, Rd, Rn, Op2);
    }
    inline void
    AND(int cc, int s, int Rd, int Rn, uint32_t Op2) {
        dataProcessing(opAND, cc, s, Rd, Rn, Op2);
    }
    inline void
    BIC(int cc, int s, int Rd, int Rn, uint32_t Op2) {
        dataProcessing(opBIC, cc, s, Rd, Rn, Op2);
    }
    inline void
    EOR(int cc, int s, int Rd, int Rn, uint32_t Op2) {
        dataProcessing(opEOR, cc, s, Rd, Rn, Op2);
    }
    inline void
    MOV(int cc, int s, int Rd, uint32_t Op2) {
        dataProcessing(opMOV, cc, s, Rd, 0, Op2);
    }
    inline void
    MVN(int cc, int s, int Rd, uint32_t Op2) {
        dataProcessing(opMVN, cc, s, Rd, 0, Op2);
    }
    inline void
    ORR(int cc, int s, int Rd, int Rn, uint32_t Op2) {
        dataProcessing(opORR, cc, s, Rd, Rn, Op2);
    }
    inline void
    RSB(int cc, int s, int Rd, int Rn, uint32_t Op2) {
        dataProcessing(opRSB, cc, s, Rd, Rn, Op2);
    }
    inline void
    RSC(int cc, int s, int Rd, int Rn, uint32_t Op2) {
        dataProcessing(opRSC, cc, s, Rd, Rn, Op2);
    }
    inline void
    SBC(int cc, int s, int Rd, int Rn, uint32_t Op2) {
        dataProcessing(opSBC, cc, s, Rd, Rn, Op2);
    }
    inline void
    SUB(int cc, int s, int Rd, int Rn, uint32_t Op2) {
        dataProcessing(opSUB, cc, s, Rd, Rn, Op2);
    }
    inline void
    TEQ(int cc, int Rn, uint32_t Op2) {
        dataProcessing(opTEQ, cc, 1, 0, Rn, Op2);
    }
    inline void
    TST(int cc, int Rn, uint32_t Op2) {
        dataProcessing(opTST, cc, 1, 0, Rn, Op2);
    }
    inline void
    CMP(int cc, int Rn, uint32_t Op2) {
        dataProcessing(opCMP, cc, 1, 0, Rn, Op2);
    }
    inline void
    CMN(int cc, int Rn, uint32_t Op2) {
        dataProcessing(opCMN, cc, 1, 0, Rn, Op2);
    }

    inline void SMULBB(int cc, int Rd, int Rm, int Rs) {
        SMUL(cc, xyBB, Rd, Rm, Rs);    }
    inline void SMULTB(int cc, int Rd, int Rm, int Rs) {
        SMUL(cc, xyTB, Rd, Rm, Rs);    }
    inline void SMULBT(int cc, int Rd, int Rm, int Rs) {
        SMUL(cc, xyBT, Rd, Rm, Rs);    }
    inline void SMULTT(int cc, int Rd, int Rm, int Rs) {
        SMUL(cc, xyTT, Rd, Rm, Rs);    }

    inline void SMULWB(int cc, int Rd, int Rm, int Rs) {
        SMULW(cc, yB, Rd, Rm, Rs);    }
    inline void SMULWT(int cc, int Rd, int Rm, int Rs) {
        SMULW(cc, yT, Rd, Rm, Rs);    }

    inline void
    SMLABB(int cc, int Rd, int Rm, int Rs, int Rn) {
        SMLA(cc, xyBB, Rd, Rm, Rs, Rn);    }
    inline void
    SMLATB(int cc, int Rd, int Rm, int Rs, int Rn) {
        SMLA(cc, xyTB, Rd, Rm, Rs, Rn);    }
    inline void
    SMLABT(int cc, int Rd, int Rm, int Rs, int Rn) {
        SMLA(cc, xyBT, Rd, Rm, Rs, Rn);    }
    inline void
    SMLATT(int cc, int Rd, int Rm, int Rs, int Rn) {
        SMLA(cc, xyTT, Rd, Rm, Rs, Rn);    }

    inline void
    SMLALBB(int cc, int RdHi, int RdLo, int Rs, int Rm) {
        SMLAL(cc, xyBB, RdHi, RdLo, Rs, Rm);    }
    inline void
    SMLALTB(int cc, int RdHi, int RdLo, int Rs, int Rm) {
        SMLAL(cc, xyTB, RdHi, RdLo, Rs, Rm);    }
    inline void
    SMLALBT(int cc, int RdHi, int RdLo, int Rs, int Rm) {
        SMLAL(cc, xyBT, RdHi, RdLo, Rs, Rm);    }
    inline void
    SMLALTT(int cc, int RdHi, int RdLo, int Rs, int Rm) {
        SMLAL(cc, xyTT, RdHi, RdLo, Rs, Rm);    }

    inline void
    SMLAWB(int cc, int Rd, int Rm, int Rs, int Rn) {
        SMLAW(cc, yB, Rd, Rm, Rs, Rn);    }
    inline void
    SMLAWT(int cc, int Rd, int Rm, int Rs, int Rn) {
        SMLAW(cc, yT, Rd, Rm, Rs, Rn);    }
};

}; // namespace android

#endif //ANDROID_ARMASSEMBLER_INTERFACE_H
