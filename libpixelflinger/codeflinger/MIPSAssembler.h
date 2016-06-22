/* libs/pixelflinger/codeflinger/MIPSAssembler.h
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

#ifndef ANDROID_MIPSASSEMBLER_H
#define ANDROID_MIPSASSEMBLER_H

#include <stdint.h>
#include <sys/types.h>

#include "tinyutils/smartpointer.h"
#include "utils/KeyedVector.h"
#include "utils/Vector.h"

#include "ARMAssemblerInterface.h"
#include "CodeCache.h"

namespace android {

class MIPSAssembler;    // forward reference

// this class mimics ARMAssembler interface
//  intent is to translate each ARM instruction to 1 or more MIPS instr
//  implementation calls MIPSAssembler class to generate mips code
class ArmToMipsAssembler : public ARMAssemblerInterface
{
public:
                ArmToMipsAssembler(const sp<Assembly>& assembly,
                        char *abuf = 0, int linesz = 0, int instr_count = 0);
    virtual     ~ArmToMipsAssembler();

    uint32_t*   base() const;
    uint32_t*   pc() const;
    void        disassemble(const char* name);

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
    // LDR(B)/STR(B)/PLD
    // (immediate and Rm can be negative, which indicates U=0)
    virtual uint32_t    immed12_pre(int32_t immed12, int W=0);
    virtual uint32_t    immed12_post(int32_t immed12);
    virtual uint32_t    reg_scale_pre(int Rm, int type=0, uint32_t shift=0, int W=0);
    virtual uint32_t    reg_scale_post(int Rm, int type=0, uint32_t shift=0);

    // LDRH/LDRSB/LDRSH/STRH
    // (immediate and Rm can be negative, which indicates U=0)
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

    // byte/half word extract...
    virtual void UXTB16(int cc, int Rd, int Rm, int rotate);

    // bit manipulation...
    virtual void UBFX(int cc, int Rd, int Rn, int lsb, int width);

    // this is some crap to share is MIPSAssembler class for debug
    char *      mArmDisassemblyBuffer;
    int         mArmLineLength;
    int         mArmInstrCount;

    int         mInum;      // current arm instuction number (0..n)
    uint32_t**  mArmPC;     // array: PC for 1st mips instr of
                            //      each translated ARM instr


private:
    ArmToMipsAssembler(const ArmToMipsAssembler& rhs);
    ArmToMipsAssembler& operator = (const ArmToMipsAssembler& rhs);

    void init_conditional_labels(void);

    void protectConditionalOperands(int Rd);

    // reg__tmp set to MIPS AT, reg 1
    int dataProcAdrModes(int op, int& source, bool sign = false, int reg_tmp = 1);

    sp<Assembly>        mAssembly;
    MIPSAssembler*      mMips;


    enum misc_constants_t {
        ARM_MAX_INSTUCTIONS = 512  // based on ASSEMBLY_SCRATCH_SIZE
    };

    enum {
        SRC_REG = 0,
        SRC_IMM,
        SRC_ERROR = -1
    };

    enum addr_modes {
        // start above the range of legal mips reg #'s (0-31)
        AMODE_REG = 0x20,
        AMODE_IMM, AMODE_REG_IMM,               // for data processing
        AMODE_IMM_12_PRE, AMODE_IMM_12_POST,    // for load/store
        AMODE_REG_SCALE_PRE, AMODE_IMM_8_PRE,
        AMODE_IMM_8_POST, AMODE_REG_PRE,
        AMODE_UNSUPPORTED
    };

    struct addr_mode_t {    // address modes for current ARM instruction
        int         reg;
        int         stype;
        uint32_t    value;
        bool        writeback;  // writeback the adr reg after modification
    } amode;

    enum cond_types {
        CMP_COND = 1,
        SBIT_COND
    };

    struct cond_mode_t {    // conditional-execution info for current ARM instruction
        cond_types  type;
        int         r1;
        int         r2;
        int         labelnum;
        char        label[100][10];
    } cond;

};




// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------

// This is the basic MIPS assembler, which just creates the opcodes in memory.
// All the more complicated work is done in ArmToMipsAssember above.

class MIPSAssembler
{
public:
                MIPSAssembler(const sp<Assembly>& assembly, ArmToMipsAssembler *parent);
                MIPSAssembler(void* assembly);
    virtual     ~MIPSAssembler();

    virtual uint32_t*   base() const;
    virtual uint32_t*   pc() const;
    virtual void        reset();

    virtual void        disassemble(const char* name);

    virtual void        prolog();
    virtual void        epilog(uint32_t touched);
    virtual int         generate(const char* name);
    virtual void        comment(const char* string);
    virtual void        label(const char* string);

    // valid only after generate() has been called
    virtual uint32_t*   pcForLabel(const char* label);


    // ------------------------------------------------------------------------
    // MIPSAssemblerInterface...
    // ------------------------------------------------------------------------

#if 0
#pragma mark -
#pragma mark Arithmetic...
#endif

    void ADDU(int Rd, int Rs, int Rt);
    void ADDIU(int Rt, int Rs, int16_t imm);
    void SUBU(int Rd, int Rs, int Rt);
    void SUBIU(int Rt, int Rs, int16_t imm);
    void NEGU(int Rd, int Rs);
    void MUL(int Rd, int Rs, int Rt);
    void MULT(int Rs, int Rt);      // dest is hi,lo
    void MULTU(int Rs, int Rt);     // dest is hi,lo
    void MADD(int Rs, int Rt);      // hi,lo = hi,lo + Rs * Rt
    void MADDU(int Rs, int Rt);     // hi,lo = hi,lo + Rs * Rt
    void MSUB(int Rs, int Rt);      // hi,lo = hi,lo - Rs * Rt
    void MSUBU(int Rs, int Rt);     // hi,lo = hi,lo - Rs * Rt
    void SEB(int Rd, int Rt);       // sign-extend byte (mips32r2)
    void SEH(int Rd, int Rt);       // sign-extend half-word (mips32r2)


#if 0
#pragma mark -
#pragma mark Comparisons...
#endif

    void SLT(int Rd, int Rs, int Rt);
    void SLTI(int Rt, int Rs, int16_t imm);
    void SLTU(int Rd, int Rs, int Rt);
    void SLTIU(int Rt, int Rs, int16_t imm);


#if 0
#pragma mark -
#pragma mark Logical...
#endif

    void AND(int Rd, int Rs, int Rt);
    void ANDI(int Rd, int Rs, uint16_t imm);
    void OR(int Rd, int Rs, int Rt);
    void ORI(int Rt, int Rs, uint16_t imm);
    void NOR(int Rd, int Rs, int Rt);
    void NOT(int Rd, int Rs);
    void XOR(int Rd, int Rs, int Rt);
    void XORI(int Rt, int Rs, uint16_t imm);

    void SLL(int Rd, int Rt, int shft);
    void SLLV(int Rd, int Rt, int Rs);
    void SRL(int Rd, int Rt, int shft);
    void SRLV(int Rd, int Rt, int Rs);
    void SRA(int Rd, int Rt, int shft);
    void SRAV(int Rd, int Rt, int Rs);
    void ROTR(int Rd, int Rt, int shft);    // mips32r2
    void ROTRV(int Rd, int Rt, int Rs);     // mips32r2
    void RORsyn(int Rd, int Rs, int Rt);    // synthetic: d = s rotated by t
    void RORIsyn(int Rd, int Rt, int rot);  // synthetic: d = s rotated by immed

    void CLO(int Rd, int Rs);
    void CLZ(int Rd, int Rs);
    void WSBH(int Rd, int Rt);


#if 0
#pragma mark -
#pragma mark Load/store...
#endif

    void LW(int Rt, int Rbase, int16_t offset);
    void SW(int Rt, int Rbase, int16_t offset);
    void LB(int Rt, int Rbase, int16_t offset);
    void LBU(int Rt, int Rbase, int16_t offset);
    void SB(int Rt, int Rbase, int16_t offset);
    void LH(int Rt, int Rbase, int16_t offset);
    void LHU(int Rt, int Rbase, int16_t offset);
    void SH(int Rt, int Rbase, int16_t offset);
    void LUI(int Rt, int16_t offset);

#if 0
#pragma mark -
#pragma mark Register moves...
#endif

    void MOVE(int Rd, int Rs);
    void MOVN(int Rd, int Rs, int Rt);
    void MOVZ(int Rd, int Rs, int Rt);
    void MFHI(int Rd);
    void MFLO(int Rd);
    void MTHI(int Rs);
    void MTLO(int Rs);

#if 0
#pragma mark -
#pragma mark Branch...
#endif

    void B(const char* label);
    void BEQ(int Rs, int Rt, const char* label);
    void BNE(int Rs, int Rt, const char* label);
    void BGEZ(int Rs, const char* label);
    void BGTZ(int Rs, const char* label);
    void BLEZ(int Rs, const char* label);
    void BLTZ(int Rs, const char* label);
    void JR(int Rs);


#if 0
#pragma mark -
#pragma mark Synthesized Branch...
#endif

    // synthetic variants of above (using slt & friends)
    void BEQZ(int Rs, const char* label);
    void BNEZ(int Rs, const char* label);
    void BGE(int Rs, int Rt, const char* label);
    void BGEU(int Rs, int Rt, const char* label);
    void BGT(int Rs, int Rt, const char* label);
    void BGTU(int Rs, int Rt, const char* label);
    void BLE(int Rs, int Rt, const char* label);
    void BLEU(int Rs, int Rt, const char* label);
    void BLT(int Rs, int Rt, const char* label);
    void BLTU(int Rs, int Rt, const char* label);

#if 0
#pragma mark -
#pragma mark Misc...
#endif

    void NOP(void);
    void NOP2(void);
    void UNIMPL(void);





protected:
    virtual void string_detab(char *s);
    virtual void string_pad(char *s, int padded_len);

    ArmToMipsAssembler *mParent;
    sp<Assembly>    mAssembly;
    uint32_t*       mBase;
    uint32_t*       mPC;
    uint32_t*       mPrologPC;
    int64_t         mDuration;

    struct branch_target_t {
        inline branch_target_t() : label(0), pc(0) { }
        inline branch_target_t(const char* l, uint32_t* p)
            : label(l), pc(p) { }
        const char* label;
        uint32_t*   pc;
    };

    Vector<branch_target_t>                 mBranchTargets;
    KeyedVector< const char*, uint32_t* >   mLabels;
    KeyedVector< uint32_t*, const char* >   mLabelsInverseMapping;
    KeyedVector< uint32_t*, const char* >   mComments;




    // opcode field of all instructions
    enum opcode_field {
        spec_op, regimm_op, j_op, jal_op,           // 00
        beq_op, bne_op, blez_op, bgtz_op,
        addi_op, addiu_op, slti_op, sltiu_op,       // 08
        andi_op, ori_op, xori_op, lui_op,
        cop0_op, cop1_op, cop2_op, cop1x_op,        // 10
        beql_op, bnel_op, blezl_op, bgtzl_op,
        daddi_op, daddiu_op, ldl_op, ldr_op,        // 18
        spec2_op, jalx_op, mdmx_op, spec3_op,
        lb_op, lh_op, lwl_op, lw_op,                // 20
        lbu_op, lhu_op, lwr_op, lwu_op,
        sb_op, sh_op, swl_op, sw_op,                // 28
        sdl_op, sdr_op, swr_op, cache_op,
        ll_op, lwc1_op, lwc2_op, pref_op,           // 30
        lld_op, ldc1_op, ldc2_op, ld_op,
        sc_op, swc1_op, swc2_op, rsrv_3b_op,        // 38
        scd_op, sdc1_op, sdc2_op, sd_op
    };


    // func field for special opcode
    enum func_spec_op {
        sll_fn, movc_fn, srl_fn, sra_fn,            // 00
        sllv_fn, pmon_fn, srlv_fn, srav_fn,
        jr_fn, jalr_fn, movz_fn, movn_fn,           // 08
        syscall_fn, break_fn, spim_fn, sync_fn,
        mfhi_fn, mthi_fn, mflo_fn, mtlo_fn,         // 10
        dsllv_fn, rsrv_spec_2, dsrlv_fn, dsrav_fn,
        mult_fn, multu_fn, div_fn, divu_fn,         // 18
        dmult_fn, dmultu_fn, ddiv_fn, ddivu_fn,
        add_fn, addu_fn, sub_fn, subu_fn,           // 20
        and_fn, or_fn, xor_fn, nor_fn,
        rsrv_spec_3, rsrv_spec_4, slt_fn, sltu_fn,  // 28
        dadd_fn, daddu_fn, dsub_fn, dsubu_fn,
        tge_fn, tgeu_fn, tlt_fn, tltu_fn,           // 30
        teq_fn, rsrv_spec_5, tne_fn, rsrv_spec_6,
        dsll_fn, rsrv_spec_7, dsrl_fn, dsra_fn,     // 38
        dsll32_fn, rsrv_spec_8, dsrl32_fn, dsra32_fn
    };

    // func field for spec2 opcode
    enum func_spec2_op {
        madd_fn, maddu_fn, mul_fn, rsrv_spec2_3,
        msub_fn, msubu_fn,
        clz_fn = 0x20, clo_fn,
        dclz_fn = 0x24, dclo_fn,
        sdbbp_fn = 0x3f
    };

    // func field for spec3 opcode
    enum func_spec3_op {
        ext_fn, dextm_fn, dextu_fn, dext_fn,
        ins_fn, dinsm_fn, dinsu_fn, dins_fn,
        bshfl_fn = 0x20,
        dbshfl_fn = 0x24,
        rdhwr_fn = 0x3b
    };

    // sa field for spec3 opcodes, with BSHFL function
    enum func_spec3_bshfl {
        wsbh_fn = 0x02,
        seb_fn = 0x10,
        seh_fn = 0x18
    };

    // rt field of regimm opcodes.
    enum regimm_fn {
        bltz_fn, bgez_fn, bltzl_fn, bgezl_fn,
        rsrv_ri_fn4, rsrv_ri_fn5, rsrv_ri_fn6, rsrv_ri_fn7,
        tgei_fn, tgeiu_fn, tlti_fn, tltiu_fn,
        teqi_fn, rsrv_ri_fn_0d, tnei_fn, rsrv_ri_fn0f,
        bltzal_fn, bgezal_fn, bltzall_fn, bgezall_fn,
        bposge32_fn= 0x1c,
        synci_fn = 0x1f
    };


    // func field for mad opcodes (MIPS IV).
    enum mad_func {
        madd_fp_op      = 0x08, msub_fp_op      = 0x0a,
        nmadd_fp_op     = 0x0c, nmsub_fp_op     = 0x0e
    };


    enum mips_inst_shifts {
        OP_SHF       = 26,
        JTARGET_SHF  = 0,
        RS_SHF       = 21,
        RT_SHF       = 16,
        RD_SHF       = 11,
        RE_SHF       = 6,
        SA_SHF       = RE_SHF,  // synonym
        IMM_SHF      = 0,
        FUNC_SHF     = 0,

        // mask values
        MSK_16       = 0xffff,


        CACHEOP_SHF  = 18,
        CACHESEL_SHF = 16,
    };
};

enum mips_regnames {
    R_zero = 0,
            R_at,   R_v0,   R_v1,   R_a0,   R_a1,   R_a2,   R_a3,
#if __mips_isa_rev < 6
    R_t0,   R_t1,   R_t2,   R_t3,   R_t4,   R_t5,   R_t6,   R_t7,
#else
    R_a4,   R_a5,   R_a6,   R_a7,   R_t0,   R_t1,   R_t2,   R_t3,
#endif
    R_s0,   R_s1,   R_s2,   R_s3,   R_s4,   R_s5,   R_s6,   R_s7,
    R_t8,   R_t9,   R_k0,   R_k1,   R_gp,   R_sp,   R_s8,   R_ra,
    R_lr = R_s8,

    // arm regs 0-15 are mips regs 2-17 (meaning s0 & s1 are used)
    R_at2  = R_s2,    // R_at2 = 18 = s2
    R_cmp  = R_s3,    // R_cmp = 19 = s3
    R_cmp2 = R_s4     // R_cmp2 = 20 = s4
};



}; // namespace android

#endif //ANDROID_MIPSASSEMBLER_H
