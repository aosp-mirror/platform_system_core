/* libs/pixelflinger/codeflinger/MIPS64Assembler.h
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

#ifndef ANDROID_MIPS64ASSEMBLER_H
#define ANDROID_MIPS64ASSEMBLER_H

#include <stdint.h>
#include <sys/types.h>

#include "utils/KeyedVector.h"
#include "utils/Vector.h"
#include "tinyutils/smartpointer.h"

#include "ARMAssemblerInterface.h"
#include "MIPSAssembler.h"
#include "CodeCache.h"

namespace android {

class MIPS64Assembler;    // forward reference

// this class mimics ARMAssembler interface
// intent is to translate each ARM instruction to 1 or more MIPS instr
// implementation calls MIPS64Assembler class to generate mips code
class ArmToMips64Assembler : public ARMAssemblerInterface
{
public:
                ArmToMips64Assembler(const sp<Assembly>& assembly,
                        char *abuf = 0, int linesz = 0, int instr_count = 0);
                ArmToMips64Assembler(void* assembly);
    virtual     ~ArmToMips64Assembler();

    uint32_t*   base() const;
    uint32_t*   pc() const;
    void        disassemble(const char* name);

    virtual void    reset();

    virtual int     generate(const char* name);
    virtual int     getCodegenArch();

    virtual void    prolog();
    virtual void    epilog(uint32_t touched);
    virtual void    comment(const char* string);
    // for testing purposes
    void        fix_branches();
    void        set_condition(int mode, int R1, int R2);


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

    // Address loading/storing/manipulation
    virtual void ADDR_LDR(int cc, int Rd, int Rn, uint32_t offset = __immed12_pre(0));
    virtual void ADDR_STR(int cc, int Rd, int Rn, uint32_t offset = __immed12_pre(0));
    virtual void ADDR_ADD(int cc, int s, int Rd, int Rn, uint32_t Op2);
    virtual void ADDR_SUB(int cc, int s, int Rd, int Rn, uint32_t Op2);

    // this is some crap to share is MIPS64Assembler class for debug
    char *      mArmDisassemblyBuffer;
    int         mArmLineLength;
    int         mArmInstrCount;

    int         mInum;      // current arm instuction number (0..n)
    uint32_t**  mArmPC;     // array: PC for 1st mips instr of
                            //      each translated ARM instr


private:
    ArmToMips64Assembler(const ArmToMips64Assembler& rhs);
    ArmToMips64Assembler& operator = (const ArmToMips64Assembler& rhs);

    void init_conditional_labels(void);

    void protectConditionalOperands(int Rd);

    // reg__tmp set to MIPS AT, reg 1
    int dataProcAdrModes(int op, int& source, bool sign = false, int reg_tmp = 1);

    sp<Assembly>        mAssembly;
    MIPS64Assembler*    mMips;


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

// This is the basic MIPS64 assembler, which just creates the opcodes in memory.
// All the more complicated work is done in ArmToMips64Assember above.
// Inherits MIPSAssembler class, and overrides only MIPS64r6 specific stuff

class MIPS64Assembler : public MIPSAssembler
{
public:
                MIPS64Assembler(const sp<Assembly>& assembly, ArmToMips64Assembler *parent);
                MIPS64Assembler(void* assembly, ArmToMips64Assembler *parent);
    virtual     ~MIPS64Assembler();

    virtual void        reset();
    virtual void        disassemble(const char* name);

    void        fix_branches();

    // ------------------------------------------------------------------------
    // MIPS64AssemblerInterface...
    // ------------------------------------------------------------------------

#if 0
#pragma mark -
#pragma mark Arithmetic...
#endif

    void DADDU(int Rd, int Rs, int Rt);
    void DADDIU(int Rt, int Rs, int16_t imm);
    void DSUBU(int Rd, int Rs, int Rt);
    void DSUBIU(int Rt, int Rs, int16_t imm);
    virtual void MUL(int Rd, int Rs, int Rt);
    void MUH(int Rd, int Rs, int Rt);

#if 0
#pragma mark -
#pragma mark Logical...
#endif

    virtual void CLO(int Rd, int Rs);
    virtual void CLZ(int Rd, int Rs);

#if 0
#pragma mark -
#pragma mark Load/store...
#endif

    void LD(int Rt, int Rbase, int16_t offset);
    void SD(int Rt, int Rbase, int16_t offset);
    virtual void LUI(int Rt, int16_t offset);

#if 0
#pragma mark -
#pragma mark Branch...
#endif

    void JR(int Rs);


protected:
    ArmToMips64Assembler *mParent;

    // opcode field of all instructions
    enum opcode_field {
        spec_op, regimm_op, j_op, jal_op,                  // 0x00 - 0x03
        beq_op, bne_op, pop06_op, pop07_op,                // 0x04 - 0x07
        pop10_op, addiu_op, slti_op, sltiu_op,             // 0x08 - 0x0b
        andi_op, ori_op, xori_op, aui_op,                  // 0x0c - 0x0f
        cop0_op, cop1_op, cop2_op, rsrv_opc_0,             // 0x10 - 0x13
        rsrv_opc_1, rsrv_opc_2, pop26_op, pop27_op,        // 0x14 - 0x17
        pop30_op, daddiu_op, rsrv_opc_3, rsrv_opc_4,       // 0x18 - 0x1b
        rsrv_opc_5, daui_op, msa_op, spec3_op,             // 0x1c - 0x1f
        lb_op, lh_op, rsrv_opc_6, lw_op,                   // 0x20 - 0x23
        lbu_op, lhu_op, rsrv_opc_7, lwu_op,                // 0x24 - 0x27
        sb_op, sh_op, rsrv_opc_8, sw_op,                   // 0x28 - 0x2b
        rsrv_opc_9, rsrv_opc_10, rsrv_opc_11, rsrv_opc_12, // 0x2c - 0x2f
        rsrv_opc_13, lwc1_op, bc_op, rsrv_opc_14,          // 0x2c - 0x2f
        rsrv_opc_15, ldc1_op, pop66_op, ld_op,             // 0x30 - 0x33
        rsrv_opc_16, swc1_op, balc_op, pcrel_op,           // 0x34 - 0x37
        rsrv_opc_17, sdc1_op, pop76_op, sd_op              // 0x38 - 0x3b
    };


    // func field for special opcode
    enum func_spec_op {
        sll_fn, rsrv_spec_0, srl_fn, sra_fn,
        sllv_fn, lsa_fn, srlv_fn, srav_fn,
        rsrv_spec_1, jalr_fn, rsrv_spec_2, rsrv_spec_3,
        syscall_fn, break_fn, sdbbp_fn, sync_fn,
        clz_fn, clo_fn, dclz_fn, dclo_fn,
        dsllv_fn, dlsa_fn, dsrlv_fn, dsrav_fn,
        sop30_fn, sop31_fn, sop32_fn, sop33_fn,
        sop34_fn, sop35_fn, sop36_fn, sop37_fn,
        add_fn, addu_fn, sub_fn, subu_fn,
        and_fn, or_fn, xor_fn, nor_fn,
        rsrv_spec_4, rsrv_spec_5, slt_fn, sltu_fn,
        dadd_fn, daddu_fn, dsub_fn, dsubu_fn,
        tge_fn, tgeu_fn, tlt_fn, tltu_fn,
        teq_fn, seleqz_fn, tne_fn, selnez_fn,
        dsll_fn, rsrv_spec_6, dsrl_fn, dsra_fn,
        dsll32_fn, rsrv_spec_7, dsrl32_fn, dsra32_fn
    };

    // func field for spec3 opcode
    enum func_spec3_op {
        ext_fn, dextm_fn, dextu_fn, dext_fn,
        ins_fn, dinsm_fn, dinsu_fn, dins_fn,
        cachee_fn = 0x1b, sbe_fn, she_fn, sce_fn, swe_fn,
        bshfl_fn, prefe_fn = 0x23, dbshfl_fn, cache_fn, sc_fn, scd_fn,
        lbue_fn, lhue_fn, lbe_fn = 0x2c, lhe_fn, lle_fn, lwe_fn,
        pref_fn = 0x35, ll_fn, lld_fn, rdhwr_fn = 0x3b
    };

    // sa field for spec3 opcodes, with BSHFL function
    enum func_spec3_bshfl {
        bitswap_fn,
        wsbh_fn = 0x02,
        dshd_fn = 0x05,
        seb_fn = 0x10,
        seh_fn = 0x18
    };

    // rt field of regimm opcodes.
    enum regimm_fn {
        bltz_fn, bgez_fn,
        dahi_fn = 0x6,
        nal_fn = 0x10, bal_fn, bltzall_fn, bgezall_fn,
        sigrie_fn = 0x17,
        dati_fn = 0x1e, synci_fn
    };

    enum muldiv_fn {
        mul_fn = 0x02, muh_fn
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


}; // namespace android

#endif //ANDROID_MIPS64ASSEMBLER_H
