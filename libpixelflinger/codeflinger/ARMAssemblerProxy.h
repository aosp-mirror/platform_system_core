/* libs/pixelflinger/codeflinger/ARMAssemblerProxy.h
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


#ifndef ANDROID_ARMASSEMBLER_PROXY_H
#define ANDROID_ARMASSEMBLER_PROXY_H

#include <stdint.h>
#include <sys/types.h>

#include "codeflinger/ARMAssemblerInterface.h"

namespace android {

// ----------------------------------------------------------------------------

class ARMAssemblerProxy : public ARMAssemblerInterface
{
public:
    // ARMAssemblerProxy take ownership of the target

                ARMAssemblerProxy();
                ARMAssemblerProxy(ARMAssemblerInterface* target);
    virtual     ~ARMAssemblerProxy();

    void setTarget(ARMAssemblerInterface* target);

    virtual void    reset();
    virtual int     generate(const char* name);
    virtual void    disassemble(const char* name);

    virtual void    prolog();
    virtual void    epilog(uint32_t touched);
    virtual void    comment(const char* string);

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

    uint32_t* pcForLabel(const char* label);

    virtual void LDR (int cc, int Rd,
                int Rn, uint32_t offset = immed12_pre(0));
    virtual void LDRB(int cc, int Rd,
                int Rn, uint32_t offset = immed12_pre(0));
    virtual void STR (int cc, int Rd,
                int Rn, uint32_t offset = immed12_pre(0));
    virtual void STRB(int cc, int Rd,
                int Rn, uint32_t offset = immed12_pre(0));
    virtual void LDRH (int cc, int Rd,
                int Rn, uint32_t offset = immed8_pre(0));
    virtual void LDRSB(int cc, int Rd, 
                int Rn, uint32_t offset = immed8_pre(0));
    virtual void LDRSH(int cc, int Rd,
                int Rn, uint32_t offset = immed8_pre(0));
    virtual void STRH (int cc, int Rd,
                int Rn, uint32_t offset = immed8_pre(0));
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

private:
    ARMAssemblerInterface*  mTarget;
};

}; // namespace android

#endif //ANDROID_ARMASSEMBLER_PROXY_H
