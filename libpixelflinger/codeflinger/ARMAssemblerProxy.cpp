/* libs/pixelflinger/codeflinger/ARMAssemblerProxy.cpp
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


#include <stdint.h>
#include <sys/types.h>

#include "codeflinger/ARMAssemblerProxy.h"

namespace android {

// ----------------------------------------------------------------------------

ARMAssemblerProxy::ARMAssemblerProxy()
    : mTarget(0)
{
}

ARMAssemblerProxy::ARMAssemblerProxy(ARMAssemblerInterface* target)
    : mTarget(target)
{
}

ARMAssemblerProxy::~ARMAssemblerProxy()
{
    delete mTarget;
}

void ARMAssemblerProxy::setTarget(ARMAssemblerInterface* target)
{
    delete mTarget;
    mTarget = target;
}

void ARMAssemblerProxy::reset() {
    mTarget->reset();
}
int ARMAssemblerProxy::generate(const char* name) {
    return mTarget->generate(name);
}
void ARMAssemblerProxy::disassemble(const char* name) {
    return mTarget->disassemble(name);
}
void ARMAssemblerProxy::prolog() {
    mTarget->prolog();
}
void ARMAssemblerProxy::epilog(uint32_t touched) {
    mTarget->epilog(touched);
}
void ARMAssemblerProxy::comment(const char* string) {
    mTarget->comment(string);
}


void ARMAssemblerProxy::dataProcessing( int opcode, int cc, int s,
                                        int Rd, int Rn, uint32_t Op2)
{
    mTarget->dataProcessing(opcode, cc, s, Rd, Rn, Op2);
}

void ARMAssemblerProxy::MLA(int cc, int s, int Rd, int Rm, int Rs, int Rn) {
    mTarget->MLA(cc, s, Rd, Rm, Rs, Rn);
}
void ARMAssemblerProxy::MUL(int cc, int s, int Rd, int Rm, int Rs) {
    mTarget->MUL(cc, s, Rd, Rm, Rs);
}
void ARMAssemblerProxy::UMULL(int cc, int s,
            int RdLo, int RdHi, int Rm, int Rs) {
    mTarget->UMULL(cc, s, RdLo, RdHi, Rm, Rs); 
}
void ARMAssemblerProxy::UMUAL(int cc, int s,
            int RdLo, int RdHi, int Rm, int Rs) {
    mTarget->UMUAL(cc, s, RdLo, RdHi, Rm, Rs); 
}
void ARMAssemblerProxy::SMULL(int cc, int s,
            int RdLo, int RdHi, int Rm, int Rs) {
    mTarget->SMULL(cc, s, RdLo, RdHi, Rm, Rs); 
}
void ARMAssemblerProxy::SMUAL(int cc, int s,
            int RdLo, int RdHi, int Rm, int Rs) {
    mTarget->SMUAL(cc, s, RdLo, RdHi, Rm, Rs); 
}

void ARMAssemblerProxy::B(int cc, uint32_t* pc) {
    mTarget->B(cc, pc); 
}
void ARMAssemblerProxy::BL(int cc, uint32_t* pc) {
    mTarget->BL(cc, pc); 
}
void ARMAssemblerProxy::BX(int cc, int Rn) {
    mTarget->BX(cc, Rn); 
}
void ARMAssemblerProxy::label(const char* theLabel) {
    mTarget->label(theLabel);
}
void ARMAssemblerProxy::B(int cc, const char* label) {
    mTarget->B(cc, label);
}
void ARMAssemblerProxy::BL(int cc, const char* label) {
    mTarget->BL(cc, label);
}

uint32_t* ARMAssemblerProxy::pcForLabel(const char* label) {
    return mTarget->pcForLabel(label);
}

void ARMAssemblerProxy::LDR(int cc, int Rd, int Rn, uint32_t offset) {
    mTarget->LDR(cc, Rd, Rn, offset);
}
void ARMAssemblerProxy::LDRB(int cc, int Rd, int Rn, uint32_t offset) {
    mTarget->LDRB(cc, Rd, Rn, offset);
}
void ARMAssemblerProxy::STR(int cc, int Rd, int Rn, uint32_t offset) {
    mTarget->STR(cc, Rd, Rn, offset);
}
void ARMAssemblerProxy::STRB(int cc, int Rd, int Rn, uint32_t offset) {
    mTarget->STRB(cc, Rd, Rn, offset);
}
void ARMAssemblerProxy::LDRH(int cc, int Rd, int Rn, uint32_t offset) {
    mTarget->LDRH(cc, Rd, Rn, offset);
}
void ARMAssemblerProxy::LDRSB(int cc, int Rd, int Rn, uint32_t offset) {
    mTarget->LDRSB(cc, Rd, Rn, offset);
}
void ARMAssemblerProxy::LDRSH(int cc, int Rd, int Rn, uint32_t offset) {
    mTarget->LDRSH(cc, Rd, Rn, offset);
}
void ARMAssemblerProxy::STRH(int cc, int Rd, int Rn, uint32_t offset) {
    mTarget->STRH(cc, Rd, Rn, offset);
}
void ARMAssemblerProxy::LDM(int cc, int dir, int Rn, int W, uint32_t reg_list) {
    mTarget->LDM(cc, dir, Rn, W, reg_list);
}
void ARMAssemblerProxy::STM(int cc, int dir, int Rn, int W, uint32_t reg_list) {
    mTarget->STM(cc, dir, Rn, W, reg_list);
}

void ARMAssemblerProxy::SWP(int cc, int Rn, int Rd, int Rm) {
    mTarget->SWP(cc, Rn, Rd, Rm);
}
void ARMAssemblerProxy::SWPB(int cc, int Rn, int Rd, int Rm) {
    mTarget->SWPB(cc, Rn, Rd, Rm);
}
void ARMAssemblerProxy::SWI(int cc, uint32_t comment) {
    mTarget->SWI(cc, comment);
}


void ARMAssemblerProxy::PLD(int Rn, uint32_t offset) {
    mTarget->PLD(Rn, offset);
}
void ARMAssemblerProxy::CLZ(int cc, int Rd, int Rm) {
    mTarget->CLZ(cc, Rd, Rm);
}
void ARMAssemblerProxy::QADD(int cc, int Rd, int Rm, int Rn) {
    mTarget->QADD(cc, Rd, Rm, Rn);
}
void ARMAssemblerProxy::QDADD(int cc, int Rd, int Rm, int Rn) {
    mTarget->QDADD(cc, Rd, Rm, Rn);
}
void ARMAssemblerProxy::QSUB(int cc, int Rd, int Rm, int Rn) {
    mTarget->QSUB(cc, Rd, Rm, Rn);
}
void ARMAssemblerProxy::QDSUB(int cc, int Rd, int Rm, int Rn) {
    mTarget->QDSUB(cc, Rd, Rm, Rn);
}
void ARMAssemblerProxy::SMUL(int cc, int xy, int Rd, int Rm, int Rs) {
    mTarget->SMUL(cc, xy, Rd, Rm, Rs);
}
void ARMAssemblerProxy::SMULW(int cc, int y, int Rd, int Rm, int Rs) {
    mTarget->SMULW(cc, y, Rd, Rm, Rs);
}
void ARMAssemblerProxy::SMLA(int cc, int xy, int Rd, int Rm, int Rs, int Rn) {
    mTarget->SMLA(cc, xy, Rd, Rm, Rs, Rn);
}
void ARMAssemblerProxy::SMLAL(  int cc, int xy,
                                int RdHi, int RdLo, int Rs, int Rm) {
    mTarget->SMLAL(cc, xy, RdHi, RdLo, Rs, Rm);
}
void ARMAssemblerProxy::SMLAW(int cc, int y, int Rd, int Rm, int Rs, int Rn) {
    mTarget->SMLAW(cc, y, Rd, Rm, Rs, Rn);
}

void ARMAssemblerProxy::UXTB16(int cc, int Rd, int Rm, int rotate) {
    mTarget->UXTB16(cc, Rd, Rm, rotate);
}

void ARMAssemblerProxy::UBFX(int cc, int Rd, int Rn, int lsb, int width) {
    mTarget->UBFX(cc, Rd, Rn, lsb, width);
}

}; // namespace android

