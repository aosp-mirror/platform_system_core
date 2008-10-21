/* libs/pixelflinger/codeflinger/ARMAssemblerInterface.cpp
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


#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>

#include <cutils/log.h>
#include "codeflinger/ARMAssemblerInterface.h"

namespace android {

// ----------------------------------------------------------------------------

ARMAssemblerInterface::~ARMAssemblerInterface()
{
}

int ARMAssemblerInterface::buildImmediate(
        uint32_t immediate, uint32_t& rot, uint32_t& imm)
{
    rot = 0;
    imm = immediate;
    if (imm > 0x7F) { // skip the easy cases
        while (!(imm&3)  || (imm&0xFC000000)) {
            uint32_t newval;
            newval = imm >> 2;
            newval |= (imm&3) << 30;
            imm = newval;
            rot += 2;
            if (rot == 32) {
                rot = 0;
                break;
            }
        }
    }
    rot = (16 - (rot>>1)) & 0xF;

    if (imm>=0x100)
        return -EINVAL;

    if (((imm>>(rot<<1)) | (imm<<(32-(rot<<1)))) != immediate)
        return -1;

    return 0;
}

// shifters...

bool ARMAssemblerInterface::isValidImmediate(uint32_t immediate)
{
    uint32_t rot, imm;
    return buildImmediate(immediate, rot, imm) == 0;
}

uint32_t ARMAssemblerInterface::imm(uint32_t immediate)
{
    uint32_t rot, imm;
    int err = buildImmediate(immediate, rot, imm);

    LOG_ALWAYS_FATAL_IF(err==-EINVAL,
                        "immediate %08x cannot be encoded",
                        immediate);

    LOG_ALWAYS_FATAL_IF(err,
                        "immediate (%08x) encoding bogus!",
                        immediate);

    return (1<<25) | (rot<<8) | imm;
}

uint32_t ARMAssemblerInterface::reg_imm(int Rm, int type, uint32_t shift)
{
    return ((shift&0x1F)<<7) | ((type&0x3)<<5) | (Rm&0xF);
}

uint32_t ARMAssemblerInterface::reg_rrx(int Rm)
{
    return (ROR<<5) | (Rm&0xF);
}

uint32_t ARMAssemblerInterface::reg_reg(int Rm, int type, int Rs)
{
    return ((Rs&0xF)<<8) | ((type&0x3)<<5) | (1<<4) | (Rm&0xF);
}

// addressing modes... 
// LDR(B)/STR(B)/PLD (immediate and Rm can be negative, which indicate U=0)
uint32_t ARMAssemblerInterface::immed12_pre(int32_t immed12, int W)
{
    LOG_ALWAYS_FATAL_IF(abs(immed12) >= 0x800,
                        "LDR(B)/STR(B)/PLD immediate too big (%08x)",
                        immed12);
    return (1<<24) | (((uint32_t(immed12)>>31)^1)<<23) |
            ((W&1)<<21) | (abs(immed12)&0x7FF);
}

uint32_t ARMAssemblerInterface::immed12_post(int32_t immed12)
{
    LOG_ALWAYS_FATAL_IF(abs(immed12) >= 0x800,
                        "LDR(B)/STR(B)/PLD immediate too big (%08x)",
                        immed12);

    return (((uint32_t(immed12)>>31)^1)<<23) | (abs(immed12)&0x7FF);
}

uint32_t ARMAssemblerInterface::reg_scale_pre(int Rm, int type, 
        uint32_t shift, int W)
{
    return  (1<<25) | (1<<24) | 
            (((uint32_t(Rm)>>31)^1)<<23) | ((W&1)<<21) |
            reg_imm(abs(Rm), type, shift);
}

uint32_t ARMAssemblerInterface::reg_scale_post(int Rm, int type, uint32_t shift)
{
    return (1<<25) | (((uint32_t(Rm)>>31)^1)<<23) | reg_imm(abs(Rm), type, shift);
}

// LDRH/LDRSB/LDRSH/STRH (immediate and Rm can be negative, which indicate U=0)
uint32_t ARMAssemblerInterface::immed8_pre(int32_t immed8, int W)
{
    uint32_t offset = abs(immed8);

    LOG_ALWAYS_FATAL_IF(abs(immed8) >= 0x100,
                        "LDRH/LDRSB/LDRSH/STRH immediate too big (%08x)",
                        immed8);

    return  (1<<24) | (1<<22) | (((uint32_t(immed8)>>31)^1)<<23) |
            ((W&1)<<21) | (((offset&0xF0)<<4)|(offset&0xF));
}

uint32_t ARMAssemblerInterface::immed8_post(int32_t immed8)
{
    uint32_t offset = abs(immed8);

    LOG_ALWAYS_FATAL_IF(abs(immed8) >= 0x100,
                        "LDRH/LDRSB/LDRSH/STRH immediate too big (%08x)",
                        immed8);

    return (1<<22) | (((uint32_t(immed8)>>31)^1)<<23) |
            (((offset&0xF0)<<4) | (offset&0xF));
}

uint32_t ARMAssemblerInterface::reg_pre(int Rm, int W)
{
    return (1<<24) | (((uint32_t(Rm)>>31)^1)<<23) | ((W&1)<<21) | (abs(Rm)&0xF);
}

uint32_t ARMAssemblerInterface::reg_post(int Rm)
{
    return (((uint32_t(Rm)>>31)^1)<<23) | (abs(Rm)&0xF);
}


}; // namespace android

