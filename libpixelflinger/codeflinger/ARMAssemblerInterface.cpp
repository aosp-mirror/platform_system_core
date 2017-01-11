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
#define LOG_TAG "pixelflinger-code"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>

#include <log/log.h>

#include "ARMAssemblerInterface.h"

namespace android {

// ----------------------------------------------------------------------------

ARMAssemblerInterface::~ARMAssemblerInterface()
{
}

// --------------------------------------------------------------------

// The following two functions are static and used for initializers
// in the original ARM code. The above versions (without __), are now
// virtual, and can be overridden in the MIPS code. But since these are
// needed at initialization time, they must be static. Not thrilled with
// this implementation, but it works...

uint32_t ARMAssemblerInterface::__immed12_pre(int32_t immed12, int W)
{
    LOG_ALWAYS_FATAL_IF(abs(immed12) >= 0x800,
                        "LDR(B)/STR(B)/PLD immediate too big (%08x)",
                        immed12);
    return (1<<24) | (((uint32_t(immed12)>>31)^1)<<23) |
            ((W&1)<<21) | (abs(immed12)&0x7FF);
}

uint32_t ARMAssemblerInterface::__immed8_pre(int32_t immed8, int W)
{
    uint32_t offset = abs(immed8);

    LOG_ALWAYS_FATAL_IF(abs(immed8) >= 0x100,
                        "LDRH/LDRSB/LDRSH/STRH immediate too big (%08x)",
                        immed8);

    return  (1<<24) | (1<<22) | (((uint32_t(immed8)>>31)^1)<<23) |
            ((W&1)<<21) | (((offset&0xF0)<<4)|(offset&0xF));
}

// The following four functions are required for address manipulation
// These are virtual functions, which can be overridden by architectures
// that need special handling of address values (e.g. 64-bit arch)

void ARMAssemblerInterface::ADDR_LDR(int cc, int Rd,
     int Rn, uint32_t offset)
{
    LDR(cc, Rd, Rn, offset);
}
void ARMAssemblerInterface::ADDR_STR(int cc, int Rd,
     int Rn, uint32_t offset)
{
    STR(cc, Rd, Rn, offset);
}
void ARMAssemblerInterface::ADDR_ADD(int cc, int s,
     int Rd, int Rn, uint32_t Op2)
{
    dataProcessing(opADD, cc, s, Rd, Rn, Op2);
}
void ARMAssemblerInterface::ADDR_SUB(int cc, int s,
     int Rd, int Rn, uint32_t Op2)
{
    dataProcessing(opSUB, cc, s, Rd, Rn, Op2);
}
}; // namespace android

