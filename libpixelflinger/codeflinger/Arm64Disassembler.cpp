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

#include <stdio.h>
#include <inttypes.h>
#include <string.h>

struct disasm_table_entry_t
{
    uint32_t       mask;
    uint32_t       value;
    const char*    instr_template;
};


static disasm_table_entry_t disasm_table[] =
{
    {0xff000000, 0x91000000, "add <xd|sp>, <xn|sp>, #<imm1>, <shift1>"},
    {0xff000000, 0xd1000000, "sub <xd|sp>, <xn|sp>, #<imm1>, <shift1>"},
    {0xff200000, 0x8b000000, "add <xd>, <xn>, <xm>, <shift2> #<amt1>"},
    {0xff200000, 0x0b000000, "add <wd>, <wn>, <wm>, <shift2> #<amt1>"},
    {0xff200000, 0x4b000000, "sub <wd>, <wn>, <wm>, <shift2> #<amt1>"},
    {0xff200000, 0x6b000000, "subs <wd>, <wn>, <wm>, <shift2> #<amt1>"},
    {0xff200000, 0x0a000000, "and <wd>, <wn>, <wm>, <shift2> #<amt1>"},
    {0xff200000, 0x2a000000, "orr <wd>, <wn>, <wm>, <shift2> #<amt1>"},
    {0xff200000, 0x2a200000, "orn <wd>, <wn>, <wm>, <shift2> #<amt1>"},
    {0xff800000, 0x72800000, "movk <wd>, #<imm2>, lsl #<shift3>"},
    {0xff800000, 0x52800000, "movz <wd>, #<imm2>, lsl #<shift3>"},
    {0xff800000, 0xd2800000, "movz <xd>, #<imm2>, lsl #<shift3>"},
    {0xffe00c00, 0x1a800000, "csel <wd>, <wn>, <wm>, <cond1>"},
    {0xffe00c00, 0x9a800000, "csel <xd>, <xn>, <xm>, <cond1>"},
    {0xffe00c00, 0x5a800000, "csinv <wd>, <wn>, <wm>, <cond1>"},
    {0xffe08000, 0x1b000000, "madd <wd>, <wn>, <wm>, <wa>"},
    {0xffe08000, 0x9b200000, "smaddl <xd>, <wn>, <wm>, <xa>"},
    {0xffe04c00, 0xb8604800, "ldr <wt>, [<xn|sp>, <r1><m1>, <ext1> #<amt2>]"},
    {0xffe04c00, 0xb8204800, "str <wt>, [<xn|sp>, <r1><m1>, <ext1> #<amt2>]"},
    {0xffe04c00, 0xf8604800, "ldr <xt>, [<xn|sp>, <r1><m1>, <ext1> #<amt3>]"},
    {0xffe04c00, 0xf8204800, "str <xt>, [<xn|sp>, <r1><m1>, <ext1> #<amt3>]"},
    {0xffe04c00, 0x38604800, "ldrb <wt>, [<xn|sp>, <r1><m1>, <ext1> <amt5>]"},
    {0xffe04c00, 0x38204800, "strb <wt>, [<xn|sp>, <r1><m1>, <ext1> <amt5>]"},
    {0xffe04c00, 0x78604800, "ldrh <wt>, [<xn|sp>, <r1><m1>, <ext1> #<amt6>]"},
    {0xffe04c00, 0x78204800, "strh <wt>, [<xn|sp>, <r1><m1>, <ext1> #<amt6>]"},
    {0xffe00c00, 0xb8400400, "ldr <wt>, [<xn|sp>], #<simm1>"},
    {0xffe00c00, 0xb8000c00, "str <wt>, [<xn|sp>, #<simm1>]!"},
    {0xffc00000, 0x13000000, "sbfm <wd>, <wn>, #<immr1>, #<imms1>"},
    {0xffc00000, 0x53000000, "ubfm <wd>, <wn>, #<immr1>, #<imms1>"},
    {0xffc00000, 0xd3400000, "ubfm <xd>, <xn>, #<immr1>, #<imms1>"},
    {0xffe00000, 0x13800000, "extr <wd>, <wn>, <wm>, #<lsb1>"},
    {0xff000000, 0x54000000, "b.<cond2> <label1>"},
    {0xfffffc1f, 0xd65f0000, "ret <xn>"},
    {0xffe00000, 0x8b200000, "add <xd|sp>, <xn|sp>, <r2><m1>, <ext2> #<amt4>"},
    {0xffe00000, 0xcb200000, "sub <xd|sp>, <xn|sp>, <r2><m1>, <ext2> #<amt4>"}
};

static int32_t bits_signed(uint32_t instr, uint32_t msb, uint32_t lsb)
{
    int32_t value;
    value   = ((int32_t)instr) << (31 - msb);
    value >>= (31 - msb);
    value >>= lsb;
    return value;
}
static uint32_t bits_unsigned(uint32_t instr, uint32_t msb, uint32_t lsb)
{
    uint32_t width = msb - lsb + 1;
    uint32_t mask  = (1 << width) - 1;
    return ((instr >> lsb) & mask);
}

static void get_token(const char *instr, uint32_t index, char *token)
{
    uint32_t i, j;
    for(i = index, j = 0; i < strlen(instr); ++i)
    {
        if(instr[index] == '<' && instr[i] == '>')
        {
            token[j++] = instr[i];
            break;
        }
        else if(instr[index] != '<' && instr[i] == '<')
        {
            break;
        }
        else
        {
            token[j++] = instr[i];
        }
    }
    token[j] = '\0';
    return;
}


static const char * token_cc_table[] =
{
    "eq", "ne", "cs", "cc", "mi",
    "pl", "vs", "vc", "hi", "ls",
    "ge", "lt", "gt", "le", "al", "nv"
};

static void decode_rx_zr_token(uint32_t reg, const char *prefix, char *instr_part)
{
    if(reg == 31)
        sprintf(instr_part, "%s%s", prefix, "zr");
    else
        sprintf(instr_part, "%s%d", prefix, reg);
}

static void decode_token(uint32_t code, char *token, char *instr_part)
{
    if(strcmp(token, "<imm1>") == 0)
        sprintf(instr_part, "0x%x", bits_unsigned(code, 21,10));
    else if(strcmp(token, "<imm2>") == 0)
        sprintf(instr_part, "0x%x", bits_unsigned(code, 20,5));
    else if(strcmp(token, "<shift1>") == 0)
        sprintf(instr_part, "lsl #%d", bits_unsigned(code, 23,22) * 12);
    else if(strcmp(token, "<shift2>") == 0)
    {
        static const char * shift2_table[] = { "lsl", "lsr", "asr", "ror"};
        sprintf(instr_part, "%s", shift2_table[bits_unsigned(code, 23,22)]);
    }
    else if(strcmp(token, "<shift3>") == 0)
        sprintf(instr_part, "%d", bits_unsigned(code, 22,21) * 16);
    else if(strcmp(token, "<amt1>") == 0)
        sprintf(instr_part, "%d", bits_unsigned(code, 15,10));
    else if(strcmp(token, "<amt2>") == 0)
        sprintf(instr_part, "%d", bits_unsigned(code, 12,12) * 2);
    else if(strcmp(token, "<amt3>") == 0)
        sprintf(instr_part, "%d", bits_unsigned(code, 12,12) * 3);
    else if(strcmp(token, "<amt4>") == 0)
        sprintf(instr_part, "%d", bits_unsigned(code, 12,10));
    else if(strcmp(token, "<amt5>") == 0)
    {
        static const char * amt5_table[] = {"", "#0"};
        sprintf(instr_part, "%s", amt5_table[bits_unsigned(code, 12,12)]);
    }
    else if(strcmp(token, "<amt6>") == 0)
        sprintf(instr_part, "%d", bits_unsigned(code, 12,12));
    else if(strcmp(token, "<simm1>") == 0)
        sprintf(instr_part, "%d", bits_signed(code, 20,12));
    else if(strcmp(token, "<immr1>") == 0)
        sprintf(instr_part, "%d", bits_unsigned(code, 21,16));
    else if(strcmp(token, "<imms1>") == 0)
        sprintf(instr_part, "%d", bits_unsigned(code, 15,10));
    else if(strcmp(token, "<lsb1>") == 0)
        sprintf(instr_part, "%d", bits_unsigned(code, 15,10));
    else if(strcmp(token, "<cond1>") == 0)
        sprintf(instr_part, "%s", token_cc_table[bits_unsigned(code, 15,12)]);
    else if(strcmp(token, "<cond2>") == 0)
        sprintf(instr_part, "%s", token_cc_table[bits_unsigned(code, 4,0)]);
    else if(strcmp(token, "<r1>") == 0)
    {
        const char * token_r1_table[] =
        {
            "reserved", "reserved", "w", "x",
            "reserved", "reserved", "w", "x"
        };
        sprintf(instr_part, "%s", token_r1_table[bits_unsigned(code, 15,13)]);
    }
    else if(strcmp(token, "<r2>") == 0)
    {
        static const char * token_r2_table[] =
        {
                "w","w","w", "x", "w", "w", "w", "x"
        };
        sprintf(instr_part, "%s", token_r2_table[bits_unsigned(code, 15,13)]);
    }
    else if(strcmp(token, "<m1>") == 0)
    {
        uint32_t reg = bits_unsigned(code, 20,16);
        if(reg == 31)
            sprintf(instr_part, "%s", "zr");
        else
            sprintf(instr_part, "%d", reg);
    }
    else if(strcmp(token, "<ext1>") == 0)
    {
        static const char * token_ext1_table[] =
        {
             "reserved","reserved","uxtw", "lsl",
             "reserved","reserved", "sxtw", "sxtx"
        };
        sprintf(instr_part, "%s", token_ext1_table[bits_unsigned(code, 15,13)]);
    }
    else if(strcmp(token, "<ext2>") == 0)
    {
        static const char * token_ext2_table[] =
        {
                "uxtb","uxth","uxtw","uxtx",
                "sxtb","sxth","sxtw","sxtx"
        };
        sprintf(instr_part, "%s", token_ext2_table[bits_unsigned(code, 15,13)]);
    }
    else if (strcmp(token, "<label1>") == 0)
    {
        int32_t offset = bits_signed(code, 23,5) * 4;
        if(offset > 0)
            sprintf(instr_part, "#.+%d", offset);
        else
            sprintf(instr_part, "#.-%d", -offset);
    }
    else if (strcmp(token, "<xn|sp>") == 0)
    {
        uint32_t reg = bits_unsigned(code, 9, 5);
        if(reg == 31)
            sprintf(instr_part, "%s", "sp");
        else
            sprintf(instr_part, "x%d", reg);
    }
    else if (strcmp(token, "<xd|sp>") == 0)
    {
        uint32_t reg = bits_unsigned(code, 4, 0);
        if(reg == 31)
            sprintf(instr_part, "%s", "sp");
        else
            sprintf(instr_part, "x%d", reg);
    }
    else if (strcmp(token, "<xn>") == 0)
        decode_rx_zr_token(bits_unsigned(code, 9, 5), "x", instr_part);
    else if (strcmp(token, "<xd>") == 0)
        decode_rx_zr_token(bits_unsigned(code, 4, 0), "x", instr_part);
    else if (strcmp(token, "<xm>") == 0)
        decode_rx_zr_token(bits_unsigned(code, 20, 16), "x", instr_part);
    else if (strcmp(token, "<xa>") == 0)
        decode_rx_zr_token(bits_unsigned(code, 14, 10), "x", instr_part);
    else if (strcmp(token, "<xt>") == 0)
        decode_rx_zr_token(bits_unsigned(code, 4, 0), "x", instr_part);
    else if (strcmp(token, "<wn>") == 0)
        decode_rx_zr_token(bits_unsigned(code, 9, 5), "w", instr_part);
    else if (strcmp(token, "<wd>") == 0)
        decode_rx_zr_token(bits_unsigned(code, 4, 0), "w", instr_part);
    else if (strcmp(token, "<wm>") == 0)
        decode_rx_zr_token(bits_unsigned(code, 20, 16), "w", instr_part);
    else if (strcmp(token, "<wa>") == 0)
        decode_rx_zr_token(bits_unsigned(code, 14, 10), "w", instr_part);
    else if (strcmp(token, "<wt>") == 0)
        decode_rx_zr_token(bits_unsigned(code, 4, 0), "w", instr_part);
    else
    {
        sprintf(instr_part, "error");
    }
    return;
}

int arm64_disassemble(uint32_t code, char* instr)
{
    uint32_t i;
    char token[256];
    char instr_part[256];

    if(instr == NULL)
        return -1;

    bool matched = false;
    disasm_table_entry_t *entry = NULL;
    for(i = 0; i < sizeof(disasm_table)/sizeof(disasm_table_entry_t); ++i)
    {
        entry = &disasm_table[i];
        if((code & entry->mask) == entry->value)
        {
            matched = true;
            break;
        }
    }
    if(matched == false)
    {
        strcpy(instr, "Unknown Instruction");
        return -1;
    }
    else
    {
        uint32_t index = 0;
        uint32_t length = strlen(entry->instr_template);
        instr[0] = '\0';
        do
        {
            get_token(entry->instr_template, index, token);
            if(token[0] == '<')
            {
                decode_token(code, token, instr_part);
                strcat(instr, instr_part);
            }
            else
            {
                strcat(instr, token);
            }
            index += strlen(token);
        }while(index < length);
        return 0;
    }
}
