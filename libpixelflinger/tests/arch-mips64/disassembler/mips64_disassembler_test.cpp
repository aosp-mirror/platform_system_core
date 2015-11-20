/*
 * Copyright (C) 2015 The Android Open Source Project
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
#include "../../../codeflinger/mips64_disassem.h"

//typedef uint64_t db_addr_t;
//db_addr_t mips_disassem(db_addr_t loc, char *di_buffer, int alt_format);

struct test_table_entry_t
{
     uint32_t code;
     const char *instr;
};

static test_table_entry_t test_table [] =
{
    { 0x00011020, "add\tv0,zero,at"     },
    { 0x00832820, "add\ta1,a0,v1"       },
    { 0x00c74020, "add\ta4,a2,a3"       },
    { 0x012a5820, "add\ta7,a5,a6"       },
    { 0x258dffff, "addiu\tt1,t0,-1"     },
    { 0x25cf0004, "addiu\tt3,t2,4"      },
    { 0x02119021, "addu\ts2,s0,s1"      },
    { 0x0274a821, "addu\ts5,s3,s4"      },
    { 0x02d7c024, "and\tt8,s6,s7"       },
    { 0x333aff00, "andi\tk0,t9,0xff00"  },
    { 0x3f7cffff, "aui\tgp,k1,-1"       },
    { 0x3c1dffff, "lui\tsp,0xffff"      },
    { 0x00e04051, "clo\ta4,a3"          },
    { 0x01205050, "clz\ta6,a5"          },
    { 0x016c682c, "dadd\tt1,a7,t0"      },
    { 0x65cf0008, "daddiu\tt3,t2,8"     },
    { 0x0211902d, "daddu\ts2,s0,s1"     },
    { 0x7e741403, "dext\ts4,s3,16,3"    },
    { 0x7eb6f801, "dextm\ts6,s5,0,64"   },
    { 0x7ef87c02, "dextu\tt8,s7,48,16"  },
    { 0x7f3a8207, "dins\tk0,t9,8,9"     },
    { 0x7f7c0005, "dinsm\tgp,k1,0,33"   },
    { 0x7fbe0806, "dinsu\ts8,sp,32,2"   },
    { 0x03e1102e, "dsub\tv0,ra,at"      },
    { 0x0064282f, "dsubu\ta1,v1,a0"     },
    { 0x7cc77a00, "ext\ta3,a2,8,16"     },
    { 0x7d09fc04, "ins\ta5,a4,16,16"    },
    { 0x00200009, "jr\tat"              },
    { 0x00201009, "jalr\tv0,at"         },
    { 0x0020f809, "jalr\tat"            },
    { 0x8082fff0, "lb\tv0,-16(a0)"      },
    { 0x916c0008, "lbu\tt0,8(a7)"       },
    { 0xdfa3ffe8, "ld\tv1,-24(sp)"      },
    { 0x84850080, "lh\ta1,128(a0)"      },
    { 0x94c7ff80, "lhu\ta3,-128(a2)"    },
    { 0x8d09000c, "lw\ta5,12(a4)"       },
    { 0x9d4bfff4, "lwu\ta7,-12(a6)"     },
    { 0x00620898, "mul\tat,v1,v0"       },
    { 0x006208d8, "muh\tat,v1,v0"       },
    { 0x00620899, "mulu\tat,v1,v0"      },
    { 0x006208d9, "muhu\tat,v1,v0"      },
    { 0x00000000, "nop"                 },
    { 0x02329827, "nor\ts3,s1,s2"       },
    { 0x0295b025, "or\ts6,s4,s5"        },
    { 0x36f0ff00, "ori\ts0,s7,0xff00"   },
    { 0x7c03103b, "rdhwr\tv0,v1"        },
    { 0x00242a02, "rotr\ta1,a0,8"       },
    { 0x00c74046, "rotrv\ta4,a3,a2"     },
    { 0xa12afff0, "sb\ta6,-16(a5)"      },
    { 0xfd6c0100, "sd\tt0,256(a7)"      },
    { 0x7c0d7420, "seb\tt2,t1"          },
    { 0x7c0f8620, "seh\ts0,t3"          },
    { 0x02329835, "seleqz\ts3,s1,s2"    },
    { 0x0295b037, "selnez\ts6,s4,s5"    },
    { 0xa6f84000, "sh\tt8,16384(s7)"    },
    { 0x0019d100, "sll\tk0,t9,4"        },
    { 0x037ce804, "sllv\tsp,gp,k1"      },
    { 0x03df082a, "slt\tat,s8,ra"       },
    { 0x28430007, "slti\tv1,v0,7"       },
    { 0x2c850020, "sltiu\ta1,a0,32"     },
    { 0x00c7402b, "sltu\ta4,a2,a3"      },
    { 0x00095103, "sra\ta6,a5,4"        },
    { 0x016c6807, "srav\tt1,t0,a7"      },
    { 0x000e7a02, "srl\tt3,t2,8"        },
    { 0x02119006, "srlv\ts2,s1,s0"      },
    { 0x0274a822, "sub\ts5,s3,s4"       },
    { 0x02d7c023, "subu\tt8,s6,s7"      },
    { 0xaf3afffc, "sw\tk0,-4(t9)"       },
    { 0x7c1be0a0, "wsbh\tgp,k1"         },
    { 0x03bef826, "xor\tra,sp,s8"       },
    { 0x3801ffff, "li\tat,0xffff"       },
    { 0x3843ffff, "xori\tv1,v0,0xffff"  },
};

struct test_branches_table_entry_t
{
     uint32_t code;
     const char *instr;
     int16_t offset;
};

static test_branches_table_entry_t test_branches_table [] = {
    { 0x1000ffff, "b\t", static_cast<int16_t>(0xffff)         },
    { 0x13df0008, "beq\ts8,ra,", 0x8                          },
    { 0x042100ff, "bgez\tat,", 0xff                           },
    { 0x1c40ff00, "bgtz\tv0,", static_cast<int16_t>(0xff00)   },
    { 0x18605555, "blez\tv1,", 0x5555                         },
    { 0x0480aaaa, "bltz\ta0,", static_cast<int16_t>(0xaaaa)   },
    { 0x14a68888, "bne\ta1,a2,", static_cast<int16_t>(0x8888) },
};

struct test_jump_table_entry_t
{
     uint32_t code;
     const char *instr;
     int32_t offset;
};

static test_jump_table_entry_t test_jump_table [] = {
    { 0x0956ae66, "j\t", 0x156ae66          },
    { 0x0d56ae66, "jal\t", 0x156ae66        },
};

int main()
{
    char instr[256];
    uint32_t failed = 0;

    for(uint32_t i = 0; i < sizeof(test_table)/sizeof(test_table_entry_t); ++i)
    {
        test_table_entry_t *test;
        test = &test_table[i];
        mips_disassem(&test->code, instr, 0);
        if(strcmp(instr, test->instr) != 0)
        {
            printf("Test Failed \n"
                   "Code     : 0x%0x\n"
                   "Expected : %s\n"
                   "Actual   : %s\n", test->code, test->instr, instr);
            failed++;
        }
    }
    for(uint32_t i = 0; i < sizeof(test_branches_table)/sizeof(test_branches_table_entry_t); ++i)
    {
        test_branches_table_entry_t *test;
        test = &test_branches_table[i];
        mips_disassem(&test->code, instr, 0);
        //printf("DBG code address: %lx\n", (uint64_t)(&test->code));
        uint64_t loc = (uint64_t)test + 4 + (test->offset << 2);
        //printf("DBG loc: %lx\n", loc);
        char temp[256], address[16];
        strcpy(temp, test->instr);
        sprintf(address, "0x%lx", loc);
        strcat(temp, address);
        if(strcmp(instr, temp) != 0)
        {
            printf("Test Failed \n"
                   "Code     : 0x%0x\n"
                   "Expected : %s\n"
                   "Actual   : %s\n", test->code, temp, instr);
            failed++;
        }
    }
    for(uint32_t i = 0; i < sizeof(test_jump_table)/sizeof(test_jump_table_entry_t); ++i)
    {
        test_jump_table_entry_t *test;
        test = &test_jump_table[i];
        mips_disassem(&test->code, instr, 0);
        //printf("DBG code address: %lx\n", (uint64_t)(&test->code));
        uint64_t loc = ((uint64_t)test & 0xfffffffff0000000) | (test->offset << 2);
        //printf("DBG loc: %lx\n", loc);
        char temp[256], address[16];
        strcpy(temp, test->instr);
        sprintf(address, "0x%08lx", loc);
        strcat(temp, address);
        if(strcmp(instr, temp) != 0)
        {
            printf("Test Failed \n"
                   "Code     : 0x%0x\n"
                   "Expected : '%s'\n"
                   "Actual   : '%s'\n", test->code, temp, instr);
            failed++;
        }
    }
    if(failed == 0)
    {
        printf("All tests PASSED\n");
        return 0;
    }
    else
    {
        printf("%d tests FAILED\n", failed);
        return -1;
    }
}
