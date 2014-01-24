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

int arm64_disassemble(uint32_t code, char* instr);

struct test_table_entry_t
{
     uint32_t code;
     const char *instr;
};
static test_table_entry_t test_table [] =
{
    { 0x91000240, "add x0, x18, #0x0, lsl #0"         },
    { 0x9140041f, "add sp, x0, #0x1, lsl #12"         },
    { 0x917ffff2, "add x18, sp, #0xfff, lsl #12"      },

    { 0xd13ffe40, "sub x0, x18, #0xfff, lsl #0"       },
    { 0xd140001f, "sub sp, x0, #0x0, lsl #12"         },
    { 0xd14007f2, "sub x18, sp, #0x1, lsl #12"        },

    { 0x8b1e0200, "add x0, x16, x30, lsl #0"          },
    { 0x8b507fdf, "add xzr, x30, x16, lsr #31"        },
    { 0x8b8043f0, "add x16, xzr, x0, asr #16"         },
    { 0x8b5f401e, "add x30, x0, xzr, lsr #16"         },


    { 0x4b1e0200, "sub w0, w16, w30, lsl #0"          },
    { 0x4b507fdf, "sub wzr, w30, w16, lsr #31"        },
    { 0x4b8043f0, "sub w16, wzr, w0, asr #16"         },
    { 0x4b5f401e, "sub w30, w0, wzr, lsr #16"         },

    { 0x6b1e0200, "subs w0, w16, w30, lsl #0"         },
    { 0x6b507fdf, "subs wzr, w30, w16, lsr #31"       },
    { 0x6b8043f0, "subs w16, wzr, w0, asr #16"        },
    { 0x6b5f401e, "subs w30, w0, wzr, lsr #16"        },

    { 0x0a1e0200, "and w0, w16, w30, lsl #0"          },
    { 0x0a507fdf, "and wzr, w30, w16, lsr #31"        },
    { 0x0a8043f0, "and w16, wzr, w0, asr #16"         },
    { 0x0adf401e, "and w30, w0, wzr, ror #16"         },

    { 0x2a1e0200, "orr w0, w16, w30, lsl #0"          },
    { 0x2a507fdf, "orr wzr, w30, w16, lsr #31"        },
    { 0x2a8043f0, "orr w16, wzr, w0, asr #16"         },
    { 0x2adf401e, "orr w30, w0, wzr, ror #16"         },

    { 0x2a3e0200, "orn w0, w16, w30, lsl #0"          },
    { 0x2a707fdf, "orn wzr, w30, w16, lsr #31"        },
    { 0x2aa043f0, "orn w16, wzr, w0, asr #16"         },
    { 0x2aff401e, "orn w30, w0, wzr, ror #16"         },

    { 0x729fffe0, "movk w0, #0xffff, lsl #0"          },
    { 0x72a0000f, "movk w15, #0x0, lsl #16"           },
    { 0x7281fffe, "movk w30, #0xfff, lsl #0"          },
    { 0x72a0003f, "movk wzr, #0x1, lsl #16"           },

    { 0x529fffe0, "movz w0, #0xffff, lsl #0"          },
    { 0x52a0000f, "movz w15, #0x0, lsl #16"           },
    { 0x5281fffe, "movz w30, #0xfff, lsl #0"          },
    { 0x52a0003f, "movz wzr, #0x1, lsl #16"           },

    { 0xd29fffe0, "movz x0, #0xffff, lsl #0"          },
    { 0xd2a0000f, "movz x15, #0x0, lsl #16"           },
    { 0xd2c1fffe, "movz x30, #0xfff, lsl #32"         },
    { 0xd2e0003f, "movz xzr, #0x1, lsl #48"           },

    { 0x1a8003e0, "csel w0, wzr, w0, eq"              },
    { 0x1a831001, "csel w1, w0, w3, ne"               },
    { 0x1a9e2022, "csel w2, w1, w30, cs"              },
    { 0x1a8a3083, "csel w3, w4, w10, cc"              },
    { 0x1a8b40e4, "csel w4, w7, w11, mi"              },
    { 0x1a9b5105, "csel w5, w8, w27, pl"              },
    { 0x1a846167, "csel w7, w11, w4, vs"              },
    { 0x1a8671c8, "csel w8, w14, w6, vc"              },
    { 0x1a878289, "csel w9, w20, w7, hi"              },
    { 0x1a8c92aa, "csel w10, w21, w12, ls"            },
    { 0x1a8ea2ce, "csel w14, w22, w14, ge"            },
    { 0x1a9fb3b2, "csel w18, w29, wzr, lt"            },
    { 0x1a9fc3d8, "csel w24, w30, wzr, gt"            },
    { 0x1a82d17e, "csel w30, w11, w2, le"             },
    { 0x1a81e19f, "csel wzr, w12, w1, al"             },

    { 0x9a8003e0, "csel x0, xzr, x0, eq"              },
    { 0x9a831001, "csel x1, x0, x3, ne"               },
    { 0x9a9e2022, "csel x2, x1, x30, cs"              },
    { 0x9a8a3083, "csel x3, x4, x10, cc"              },
    { 0x9a8b40e4, "csel x4, x7, x11, mi"              },
    { 0x9a9b5105, "csel x5, x8, x27, pl"              },
    { 0x9a846167, "csel x7, x11, x4, vs"              },
    { 0x9a8671c8, "csel x8, x14, x6, vc"              },
    { 0x9a878289, "csel x9, x20, x7, hi"              },
    { 0x9a8c92aa, "csel x10, x21, x12, ls"            },
    { 0x9a8ea2ce, "csel x14, x22, x14, ge"            },
    { 0x9a9fb3b2, "csel x18, x29, xzr, lt"            },
    { 0x9a9fc3d8, "csel x24, x30, xzr, gt"            },
    { 0x9a82d17e, "csel x30, x11, x2, le"             },
    { 0x9a81e19f, "csel xzr, x12, x1, al"             },

    { 0x5a8003e0, "csinv w0, wzr, w0, eq"             },
    { 0x5a831001, "csinv w1, w0, w3, ne"              },
    { 0x5a9e2022, "csinv w2, w1, w30, cs"             },
    { 0x5a8a3083, "csinv w3, w4, w10, cc"             },
    { 0x5a8b40e4, "csinv w4, w7, w11, mi"             },
    { 0x5a9b5105, "csinv w5, w8, w27, pl"             },
    { 0x5a846167, "csinv w7, w11, w4, vs"             },
    { 0x5a8671c8, "csinv w8, w14, w6, vc"             },
    { 0x5a878289, "csinv w9, w20, w7, hi"             },
    { 0x5a8c92aa, "csinv w10, w21, w12, ls"           },
    { 0x5a8ea2ce, "csinv w14, w22, w14, ge"           },
    { 0x5a9fb3b2, "csinv w18, w29, wzr, lt"           },
    { 0x5a9fc3d8, "csinv w24, w30, wzr, gt"           },
    { 0x5a82d17e, "csinv w30, w11, w2, le"            },
    { 0x5a81e19f, "csinv wzr, w12, w1, al"            },

    { 0x1b1f3fc0, "madd w0, w30, wzr, w15"            },
    { 0x1b0079ef, "madd w15, w15, w0, w30"            },
    { 0x1b0f7ffe, "madd w30, wzr, w15, wzr"           },
    { 0x1b1e001f, "madd wzr, w0, w30, w0"             },

    { 0x9b3f3fc0, "smaddl x0, w30, wzr, x15"          },
    { 0x9b2079ef, "smaddl x15, w15, w0, x30"          },
    { 0x9b2f7ffe, "smaddl x30, wzr, w15, xzr"         },
    { 0x9b3e001f, "smaddl xzr, w0, w30, x0"           },

    { 0xd65f0000, "ret x0"                            },
    { 0xd65f01e0, "ret x15"                           },
    { 0xd65f03c0, "ret x30"                           },
    { 0xd65f03e0, "ret xzr"                           },

    { 0xb87f4be0, "ldr w0, [sp, wzr, uxtw #0]"        },
    { 0xb87ed80f, "ldr w15, [x0, w30, sxtw #2]"       },
    { 0xb86fc9fe, "ldr w30, [x15, w15, sxtw #0]"      },
    { 0xb8605bdf, "ldr wzr, [x30, w0, uxtw #2]"       },
    { 0xb87febe0, "ldr w0, [sp, xzr, sxtx #0]"        },
    { 0xb87e780f, "ldr w15, [x0, x30, lsl #2]"        },
    { 0xb86f69fe, "ldr w30, [x15, x15, lsl #0]"       },
    { 0xb860fbdf, "ldr wzr, [x30, x0, sxtx #2]"       },

    { 0xb83f4be0, "str w0, [sp, wzr, uxtw #0]"        },
    { 0xb83ed80f, "str w15, [x0, w30, sxtw #2]"       },
    { 0xb82fc9fe, "str w30, [x15, w15, sxtw #0]"      },
    { 0xb8205bdf, "str wzr, [x30, w0, uxtw #2]"       },
    { 0xb83febe0, "str w0, [sp, xzr, sxtx #0]"        },
    { 0xb83e780f, "str w15, [x0, x30, lsl #2]"        },
    { 0xb82f69fe, "str w30, [x15, x15, lsl #0]"       },
    { 0xb820fbdf, "str wzr, [x30, x0, sxtx #2]"       },

    { 0x787f4be0, "ldrh w0, [sp, wzr, uxtw #0]"       },
    { 0x787ed80f, "ldrh w15, [x0, w30, sxtw #1]"      },
    { 0x786fc9fe, "ldrh w30, [x15, w15, sxtw #0]"     },
    { 0x78605bdf, "ldrh wzr, [x30, w0, uxtw #1]"      },
    { 0x787febe0, "ldrh w0, [sp, xzr, sxtx #0]"       },
    { 0x787e780f, "ldrh w15, [x0, x30, lsl #1]"       },
    { 0x786f69fe, "ldrh w30, [x15, x15, lsl #0]"      },
    { 0x7860fbdf, "ldrh wzr, [x30, x0, sxtx #1]"      },

    { 0x783f4be0, "strh w0, [sp, wzr, uxtw #0]"       },
    { 0x783ed80f, "strh w15, [x0, w30, sxtw #1]"      },
    { 0x782fc9fe, "strh w30, [x15, w15, sxtw #0]"     },
    { 0x78205bdf, "strh wzr, [x30, w0, uxtw #1]"      },
    { 0x783febe0, "strh w0, [sp, xzr, sxtx #0]"       },
    { 0x783e780f, "strh w15, [x0, x30, lsl #1]"       },
    { 0x782f69fe, "strh w30, [x15, x15, lsl #0]"      },
    { 0x7820fbdf, "strh wzr, [x30, x0, sxtx #1]"      },

    { 0x387f5be0, "ldrb w0, [sp, wzr, uxtw #0]"       },
    { 0x387ec80f, "ldrb w15, [x0, w30, sxtw ]"        },
    { 0x386fd9fe, "ldrb w30, [x15, w15, sxtw #0]"     },
    { 0x38604bdf, "ldrb wzr, [x30, w0, uxtw ]"        },
    { 0x387ffbe0, "ldrb w0, [sp, xzr, sxtx #0]"       },
    { 0x387e780f, "ldrb w15, [x0, x30, lsl #0]"       },
    { 0x386f79fe, "ldrb w30, [x15, x15, lsl #0]"      },
    { 0x3860ebdf, "ldrb wzr, [x30, x0, sxtx ]"        },

    { 0x383f5be0, "strb w0, [sp, wzr, uxtw #0]"       },
    { 0x383ec80f, "strb w15, [x0, w30, sxtw ]"        },
    { 0x382fd9fe, "strb w30, [x15, w15, sxtw #0]"     },
    { 0x38204bdf, "strb wzr, [x30, w0, uxtw ]"        },
    { 0x383ffbe0, "strb w0, [sp, xzr, sxtx #0]"       },
    { 0x383e780f, "strb w15, [x0, x30, lsl #0]"       },
    { 0x382f79fe, "strb w30, [x15, x15, lsl #0]"      },
    { 0x3820ebdf, "strb wzr, [x30, x0, sxtx ]"        },

    { 0xf87f4be0, "ldr x0, [sp, wzr, uxtw #0]"        },
    { 0xf87ed80f, "ldr x15, [x0, w30, sxtw #3]"       },
    { 0xf86fc9fe, "ldr x30, [x15, w15, sxtw #0]"      },
    { 0xf8605bdf, "ldr xzr, [x30, w0, uxtw #3]"       },
    { 0xf87febe0, "ldr x0, [sp, xzr, sxtx #0]"        },
    { 0xf87e780f, "ldr x15, [x0, x30, lsl #3]"        },
    { 0xf86f69fe, "ldr x30, [x15, x15, lsl #0]"       },
    { 0xf860fbdf, "ldr xzr, [x30, x0, sxtx #3]"       },

    { 0xf83f4be0, "str x0, [sp, wzr, uxtw #0]"        },
    { 0xf83ed80f, "str x15, [x0, w30, sxtw #3]"       },
    { 0xf82fc9fe, "str x30, [x15, w15, sxtw #0]"      },
    { 0xf8205bdf, "str xzr, [x30, w0, uxtw #3]"       },
    { 0xf83febe0, "str x0, [sp, xzr, sxtx #0]"        },
    { 0xf83e780f, "str x15, [x0, x30, lsl #3]"        },
    { 0xf82f69fe, "str x30, [x15, x15, lsl #0]"       },
    { 0xf820fbdf, "str xzr, [x30, x0, sxtx #3]"       },

    { 0xb85007e0, "ldr w0, [sp], #-256"               },
    { 0xb840040f, "ldr w15, [x0], #0"                 },
    { 0xb84015fe, "ldr w30, [x15], #1"                },
    { 0xb84ff7df, "ldr wzr, [x30], #255"              },
    { 0xb8100fe0, "str w0, [sp, #-256]!"              },
    { 0xb8000c0f, "str w15, [x0, #0]!"                },
    { 0xb8001dfe, "str w30, [x15, #1]!"               },
    { 0xb80fffdf, "str wzr, [x30, #255]!"             },

    { 0x13017be0, "sbfm w0, wzr, #1, #30"             },
    { 0x131e7fcf, "sbfm w15, w30, #30, #31"           },
    { 0x131f01fe, "sbfm w30, w15, #31, #0"            },
    { 0x1300041f, "sbfm wzr, w0, #0, #1"              },

    { 0x53017be0, "ubfm w0, wzr, #1, #30"             },
    { 0x531e7fcf, "ubfm w15, w30, #30, #31"           },
    { 0x531f01fe, "ubfm w30, w15, #31, #0"            },
    { 0x5300041f, "ubfm wzr, w0, #0, #1"              },
    { 0xd3417fe0, "ubfm x0, xzr, #1, #31"             },
    { 0xd35fffcf, "ubfm x15, x30, #31, #63"           },
    { 0xd35f01fe, "ubfm x30, x15, #31, #0"            },
    { 0xd340041f, "ubfm xzr, x0, #0, #1"              },

    { 0x139e7be0, "extr w0, wzr, w30, #30"            },
    { 0x138f7fcf, "extr w15, w30, w15, #31"           },
    { 0x138001fe, "extr w30, w15, w0, #0"             },
    { 0x139f041f, "extr wzr, w0, wzr, #1"             },

    { 0x54000020, "b.eq #.+4"                         },
    { 0x54000201, "b.ne #.+64"                        },
    { 0x54000802, "b.cs #.+256"                       },
    { 0x54002003, "b.cc #.+1024"                      },
    { 0x54008004, "b.mi #.+4096"                      },
    { 0x54ffffe5, "b.pl #.-4"                         },
    { 0x54ffff06, "b.vs #.-32"                        },
    { 0x54fffc07, "b.vc #.-128"                       },
    { 0x54fff008, "b.hi #.-512"                       },
    { 0x54000049, "b.ls #.+8"                         },
    { 0x5400006a, "b.ge #.+12"                        },
    { 0x5400008b, "b.lt #.+16"                        },
    { 0x54ffffcc, "b.gt #.-8"                         },
    { 0x54ffffad, "b.le #.-12"                        },
    { 0x54ffff8e, "b.al #.-16"                        },

    { 0x8b2001e0, "add x0, x15, w0, uxtb #0"          },
    { 0x8b2f27cf, "add x15, x30, w15, uxth #1"        },
    { 0x8b3e4bfe, "add x30, sp, w30, uxtw #2"         },
    { 0x8b3f6c1f, "add sp, x0, xzr, uxtx #3"          },
    { 0x8b2091e0, "add x0, x15, w0, sxtb #4"          },
    { 0x8b2fa3cf, "add x15, x30, w15, sxth #0"        },
    { 0x8b3ec7fe, "add x30, sp, w30, sxtw #1"         },
    { 0x8b3fe81f, "add sp, x0, xzr, sxtx #2"          },

    { 0xcb2001e0, "sub x0, x15, w0, uxtb #0"          },
    { 0xcb2f27cf, "sub x15, x30, w15, uxth #1"        },
    { 0xcb3e4bfe, "sub x30, sp, w30, uxtw #2"         },
    { 0xcb3f6c1f, "sub sp, x0, xzr, uxtx #3"          },
    { 0xcb2091e0, "sub x0, x15, w0, sxtb #4"          },
    { 0xcb2fa3cf, "sub x15, x30, w15, sxth #0"        },
    { 0xcb3ec7fe, "sub x30, sp, w30, sxtw #1"         },
    { 0xcb3fe81f, "sub sp, x0, xzr, sxtx #2"          }
};

int main()
{
    char instr[256];
    uint32_t failed = 0;
    for(uint32_t i = 0; i < sizeof(test_table)/sizeof(test_table_entry_t); ++i)
    {
        test_table_entry_t *test;
        test = &test_table[i];
        arm64_disassemble(test->code, instr);
        if(strcmp(instr, test->instr) != 0)
        {
            printf("Test Failed \n"
                   "Code     : 0x%0x\n"
                   "Expected : %s\n"
                   "Actual   : %s\n", test->code, test->instr, instr);
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
