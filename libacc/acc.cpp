/*
 Obfuscated Tiny C Compiler

 Copyright (C) 2001-2003 Fabrice Bellard

 This software is provided 'as-is', without any express or implied
 warranty.  In no event will the authors be held liable for any damages
 arising from the use of this software.

 Permission is granted to anyone to use this software for any purpose,
 including commercial applications, and to alter it and redistribute it
 freely, subject to the following restrictions:

 1. The origin of this software must not be misrepresented; you must not
 claim that you wrote the original software. If you use this software
 in a product, an acknowledgment in the product and its documentation
 *is* required.
 2. Altered source versions must be plainly marked as such, and must not be
 misrepresented as being the original software.
 3. This notice may not be removed or altered from any source distribution.
 */

#include <ctype.h>
#include <dlfcn.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__arm__)
#include <unistd.h>
#endif

#include "disassem.h"

namespace acc {

class compiler {
    class CodeBuf {
        char* ind;
        char* pProgramBase;

        void release() {
            if (pProgramBase != 0) {
                free(pProgramBase);
                pProgramBase = 0;
            }
        }

    public:
        CodeBuf() {
            pProgramBase = 0;
            ind = 0;
        }

        ~CodeBuf() {
            release();
        }

        void init(int size) {
            release();
            pProgramBase = (char*) calloc(1, size);
            ind = pProgramBase;
        }

        void o(int n) {
            /* cannot use unsigned, so we must do a hack */
            while (n && n != -1) {
                *ind++ = n;
                n = n >> 8;
            }
        }

        int o4(int n) {
            int result = (int) ind;
            * (int*) ind = n;
            ind += 4;
            return result;
        }

        /*
         * Output a byte. Handles all values, 0..ff.
         */
        void ob(int n) {
            *ind++ = n;
        }

        /* output a symbol and patch all calls to it */
        void gsym(int t) {
            int n;
            while (t) {
                n = *(int *) t; /* next value */
                *(int *) t = ((int) ind) - t - 4;
                t = n;
            }
        }

        /* psym is used to put an instruction with a data field which is a
         reference to a symbol. It is in fact the same as oad ! */
        int psym(int n, int t) {
            return oad(n, t);
        }

        /* instruction + address */
        int oad(int n, int t) {
            o(n);
            *(int *) ind = t;
            t = (int) ind;
            ind = ind + 4;
            return t;
        }

        inline void* getBase() {
            return (void*) pProgramBase;
        }

        int getSize() {
            return ind - pProgramBase;
        }

        int getPC() {
            return (int) ind;
        }
    };

    class CodeGenerator {
    public:
        CodeGenerator() {}
        virtual ~CodeGenerator() {}

        virtual void init(CodeBuf* pCodeBuf) {
            this->pCodeBuf = pCodeBuf;
        }

        /* returns address to patch with local variable size
        */
        virtual int functionEntry(int argCount) = 0;

        virtual void functionExit(int argCount, int localVariableAddress, int localVariableSize) = 0;

        /* load immediate value */
        virtual void li(int t) = 0;

        virtual int gjmp(int t) = 0;

        /* l = 0: je, l == 1: jne */
        virtual int gtst(bool l, int t) = 0;

        virtual void gcmp(int op) = 0;

        virtual void genOp(int op) = 0;

        virtual void clearECX() = 0;

        virtual void pushEAX() = 0;

        virtual void popECX() = 0;

        virtual void storeEAXToAddressECX(bool isInt) = 0;

        virtual void loadEAXIndirect(bool isInt) = 0;

        virtual void leaEAX(int ea) = 0;

        virtual void storeEAX(int ea) = 0;

        virtual void loadEAX(int ea) = 0;

        virtual void postIncrementOrDecrement(int n, int op) = 0;

        virtual int beginFunctionCallArguments() = 0;

        virtual void endFunctionCallArguments(int a, int l) = 0;

        virtual void storeEAToArg(int l) = 0;

        virtual int callForward(int symbol) = 0;

        virtual void callRelative(int t) = 0;

        virtual void callIndirect(int l) = 0;

        virtual void adjustStackAfterCall(int l) = 0;

        virtual int disassemble(FILE* out) = 0;

        /* output a symbol and patch all calls to it */
        virtual void gsym(int t) {
            pCodeBuf->gsym(t);
        }

        virtual int finishCompile() {
#if defined(__arm__)
            const long base = long(pCodeBuf->getBase());
            const long curr = base + long(pCodeBuf->getSize());
            int err = cacheflush(base, curr, 0);
            return err;
#else
            return 0;
#endif
        }

        /**
         * Adjust relative branches by this amount.
         */
        virtual int jumpOffset() = 0;

    protected:
        void o(int n) {
            pCodeBuf->o(n);
        }

        /*
         * Output a byte. Handles all values, 0..ff.
         */
        void ob(int n) {
            pCodeBuf->ob(n);
        }

        /* psym is used to put an instruction with a data field which is a
         reference to a symbol. It is in fact the same as oad ! */
        int psym(int n, int t) {
            return oad(n, t);
        }

        /* instruction + address */
        int oad(int n, int t) {
            return pCodeBuf->oad(n,t);
        }

        int getBase() {
            return (int) pCodeBuf->getBase();
        }

        int getPC() {
            return pCodeBuf->getPC();
        }

        int o4(int data) {
            return pCodeBuf->o4(data);
        }
    private:
        CodeBuf* pCodeBuf;
    };

    class ARMCodeGenerator : public CodeGenerator {
    public:
        ARMCodeGenerator() {}
        virtual ~ARMCodeGenerator() {}

        /* returns address to patch with local variable size
        */
        virtual int functionEntry(int argCount) {
            fprintf(stderr, "functionEntry(%d);\n", argCount);
            // sp -> arg4 arg5 ...
            // Push our register-based arguments back on the stack
            if (argCount > 0) {
                int regArgCount = argCount <= 4 ? argCount : 4;
                o4(0xE92D0000 | ((1 << argCount) - 1)); // stmfd    sp!, {}
            }
            // sp -> arg0 arg1 ...
            o4(0xE92D4800); // stmfd sp!, {fp, lr}
            // sp, fp -> oldfp, retadr, arg0 arg1 ....
            o4(0xE1A0B00D); // mov    fp, sp
            return o4(0xE24DD000); // sub    sp, sp, # <local variables>
        }

        virtual void functionExit(int argCount, int localVariableAddress, int localVariableSize) {
            fprintf(stderr, "functionExit(%d, %d, %d);\n", argCount, localVariableAddress, localVariableSize);
            // Patch local variable allocation code:
            if (localVariableSize < 0 || localVariableSize > 255) {
                error("LocalVariableSize");
            }
            *(char*) (localVariableAddress) = localVariableSize;

            // sp -> locals .... fp -> oldfp, retadr, arg0, arg1, ...
            o4(0xE1A0E00B); // mov lr, fp
            o4(0xE59BB000); // ldr fp, [fp]
            o4(0xE28ED004); // add sp, lr, #4
            // sp -> retadr, arg0, ...
            o4(0xE8BD4000); // ldmfd    sp!, {lr}
            // sp -> arg0 ....
            if (argCount > 0) {
                // We store the PC into the lr so we can adjust the sp before
                // returning. (We need to pull off the registers we pushed
                // earlier. We don't need to actually store them anywhere,
                // just adjust the stack.
                int regArgCount = argCount <= 4 ? argCount : 4;
                o4(0xE28DD000 | (regArgCount << 2)); // add sp, sp, #argCount << 2
            }
            o4(0xE12FFF1E); // bx lr
        }

        /* load immediate value */
        virtual void li(int t) {
            fprintf(stderr, "li(%d);\n", t);
            if (t >= 0 && t < 255) {
                 o4(0xE3A00000 + t); // mov    r0, #0
            } else if (t >= -256 && t < 0) {
                // mvn means move constant ^ ~0
                o4(0xE3E00001 - t); // mvn    r0, #0
            } else {
                  o4(0xE51F0000); //         ldr    r0, .L3
                  o4(0xEA000000); //         b .L99
                  o4(t);          // .L3:   .word 0
                                  // .L99:
            }
        }

        virtual int gjmp(int t) {
            fprintf(stderr, "gjmp(%d);\n", t);
            return o4(0xEA000000 + encodeAddress(t)); // b .L33
        }

        /* l = 0: je, l == 1: jne */
        virtual int gtst(bool l, int t) {
            fprintf(stderr, "gtst(%d, %d);\n", l, t);
            error("Unimplemented");
            o(0x0fc085); /* test %eax, %eax, je/jne xxx */
            return psym(0x84 + l, t);
        }

        virtual void gcmp(int op) {
            fprintf(stderr, "gcmp(%d);\n", op);
            error("Unimplemented");
#if 0
            int t = decodeOp(op);
            o(0xc139); /* cmp %eax,%ecx */
            li(0);
            o(0x0f); /* setxx %al */
            o(t + 0x90);
            o(0xc0);
#endif
        }

        virtual void genOp(int op) {
            fprintf(stderr, "genOp(%d);\n", op);
            switch(op) {
            case OP_MUL:
                o4(0x0E0000091); // mul     r0,r1,r0
                break;
            case OP_PLUS:
                o4(0xE0810000);  // add     r0,r1,r0
                break;
            case OP_MINUS:
                o4(0xE0410000);  // sub     r0,r1,r0
                break;
            case OP_SHIFT_LEFT:
                o4(0xE1A00011);  // lsl     r0,r1,r0
                break;
            case OP_SHIFT_RIGHT:
                o4(0xE1A00051);  // asr     r0,r1,r0
                break;
            case OP_BIT_AND:
                o4(0xE0010000);  // and     r0,r1,r0
                break;
            case OP_BIT_XOR:
                o4(0xE0210000);  // eor     r0,r1,r0
                break;
            case OP_BIT_OR:
                o4(0xE1810000);  // orr     r0,r1,r0
                break;
            case OP_BIT_NOT:
                o4(0xE1E00000);  // mvn     r0, r0
                break;
            default:
                error("Unimplemented op %d\n", op);
                break;
            }
#if 0
            o(decodeOp(op));
            if (op == OP_MOD)
                o(0x92); /* xchg %edx, %eax */
#endif
        }

        virtual void clearECX() {
            fprintf(stderr, "clearECX();\n");
            o4(0xE3A01000);  // mov    r1, #0
        }

        virtual void pushEAX() {
            fprintf(stderr, "pushEAX();\n");
            o4(0xE92D0001);  // stmfd   sp!,{r0}
        }

        virtual void popECX() {
            fprintf(stderr, "popECX();\n");
            o4(0xE8BD0002);  // ldmfd   sp!,{r1}
        }

        virtual void storeEAXToAddressECX(bool isInt) {
            fprintf(stderr, "storeEAXToAddressECX(%d);\n", isInt);
            o4(0x0188 + isInt); /* movl %eax/%al, (%ecx) */
        }

        virtual void loadEAXIndirect(bool isInt) {
            fprintf(stderr, "loadEAXIndirect(%d);\n", isInt);
            if (isInt)
                o4(0xE5900000); // ldr r0, [r0]
            else
                o4(0xE5D00000); // ldrb r0, [r0]
        }

        virtual void leaEAX(int ea) {
            fprintf(stderr, "[!!! fixme !!!] leaEAX(%d);\n", ea);
            error("Unimplemented");
            if (ea < -4095 || ea > 4095) {
                error("Offset out of range: %08x", ea);
            }
            o4(0xE59B0000 | (0x1fff & ea)); //ldr r0, [fp,#ea]
        }

        virtual void storeEAX(int ea) {
            fprintf(stderr, "storeEAX(%d);\n", ea);
            int fpOffset = ea;
            if (fpOffset < -4095 || fpOffset > 4095) {
                error("Offset out of range: %08x", ea);
            }
            if (fpOffset < 0) {
                o4(0xE50B0000 | (0xfff & (-fpOffset))); // str r0, [fp,#-ea]
            } else {
                o4(0xE58B0000 | (0xfff & fpOffset)); // str r0, [fp,#ea]
            }
        }

        virtual void loadEAX(int ea) {
            fprintf(stderr, "loadEAX(%d);\n", ea);
            int fpOffset = ea;
            if (fpOffset < -4095 || fpOffset > 4095) {
                error("Offset out of range: %08x", ea);
            }
            if (fpOffset < 0) {
                o4(0xE51B0000 | (0xfff & (-fpOffset))); // ldr r0, [fp,#-ea]
            } else {
                o4(0xE59B0000 | (0xfff & fpOffset)); //ldr r0, [fp,#ea]
            }
        }

        virtual void postIncrementOrDecrement(int n, int op) {
            fprintf(stderr, "postIncrementOrDecrement(%d, %d);\n", n, op);
            /* Implement post-increment or post decrement.
             */

            error("Unimplemented");
#if 0
            gmov(0, n); /* 83 ADD */
            o(decodeOp(op));
#endif
        }

        virtual int beginFunctionCallArguments() {
            fprintf(stderr, "beginFunctionCallArguments();\n");
            return o4(0xE24DDF00); // Placeholder
        }

        virtual void endFunctionCallArguments(int a, int l) {
            fprintf(stderr, "endFunctionCallArguments(0x%08x, %d);\n", a, l);
            if (l < 0 || l > 0x3FC) {
                error("L out of range for stack adjustment: 0x%08x", l);
            }
            * (int*) a = 0xE24DDF00 | (l >> 2); // sub    sp, sp, #0 << 2
            int argCount = l >> 2;
            if (argCount > 0) {
                int regArgCount = argCount > 4 ? 4 : argCount;
                o4(0xE8BD0000 | ((1 << regArgCount) - 1)); // ldmfd   sp!,{}
            }
        }

        virtual void storeEAToArg(int l) {
            fprintf(stderr, "storeEAToArg(%d);\n", l);
            if (l < 0 || l > 4096-4) {
                error("l out of range for stack offset: 0x%08x", l);
            }
            o4(0xE58D0000 + l); // str r0, [sp, #4]
        }

        virtual int callForward(int symbol) {
            fprintf(stderr, "callForward(%d);\n", symbol);
            // Forward calls are always short (local)
            return o4(0xEB000000 | encodeAddress(symbol));
        }

        virtual void callRelative(int t) {
            fprintf(stderr, "callRelative(%d);\n", t);
            int abs = t + getPC() + jumpOffset();
            fprintf(stderr, "abs=%d (0x08%x)\n", abs, abs);
            if (t >= - (1 << 25) && t < (1 << 25)) {
                o4(0xEB000000 | encodeAddress(t));
            } else {
                // Long call.
                o4(0xE59FC000); //         ldr    r12, .L1
                o4(0xEA000000); //         b .L99
                o4(t - 16);     // .L1:    .word 0
                o4(0xE08CC00F); // .L99:   add r12,pc
                o4(0xE12FFF3C); //         blx r12
           }
        }

        virtual void callIndirect(int l) {
            fprintf(stderr, "callIndirect(%d);\n", l);
            oad(0x2494ff, l); /* call *xxx(%esp) */
        }

        virtual void adjustStackAfterCall(int l) {
            fprintf(stderr, "adjustStackAfterCall(%d);\n", l);
            if (l < 0 || l > 0x3FC) {
                error("L out of range for stack adjustment: 0x%08x", l);
            }
            int argCount = l >> 2;
            if (argCount > 4) {
                int remainingArgs = argCount - 4;
                o4(0xE28DDF00 | remainingArgs); // add    sp, sp, #0x3fc
            }

        }

        virtual int jumpOffset() {
            return 4;
        }

        /* output a symbol and patch all calls to it */
        virtual void gsym(int t) {
            fprintf(stderr, "gsym(0x%x)\n", t);
            int n;
            int base = getBase();
            int pc = getPC();
            fprintf(stderr, "pc = 0x%x\n", pc);
            while (t) {
                int data = * (int*) t;
                int decodedOffset = ((BRANCH_REL_ADDRESS_MASK & data) << 2);
                if (decodedOffset == 0) {
                    n = 0;
                } else {
                    n = base + decodedOffset; /* next value */
                }
                *(int *) t = (data & ~BRANCH_REL_ADDRESS_MASK)
                    | encodeRelAddress(pc - t - 8);
                t = n;
            }
        }

        virtual int disassemble(FILE* out) {
               disasmOut = out;
            disasm_interface_t  di;
            di.di_readword = disassemble_readword;
            di.di_printaddr = disassemble_printaddr;
            di.di_printf = disassemble_printf;

            int base = getBase();
            int pc = getPC();
            for(int i = base; i < pc; i += 4) {
                fprintf(out, "%08x: %08x  ", i, *(int*) i);
                ::disasm(&di, i, 0);
            }
            return 0;
        }
    private:
        static FILE* disasmOut;

        static u_int
        disassemble_readword(u_int address)
        {
            return(*((u_int *)address));
        }

        static void
        disassemble_printaddr(u_int address)
        {
            fprintf(disasmOut, "0x%08x", address);
        }

        static void
        disassemble_printf(const char *fmt, ...) {
            va_list ap;
            va_start(ap, fmt);
            vfprintf(disasmOut, fmt, ap);
            va_end(ap);
        }

        static const int BRANCH_REL_ADDRESS_MASK = 0x00ffffff;

        /** Encode a relative address that might also be
         * a label.
         */
        int encodeAddress(int value) {
            int base = getBase();
            if (value >= base && value <= getPC() ) {
                // This is a label, encode it relative to the base.
                value = value - base;
            }
            return encodeRelAddress(value);
        }

        int encodeRelAddress(int value) {
            return BRANCH_REL_ADDRESS_MASK & (value >> 2);
        }

        void error(const char* fmt,...) {
            va_list ap;
            va_start(ap, fmt);
            vfprintf(stderr, fmt, ap);
            va_end(ap);
            exit(12);
        }
    };

    class X86CodeGenerator : public CodeGenerator {
    public:
        X86CodeGenerator() {}
        virtual ~X86CodeGenerator() {}

        /* returns address to patch with local variable size
        */
        virtual int functionEntry(int argCount) {
            o(0xe58955); /* push   %ebp, mov %esp, %ebp */
            return oad(0xec81, 0); /* sub $xxx, %esp */
        }

        virtual void functionExit(int argCount, int localVariableAddress, int localVariableSize) {
            o(0xc3c9); /* leave, ret */
            *(int *) localVariableAddress = localVariableSize; /* save local variables */
        }

        /* load immediate value */
        virtual void li(int t) {
            oad(0xb8, t); /* mov $xx, %eax */
        }

        virtual int gjmp(int t) {
            return psym(0xe9, t);
        }

        /* l = 0: je, l == 1: jne */
        virtual int gtst(bool l, int t) {
            o(0x0fc085); /* test %eax, %eax, je/jne xxx */
            return psym(0x84 + l, t);
        }

        virtual void gcmp(int op) {
            int t = decodeOp(op);
            o(0xc139); /* cmp %eax,%ecx */
            li(0);
            o(0x0f); /* setxx %al */
            o(t + 0x90);
            o(0xc0);
        }

        virtual void genOp(int op) {
            o(decodeOp(op));
            if (op == OP_MOD)
                o(0x92); /* xchg %edx, %eax */
        }

        virtual void clearECX() {
            oad(0xb9, 0); /* movl $0, %ecx */
        }

        virtual void pushEAX() {
            o(0x50); /* push %eax */
        }

        virtual void popECX() {
            o(0x59); /* pop %ecx */
        }

        virtual void storeEAXToAddressECX(bool isInt) {
            o(0x0188 + isInt); /* movl %eax/%al, (%ecx) */
        }

        virtual void loadEAXIndirect(bool isInt) {
            if (isInt)
                o(0x8b); /* mov (%eax), %eax */
            else
                o(0xbe0f); /* movsbl (%eax), %eax */
            ob(0); /* add zero in code */
        }

        virtual void leaEAX(int ea) {
            gmov(10, ea); /* leal EA, %eax */
        }

        virtual void storeEAX(int ea) {
            gmov(6, ea); /* mov %eax, EA */
        }

        virtual void loadEAX(int ea) {
            gmov(8, ea); /* mov EA, %eax */
        }

        virtual void postIncrementOrDecrement(int n, int op) {
            /* Implement post-increment or post decrement.
             */
            gmov(0, n); /* 83 ADD */
            o(decodeOp(op));
        }

        virtual int beginFunctionCallArguments() {
            return oad(0xec81, 0); /* sub $xxx, %esp */
        }

        virtual void endFunctionCallArguments(int a, int l) {
            * (int*) a = l;
        }

        virtual void storeEAToArg(int l) {
            oad(0x248489, l); /* movl %eax, xxx(%esp) */
        }

        virtual int callForward(int symbol) {
            return psym(0xe8, symbol); /* call xxx */
        }

        virtual void callRelative(int t) {
            psym(0xe8, t); /* call xxx */
        }

        virtual void callIndirect(int l) {
            oad(0x2494ff, l); /* call *xxx(%esp) */
        }

        virtual void adjustStackAfterCall(int l) {
            oad(0xc481, l); /* add $xxx, %esp */
        }

        virtual int jumpOffset() {
            return 5;
        }

        virtual int disassemble(FILE* out) {
            return 1;
        }

    private:
        static const int operatorHelper[];

        int decodeOp(int op) {
            if (op < 0 || op > OP_COUNT) {
                fprintf(stderr, "Out-of-range operator: %d\n", op);
                exit(1);
            }
            return operatorHelper[op];
        }

        void gmov(int l, int t) {
            o(l + 0x83);
            oad((t < LOCAL) << 7 | 5, t);
        }
    };

    /* vars: value of variables
     loc : local variable index
     glo : global variable index
     ind : output code ptr
     rsym: return symbol
     prog: output code
     dstk: define stack
     dptr, dch: macro state
     */
    int tok, tokc, tokl, ch, vars, rsym, loc, glo, sym_stk, dstk,
            dptr, dch, last_id;
    void* pSymbolBase;
    void* pGlobalBase;
    void* pVarsBase;
    FILE* file;

    CodeBuf codeBuf;
    CodeGenerator* pGen;

    static const int ALLOC_SIZE = 99999;

    /* depends on the init string */
    static const int TOK_STR_SIZE = 48;
    static const int TOK_IDENT = 0x100;
    static const int TOK_INT = 0x100;
    static const int TOK_IF = 0x120;
    static const int TOK_ELSE = 0x138;
    static const int TOK_WHILE = 0x160;
    static const int TOK_BREAK = 0x190;
    static const int TOK_RETURN = 0x1c0;
    static const int TOK_FOR = 0x1f8;
    static const int TOK_DEFINE = 0x218;
    static const int TOK_MAIN = 0x250;

    static const int TOK_DUMMY = 1;
    static const int TOK_NUM = 2;

    static const int LOCAL = 0x200;

    static const int SYM_FORWARD = 0;
    static const int SYM_DEFINE = 1;

    /* tokens in string heap */
    static const int TAG_TOK = ' ';
    static const int TAG_MACRO = 2;

    static const int OP_INCREMENT = 0;
    static const int OP_DECREMENT = 1;
    static const int OP_MUL = 2;
    static const int OP_DIV = 3;
    static const int OP_MOD = 4;
    static const int OP_PLUS = 5;
    static const int OP_MINUS = 6;
    static const int OP_SHIFT_LEFT = 7;
    static const int OP_SHIFT_RIGHT = 8;
    static const int OP_LESS_EQUAL = 9;
    static const int OP_GREATER_EQUAL = 10;
    static const int OP_LESS = 11;
    static const int OP_GREATER = 12;
    static const int OP_EQUALS = 13;
    static const int OP_NOT_EQUALS = 14;
    static const int OP_LOGICAL_AND = 15;
    static const int OP_LOGICAL_OR = 16;
    static const int OP_BIT_AND = 17;
    static const int OP_BIT_XOR = 18;
    static const int OP_BIT_OR = 19;
    static const int OP_BIT_NOT = 20;
    static const int OP_LOGICAL_NOT = 21;
    static const int OP_COUNT = 22;

    /* Operators are searched from front, the two-character operators appear
     * before the single-character operators with the same first character.
     * @ is used to pad out single-character operators.
     */
    static const char* operatorChars;
    static const char operatorLevel[];

    void pdef(int t) {
        *(char *) dstk++ = t;
    }

    void inp() {
        if (dptr) {
            ch = *(char *) dptr++;
            if (ch == TAG_MACRO) {
                dptr = 0;
                ch = dch;
            }
        } else
            ch = fgetc(file);
        /*    printf("ch=%c 0x%x\n", ch, ch); */
    }

    int isid() {
        return isalnum(ch) | (ch == '_');
    }

    /* read a character constant */
    void getq() {
        if (ch == '\\') {
            inp();
            if (ch == 'n')
                ch = '\n';
        }
    }

    void next() {
        int l, a;

        while (isspace(ch) | (ch == '#')) {
            if (ch == '#') {
                inp();
                next();
                if (tok == TOK_DEFINE) {
                    next();
                    pdef(TAG_TOK); /* fill last ident tag */
                    *(int *) tok = SYM_DEFINE;
                    *(int *) (tok + 4) = dstk; /* define stack */
                }
                /* well we always save the values ! */
                while (ch != '\n') {
                    pdef(ch);
                    inp();
                }
                pdef(ch);
                pdef(TAG_MACRO);
            }
            inp();
        }
        tokl = 0;
        tok = ch;
        /* encode identifiers & numbers */
        if (isid()) {
            pdef(TAG_TOK);
            last_id = dstk;
            while (isid()) {
                pdef(ch);
                inp();
            }
            if (isdigit(tok)) {
                tokc = strtol((char*) last_id, 0, 0);
                tok = TOK_NUM;
            } else {
                *(char *) dstk = TAG_TOK; /* no need to mark end of string (we
                 suppose data is initialized to zero by calloc) */
                tok = (int) (strstr((char*) sym_stk, (char*) (last_id - 1))
                        - sym_stk);
                *(char *) dstk = 0; /* mark real end of ident for dlsym() */
                tok = tok * 8 + TOK_IDENT;
                if (tok > TOK_DEFINE) {
                    tok = vars + tok;
                    /*        printf("tok=%s %x\n", last_id, tok); */
                    /* define handling */
                    if (*(int *) tok == SYM_DEFINE) {
                        dptr = *(int *) (tok + 4);
                        dch = ch;
                        inp();
                        next();
                    }
                }
            }
        } else {
            inp();
            if (tok == '\'') {
                tok = TOK_NUM;
                getq();
                tokc = ch;
                inp();
                inp();
            } else if ((tok == '/') & (ch == '*')) {
                inp();
                while (ch) {
                    while (ch != '*')
                        inp();
                    inp();
                    if (ch == '/')
                        ch = 0;
                }
                inp();
                next();
            } else {
                const char* t = operatorChars;
                int opIndex = 0;
                while ((l = *t++) != 0) {
                    a = *t++;
                    tokl = operatorLevel[opIndex];
                    tokc = opIndex;
                    if ((l == tok) & ((a == ch) | (a == '@'))) {
#if 0
                        printf("%c%c -> tokl=%d tokc=0x%x\n",
                                l, a, tokl, tokc);
#endif
                        if (a == ch) {
                            inp();
                            tok = TOK_DUMMY; /* dummy token for double tokens */
                        }
                        break;
                    }
                    opIndex++;
                }
                if (l == 0) {
                    tokl = 0;
                    tokc = 0;
                }
            }
        }
#if 0
        {
            int p;

            printf("tok=0x%x ", tok);
            if (tok >= TOK_IDENT) {
                printf("'");
                if (tok> TOK_DEFINE)
                p = sym_stk + 1 + (tok - vars - TOK_IDENT) / 8;
                else
                p = sym_stk + 1 + (tok - TOK_IDENT) / 8;
                while (*(char *)p != TAG_TOK && *(char *)p)
                printf("%c", *(char *)p++);
                printf("'\n");
            } else if (tok == TOK_NUM) {
                printf("%d\n", tokc);
            } else {
                printf("'%c'\n", tok);
            }
        }
#endif
    }

    void error(const char *fmt, ...) {
        va_list ap;

        va_start(ap, fmt);
        fprintf(stderr, "%ld: ", ftell((FILE *) file));
        vfprintf(stderr, fmt, ap);
        fprintf(stderr, "\n");
        va_end(ap);
        exit(1);
    }

    void skip(int c) {
        if (tok != c) {
            error("'%c' expected", c);
        }
        next();
    }

    /* l is one if '=' parsing wanted (quick hack) */
    void unary(int l) {
        int n, t, a, c;
        t = 0;
        n = 1; /* type of expression 0 = forward, 1 = value, other =
         lvalue */
        if (tok == '\"') {
            pGen->li(glo);
            while (ch != '\"') {
                getq();
                *(char *) glo++ = ch;
                inp();
            }
            *(char *) glo = 0;
            glo = (glo + 4) & -4; /* align heap */
            inp();
            next();
        } else {
            c = tokl;
            a = tokc;
            t = tok;
            next();
            if (t == TOK_NUM) {
                pGen->li(a);
            } else if (c == 2) {
                /* -, +, !, ~ */
                unary(0);
                pGen->clearECX();
                if (t == '!')
                    pGen->gcmp(a);
                else
                    pGen->genOp(a);
            } else if (t == '(') {
                expr();
                skip(')');
            } else if (t == '*') {
                /* parse cast */
                skip('(');
                t = tok; /* get type */
                next(); /* skip int/char/void */
                next(); /* skip '*' or '(' */
                if (tok == '*') {
                    /* function type */
                    skip('*');
                    skip(')');
                    skip('(');
                    skip(')');
                    t = 0;
                }
                skip(')');
                unary(0);
                if (tok == '=') {
                    next();
                    pGen->pushEAX();
                    expr();
                    pGen->popECX();
                    pGen->storeEAXToAddressECX(t == TOK_INT);
                } else if (t) {
                    pGen->loadEAXIndirect(t == TOK_INT);
                }
            } else if (t == '&') {
                pGen->leaEAX(*(int *) tok);
                next();
            } else {
                n = *(int *) t;
                /* forward reference: try dlsym */
                if (!n) {
                    n = (int) dlsym(RTLD_DEFAULT, (char*) last_id);
                }
                if ((tok == '=') & l) {
                    /* assignment */
                    next();
                    expr();
                    pGen->storeEAX(n);
                } else if (tok != '(') {
                    /* variable */
                    pGen->loadEAX(n);
                    if (tokl == 11) {
                        pGen->postIncrementOrDecrement(n, tokc);
                        next();
                    }
                }
            }
        }

        /* function call */
        if (tok == '(') {
            if (n == 1)
                pGen->pushEAX();

            /* push args and invert order */
            a = pGen->beginFunctionCallArguments();
            next();
            l = 0;
            while (tok != ')') {
                expr();
                pGen->storeEAToArg(l);
                if (tok == ',')
                    next();
                l = l + 4;
            }
            pGen->endFunctionCallArguments(a, l);
            next();
            if (!n) {
                /* forward reference */
                t = t + 4;
                *(int *) t = pGen->callForward(*(int *) t);
            } else if (n == 1) {
                pGen->callIndirect(l);
                l = l + 4;
            } else {
                pGen->callRelative(n - codeBuf.getPC() - pGen->jumpOffset()); /* call xxx */
            }
            if (l)
                pGen->adjustStackAfterCall(l);
        }
    }

    void sum(int l) {
        int t, n, a;
        t = 0;
        if (l-- == 1)
            unary(1);
        else {
            sum(l);
            a = 0;
            while (l == tokl) {
                n = tok;
                t = tokc;
                next();

                if (l > 8) {
                    a = pGen->gtst(t == OP_LOGICAL_OR, a); /* && and || output code generation */
                    sum(l);
                } else {
                    pGen->pushEAX();
                    sum(l);
                    pGen->popECX();

                    if ((l == 4) | (l == 5)) {
                        pGen->gcmp(t);
                    } else {
                        pGen->genOp(t);
                    }
                }
            }
            /* && and || output code generation */
            if (a && l > 8) {
                a = pGen->gtst(t == OP_LOGICAL_OR, a);
                pGen->li(t != OP_LOGICAL_OR);
                pGen->gjmp(5); /* jmp $ + 5 (sizeof li, FIXME for ARM) */
                pGen->gsym(a);
                pGen->li(t == OP_LOGICAL_OR);
            }
        }
    }

    void expr() {
        sum(11);
    }

    int test_expr() {
        expr();
        return pGen->gtst(0, 0);
    }

    void block(int l) {
        int a, n, t;

        if (tok == TOK_IF) {
            next();
            skip('(');
            a = test_expr();
            skip(')');
            block(l);
            if (tok == TOK_ELSE) {
                next();
                n = pGen->gjmp(0); /* jmp */
                pGen->gsym(a);
                block(l);
                pGen->gsym(n); /* patch else jmp */
            } else {
                pGen->gsym(a); /* patch if test */
            }
        } else if ((tok == TOK_WHILE) | (tok == TOK_FOR)) {
            t = tok;
            next();
            skip('(');
            if (t == TOK_WHILE) {
                n = codeBuf.getPC(); // top of loop, target of "next" iteration
                a = test_expr();
            } else {
                if (tok != ';')
                    expr();
                skip(';');
                n = codeBuf.getPC();
                a = 0;
                if (tok != ';')
                    a = test_expr();
                skip(';');
                if (tok != ')') {
                    t = pGen->gjmp(0);
                    expr();
                    pGen->gjmp(n - codeBuf.getPC() - pGen->jumpOffset());
                    pGen->gsym(t);
                    n = t + 4;
                }
            }
            skip(')');
            block((int) &a);
            pGen->gjmp(n - codeBuf.getPC() - pGen->jumpOffset()); /* jmp */
            pGen->gsym(a);
        } else if (tok == '{') {
            next();
            /* declarations */
            decl(1);
            while (tok != '}')
                block(l);
            next();
        } else {
            if (tok == TOK_RETURN) {
                next();
                if (tok != ';')
                    expr();
                rsym = pGen->gjmp(rsym); /* jmp */
            } else if (tok == TOK_BREAK) {
                next();
                *(int *) l = pGen->gjmp(*(int *) l);
            } else if (tok != ';')
                expr();
            skip(';');
        }
    }

    /* 'l' is true if local declarations */
    void decl(int l) {
        int a;

        while ((tok == TOK_INT) | ((tok != -1) & (!l))) {
            if (tok == TOK_INT) {
                next();
                while (tok != ';') {
                    if (l) {
                        loc = loc + 4;
                        *(int *) tok = -loc;
                    } else {
                        *(int *) tok = glo;
                        glo = glo + 4;
                    }
                    next();
                    if (tok == ',')
                        next();
                }
                skip(';');
            } else {
                /* patch forward references (XXX: do not work for function
                 pointers) */
                pGen->gsym(*(int *) (tok + 4));
                /* put function address */
                *(int *) tok = codeBuf.getPC();
                next();
                skip('(');
                a = 8;
                int argCount = 0;
                while (tok != ')') {
                    /* read param name and compute offset */
                    *(int *) tok = a;
                    a = a + 4;
                    next();
                    if (tok == ',')
                        next();
                    argCount++;
                }
                next(); /* skip ')' */
                rsym = loc = 0;
                a = pGen->functionEntry(argCount);
                block(0);
                pGen->gsym(rsym);
                pGen->functionExit(argCount, a, loc);
            }
        }
    }

    void cleanup() {
        if (sym_stk != 0) {
            free((void*) sym_stk);
            sym_stk = 0;
        }
        if (pGlobalBase != 0) {
            free((void*) pGlobalBase);
            pGlobalBase = 0;
        }
        if (pVarsBase != 0) {
            free(pVarsBase);
            pVarsBase = 0;
        }
        if (pGen) {
            delete pGen;
            pGen = 0;
        }
    }

    void clear() {
        tok = 0;
        tokc = 0;
        tokl = 0;
        ch = 0;
        vars = 0;
        rsym = 0;
        loc = 0;
        glo = 0;
        sym_stk = 0;
        dstk = 0;
        dptr = 0;
        dch = 0;
        last_id = 0;
        file = 0;
        pGlobalBase = 0;
        pVarsBase = 0;
        pGen = 0;
    }

    void setArchitecture(const char* architecture) {
        delete pGen;
        pGen = 0;

        if (architecture != NULL) {
            if (strcmp(architecture, "arm") == 0) {
                pGen = new ARMCodeGenerator();
            } else if (strcmp(architecture, "x86") == 0) {
                pGen = new X86CodeGenerator();
            } else {
                fprintf(stderr, "Unknown architecture %s", architecture);
            }
        }

        if (pGen == NULL) {
            pGen = new ARMCodeGenerator();
        }
    }

public:
    struct args {
        args() {
            architecture = 0;
        }
        const char* architecture;
    };

    compiler() {
        clear();
    }

    ~compiler() {
        cleanup();
    }

    int compile(FILE* in, args& args) {
        cleanup();
        clear();
        codeBuf.init(ALLOC_SIZE);
        setArchitecture(args.architecture);
        pGen->init(&codeBuf);
        file = in;
        sym_stk = (int) calloc(1, ALLOC_SIZE);
        dstk = (int) strcpy((char*) sym_stk,
                " int if else while break return for define main ")
                + TOK_STR_SIZE;
        pGlobalBase = calloc(1, ALLOC_SIZE);
        glo = (int) pGlobalBase;
        pVarsBase = calloc(1, ALLOC_SIZE);
        vars = (int) pVarsBase;
        inp();
        next();
        decl(0);
        pGen->finishCompile();
        return 0;
    }

    int run(int argc, char** argv) {
        typedef int (*mainPtr)(int argc, char** argv);
        mainPtr aMain = (mainPtr) *(int*) (vars + TOK_MAIN);
        if (!aMain) {
            fprintf(stderr, "Could not find function \"main\".\n");
            return -1;
        }
        return aMain(argc, argv);
    }

    int dump(FILE* out) {
        fwrite(codeBuf.getBase(), 1, codeBuf.getSize(), out);
        return 0;
    }

    int disassemble(FILE* out) {
        return pGen->disassemble(out);
    }

};

const char* compiler::operatorChars =
    "++--*@/@%@+@-@<<>><=>=<@>@==!=&&||&@^@|@~@!@";

const char compiler::operatorLevel[] =
    {11, 11, 1, 1, 1, 2, 2, 3, 3, 4, 4, 4, 4,
            5, 5, /* ==, != */
            9, 10, /* &&, || */
            6, 7, 8, /* & ^ | */
            2, 2 /* ~ ! */
            };

FILE* compiler::ARMCodeGenerator::disasmOut;

const int compiler::X86CodeGenerator::operatorHelper[] = {
        0x1,     // ++
        0xff,    // --
        0xc1af0f, // *
        0xf9f79991, // /
        0xf9f79991, // % (With manual assist to swap results)
        0xc801, // +
        0xd8f7c829, // -
        0xe0d391, // <<
        0xf8d391, // >>
        0xe, // <=
        0xd, // >=
        0xc, // <
        0xf, // >
        0x4, // ==
        0x5, // !=
        0x0, // &&
        0x1, // ||
        0xc821, // &
        0xc831, // ^
        0xc809, // |
        0xd0f7, // ~
        0x4     // !
};

} // namespace acc

// This is a separate function so it can easily be set by breakpoint in gdb.
int run(acc::compiler& c, int argc, char** argv) {
    return c.run(argc, argv);
}

int main(int argc, char** argv) {
    bool doDump = false;
    bool doDisassemble = false;
    const char* inFile = NULL;
    const char* outFile = NULL;
    const char* architecture = "arm";
    int i;
    for (i = 1; i < argc; i++) {
        char* arg = argv[i];
        if (arg[0] == '-') {
            switch (arg[1]) {
            case 'a':
                if (i + 1 >= argc) {
                    fprintf(stderr, "Expected architecture after -a\n");
                    return 2;
                }
                architecture = argv[i+1];
                i += 1;
                break;
            case 'd':
                if (i + 1 >= argc) {
                    fprintf(stderr, "Expected filename after -d\n");
                    return 2;
                }
                doDump = true;
                outFile = argv[i + 1];
                i += 1;
                break;
            case 'S':
                doDisassemble = true;
                break;
            default:
                fprintf(stderr, "Unrecognized flag %s\n", arg);
                return 3;
            }
        } else if (inFile == NULL) {
            inFile = arg;
        } else {
            break;
        }
    }

    FILE* in = stdin;
    if (inFile) {
        in = fopen(inFile, "r");
        if (!in) {
            fprintf(stderr, "Could not open input file %s\n", inFile);
            return 1;
        }
    }
    acc::compiler compiler;
    acc::compiler::args args;
    args.architecture = architecture;
    int compileResult = compiler.compile(in, args);
    if (in != stdin) {
        fclose(in);
    }
    if (compileResult) {
        fprintf(stderr, "Compile failed: %d\n", compileResult);
        return 6;
    }
    if (doDisassemble) {
        compiler.disassemble(stderr);
    }
    if (doDump) {
        FILE* save = fopen(outFile, "w");
        if (!save) {
            fprintf(stderr, "Could not open output file %s\n", outFile);
            return 5;
        }
        compiler.dump(save);
        fclose(save);
    } else {
        fprintf(stderr, "Executing compiled code:\n");
        int codeArgc = argc - i + 1;
        char** codeArgv = argv + i - 1;
        codeArgv[0] = (char*) (inFile ? inFile : "stdin");
        int result = run(compiler, codeArgc, codeArgv);
        fprintf(stderr, "result: %d\n", result);
        return result;
    }

    return 0;
}
