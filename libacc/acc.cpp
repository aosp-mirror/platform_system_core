/*
 * Android "Almost" C Compiler.
 * This is a compiler for a small subset of the C language, intended for use
 * in scripting environments where speed and memory footprint are important.
 *
 * This code is based upon the "unobfuscated" version of the
 * Obfuscated Tiny C compiler, see the file LICENSE for details.
 *
 */

#include <ctype.h>
#include <dlfcn.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cutils/hashmap.h>

#if defined(__arm__)
#include <unistd.h>
#endif

#if defined(__arm__)
#define DEFAULT_ARM_CODEGEN
#define PROVIDE_ARM_CODEGEN
#elif defined(__i386__)
#define DEFAULT_X86_CODEGEN
#define PROVIDE_X86_CODEGEN
#elif defined(__x86_64__)
#define DEFAULT_X64_CODEGEN
#define PROVIDE_X64_CODEGEN
#endif


#ifdef PROVIDE_ARM_CODEGEN
#include "disassem.h"
#endif

#include <acc/acc.h>

#define LOG_API(...) do {} while(0)
// #define LOG_API(...) fprintf (stderr, __VA_ARGS__)
// #define ENABLE_ARM_DISASSEMBLY

namespace acc {

class ErrorSink {
public:
    void error(const char *fmt, ...) {
        va_list ap;
        va_start(ap, fmt);
        verror(fmt, ap);
        va_end(ap);
    }

    virtual void verror(const char* fmt, va_list ap) = 0;
};

class Compiler : public ErrorSink {
    class CodeBuf {
        char* ind; // Output code pointer
        char* pProgramBase;
        ErrorSink* mErrorSink;
        int mSize;

        void release() {
            if (pProgramBase != 0) {
                free(pProgramBase);
                pProgramBase = 0;
            }
        }

        void check(int n) {
            int newSize = ind - pProgramBase + n;
            if (newSize > mSize) {
                if (mErrorSink) {
                    mErrorSink->error("Code too large: %d bytes", newSize);
                }
            }
        }

    public:
        CodeBuf() {
            pProgramBase = 0;
            ind = 0;
            mErrorSink = 0;
            mSize = 0;
        }

        ~CodeBuf() {
            release();
        }

        void init(int size) {
            release();
            mSize = size;
            pProgramBase = (char*) calloc(1, size);
            ind = pProgramBase;
        }

        void setErrorSink(ErrorSink* pErrorSink) {
            mErrorSink = pErrorSink;
        }

        int o4(int n) {
            check(4);
            intptr_t result = (intptr_t) ind;
            * (int*) ind = n;
            ind += 4;
            return result;
        }

        /*
         * Output a byte. Handles all values, 0..ff.
         */
        void ob(int n) {
            check(1);
            *ind++ = n;
        }

        inline void* getBase() {
            return (void*) pProgramBase;
        }

        intptr_t getSize() {
            return ind - pProgramBase;
        }

        intptr_t getPC() {
            return (intptr_t) ind;
        }
    };

    /**
     * A code generator creates an in-memory program, generating the code on
     * the fly. There is one code generator implementation for each supported
     * architecture.
     *
     * The code generator implements the following abstract machine:
     * R0 - the main accumulator.
     * R1 - the secondary accumulator.
     * FP - a frame pointer for accessing function arguments and local
     *      variables.
     * SP - a stack pointer for storing intermediate results while evaluating
     *      expressions. The stack pointer grows downwards.
     *
     * The function calling convention is that all arguments are placed on the
     * stack such that the first argument has the lowest address.
     * After the call, the result is in R0. The caller is responsible for
     * removing the arguments from the stack.
     * The R0 and R1 registers are not saved across function calls. The
     * FP and SP registers are saved.
     */

    class CodeGenerator {
    public:
        CodeGenerator() {
            mErrorSink = 0;
            pCodeBuf = 0;
        }
        virtual ~CodeGenerator() {}

        virtual void init(CodeBuf* pCodeBuf) {
            this->pCodeBuf = pCodeBuf;
            pCodeBuf->setErrorSink(mErrorSink);
        }

        void setErrorSink(ErrorSink* pErrorSink) {
            mErrorSink = pErrorSink;
            if (pCodeBuf) {
                pCodeBuf->setErrorSink(mErrorSink);
            }
        }

        /* Emit a function prolog.
         * argCount is the number of arguments.
         * Save the old value of the FP.
         * Set the new value of the FP.
         * Convert from the native platform calling convention to
         * our stack-based calling convention. This may require
         * pushing arguments from registers to the stack.
         * Allocate "N" bytes of stack space. N isn't known yet, so
         * just emit the instructions for adjusting the stack, and return
         * the address to patch up. The patching will be done in
         * functionExit().
         * returns address to patch with local variable size.
        */
        virtual int functionEntry(int argCount) = 0;

        /* Emit a function epilog.
         * Restore the old SP and FP register values.
         * Return to the calling function.
         * argCount - the number of arguments to the function.
         * localVariableAddress - returned from functionEntry()
         * localVariableSize - the size in bytes of the local variables.
         */
        virtual void functionExit(int argCount, int localVariableAddress,
                                  int localVariableSize) = 0;

        /* load immediate value to R0 */
        virtual void li(int t) = 0;

        /* Jump to a target, and return the address of the word that
         * holds the target data, in case it needs to be fixed up later.
         */
        virtual int gjmp(int t) = 0;

        /* Test R0 and jump to a target if the test succeeds.
         * l = 0: je, l == 1: jne
         * Return the address of the word that holds the targed data, in
         * case it needs to be fixed up later.
         */
        virtual int gtst(bool l, int t) = 0;

        /* Compare R1 against R0, and store the boolean result in R0.
         * op specifies the comparison.
         */
        virtual void gcmp(int op) = 0;

        /* Perform the arithmetic op specified by op. R1 is the
         * left argument, R0 is the right argument.
         */
        virtual void genOp(int op) = 0;

        /* Set R1 to 0.
         */
        virtual void clearR1() = 0;

        /* Push R0 onto the stack.
         */
        virtual void pushR0() = 0;

        /* Pop R1 off of the stack.
         */
        virtual void popR1() = 0;

        /* Store R0 to the address stored in R1.
         * isInt is true if a whole 4-byte integer value
         * should be stored, otherwise a 1-byte character
         * value should be stored.
         */
        virtual void storeR0ToR1(bool isInt) = 0;

        /* Load R0 from the address stored in R0.
         * isInt is true if a whole 4-byte integer value
         * should be loaded, otherwise a 1-byte character
         * value should be loaded.
         */
        virtual void loadR0FromR0(bool isInt) = 0;

        /* Load the absolute address of a variable to R0.
         * If ea <= LOCAL, then this is a local variable, or an
         * argument, addressed relative to FP.
         * else it is an absolute global address.
         */
        virtual void leaR0(int ea) = 0;

        /* Store R0 to a variable.
         * If ea <= LOCAL, then this is a local variable, or an
         * argument, addressed relative to FP.
         * else it is an absolute global address.
         */
        virtual void storeR0(int ea) = 0;

        /* load R0 from a variable.
         * If ea <= LOCAL, then this is a local variable, or an
         * argument, addressed relative to FP.
         * else it is an absolute global address.
         * If isIncDec is true, then the stored variable's value
         * should be post-incremented or post-decremented, based
         * on the value of op.
         */
        virtual void loadR0(int ea, bool isIncDec, int op) = 0;

        /* Emit code to adjust the stack for a function call. Return the
         * label for the address of the instruction that adjusts the
         * stack size. This will be passed as argument "a" to
         * endFunctionCallArguments.
         */
        virtual int beginFunctionCallArguments() = 0;

        /* Emit code to store R0 to the stack at byte offset l.
         */
        virtual void storeR0ToArg(int l) = 0;

        /* Patch the function call preamble.
         * a is the address returned from beginFunctionCallArguments
         * l is the number of bytes the arguments took on the stack.
         * Typically you would also emit code to convert the argument
         * list into whatever the native function calling convention is.
         * On ARM for example you would pop the first 5 arguments into
         * R0..R4
         */
        virtual void endFunctionCallArguments(int a, int l) = 0;

        /* Emit a call to an unknown function. The argument "symbol" needs to
         * be stored in the location where the address should go. It forms
         * a chain. The address will be patched later.
         * Return the address of the word that has to be patched.
         */
        virtual int callForward(int symbol) = 0;

        /* Call a function using PC-relative addressing. t is the PC-relative
         * address of the function. It has already been adjusted for the
         * architectural jump offset, so just store it as-is.
         */
        virtual void callRelative(int t) = 0;

        /* Call a function pointer. L is the number of bytes the arguments
         * take on the stack. The address of the function is stored at
         * location SP + l.
         */
        virtual void callIndirect(int l) = 0;

        /* Adjust SP after returning from a function call. l is the
         * number of bytes of arguments stored on the stack. isIndirect
         * is true if this was an indirect call. (In which case the
         * address of the function is stored at location SP + l.)
         */
        virtual void adjustStackAfterCall(int l, bool isIndirect) = 0;

        /* Print a disassembly of the assembled code to out. Return
         * non-zero if there is an error.
         */
        virtual int disassemble(FILE* out) = 0;

        /* Generate a symbol at the current PC. t is the head of a
         * linked list of addresses to patch.
         */
        virtual void gsym(int t) = 0;

        /*
         * Do any cleanup work required at the end of a compile.
         * For example, an instruction cache might need to be
         * invalidated.
         * Return non-zero if there is an error.
         */
        virtual int finishCompile() = 0;

        /**
         * Adjust relative branches by this amount.
         */
        virtual int jumpOffset() = 0;

    protected:
        /*
         * Output a byte. Handles all values, 0..ff.
         */
        void ob(int n) {
            pCodeBuf->ob(n);
        }

        intptr_t o4(int data) {
            return pCodeBuf->o4(data);
        }

        intptr_t getBase() {
            return (intptr_t) pCodeBuf->getBase();
        }

        intptr_t getPC() {
            return pCodeBuf->getPC();
        }

        intptr_t getSize() {
            return pCodeBuf->getSize();
        }

        void error(const char* fmt,...) {
            va_list ap;
            va_start(ap, fmt);
            mErrorSink->verror(fmt, ap);
            va_end(ap);
        }
    private:
        CodeBuf* pCodeBuf;
        ErrorSink* mErrorSink;
    };

#ifdef PROVIDE_ARM_CODEGEN

    class ARMCodeGenerator : public CodeGenerator {
    public:
        ARMCodeGenerator() {}
        virtual ~ARMCodeGenerator() {}

        /* returns address to patch with local variable size
        */
        virtual int functionEntry(int argCount) {
            LOG_API("functionEntry(%d);\n", argCount);
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
            LOG_API("functionExit(%d, %d, %d);\n", argCount, localVariableAddress, localVariableSize);
            // Patch local variable allocation code:
            if (localVariableSize < 0 || localVariableSize > 255) {
                error("localVariables out of range: %d", localVariableSize);
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
                // returning. We need to pull off the registers we pushed
                // earlier. We don't need to actually store them anywhere,
                // just adjust the stack.
                int regArgCount = argCount <= 4 ? argCount : 4;
                o4(0xE28DD000 | (regArgCount << 2)); // add sp, sp, #argCount << 2
            }
            o4(0xE12FFF1E); // bx lr
        }

        /* load immediate value */
        virtual void li(int t) {
            LOG_API("li(%d);\n", t);
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
            LOG_API("gjmp(%d);\n", t);
            return o4(0xEA000000 | encodeAddress(t)); // b .L33
        }

        /* l = 0: je, l == 1: jne */
        virtual int gtst(bool l, int t) {
            LOG_API("gtst(%d, %d);\n", l, t);
            o4(0xE3500000); // cmp r0,#0
            int branch = l ? 0x1A000000 : 0x0A000000; // bne : beq
            return o4(branch | encodeAddress(t));
        }

        virtual void gcmp(int op) {
            LOG_API("gcmp(%d);\n", op);
            o4(0xE1510000); // cmp r1, r1
            switch(op) {
            case OP_EQUALS:
                o4(0x03A00001); // moveq r0,#1
                o4(0x13A00000); // movne r0,#0
                break;
            case OP_NOT_EQUALS:
                o4(0x03A00000); // moveq r0,#0
                o4(0x13A00001); // movne r0,#1
                break;
            case OP_LESS_EQUAL:
                o4(0xD3A00001); // movle r0,#1
                o4(0xC3A00000); // movgt r0,#0
                break;
            case OP_GREATER:
                o4(0xD3A00000); // movle r0,#0
                o4(0xC3A00001); // movgt r0,#1
                break;
            case OP_GREATER_EQUAL:
                o4(0xA3A00001); // movge r0,#1
                o4(0xB3A00000); // movlt r0,#0
                break;
            case OP_LESS:
                o4(0xA3A00000); // movge r0,#0
                o4(0xB3A00001); // movlt r0,#1
                break;
            default:
                error("Unknown comparison op %d", op);
                break;
            }
        }

        virtual void genOp(int op) {
            LOG_API("genOp(%d);\n", op);
            switch(op) {
            case OP_MUL:
                o4(0x0E0000091); // mul     r0,r1,r0
                break;
            case OP_DIV:
                callRuntime(runtime_DIV);
                break;
            case OP_MOD:
                callRuntime(runtime_MOD);
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

        virtual void clearR1() {
            LOG_API("clearR1();\n");
            o4(0xE3A01000);  // mov    r1, #0
        }

        virtual void pushR0() {
            LOG_API("pushR0();\n");
            o4(0xE92D0001);  // stmfd   sp!,{r0}
        }

        virtual void popR1() {
            LOG_API("popR1();\n");
            o4(0xE8BD0002);  // ldmfd   sp!,{r1}
        }

        virtual void storeR0ToR1(bool isInt) {
            LOG_API("storeR0ToR1(%d);\n", isInt);
            if (isInt) {
                o4(0xE5810000); // str r0, [r1]
            } else {
                o4(0xE5C10000); // strb r0, [r1]
            }
        }

        virtual void loadR0FromR0(bool isInt) {
            LOG_API("loadR0FromR0(%d);\n", isInt);
            if (isInt)
                o4(0xE5900000); // ldr r0, [r0]
            else
                o4(0xE5D00000); // ldrb r0, [r0]
        }

        virtual void leaR0(int ea) {
            LOG_API("leaR0(%d);\n", ea);
            if (ea < LOCAL) {
                // Local, fp relative
                if (ea < -1023 || ea > 1023 || ((ea & 3) != 0)) {
                    error("Offset out of range: %08x", ea);
                }
                if (ea < 0) {
                    o4(0xE24B0F00 | (0xff & ((-ea) >> 2))); // sub    r0, fp, #ea
                } else {
                    o4(0xE28B0F00 | (0xff & (ea >> 2))); // add    r0, fp, #ea
                }
            } else {
                // Global, absolute.
                o4(0xE59F0000); //        ldr    r0, .L1
                o4(0xEA000000); //        b .L99
                o4(ea);         // .L1:   .word 0
                                // .L99:
            }
        }

        virtual void storeR0(int ea) {
            LOG_API("storeR0(%d);\n", ea);
            if (ea < LOCAL) {
                // Local, fp relative
                if (ea < -4095 || ea > 4095) {
                    error("Offset out of range: %08x", ea);
                }
                if (ea < 0) {
                    o4(0xE50B0000 | (0xfff & (-ea))); // str r0, [fp,#-ea]
                } else {
                    o4(0xE58B0000 | (0xfff & ea)); // str r0, [fp,#ea]
                }
            } else{
                // Global, absolute
                o4(0xE59F1000); //         ldr r1, .L1
                o4(0xEA000000); //         b .L99
                o4(ea);         // .L1:    .word 0
                o4(0xE5810000); // .L99:   str r0, [r1]
            }
        }

        virtual void loadR0(int ea, bool isIncDec, int op) {
            LOG_API("loadR0(%d, %d, %d);\n", ea, isIncDec, op);
            if (ea < LOCAL) {
                // Local, fp relative
                if (ea < -4095 || ea > 4095) {
                    error("Offset out of range: %08x", ea);
                }
                if (ea < 0) {
                    o4(0xE51B0000 | (0xfff & (-ea))); // ldr r0, [fp,#-ea]
                } else {
                    o4(0xE59B0000 | (0xfff & ea));    // ldr r0, [fp,#ea]
                }
            } else {
                // Global, absolute
                o4(0xE59F2000); //        ldr r2, .L1
                o4(0xEA000000); //        b .L99
                o4(ea);         // .L1:   .word ea
                o4(0xE5920000); // .L99:  ldr r0, [r2]
            }

            if (isIncDec) {
                switch (op) {
                case OP_INCREMENT:
                    o4(0xE2801001); // add r1, r0, #1
                    break;
                case OP_DECREMENT:
                    o4(0xE2401001); // sub r1, r0, #1
                    break;
                default:
                    error("unknown opcode: %d", op);
                }
                if (ea < LOCAL) {
                    // Local, fp relative
                    // Don't need range check, was already checked above
                    if (ea < 0) {
                        o4(0xE50B1000 | (0xfff & (-ea))); // str r1, [fp,#-ea]
                    } else {
                        o4(0xE58B1000 | (0xfff & ea));    // str r1, [fp,#ea]
                    }
                } else{
                    // Global, absolute
                    // r2 is already set up from before.
                    o4(0xE5821000); // str r1, [r2]
               }
            }
        }

        virtual int beginFunctionCallArguments() {
            LOG_API("beginFunctionCallArguments();\n");
            return o4(0xE24DDF00); // Placeholder
        }

        virtual void storeR0ToArg(int l) {
            LOG_API("storeR0ToArg(%d);\n", l);
            if (l < 0 || l > 4096-4) {
                error("l out of range for stack offset: 0x%08x", l);
            }
            o4(0xE58D0000 + l); // str r0, [sp, #4]
        }

        virtual void endFunctionCallArguments(int a, int l) {
            LOG_API("endFunctionCallArguments(0x%08x, %d);\n", a, l);
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

        virtual int callForward(int symbol) {
            LOG_API("callForward(%d);\n", symbol);
            // Forward calls are always short (local)
            return o4(0xEB000000 | encodeAddress(symbol));
        }

        virtual void callRelative(int t) {
            LOG_API("callRelative(%d);\n", t);
            int abs = t + getPC() + jumpOffset();
            LOG_API("abs=%d (0x%08x)\n", abs, abs);
            if (t >= - (1 << 25) && t < (1 << 25)) {
                o4(0xEB000000 | encodeAddress(t));
            } else {
                // Long call.
                o4(0xE59FC000); //         ldr    r12, .L1
                o4(0xEA000000); //         b .L99
                o4(t - 12);     // .L1:    .word 0
                o4(0xE08CC00F); // .L99:   add r12,pc
                o4(0xE12FFF3C); //         blx r12
           }
        }

        virtual void callIndirect(int l) {
            LOG_API("callIndirect(%d);\n", l);
            int argCount = l >> 2;
            int poppedArgs = argCount > 4 ? 4 : argCount;
            int adjustedL = l - (poppedArgs << 2);
            if (adjustedL < 0 || adjustedL > 4096-4) {
                error("l out of range for stack offset: 0x%08x", l);
            }
            o4(0xE59DC000 | (0xfff & adjustedL)); // ldr    r12, [sp,#adjustedL]
            o4(0xE12FFF3C); // blx r12
        }

        virtual void adjustStackAfterCall(int l, bool isIndirect) {
            LOG_API("adjustStackAfterCall(%d, %d);\n", l, isIndirect);
            int argCount = l >> 2;
            int stackArgs = argCount > 4 ? argCount - 4 : 0;
            int stackUse = stackArgs + (isIndirect ? 1 : 0);
            if (stackUse) {
                if (stackUse < 0 || stackUse > 255) {
                    error("L out of range for stack adjustment: 0x%08x", l);
                }
                o4(0xE28DDF00 | stackUse); // add    sp, sp, #stackUse << 2
            }
        }

        virtual int jumpOffset() {
            return 8;
        }

        /* output a symbol and patch all calls to it */
        virtual void gsym(int t) {
            LOG_API("gsym(0x%x)\n", t);
            int n;
            int base = getBase();
            int pc = getPC();
            LOG_API("pc = 0x%x\n", pc);
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

        virtual int finishCompile() {
#if defined(__arm__)
            const long base = long(getBase());
            const long curr = long(getPC());
            int err = cacheflush(base, curr, 0);
            return err;
#else
            return 0;
#endif
        }

        virtual int disassemble(FILE* out) {
#ifdef ENABLE_ARM_DISASSEMBLY
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
#endif
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

        typedef int (*int2FnPtr)(int a, int b);
        void callRuntime(int2FnPtr fn) {
            o4(0xE59F2000); // ldr    r2, .L1
            o4(0xEA000000); // b      .L99
            o4((int) fn);   //.L1:  .word  fn
            o4(0xE12FFF32); //.L99: blx    r2
        }

        static int runtime_DIV(int a, int b) {
            return b / a;
        }

        static int runtime_MOD(int a, int b) {
            return b % a;
        }
    };

#endif // PROVIDE_ARM_CODEGEN

#ifdef PROVIDE_X86_CODEGEN

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

        virtual void clearR1() {
            oad(0xb9, 0); /* movl $0, %ecx */
        }

        virtual void pushR0() {
            o(0x50); /* push %eax */
        }

        virtual void popR1() {
            o(0x59); /* pop %ecx */
        }

        virtual void storeR0ToR1(bool isInt) {
            o(0x0188 + isInt); /* movl %eax/%al, (%ecx) */
        }

        virtual void loadR0FromR0(bool isInt) {
            if (isInt)
                o(0x8b); /* mov (%eax), %eax */
            else
                o(0xbe0f); /* movsbl (%eax), %eax */
            ob(0); /* add zero in code */
        }

        virtual void leaR0(int ea) {
            gmov(10, ea); /* leal EA, %eax */
        }

        virtual void storeR0(int ea) {
            gmov(6, ea); /* mov %eax, EA */
        }

        virtual void loadR0(int ea, bool isIncDec, int op) {
            gmov(8, ea); /* mov EA, %eax */
            if (isIncDec) {
                /* Implement post-increment or post decrement.
                 */
                gmov(0, ea); /* 83 ADD */
                o(decodeOp(op));
            }
        }

        virtual int beginFunctionCallArguments() {
            return oad(0xec81, 0); /* sub $xxx, %esp */
        }

        virtual void storeR0ToArg(int l) {
            oad(0x248489, l); /* movl %eax, xxx(%esp) */
        }

        virtual void endFunctionCallArguments(int a, int l) {
            * (int*) a = l;
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

        virtual void adjustStackAfterCall(int l, bool isIndirect) {
            if (isIndirect) {
                l += 4;
            }
            oad(0xc481, l); /* add $xxx, %esp */
        }

        virtual int jumpOffset() {
            return 5;
        }

        virtual int disassemble(FILE* out) {
            return 0;
        }

        /* output a symbol and patch all calls to it */
        virtual void gsym(int t) {
            int n;
            int pc = getPC();
            while (t) {
                n = *(int *) t; /* next value */
                *(int *) t = pc - t - 4;
                t = n;
            }
        }

        virtual int finishCompile() {
            return 0;
        }

    private:

        /** Output 1 to 4 bytes.
         *
         */
        void o(int n) {
            /* cannot use unsigned, so we must do a hack */
            while (n && n != -1) {
                ob(n & 0xff);
                n = n >> 8;
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
            int result = getPC();
            o4(t);
            return result;
        }


        static const int operatorHelper[];

        int decodeOp(int op) {
            if (op < 0 || op > OP_COUNT) {
                error("Out-of-range operator: %d\n", op);
            }
            return operatorHelper[op];
        }

        void gmov(int l, int t) {
            o(l + 0x83);
            oad((t < LOCAL) << 7 | 5, t);
        }
    };

#endif // PROVIDE_X86_CODEGEN

    class InputStream {
    public:
        int getChar() {
            if (bumpLine) {
                line++;
                bumpLine = false;
            }
            int ch = get();
            if (ch == '\n') {
                bumpLine = true;
            }
            return ch;
        }
        int getLine() {
            return line;
        }
    protected:
        InputStream() :
            line(1), bumpLine(false) {
        }
    private:
        virtual int get() = 0;
        int line;
        bool bumpLine;
    };

    class FileInputStream : public InputStream {
    public:
        FileInputStream(FILE* in) : f(in) {}
    private:
        virtual int get() { return fgetc(f); }
        FILE* f;
    };

    class TextInputStream : public InputStream {
    public:
        TextInputStream(const char* text, size_t textLength)
            : pText(text), mTextLength(textLength), mPosition(0) {
        }

    private:
        virtual int get() {
            return mPosition < mTextLength ? pText[mPosition++] : EOF;
        }

        const char* pText;
        size_t mTextLength;
        size_t mPosition;
    };

    int ch; // Current input character, or EOF
    intptr_t tok;     // token
    intptr_t tokc;    // token extra info
    int tokl;         // token operator level
    intptr_t rsym; // return symbol
    intptr_t loc; // local variable index
    char* glo;  // global variable index
    char* sym_stk;
    char* dstk; // Define stack
    char* dptr; // Macro state: Points to macro text during macro playback.
    int dch;    // Macro state: Saves old value of ch during a macro playback.
    char* last_id;
    char* pGlobalBase;
    char* pVarsBase; // Value of variables

    InputStream* file;

    CodeBuf codeBuf;
    CodeGenerator* pGen;

    class String {
    public:
        String() {
            mpBase = 0;
            mUsed = 0;
            mSize = 0;
        }

        String(char* item, int len, bool adopt) {
            if (adopt) {
                mpBase = item;
                mUsed = len;
                mSize = len + 1;
            } else {
                mpBase = 0;
                mUsed = 0;
                mSize = 0;
                appendBytes(item, len);
            }
        }

        ~String() {
            if (mpBase) {
                free(mpBase);
            }
        }

        inline char* getUnwrapped() {
            return mpBase;
        }

        void appendCStr(const char* s) {
            appendBytes(s, strlen(s));
        }

        void appendBytes(const char* s, int n) {
            memcpy(ensure(n), s, n + 1);
        }

        void append(char c) {
            * ensure(1) = c;
        }

        char* orphan() {
            char* result = mpBase;
            mpBase = 0;
            mUsed = 0;
            mSize = 0;
            return result;
        }

        void printf(const char* fmt,...) {
            va_list ap;
            va_start(ap, fmt);
            vprintf(fmt, ap);
            va_end(ap);
        }

        void vprintf(const char* fmt, va_list ap) {
            char* temp;
            int numChars = vasprintf(&temp, fmt, ap);
            memcpy(ensure(numChars), temp, numChars+1);
            free(temp);
        }

        inline size_t len() {
            return mUsed;
        }

    private:
        char* ensure(int n) {
            size_t newUsed = mUsed + n;
            if (newUsed > mSize) {
                size_t newSize = mSize * 2 + 10;
                if (newSize < newUsed) {
                    newSize = newUsed;
                }
                mpBase = (char*) realloc(mpBase, newSize + 1);
                mSize = newSize;
            }
            mpBase[newUsed] = '\0';
            char* result = mpBase + mUsed;
            mUsed = newUsed;
            return result;
        }

        char* mpBase;
        size_t mUsed;
        size_t mSize;
    };

    /**
     * Wrap an externally allocated string for use as a hash key.
     */
    class FakeString : public String {
    public:
        FakeString(char* string, size_t length) :
            String(string, length, true) {}

        ~FakeString() {
            orphan();
        }
    };

    template<class V> class StringTable {
    public:
        StringTable(size_t initialCapacity) {
            mpMap = hashmapCreate(initialCapacity, hashFn, equalsFn);
        }

        ~StringTable() {
            clear();
        }

        void clear() {
            hashmapForEach(mpMap, freeKeyValue, this);
        }

        bool contains(String* pKey) {
            bool result = hashmapContainsKey(mpMap, pKey);
            return result;
        }

        V* get(String* pKey) {
            V* result = (V*) hashmapGet(mpMap, pKey);
            return result;
        }

        V* remove(String* pKey) {
            V* result = (V*) hashmapRemove(mpMap, pKey);
            return result;
        }

        V* put(String* pKey, V* value) {
            V* result = (V*) hashmapPut(mpMap, pKey, value);
            if (result) {
                // The key was not adopted by the map, so delete it here.
                delete pKey;
            }
            return result;
        }

    protected:
        static int hashFn(void* pKey) {
            String* pString = (String*) pKey;
            return hashmapHash(pString->getUnwrapped(), pString->len());
        }

        static bool equalsFn(void* keyA, void* keyB) {
            String* pStringA = (String*) keyA;
            String* pStringB = (String*) keyB;
            return pStringA->len() == pStringB->len()
                && strcmp(pStringA->getUnwrapped(), pStringB->getUnwrapped())
                    == 0;
        }

        static bool freeKeyValue(void* key, void* value, void* context) {
            delete (String*) key;
            delete (V*) value;
            return true;
        }

        Hashmap* mpMap;
    };

    class MacroTable : public StringTable<String> {
    public:
        MacroTable() : StringTable<String>(10) {}
    };

    template<class E> class Array {
        public:
        Array() {
            mpBase = 0;
            mUsed = 0;
            mSize = 0;
        }

        ~Array() {
            if (mpBase) {
                free(mpBase);
            }
        }

        E get(int i) {
            if (i < 0 || i > mUsed) {
                error("internal error: Index out of range");
                return E();
            }
            return mpBase[i];
        }

        void set(int i, E val) {
            mpBase[i] =  val;
        }

        void pop() {
            if (mUsed > 0) {
                mUsed -= 1;
            }
        }

        void push(E item) {
            * ensure(1) = item;
        }

        size_t len() {
            return mUsed;
        }

    private:
        E* ensure(int n) {
            size_t newUsed = mUsed + n;
            if (newUsed > mSize) {
                size_t newSize = mSize * 2 + 10;
                if (newSize < newUsed) {
                    newSize = newUsed;
                }
                mpBase = (E*) realloc(mpBase, sizeof(E) * newSize);
                mSize = newSize;
            }
            E* result = mpBase + mUsed;
            mUsed = newUsed;
            return result;
        }

        E* mpBase;
        size_t mUsed;
        size_t mSize;
    };

    MacroTable mMacros;

    String mErrorBuf;

    jmp_buf mErrorRecoveryJumpBuf;

    String mPragmas;
    int mPragmaStringCount;

    static const int ALLOC_SIZE = 99999;

    // Indentifiers start at 0x100 and increase by # (chars + 1) * 8
    static const int TOK_IDENT = 0x100;
    static const int TOK_INT = 0x100;
    static const int TOK_CHAR = TOK_INT + 4*8;
    static const int TOK_VOID = TOK_CHAR + 5*8;
    static const int TOK_IF = TOK_VOID + 5*8;
    static const int TOK_ELSE = TOK_IF + 3*8;
    static const int TOK_WHILE = TOK_ELSE + 5*8;
    static const int TOK_BREAK = TOK_WHILE + 6*8;
    static const int TOK_RETURN = TOK_BREAK + 6*8;
    static const int TOK_FOR = TOK_RETURN + 7*8;
    static const int TOK_PRAGMA = TOK_FOR + 4*8;
    static const int TOK_DEFINE = TOK_PRAGMA + 7*8;
    static const int TOK_MAIN = TOK_DEFINE + 7*8;

    static const int TOK_DUMMY = 1;
    static const int TOK_NUM = 2;

    static const int LOCAL = 0x200;

    static const int SYM_FORWARD = 0;
    static const int SYM_DEFINE = 1;

    /* tokens in string heap */
    static const int TAG_TOK = ' ';

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
        if (dstk - sym_stk >= ALLOC_SIZE) {
            error("Symbol table exhausted");
        }
        *dstk++ = t;
    }

    void inp() {
        if (dptr) {
            ch = *dptr++;
            if (ch == 0) {
                dptr = 0;
                ch = dch;
            }
        } else
            ch = file->getChar();
#if 0
        printf("ch='%c' 0x%x\n", ch, ch);
#endif
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
                    doDefine();
                } else if (tok == TOK_PRAGMA) {
                    doPragma();
                } else {
                    error("Unsupported preprocessor directive \"%s\"", last_id);
                }

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
                tokc = strtol(last_id, 0, 0);
                tok = TOK_NUM;
            } else {
                if (dstk - sym_stk + 1 > ALLOC_SIZE) {
                    error("symbol stack overflow");
                }
                FakeString token(last_id, dstk-last_id);
                // Is this a macro?
                String* pValue = mMacros.get(&token);
                if (pValue) {
                    // Yes, it is a macro
                    dstk = last_id-1;
                    dptr = pValue->getUnwrapped();
                    dch = ch;
                    inp();
                    next();
                } else {
                    * dstk = TAG_TOK; /* no need to mark end of string (we
                     suppose data is initialized to zero by calloc) */
                    tok = (intptr_t) (strstr(sym_stk, (last_id - 1))
                            - sym_stk);
                    * dstk = 0; /* mark real end of ident for dlsym() */
                    tok = tok * 8 + TOK_IDENT;
                    if (tok > TOK_DEFINE) {
                        if (tok + 8 > ALLOC_SIZE) {
                            error("Variable Table overflow.");
                        }
                        tok = (intptr_t) (pVarsBase + tok);
                        /*        printf("tok=%s %x\n", last_id, tok); */
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
            } else if ((tok == '/') & (ch == '/')) {
                inp();
                while (ch && (ch != '\n')) {
                    inp();
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
            char* p;

            printf("tok=0x%x ", tok);
            if (tok >= TOK_IDENT) {
                printf("'");
                if (tok> TOK_DEFINE)
                p = sym_stk + 1 + ((char*) tok - pVarsBase - TOK_IDENT) / 8;
                else
                p = sym_stk + 1 + (tok - TOK_IDENT) / 8;
                while (*p != TAG_TOK && *p)
                printf("%c", *p++);
                printf("'\n");
            } else if (tok == TOK_NUM) {
                printf("%d\n", tokc);
            } else {
                printf("'%c'\n", tok);
            }
        }
#endif
    }

    void doDefine() {
        String* pName = new String();
        while (isspace(ch)) {
            inp();
        }
        while (isid()) {
            pName->append(ch);
            inp();
        }
        if (ch == '(') {
            delete pName;
            error("Defines with arguments not supported");
        }
        while (isspace(ch)) {
            inp();
        }
        String* pValue = new String();
        while (ch != '\n' && ch != EOF) {
            pValue->append(ch);
            inp();
        }
        delete mMacros.put(pName, pValue);
    }

    void doPragma() {
        // # pragma name(val)
        int state = 0;
        while(ch != EOF && ch != '\n' && state < 10) {
            switch(state) {
                case 0:
                    if (isspace(ch)) {
                        inp();
                    } else {
                        state++;
                    }
                    break;
                case 1:
                    if (isalnum(ch)) {
                        mPragmas.append(ch);
                        inp();
                    } else if (ch == '(') {
                        mPragmas.append(0);
                        inp();
                        state++;
                    } else {
                        state = 11;
                    }
                    break;
                case 2:
                    if (isalnum(ch)) {
                        mPragmas.append(ch);
                        inp();
                    } else if (ch == ')') {
                        mPragmas.append(0);
                        inp();
                        state = 10;
                    } else {
                        state = 11;
                    }
                    break;
            }
        }
        if(state != 10) {
            error("Unexpected pragma syntax");
        }
        mPragmaStringCount += 2;
    }

    virtual void verror(const char* fmt, va_list ap) {
        mErrorBuf.printf("%ld: ", file->getLine());
        mErrorBuf.vprintf(fmt, ap);
        mErrorBuf.printf("\n");
        longjmp(mErrorRecoveryJumpBuf, 1);
    }

    void skip(intptr_t c) {
        if (tok != c) {
            error("'%c' expected", c);
        }
        next();
    }

    /* l is one if '=' parsing wanted (quick hack) */
    void unary(intptr_t l) {
        intptr_t n, t, a;
        int c;
        t = 0;
        n = 1; /* type of expression 0 = forward, 1 = value, other =
         lvalue */
        if (tok == '\"') {
            pGen->li((int) glo);
            while (ch != '\"') {
                getq();
                *allocGlobalSpace(1) = ch;
                inp();
            }
            *glo = 0;
            /* align heap */
            allocGlobalSpace((char*) (((intptr_t) glo + 4) & -4) - glo);
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
                pGen->clearR1();
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
                    pGen->pushR0();
                    expr();
                    pGen->popR1();
                    pGen->storeR0ToR1(t == TOK_INT);
                } else if (t) {
                    pGen->loadR0FromR0(t == TOK_INT);
                }
            } else if (t == '&') {
                pGen->leaR0(*(int *) tok);
                next();
            } else {
                n = *(int *) t;
                /* forward reference: try dlsym */
                if (!n) {
                    n = (intptr_t) dlsym(RTLD_DEFAULT, last_id);
                }
                if ((tok == '=') & l) {
                    /* assignment */
                    next();
                    expr();
                    pGen->storeR0(n);
                } else if (tok != '(') {
                    /* variable */
                    pGen->loadR0(n, tokl == 11, tokc);
                    if (tokl == 11) {
                        next();
                    }
                }
            }
        }

        /* function call */
        if (tok == '(') {
            if (n == 1)
                pGen->pushR0();

            /* push args and invert order */
            a = pGen->beginFunctionCallArguments();
            next();
            l = 0;
            while (tok != ')') {
                expr();
                pGen->storeR0ToArg(l);
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
            } else {
                pGen->callRelative(n - codeBuf.getPC() - pGen->jumpOffset());
            }
            if (l | (n == 1))
                pGen->adjustStackAfterCall(l, n == 1);
        }
    }

    void sum(int l) {
        intptr_t t, n, a;
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
                    pGen->pushR0();
                    sum(l);
                    pGen->popR1();

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

    void block(intptr_t l) {
        intptr_t a, n, t;

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
            block((intptr_t) &a);
            pGen->gjmp(n - codeBuf.getPC() - pGen->jumpOffset()); /* jmp */
            pGen->gsym(a);
        } else if (tok == '{') {
            next();
            /* declarations */
            localDeclarations();
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

    typedef int Type;
    static const Type TY_UNKNOWN = 0;
    static const Type TY_INT = 1;
    static const Type TY_CHAR = 2;
    static const Type TY_VOID = 3;
    static const int TY_BASE_TYPE_MASK = 0xf;
    static const int TY_INDIRECTION_MASK = 0xf0;
    static const int TY_INDIRECTION_SHIFT = 4;
    static const int MAX_INDIRECTION_COUNT = 15;

    Type getBaseType(Type t) {
        return t & TY_BASE_TYPE_MASK;
    }

    int getIndirectionCount(Type t) {
        return (TY_INDIRECTION_MASK & t) >> TY_INDIRECTION_SHIFT;
    }

    void setIndirectionCount(Type& t, int count) {
        t = ((TY_INDIRECTION_MASK & (count << TY_INDIRECTION_SHIFT))
                | (t & ~TY_INDIRECTION_MASK));
    }

    bool acceptType(Type& t) {
        t = TY_UNKNOWN;
        if (tok == TOK_INT) {
            t = TY_INT;
        } else if (tok == TOK_CHAR) {
            t = TY_CHAR;
        } else if (tok == TOK_VOID) {
            t = TY_VOID;
        } else {
            return false;
        }
        next();
        return true;
    }

    Type acceptPointerDeclaration(Type& base) {
        Type t = base;
        int indirectionCount = 0;
        while (tok == '*' && indirectionCount <= MAX_INDIRECTION_COUNT) {
            next();
            indirectionCount++;
        }
        if (indirectionCount > MAX_INDIRECTION_COUNT) {
            error("Too many levels of pointer. Max %d", MAX_INDIRECTION_COUNT);
        }
        setIndirectionCount(t, indirectionCount);
        return t;
    }

    void expectType(Type& t) {
        if (!acceptType(t)) {
            error("Expected a type.");
        }
    }

    void checkSymbol() {
        if (tok <= TOK_DEFINE) {
            error("Expected a symbol");
        }
    }

    void localDeclarations() {
        intptr_t a;
        Type base;

        while (acceptType(base)) {
            while (tok != ';') {
                Type t = acceptPointerDeclaration(t);
                checkSymbol();
                loc = loc + 4;
                *(int *) tok = -loc;

                next();
                if (tok == ',')
                    next();
            }
            skip(';');
        }
    }

    void globalDeclarations() {
        while (tok != EOF) {
            Type base;
            expectType(base);
            Type t = acceptPointerDeclaration(t);
            checkSymbol();
            int name = tok;
            next();
            if (tok == ',' || tok == ';') {
                // it's a variable declaration
                for(;;) {
                    *(int* *) name = (int*) allocGlobalSpace(4);
                    if (tok != ',') {
                        break;
                    }
                    next();
                    t = acceptPointerDeclaration(t);
                    checkSymbol();
                    name = tok;
                    next();
                }
                skip(';');
            } else {
                /* patch forward references (XXX: does not work for function
                 pointers) */
                pGen->gsym(*(int *) (name + 4));
                /* put function address */
                *(int *) name = codeBuf.getPC();
                skip('(');
                intptr_t a = 8;
                int argCount = 0;
                while (tok != ')') {
                    Type aType;
                    expectType(aType);
                    aType = acceptPointerDeclaration(aType);
                    checkSymbol();
                    /* read param name and compute offset */
                    *(int *) tok = a;
                    a = a + 4;
                    next();
                    if (tok == ',')
                        next();
                    argCount++;
                }
                skip(')'); /* skip ')' */
                rsym = loc = 0;
                a = pGen->functionEntry(argCount);
                block(0);
                pGen->gsym(rsym);
                pGen->functionExit(argCount, a, loc);
            }
        }
    }

    char* allocGlobalSpace(int bytes) {
        if (glo - pGlobalBase + bytes > ALLOC_SIZE) {
            error("Global space exhausted");
        }
        char* result = glo;
        glo += bytes;
        return result;
    }

    void cleanup() {
        if (sym_stk != 0) {
            free(sym_stk);
            sym_stk = 0;
        }
        if (pGlobalBase != 0) {
            free(pGlobalBase);
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
        if (file) {
            delete file;
            file = 0;
        }
    }

    void clear() {
        tok = 0;
        tokc = 0;
        tokl = 0;
        ch = 0;
        pVarsBase = 0;
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
        mPragmaStringCount = 0;
    }

    void setArchitecture(const char* architecture) {
        delete pGen;
        pGen = 0;

        if (architecture != NULL) {
#ifdef PROVIDE_ARM_CODEGEN
            if (! pGen && strcmp(architecture, "arm") == 0) {
                pGen = new ARMCodeGenerator();
            }
#endif
#ifdef PROVIDE_X86_CODEGEN
            if (! pGen && strcmp(architecture, "x86") == 0) {
                pGen = new X86CodeGenerator();
            }
#endif
            if (!pGen ) {
                error("Unknown architecture %s\n", architecture);
            }
        }

        if (pGen == NULL) {
#if defined(DEFAULT_ARM_CODEGEN)
            pGen = new ARMCodeGenerator();
#elif defined(DEFAULT_X86_CODEGEN)
            pGen = new X86CodeGenerator();
#endif
        }
        if (pGen == NULL) {
            error("No code generator defined.");
        }
        pGen->setErrorSink(this);
    }

public:
    struct args {
        args() {
            architecture = 0;
        }
        const char* architecture;
    };

    Compiler() {
        clear();
    }

    ~Compiler() {
        cleanup();
    }

    int compile(const char* text, size_t textLength) {
        int result;
        if (! (result = setjmp(mErrorRecoveryJumpBuf))) {
            cleanup();
            clear();
            codeBuf.init(ALLOC_SIZE);
            setArchitecture(NULL);
            if (!pGen) {
                return -1;
            }
            pGen->init(&codeBuf);
            file = new TextInputStream(text, textLength);
            sym_stk = (char*) calloc(1, ALLOC_SIZE);
            static const char* predefinedSymbols =
                " int char void"
                " if else while break return for"
                " pragma define main ";
            dstk = strcpy(sym_stk, predefinedSymbols)
                    + strlen(predefinedSymbols);
            pGlobalBase = (char*) calloc(1, ALLOC_SIZE);
            glo = pGlobalBase;
            pVarsBase = (char*) calloc(1, ALLOC_SIZE);
            inp();
            next();
            globalDeclarations();
            pGen->finishCompile();
        }
        return result;
    }

    int run(int argc, char** argv) {
        typedef int (*mainPtr)(int argc, char** argv);
        mainPtr aMain = (mainPtr) *(int*) (pVarsBase + TOK_MAIN);
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

    /* Look through the symbol table to find a symbol.
     * If found, return its value.
     */
    void* lookup(const char* name) {
        if (!sym_stk) {
            return NULL;
        }
        size_t nameLen = strlen(name);
        char* pSym = sym_stk;
        char c;
        for(;;) {
            c = *pSym++;
            if (c == 0) {
                break;
            }
            if (c == TAG_TOK) {
                if (memcmp(pSym, name, nameLen) == 0
                        && pSym[nameLen] == TAG_TOK) {
                    int tok = pSym - 1 - sym_stk;
                    tok = tok * 8 + TOK_IDENT;
                    if (tok <= TOK_DEFINE) {
                        return 0;
                    } else {
                        tok = (intptr_t) (pVarsBase + tok);
                        return * (void**) tok;
                    }
                }
            }
        }
        return NULL;
    }

    void getPragmas(ACCsizei* actualStringCount,
                    ACCsizei maxStringCount, ACCchar** strings) {
        int stringCount = mPragmaStringCount;
        if (actualStringCount) {
            *actualStringCount = stringCount;
        }
        if (stringCount > maxStringCount) {
            stringCount = maxStringCount;
        }
        if (strings) {
            char* pPragmas = mPragmas.getUnwrapped();
            while (stringCount-- > 0) {
                *strings++ = pPragmas;
                pPragmas += strlen(pPragmas) + 1;
            }
        }
    }

    char* getErrorMessage() {
        return mErrorBuf.getUnwrapped();
    }

};

const char* Compiler::operatorChars =
    "++--*@/@%@+@-@<<>><=>=<@>@==!=&&||&@^@|@~@!@";

const char Compiler::operatorLevel[] =
    {11, 11, 1, 1, 1, 2, 2, 3, 3, 4, 4, 4, 4,
            5, 5, /* ==, != */
            9, 10, /* &&, || */
            6, 7, 8, /* & ^ | */
            2, 2 /* ~ ! */
            };

#ifdef PROVIDE_ARM_CODEGEN
FILE* Compiler::ARMCodeGenerator::disasmOut;
#endif

#ifdef PROVIDE_X86_CODEGEN
const int Compiler::X86CodeGenerator::operatorHelper[] = {
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
#endif

struct ACCscript {
    ACCscript() {
        text = 0;
        textLength = 0;
        accError = ACC_NO_ERROR;
    }

    ~ACCscript() {
        delete text;
    }

    void setError(ACCenum error) {
        if (accError == ACC_NO_ERROR && error != ACC_NO_ERROR) {
            accError = error;
        }
    }

    ACCenum getError() {
        ACCenum result = accError;
        accError = ACC_NO_ERROR;
        return result;
    }

    Compiler compiler;
    char* text;
    int textLength;
    ACCenum accError;
};


extern "C"
ACCscript* accCreateScript() {
    return new ACCscript();
}

extern "C"
ACCenum accGetError( ACCscript* script ) {
    return script->getError();
}

extern "C"
void accDeleteScript(ACCscript* script) {
    delete script;
}

extern "C"
void accScriptSource(ACCscript* script,
    ACCsizei count,
    const ACCchar ** string,
    const ACCint * length) {
    int totalLength = 0;
    for(int i = 0; i < count; i++) {
        int len = -1;
        const ACCchar* s = string[i];
        if (length) {
            len = length[i];
        }
        if (len < 0) {
            len = strlen(s);
        }
        totalLength += len;
    }
    delete script->text;
    char* text = new char[totalLength + 1];
    script->text = text;
    script->textLength = totalLength;
    char* dest = text;
    for(int i = 0; i < count; i++) {
        int len = -1;
        const ACCchar* s = string[i];
        if (length) {
            len = length[i];
        }
        if (len < 0) {
            len = strlen(s);
        }
        memcpy(dest, s, len);
        dest += len;
    }
    text[totalLength] = '\0';
}

extern "C"
void accCompileScript(ACCscript* script) {
    int result = script->compiler.compile(script->text, script->textLength);
    if (result) {
        script->setError(ACC_INVALID_OPERATION);
    }
}

extern "C"
void accGetScriptiv(ACCscript* script,
    ACCenum pname,
    ACCint * params) {
    switch (pname) {
        case ACC_INFO_LOG_LENGTH:
            *params = 0;
            break;
    }
}

extern "C"
void accGetScriptInfoLog(ACCscript* script,
    ACCsizei maxLength,
    ACCsizei * length,
    ACCchar * infoLog) {
    char* message = script->compiler.getErrorMessage();
    int messageLength = strlen(message) + 1;
    if (length) {
        *length = messageLength;
    }
    if (infoLog && maxLength > 0) {
        int trimmedLength = maxLength < messageLength ?
                maxLength : messageLength;
        memcpy(infoLog, message, trimmedLength);
        infoLog[trimmedLength] = 0;
    }
}

extern "C"
void accGetScriptLabel(ACCscript* script, const ACCchar * name,
                       ACCvoid ** address) {
    void* value = script->compiler.lookup(name);
    if (value) {
        *address = value;
    } else {
        script->setError(ACC_INVALID_VALUE);
    }
}

extern "C"
void accGetPragmas(ACCscript* script, ACCsizei* actualStringCount,
                   ACCsizei maxStringCount, ACCchar** strings){
    script->compiler.getPragmas(actualStringCount, maxStringCount, strings);
}


} // namespace acc

