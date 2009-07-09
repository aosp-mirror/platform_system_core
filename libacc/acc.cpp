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
#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cutils/hashmap.h>

#if defined(__i386__)
#include <sys/mman.h>
#endif

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

#define LOG_STACK(...) do {} while(0)
// #define LOG_STACK(...) fprintf (stderr, __VA_ARGS__)

// #define ENABLE_ARM_DISASSEMBLY
// #define PROVIDE_TRACE_CODEGEN

namespace acc {

// Subset of STL vector.
template<class E> class Vector {
    public:
    Vector() {
        mpBase = 0;
        mUsed = 0;
        mSize = 0;
    }

    ~Vector() {
        if (mpBase) {
            for(size_t i = 0; i < mUsed; i++)  {
                mpBase[mUsed].~E();
            }
            free(mpBase);
        }
    }

    inline E& operator[](size_t i) {
        return mpBase[i];
    }

    inline E& front() {
        return mpBase[0];
    }

    inline E& back() {
        return mpBase[mUsed - 1];
    }

    void pop_back() {
        mUsed -= 1;
        mpBase[mUsed].~E();
    }

    void push_back(const E& item) {
        * ensure(1) = item;
    }

    size_t size() {
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

class ErrorSink {
public:
    void error(const char *fmt, ...) {
        va_list ap;
        va_start(ap, fmt);
        verror(fmt, ap);
        va_end(ap);
    }

    virtual ~ErrorSink() {}
    virtual void verror(const char* fmt, va_list ap) = 0;
};

class Compiler : public ErrorSink {
    typedef int tokenid_t;
    enum TypeTag {
        TY_INT, TY_CHAR, TY_VOID, TY_FLOAT, TY_DOUBLE,
        TY_POINTER, TY_FUNC, TY_PARAM
    };

    struct Type {
        TypeTag tag;
        tokenid_t id; // For function arguments
        Type* pHead;
        Type* pTail;
    };

    class CodeBuf {
        char* ind; // Output code pointer
        char* pProgramBase;
        ErrorSink* mErrorSink;
        int mSize;
        bool mOverflowed;

        void release() {
            if (pProgramBase != 0) {
                free(pProgramBase);
                pProgramBase = 0;
            }
        }

        bool check(int n) {
            int newSize = ind - pProgramBase + n;
            bool overflow = newSize > mSize;
            if (overflow && !mOverflowed) {
                mOverflowed = true;
                if (mErrorSink) {
                    mErrorSink->error("Code too large: %d bytes", newSize);
                }
            }
            return overflow;
        }

    public:
        CodeBuf() {
            pProgramBase = 0;
            ind = 0;
            mErrorSink = 0;
            mSize = 0;
            mOverflowed = false;
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
            if(check(4)) {
                return 0;
            }
            intptr_t result = (intptr_t) ind;
            * (int*) ind = n;
            ind += 4;
            return result;
        }

        /*
         * Output a byte. Handles all values, 0..ff.
         */
        void ob(int n) {
            if(check(1)) {
                return;
            }
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
     * R0 - the accumulator.
     * FP - a frame pointer for accessing function arguments and local
     *      variables.
     * SP - a stack pointer for storing intermediate results while evaluating
     *      expressions. The stack pointer grows downwards.
     *
     * The function calling convention is that all arguments are placed on the
     * stack such that the first argument has the lowest address.
     * After the call, the result is in R0. The caller is responsible for
     * removing the arguments from the stack.
     * The R0 register is not saved across function calls. The
     * FP and SP registers are saved.
     */

    class CodeGenerator {
    public:
        CodeGenerator() {
            mErrorSink = 0;
            pCodeBuf = 0;
            pushType();
        }
        virtual ~CodeGenerator() {}

        virtual void init(CodeBuf* pCodeBuf) {
            this->pCodeBuf = pCodeBuf;
            pCodeBuf->setErrorSink(mErrorSink);
        }

        virtual void setErrorSink(ErrorSink* pErrorSink) {
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
        virtual void li(int i, Type* pType) = 0;

        /* Load floating point value from global address. */
        virtual void loadFloat(int address, Type* pType) = 0;

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

        /* Compare TOS against R0, and store the boolean result in R0.
         * Pops TOS.
         * op specifies the comparison.
         */
        virtual void gcmp(int op, Type* pResultType) = 0;

        /* Perform the arithmetic op specified by op. TOS is the
         * left argument, R0 is the right argument.
         * Pops TOS.
         */
        virtual void genOp(int op) = 0;

        /* Compare 0 against R0, and store the boolean result in R0.
         * op specifies the comparison.
         */
        virtual void gUnaryCmp(int op, Type* pResultType) = 0;

        /* Perform the arithmetic op specified by op. 0 is the
         * left argument, R0 is the right argument.
         */
        virtual void genUnaryOp(int op) = 0;

        /* Push R0 onto the stack.
         */
        virtual void pushR0() = 0;

        /* Store R0 to the address stored in TOS.
         * The TOS is popped.
         * pPointerType is the type of the pointer (of the input R0).
         */
        virtual void storeR0ToTOS(Type* pPointerType) = 0;

        /* Load R0 from the address stored in R0.
         * pPointerType is the type of the pointer (of the input R0).
         */
        virtual void loadR0FromR0(Type* pPointerType) = 0;

        /* Load the absolute address of a variable to R0.
         * If ea <= LOCAL, then this is a local variable, or an
         * argument, addressed relative to FP.
         * else it is an absolute global address.
         */
        virtual void leaR0(int ea, Type* pPointerType) = 0;

        /* Store R0 to a variable.
         * If ea <= LOCAL, then this is a local variable, or an
         * argument, addressed relative to FP.
         * else it is an absolute global address.
         */
        virtual void storeR0(int ea, Type* pType) = 0;

        /* load R0 from a variable.
         * If ea <= LOCAL, then this is a local variable, or an
         * argument, addressed relative to FP.
         * else it is an absolute global address.
         * If isIncDec is true, then the stored variable's value
         * should be post-incremented or post-decremented, based
         * on the value of op.
         */
        virtual void loadR0(int ea, bool isIncDec, int op, Type* pType) = 0;

        /**
         * Convert R0 to the given type.
         */
        virtual void convertR0(Type* pType) = 0;

        /* Emit code to adjust the stack for a function call. Return the
         * label for the address of the instruction that adjusts the
         * stack size. This will be passed as argument "a" to
         * endFunctionCallArguments.
         */
        virtual int beginFunctionCallArguments() = 0;

        /* Emit code to store R0 to the stack at byte offset l.
         * Returns stack size of object (typically 4 or 8 bytes)
         */
        virtual size_t storeR0ToArg(int l) = 0;

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
        virtual int callForward(int symbol, Type* pFunc) = 0;

        /* Call a function using PC-relative addressing. t is the PC-relative
         * address of the function. It has already been adjusted for the
         * architectural jump offset, so just store it as-is.
         */
        virtual void callRelative(int t, Type* pFunc) = 0;

        /* Call a function pointer. L is the number of bytes the arguments
         * take on the stack. The address of the function is stored at
         * location SP + l.
         */
        virtual void callIndirect(int l, Type* pFunc) = 0;

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

        /**
         * Memory alignment (in bytes) for this type of data
         */
        virtual size_t alignment(Type* type) = 0;

        /**
         * Array element alignment (in bytes) for this type of data.
         */
        virtual size_t sizeOf(Type* type) = 0;

        /**
         * Stack argument size of this data type.
         */
        virtual size_t stackSizeOf(Type* pType) = 0;

        virtual Type* getR0Type() {
            return mExpressionStack.back();
        }

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

        void assert(bool test) {
            if (!test) {
                * (char*) 0 = 0;
                error("code generator assertion failed.");
            }
        }

        void setR0Type(Type* pType) {
            mExpressionStack.back() = pType;
        }

        Type* getTOSType() {
            return mExpressionStack[mExpressionStack.size()-2];
        }

        void pushType() {
            mExpressionStack.push_back(NULL);
        }

        void popType() {
            mExpressionStack.pop_back();
        }

        bool bitsSame(Type* pA, Type* pB) {
            return collapseType(pA->tag) == collapseType(pB->tag);
        }

        TypeTag collapseType(TypeTag tag) {
            static const TypeTag collapsedTag[] = {
                    TY_INT, TY_INT, TY_VOID, TY_FLOAT, TY_DOUBLE, TY_INT,
                    TY_VOID, TY_VOID};
            return collapsedTag[tag];
        }

        TypeTag collapseTypeR0() {
            return collapseType(getR0Type()->tag);
        }

        bool isFloatType(Type* pType) {
            return isFloatTag(pType->tag);
        }

        bool isFloatTag(TypeTag tag) {
            return tag == TY_FLOAT || tag == TY_DOUBLE;
        }

    private:
        Vector<Type*> mExpressionStack;
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
            mStackUse = 0;
            // sp -> arg4 arg5 ...
            // Push our register-based arguments back on the stack
            if (argCount > 0) {
                int regArgCount = argCount <= 4 ? argCount : 4;
                o4(0xE92D0000 | ((1 << argCount) - 1)); // stmfd    sp!, {}
                mStackUse += regArgCount * 4;
            }
            // sp -> arg0 arg1 ...
            o4(0xE92D4800); // stmfd sp!, {fp, lr}
            mStackUse += 2 * 4;
            // sp, fp -> oldfp, retadr, arg0 arg1 ....
            o4(0xE1A0B00D); // mov    fp, sp
            LOG_STACK("functionEntry: %d\n", mStackUse);
            return o4(0xE24DD000); // sub    sp, sp, # <local variables>
            // We don't know how many local variables we are going to use,
            // but we will round the allocation up to a multiple of
            // STACK_ALIGNMENT, so it won't affect the stack alignment.
        }

        virtual void functionExit(int argCount, int localVariableAddress, int localVariableSize) {
            LOG_API("functionExit(%d, %d, %d);\n", argCount, localVariableAddress, localVariableSize);
            // Round local variable size up to a multiple of stack alignment
            localVariableSize = ((localVariableSize + STACK_ALIGNMENT - 1) /
                STACK_ALIGNMENT) * STACK_ALIGNMENT;
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
        virtual void li(int t, Type* pType) {
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
            setR0Type(pType);
        }

        virtual void loadFloat(int address, Type* pType) {
            error("Unimplemented.\n");
            setR0Type(pType);
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

        virtual void gcmp(int op, Type* pResultType) {
            LOG_API("gcmp(%d);\n", op);
            o4(0xE8BD0002);  // ldmfd   sp!,{r1}
            mStackUse -= 4;
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
            popType();
        }

        virtual void genOp(int op) {
            LOG_API("genOp(%d);\n", op);
            o4(0xE8BD0002);  // ldmfd   sp!,{r1}
            mStackUse -= 4;
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
            popType();
        }

        virtual void gUnaryCmp(int op, Type* pResultType) {
            LOG_API("gUnaryCmp(%d);\n", op);
            o4(0xE3A01000);  // mov    r1, #0
            o4(0xE1510000); // cmp r1, r1
            switch(op) {
            case OP_LOGICAL_NOT:
                o4(0x03A00000); // moveq r0,#0
                o4(0x13A00001); // movne r0,#1
                break;
             default:
                error("Unknown unary comparison op %d", op);
                break;
            }
            setR0Type(pResultType);
        }

        virtual void genUnaryOp(int op) {
            LOG_API("genOp(%d);\n", op);
            switch(op) {
            case OP_MINUS:
                o4(0xE3A01000);  // mov    r1, #0
                o4(0xE0410000);  // sub     r0,r1,r0
                break;
            case OP_BIT_NOT:
                o4(0xE1E00000);  // mvn     r0, r0
                break;
            default:
                error("Unknown unary op %d\n", op);
                break;
            }
        }

        virtual void pushR0() {
            LOG_API("pushR0();\n");
            o4(0xE92D0001);  // stmfd   sp!,{r0}
            mStackUse += 4;
            pushType();
            LOG_STACK("pushR0: %d\n", mStackUse);
        }

        virtual void storeR0ToTOS(Type* pPointerType) {
            LOG_API("storeR0ToTOS(%d);\n", isInt);
            assert(pPointerType->tag == TY_POINTER);
            o4(0xE8BD0002);  // ldmfd   sp!,{r1}
            mStackUse -= 4;
            switch (pPointerType->pHead->tag) {
                case TY_INT:
                    o4(0xE5810000); // str r0, [r1]
                    break;
                case TY_CHAR:
                    o4(0xE5C10000); // strb r0, [r1]
                    break;
                default:
                    error("storeR0ToTOS: unimplemented type");
                    break;
            }
            popType();
        }

        virtual void loadR0FromR0(Type* pPointerType) {
            LOG_API("loadR0FromR0(%d);\n", pPointerType);
            assert(pPointerType->tag == TY_POINTER);
            switch (pPointerType->pHead->tag) {
                case TY_INT:
                    o4(0xE5900000); // ldr r0, [r0]
                    break;
                case TY_CHAR:
                    o4(0xE5D00000); // ldrb r0, [r0]
                    break;
                default:
                    error("loadR0FromR0: unimplemented type");
                    break;
            }
            setR0Type(pPointerType->pHead);
        }

        virtual void leaR0(int ea, Type* pPointerType) {
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
            setR0Type(pPointerType);
        }

        virtual void storeR0(int ea, Type* pType) {
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

        virtual void loadR0(int ea, bool isIncDec, int op, Type* pType) {
            LOG_API("loadR0(%d, %d, %d, %d);\n", ea, isIncDec, op, pType);
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
            setR0Type(pType);
        }

        virtual void convertR0(Type* pType){
            Type* pR0Type = getR0Type();
            if (bitsSame(pType, pR0Type)) {
                // do nothing special
            } else if (isFloatType(pType) && isFloatType(pR0Type)) {
                // do nothing special, both held in same register on x87.
            } else {
                error("Incompatible types old: %d new: %d",
                      pR0Type->tag, pType->tag);
            }
            setR0Type(pType);
        }

        virtual int beginFunctionCallArguments() {
            LOG_API("beginFunctionCallArguments();\n");
            return o4(0xE24DDF00); // Placeholder
        }

        virtual size_t storeR0ToArg(int l) {
            LOG_API("storeR0ToArg(%d);\n", l);
            if (l < 0 || l > 4096-4) {
                error("l out of range for stack offset: 0x%08x", l);
            }
            o4(0xE58D0000 + l); // str r0, [sp, #4]
            return 4;
        }

        virtual void endFunctionCallArguments(int a, int l) {
            LOG_API("endFunctionCallArguments(0x%08x, %d);\n", a, l);
            int argCount = l >> 2;
            int argumentStackUse = l;
            if (argCount > 0) {
                int regArgCount = argCount > 4 ? 4 : argCount;
                argumentStackUse -= regArgCount * 4;
                o4(0xE8BD0000 | ((1 << regArgCount) - 1)); // ldmfd   sp!,{}
            }
            mStackUse += argumentStackUse;

            // Align stack.
            int missalignment = mStackUse - ((mStackUse / STACK_ALIGNMENT)
                    * STACK_ALIGNMENT);
            mStackAlignmentAdjustment = 0;
            if (missalignment > 0) {
                mStackAlignmentAdjustment = STACK_ALIGNMENT - missalignment;
            }
            l += mStackAlignmentAdjustment;

            if (l < 0 || l > 0x3FC) {
                error("L out of range for stack adjustment: 0x%08x", l);
            }
            * (int*) a = 0xE24DDF00 | (l >> 2); // sub    sp, sp, #0 << 2
            mStackUse += mStackAlignmentAdjustment;
            LOG_STACK("endFunctionCallArguments mStackUse: %d, mStackAlignmentAdjustment %d\n",
                      mStackUse, mStackAlignmentAdjustment);
        }

        virtual int callForward(int symbol, Type* pFunc) {
            LOG_API("callForward(%d);\n", symbol);
            setR0Type(pFunc->pHead);
            // Forward calls are always short (local)
            return o4(0xEB000000 | encodeAddress(symbol));
        }

        virtual void callRelative(int t, Type* pFunc) {
            LOG_API("callRelative(%d);\n", t);
            setR0Type(pFunc->pHead);
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

        virtual void callIndirect(int l, Type* pFunc) {
            LOG_API("callIndirect(%d);\n", l);
            setR0Type(pFunc->pHead);
            int argCount = l >> 2;
            int poppedArgs = argCount > 4 ? 4 : argCount;
            int adjustedL = l - (poppedArgs << 2) + mStackAlignmentAdjustment;
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
            int stackUse =  stackArgs + (isIndirect ? 1 : 0)
                + (mStackAlignmentAdjustment >> 2);
            if (stackUse) {
                if (stackUse < 0 || stackUse > 255) {
                    error("L out of range for stack adjustment: 0x%08x", l);
                }
                o4(0xE28DDF00 | stackUse); // add    sp, sp, #stackUse << 2
                mStackUse -= stackUse * 4;
                LOG_STACK("adjustStackAfterCall: %d\n", mStackUse);
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

        /**
         * alignment (in bytes) for this type of data
         */
        virtual size_t alignment(Type* pType){
            switch(pType->tag) {
                case TY_DOUBLE:
                    return 8;
                default:
                    return 4;
            }
        }

        /**
         * Array element alignment (in bytes) for this type of data.
         */
        virtual size_t sizeOf(Type* pType){
            switch(pType->tag) {
                case TY_INT:
                    return 4;
                case TY_CHAR:
                    return 1;
                default:
                    return 0;
                case TY_FLOAT:
                    return 4;
                case TY_DOUBLE:
                    return 8;
                case TY_POINTER:
                    return 4;
            }
        }

        virtual size_t stackSizeOf(Type* pType) {
            switch(pType->tag) {
                case TY_DOUBLE:
                    return 8;
                default:
                    return 4;
            }
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

        static const int STACK_ALIGNMENT = 8;
        int mStackUse;
        // This variable holds the amount we adjusted the stack in the most
        // recent endFunctionCallArguments call. It's examined by the
        // following adjustStackAfterCall call.
        int mStackAlignmentAdjustment;
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
        virtual void li(int i, Type* pType) {
            oad(0xb8, i); /* mov $xx, %eax */
            setR0Type(pType);
        }

        virtual void loadFloat(int address, Type* pType) {
            setR0Type(pType);
            switch (pType->tag) {
            case TY_FLOAT:
                oad(0x05D9, address);      // flds
                break;
            case TY_DOUBLE:
                oad(0x05DD, address);      // fldl
                break;
            default:
                assert(false);
                break;
            }
        }

        virtual int gjmp(int t) {
            return psym(0xe9, t);
        }

        /* l = 0: je, l == 1: jne */
        virtual int gtst(bool l, int t) {
            o(0x0fc085); /* test %eax, %eax, je/jne xxx */
            return psym(0x84 + l, t);
        }

        virtual void gcmp(int op, Type* pResultType) {
            Type* pR0Type = getR0Type();
            Type* pTOSType = getTOSType();
            TypeTag tagR0 = pR0Type->tag;
            TypeTag tagTOS = pTOSType->tag;
            bool isFloatR0 = isFloatTag(tagR0);
            bool isFloatTOS = isFloatTag(tagTOS);
            if (!isFloatR0 && !isFloatTOS) {
                int t = decodeOp(op);
                o(0x59); /* pop %ecx */
                o(0xc139); /* cmp %eax,%ecx */
                li(0, NULL);
                o(0x0f); /* setxx %al */
                o(t + 0x90);
                o(0xc0);
                popType();
            } else {
                setupFloatOperands();
                switch (op) {
                    case OP_EQUALS:
                        o(0xe9da);   // fucompp
                        o(0xe0df);   // fnstsw %ax
                        o(0x9e);     // sahf
                        o(0xc0940f); // sete %al
                        o(0xc29b0f); // setnp %dl
                        o(0xd021);   // andl %edx, %eax
                        break;
                    case OP_NOT_EQUALS:
                        o(0xe9da);   // fucompp
                        o(0xe0df);   // fnstsw %ax
                        o(0x9e);     // sahf
                        o(0xc0950f); // setne %al
                        o(0xc29a0f); // setp %dl
                        o(0xd009);   // orl %edx, %eax
                        break;
                    case OP_GREATER_EQUAL:
                        o(0xe9da);   // fucompp
                        o(0xe0df);   // fnstsw %ax
                        o(0x05c4f6); // testb $5, %ah
                        o(0xc0940f); // sete %al
                        break;
                    case OP_LESS:
                        o(0xc9d9);   // fxch %st(1)
                        o(0xe9da);   // fucompp
                        o(0xe0df);   // fnstsw %ax
                        o(0x9e);     // sahf
                        o(0xc0970f); // seta %al
                        break;
                    case OP_LESS_EQUAL:
                        o(0xc9d9);   // fxch %st(1)
                        o(0xe9da);   // fucompp
                        o(0xe0df);   // fnstsw %ax
                        o(0x9e);     // sahf
                        o(0xc0930f); // setea %al
                        break;
                    case OP_GREATER:
                        o(0xe9da);   // fucompp
                        o(0xe0df);   // fnstsw %ax
                        o(0x45c4f6); // testb $69, %ah
                        o(0xc0940f); // sete %al
                        break;
                    default:
                        error("Unknown comparison op");
                }
                o(0xc0b60f); // movzbl %al, %eax
            }
            setR0Type(pResultType);
        }

        virtual void genOp(int op) {
            Type* pR0Type = getR0Type();
            Type* pTOSType = getTOSType();
            TypeTag tagR0 = pR0Type->tag;
            TypeTag tagTOS = pTOSType->tag;
            bool isFloatR0 = isFloatTag(tagR0);
            bool isFloatTOS = isFloatTag(tagTOS);
            if (!isFloatR0 && !isFloatTOS) {
                // TODO: Deal with pointer arithmetic
                o(0x59); /* pop %ecx */
                o(decodeOp(op));
                if (op == OP_MOD)
                    o(0x92); /* xchg %edx, %eax */
                popType();
            } else {
                Type* pResultType = tagR0 > tagTOS ? pR0Type : pTOSType;
                setupFloatOperands();
                // Both float. x87 R0 == left hand, x87 R1 == right hand
                switch (op) {
                    case OP_MUL:
                        o(0xc9de); // fmulp
                        break;
                    case OP_DIV:
                        o(0xf1de); // fdivp
                        break;
                    case OP_PLUS:
                        o(0xc1de); // faddp
                        break;
                    case OP_MINUS:
                        o(0xe1de); // fsubp
                        break;
                    default:
                        error("Unsupported binary floating operation.");
                        break;
                }
                popType();
                setR0Type(pResultType);
                printf("genop: result type %d\n", pResultType->tag);
            }
        }



        virtual void gUnaryCmp(int op, Type* pResultType) {
            if (op != OP_LOGICAL_NOT) {
                error("Unknown unary cmp %d", op);
            } else {
                Type* pR0Type = getR0Type();
                TypeTag tag = collapseType(pR0Type->tag);
                switch(tag) {
                    case TY_INT: {
                            oad(0xb9, 0); /* movl $0, %ecx */
                            int t = decodeOp(op);
                            o(0xc139); /* cmp %eax,%ecx */
                            li(0, NULL);
                            o(0x0f); /* setxx %al */
                            o(t + 0x90);
                            o(0xc0);
                        }
                        break;
                    case TY_FLOAT:
                    case TY_DOUBLE:
                        o(0xeed9);   // fldz
                        o(0xe9da);   // fucompp
                        o(0xe0df);   // fnstsw %ax
                        o(0x9e);     // sahf
                        o(0xc0950f); // setne %al
                        o(0xc29a0f); // setp %dl
                        o(0xd009);   // orl %edx, %eax
                        o(0xc0b60f); // movzbl %al, %eax
                        o(0x01f083); // xorl $1,  %eax
                        break;
                    default:
                        error("genUnaryCmp unsupported type");
                        break;
                }
            }
            setR0Type(pResultType);
        }

        virtual void genUnaryOp(int op) {
            Type* pR0Type = getR0Type();
            TypeTag tag = collapseType(pR0Type->tag);
            switch(tag) {
                case TY_INT:
                    oad(0xb9, 0); /* movl $0, %ecx */
                    o(decodeOp(op));
                    break;
                case TY_FLOAT:
                case TY_DOUBLE:
                    switch (op) {
                        case OP_MINUS:
                            o(0xe0d9);  // fchs
                            break;
                        case OP_BIT_NOT:
                            error("Can't apply '~' operator to a float or double.");
                            break;
                        default:
                            error("Unknown unary op %d\n", op);
                            break;
                        }
                    break;
                default:
                    error("genUnaryOp unsupported type");
                    break;
            }
        }

        virtual void pushR0() {
            Type* pR0Type = getR0Type();
            TypeTag r0ct = collapseType(pR0Type->tag);
            switch(r0ct) {
                case TY_INT:
                    o(0x50); /* push %eax */
                    break;
                case TY_FLOAT:
                    o(0x50); /* push %eax */
                    o(0x241cd9); // fstps 0(%esp)
                    break;
                case TY_DOUBLE:
                    o(0x50); /* push %eax */
                    o(0x50); /* push %eax */
                    o(0x241cdd); // fstpl 0(%esp)
                    break;
                default:
                    error("pushR0 %d", r0ct);
                    break;
            }
            pushType();
        }

        virtual void storeR0ToTOS(Type* pPointerType) {
            assert(pPointerType->tag == TY_POINTER);
            o(0x59); /* pop %ecx */
            popType();
            switch (pPointerType->pHead->tag) {
                case TY_INT:
                    o(0x0189); /* movl %eax/%al, (%ecx) */
                    break;
                case TY_CHAR:
                    o(0x0188); /* movl %eax/%al, (%ecx) */
                    break;
                case TY_FLOAT:
                    o(0x19d9); /* fstps (%ecx) */
                    break;
                case TY_DOUBLE:
                    o(0x19dd); /* fstpl (%ecx) */
                    break;
                default:
                    error("storeR0ToTOS: unsupported type");
                    break;
            }
        }

        virtual void loadR0FromR0(Type* pPointerType) {
            assert(pPointerType->tag == TY_POINTER);
            switch (pPointerType->pHead->tag) {
                case TY_INT:
                    o(0x8b); /* mov (%eax), %eax */
                    break;
                case TY_CHAR:
                    o(0xbe0f); /* movsbl (%eax), %eax */
                    break;
                default:
                    error("loadR0FromR0: unsupported type");
                    break;
            }
            ob(0); /* add zero in code */
            setR0Type(pPointerType->pHead);
        }

        virtual void leaR0(int ea, Type* pPointerType) {
            gmov(10, ea); /* leal EA, %eax */
            setR0Type(pPointerType);
        }

        virtual void storeR0(int ea, Type* pType) {
            TypeTag tag = pType->tag;
            switch (tag) {
                case TY_INT:
                    gmov(6, ea); /* mov %eax, EA */
                    break;
                case TY_FLOAT:
                    if (ea < -LOCAL || ea > LOCAL) {
                        oad(0x1dd9, ea); // fstps ea
                    } else {
                        oad(0x9dd9, ea); // fstps ea(%ebp)
                    }
                    break;
                case TY_DOUBLE:
                    if (ea < -LOCAL || ea > LOCAL) {
                        oad(0x1ddd, ea); // fstpl ea
                    } else {
                        oad(0x9ddd, ea); // fstpl ea(%ebp)
                    }
                    break;
                default:
                    error("Unable to store to type %d", tag);
                    break;
            }
        }

        virtual void loadR0(int ea, bool isIncDec, int op, Type* pType) {
            TypeTag tag = collapseType(pType->tag);
            switch (tag) {
                case TY_INT:
                    gmov(8, ea); /* mov EA, %eax */
                    if (isIncDec) {
                        /* Implement post-increment or post decrement.
                         */
                        gmov(0, ea); /* 83 ADD */
                        o(decodeOp(op));
                    }
                    break;
                case TY_FLOAT:
                    if (ea < -LOCAL || ea > LOCAL) {
                        oad(0x05d9, ea); // flds ea
                    } else {
                        oad(0x85d9, ea); // flds ea(%ebp)
                    }
                    if (isIncDec) {
                        error("inc/dec not implemented for float.");
                    }
                    break;
                case TY_DOUBLE:
                    if (ea < -LOCAL || ea > LOCAL) {
                        oad(0x05dd, ea); // fldl ea
                    } else {
                        oad(0x85dd, ea); // fldl ea(%ebp)
                    }
                    if (isIncDec) {
                        error("inc/dec not implemented for double.");
                    }
                    break;
                default:
                    error("Unable to load type %d", tag);
                    break;
            }
            setR0Type(pType);
        }

        virtual void convertR0(Type* pType){
            Type* pR0Type = getR0Type();
            if (pR0Type == NULL) {
                assert(false);
                setR0Type(pType);
                return;
            }
            if (bitsSame(pType, pR0Type)) {
                // do nothing special
            } else if (isFloatType(pType) && isFloatType(pR0Type)) {
                // do nothing special, both held in same register on x87.
            } else {
                TypeTag r0Tag = collapseType(pR0Type->tag);
                TypeTag destTag = collapseType(pType->tag);
                if (r0Tag == TY_INT && isFloatTag(destTag)) {
                    // Convert R0 from int to float
                    o(0x50);      // push %eax
                    o(0x2404DB);  // fildl 0(%esp)
                    o(0x58);      // pop %eax
                } else if (isFloatTag(r0Tag) && destTag == TY_INT) {
                    // Convert R0 from float to int. Complicated because
                    // need to save and restore the rounding mode.
                    o(0x50);       // push %eax
                    o(0x50);       // push %eax
                    o(0x02247cD9); // fnstcw 2(%esp)
                    o(0x2444b70f); // movzwl 2(%esp), %eax
                    o(0x02);
                    o(0x0cb4);     // movb $12, %ah
                    o(0x24048966); // movw %ax, 0(%esp)
                    o(0x242cd9);   // fldcw 0(%esp)
                    o(0x04245cdb); // fistpl 4(%esp)
                    o(0x02246cd9); // fldcw  2(%esp)
                    o(0x58); // pop %eax
                    o(0x58); // pop %eax
                } else {
                    error("Incompatible types old: %d new: %d",
                          pR0Type->tag, pType->tag);
                }
            }
            setR0Type(pType);
        }

        virtual int beginFunctionCallArguments() {
            return oad(0xec81, 0); /* sub $xxx, %esp */
        }

        virtual size_t storeR0ToArg(int l) {
            Type* pR0Type = getR0Type();
            TypeTag r0ct = collapseType(pR0Type->tag);
            switch(r0ct) {
                case TY_INT:
                    oad(0x248489, l); /* movl %eax, xxx(%esp) */
                    return 4;
                case TY_FLOAT:
                    oad(0x249CD9, l); /* fstps   xxx(%esp) */
                    return 4;
                case TY_DOUBLE:
                    oad(0x249CDD, l); /* fstpl   xxx(%esp) */
                    return 8;
                default:
                    assert(false);
                    return 0;
            }
        }

        virtual void endFunctionCallArguments(int a, int l) {
            * (int*) a = l;
        }

        virtual int callForward(int symbol, Type* pFunc) {
            setR0Type(pFunc->pHead);
            return psym(0xe8, symbol); /* call xxx */
        }

        virtual void callRelative(int t, Type* pFunc) {
            setR0Type(pFunc->pHead);
            psym(0xe8, t); /* call xxx */
        }

        virtual void callIndirect(int l, Type* pFunc) {
            setR0Type(pFunc->pHead);
            oad(0x2494ff, l); /* call *xxx(%esp) */
        }

        virtual void adjustStackAfterCall(int l, bool isIndirect) {
            if (isIndirect) {
                l += 4;
            }
            if (l > 0) {
                oad(0xc481, l); /* add $xxx, %esp */
            }
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
            size_t pagesize = 4096;
            size_t base = (size_t) getBase() & ~ (pagesize - 1);
            size_t top =  ((size_t) getPC() + pagesize - 1) & ~ (pagesize - 1);
            int err = mprotect((void*) base, top - base, PROT_READ | PROT_WRITE | PROT_EXEC);
            if (err) {
               error("mprotect() failed: %d", errno);
            }
            return err;
        }

        /**
         * Alignment (in bytes) for this type of data
         */
        virtual size_t alignment(Type* pType){
            switch(pType->tag) {
                case TY_DOUBLE:
                    return 8;
                default:
                    return 4;
            }
        }

        /**
         * Array element alignment (in bytes) for this type of data.
         */
        virtual size_t sizeOf(Type* pType){
            switch(pType->tag) {
                case TY_INT:
                    return 4;
                case TY_CHAR:
                    return 1;
                default:
                    return 0;
                case TY_FLOAT:
                    return 4;
                case TY_DOUBLE:
                    return 8;
                case TY_POINTER:
                    return 4;
            }
        }

        virtual size_t stackSizeOf(Type* pType) {
            switch(pType->tag) {
                case TY_DOUBLE:
                    return 8;
                default:
                    return 4;
            }
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
                op = 0;
            }
            return operatorHelper[op];
        }

        void gmov(int l, int t) {
            o(l + 0x83);
            oad((t > -LOCAL && t < LOCAL) << 7 | 5, t);
        }

        void setupFloatOperands() {
            Type* pR0Type = getR0Type();
            Type* pTOSType = getTOSType();
            TypeTag tagR0 = pR0Type->tag;
            TypeTag tagTOS = pTOSType->tag;
            bool isFloatR0 = isFloatTag(tagR0);
            bool isFloatTOS = isFloatTag(tagTOS);
            if (! isFloatR0) {
                // Convert R0 from int to float
                o(0x50);      // push %eax
                o(0x2404DB);  // fildl 0(%esp)
                o(0x58);      // pop %eax
            }
            if (! isFloatTOS){
                o(0x2404DB);  // fildl 0(%esp);
                o(0x58);      // pop %eax
            } else {
                if (tagTOS == TY_FLOAT) {
                    o(0x2404d9);  // flds (%esp)
                    o(0x58);      // pop %eax
                } else {
                    o(0x2404dd);  // fldl (%esp)
                    o(0x58);      // pop %eax
                    o(0x58);      // pop %eax
                }
            }
        }
    };

#endif // PROVIDE_X86_CODEGEN

#ifdef PROVIDE_TRACE_CODEGEN
    class TraceCodeGenerator : public CodeGenerator {
    private:
        CodeGenerator* mpBase;

    public:
        TraceCodeGenerator(CodeGenerator* pBase) {
            mpBase = pBase;
        }

        virtual ~TraceCodeGenerator() {
            delete mpBase;
        }

        virtual void init(CodeBuf* pCodeBuf) {
            mpBase->init(pCodeBuf);
        }

        void setErrorSink(ErrorSink* pErrorSink) {
            mpBase->setErrorSink(pErrorSink);
        }

        /* returns address to patch with local variable size
        */
        virtual int functionEntry(int argCount) {
            int result = mpBase->functionEntry(argCount);
            fprintf(stderr, "functionEntry(%d) -> %d\n", argCount, result);
            return result;
        }

        virtual void functionExit(int argCount, int localVariableAddress, int localVariableSize) {
            fprintf(stderr, "functionExit(%d, %d, %d)\n",
                    argCount, localVariableAddress, localVariableSize);
            mpBase->functionExit(argCount, localVariableAddress, localVariableSize);
        }

        /* load immediate value */
        virtual void li(int t, Type* pType) {
            fprintf(stderr, "li(%d)\n", t);
            mpBase->li(t, pType);
        }

        virtual void loadFloat(int address, Type* pType) {
            fprintf(stderr, "loadFloat(%d, type)\n", address);
            mpBase->loadFloat(address, pType);
        }

        virtual int gjmp(int t) {
            int result = mpBase->gjmp(t);
            fprintf(stderr, "gjmp(%d) = %d\n", t, result);
            return result;
        }

        /* l = 0: je, l == 1: jne */
        virtual int gtst(bool l, int t) {
            int result = mpBase->gtst(l, t);
            fprintf(stderr, "gtst(%d,%d) = %d\n", l, t, result);
            return result;
        }

        virtual void gcmp(int op, Type* pResultType) {
            fprintf(stderr, "gcmp(%d, pResultType)\n", op);
            mpBase->gcmp(op, pResultType);
        }

        virtual void genOp(int op) {
            fprintf(stderr, "genOp(%d)\n", op);
            mpBase->genOp(op);
        }


        virtual void gUnaryCmp(int op, Type* pResultType) {
            fprintf(stderr, "gUnaryCmp(%d, pResultType)\n", op);
            mpBase->gUnaryCmp(op, pResultType);
        }

        virtual void genUnaryOp(int op) {
            fprintf(stderr, "genUnaryOp(%d)\n", op);
            mpBase->genUnaryOp(op);
        }

        virtual void pushR0() {
            fprintf(stderr, "pushR0()\n");
            mpBase->pushR0();
        }

        virtual void storeR0ToTOS(Type* pPointerType) {
            fprintf(stderr, "storeR0ToTOS(%d)\n", pPointerType->pHead->tag);
            mpBase->storeR0ToTOS(pPointerType);
        }

        virtual void loadR0FromR0(Type* pPointerType) {
            fprintf(stderr, "loadR0FromR0(%d)\n", pPointerType->pHead->tag);
            mpBase->loadR0FromR0(pPointerType);
        }

        virtual void leaR0(int ea, Type* pPointerType) {
            fprintf(stderr, "leaR0(%d)\n", ea);
            mpBase->leaR0(ea, pPointerType);
        }

        virtual void storeR0(int ea, Type* pType) {
            fprintf(stderr, "storeR0(%d, pType)\n", ea);
            mpBase->storeR0(ea, pType);
        }

        virtual void loadR0(int ea, bool isIncDec, int op, Type* pType) {
            fprintf(stderr, "loadR0(%d, %d, %d, pType)\n", ea, isIncDec, op);
            mpBase->loadR0(ea, isIncDec, op, pType);
        }

        virtual void convertR0(Type* pType){
            fprintf(stderr, "convertR0(pType)\n");
            mpBase->convertR0(pType);
        }

        virtual int beginFunctionCallArguments() {
            int result = mpBase->beginFunctionCallArguments();
            fprintf(stderr, "beginFunctionCallArguments() = %d\n", result);
            return result;
        }

        virtual size_t storeR0ToArg(int l) {
            fprintf(stderr, "storeR0ToArg(%d)\n", l);
            return mpBase->storeR0ToArg(l);
        }

        virtual void endFunctionCallArguments(int a, int l) {
            fprintf(stderr, "endFunctionCallArguments(%d, %d)\n", a, l);
            mpBase->endFunctionCallArguments(a, l);
        }

        virtual int callForward(int symbol, Type* pFunc) {
            int result = mpBase->callForward(symbol, pFunc);
            fprintf(stderr, "callForward(%d) = %d\n", symbol, result);
            return result;
        }

        virtual void callRelative(int t, Type* pFunc) {
            fprintf(stderr, "callRelative(%d)\n", t);
            mpBase->callRelative(t, pFunc);
        }

        virtual void callIndirect(int l, Type* pFunc) {
            fprintf(stderr, "callIndirect(%d)\n", l);
            mpBase->callIndirect(l, pFunc);
        }

        virtual void adjustStackAfterCall(int l, bool isIndirect) {
            fprintf(stderr, "adjustStackAfterCall(%d, %d)\n", l, isIndirect);
            mpBase->adjustStackAfterCall(l, isIndirect);
        }

        virtual int jumpOffset() {
            return mpBase->jumpOffset();
        }

        virtual int disassemble(FILE* out) {
            return mpBase->disassemble(out);
        }

        /* output a symbol and patch all calls to it */
        virtual void gsym(int t) {
            fprintf(stderr, "gsym(%d)\n", t);
            mpBase->gsym(t);
        }

        virtual int finishCompile() {
            int result = mpBase->finishCompile();
            fprintf(stderr, "finishCompile() = %d\n", result);
            return result;
        }

        /**
         * Alignment (in bytes) for this type of data
         */
        virtual size_t alignment(Type* pType){
            return mpBase->alignment(pType);
        }

        /**
         * Array element alignment (in bytes) for this type of data.
         */
        virtual size_t sizeOf(Type* pType){
            return mpBase->sizeOf(pType);
        }


        virtual size_t stackSizeOf(Type* pType) {
            return mpBase->stackSizeOf(pType);
        }


        virtual Type* getR0Type() {
            return mpBase->getR0Type();
        }
    };

#endif // PROVIDE_TRACE_CODEGEN

    class Arena {
    public:
        // Used to record a given allocation amount.
        // Used:
        // Mark mark = arena.mark();
        // ... lots of arena.allocate()
        // arena.free(mark);

        struct Mark {
            size_t chunk;
            size_t offset;
        };

        Arena() {
            mCurrentChunk = 0;
            Chunk start(CHUNK_SIZE);
            mData.push_back(start);
        }

        ~Arena() {
            for(size_t i = 0; i < mData.size(); i++) {
                mData[i].free();
            }
        }

        // Alloc using the standard alignment size safe for any variable
        void* alloc(size_t size) {
            return alloc(size, 8);
        }

        Mark mark(){
            Mark result;
            result.chunk = mCurrentChunk;
            result.offset = mData[mCurrentChunk].mOffset;
            return result;
        }

        void freeToMark(const Mark& mark) {
            mCurrentChunk = mark.chunk;
            mData[mCurrentChunk].mOffset = mark.offset;
        }

    private:
        // Allocate memory aligned to a given size
        // and a given power-of-two-sized alignment (e.g. 1,2,4,8,...)
        // Memory is not zero filled.

        void* alloc(size_t size, size_t alignment) {
            while (size > mData[mCurrentChunk].remainingCapacity(alignment)) {
                if (mCurrentChunk + 1 < mData.size()) {
                    mCurrentChunk++;
                } else {
                    size_t allocSize = CHUNK_SIZE;
                    if (allocSize < size + alignment - 1) {
                        allocSize = size + alignment - 1;
                    }
                    Chunk chunk(allocSize);
                    mData.push_back(chunk);
                    mCurrentChunk++;
                }
            }
            return mData[mCurrentChunk].allocate(size, alignment);
        }

        static const size_t CHUNK_SIZE = 128*1024;
        // Note: this class does not deallocate its
        // memory when it's destroyed. It depends upon
        // its parent to deallocate the memory.
        struct Chunk {
            Chunk() {
                mpData = 0;
                mSize = 0;
                mOffset = 0;
            }

            Chunk(size_t size) {
                mSize = size;
                mpData = (char*) malloc(size);
                mOffset = 0;
            }

            ~Chunk() {
                // Doesn't deallocate memory.
            }

            void* allocate(size_t size, size_t alignment) {
                size_t alignedOffset = aligned(mOffset, alignment);
                void* result = mpData + alignedOffset;
                mOffset = alignedOffset + size;
                return result;
            }

            void free() {
                if (mpData) {
                    ::free(mpData);
                    mpData = 0;
                }
            }

            size_t remainingCapacity(size_t alignment) {
                return aligned(mSize, alignment) - aligned(mOffset, alignment);
            }

            // Assume alignment is a power of two
            inline size_t aligned(size_t v, size_t alignment) {
                size_t mask = alignment-1;
                return (v + mask) & ~mask;
            }

            char* mpData;
            size_t mSize;
            size_t mOffset;
        };

        size_t mCurrentChunk;

        Vector<Chunk> mData;
    };

    struct VariableInfo;

    struct Token {
        int hash;
        size_t length;
        char* pText;
        tokenid_t id;

        // Current values for the token
        char* mpMacroDefinition;
        VariableInfo* mpVariableInfo;
    };

    class TokenTable {
    public:
        // Don't use 0..0xff, allows characters and operators to be tokens too.

        static const int TOKEN_BASE = 0x100;
        TokenTable() {
            mpMap = hashmapCreate(128, hashFn, equalsFn);
        }

        ~TokenTable() {
            hashmapFree(mpMap);
        }

        void setArena(Arena* pArena) {
            mpArena = pArena;
        }

        // Returns a token for a given string of characters.
        tokenid_t intern(const char* pText, size_t length) {
            Token probe;
            int hash = hashmapHash((void*) pText, length);
            {
                Token probe;
                probe.hash = hash;
                probe.length = length;
                probe.pText = (char*) pText;
                Token* pValue = (Token*) hashmapGet(mpMap, &probe);
                if (pValue) {
                    return pValue->id;
                }
            }

            Token* pToken = (Token*) mpArena->alloc(sizeof(Token));
            memset(pToken, 0, sizeof(*pToken));
            pToken->hash = hash;
            pToken->length = length;
            pToken->pText = (char*) mpArena->alloc(length + 1);
            memcpy(pToken->pText, pText, length);
            pToken->pText[length] = 0;
            pToken->id = mTokens.size() + TOKEN_BASE;
            mTokens.push_back(pToken);
            hashmapPut(mpMap, pToken, pToken);
            return pToken->id;
        }

        // Return the Token for a given tokenid.
        Token& operator[](tokenid_t id) {
            return *mTokens[id - TOKEN_BASE];
        }

        inline size_t size() {
            return mTokens.size();
        }

    private:

        static int hashFn(void* pKey) {
            Token* pToken = (Token*) pKey;
            return pToken->hash;
        }

        static bool equalsFn(void* keyA, void* keyB) {
            Token* pTokenA = (Token*) keyA;
            Token* pTokenB = (Token*) keyB;
            // Don't need to compare hash values, they should always be equal
            return pTokenA->length == pTokenB->length
                && strcmp(pTokenA->pText, pTokenB->pText) == 0;
        }

        Hashmap* mpMap;
        Vector<Token*> mTokens;
        Arena* mpArena;
    };

    class InputStream {
    public:
        virtual ~InputStream() {}
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

    class String {
    public:
        String() {
            mpBase = 0;
            mUsed = 0;
            mSize = 0;
        }

        String(const char* item, int len, bool adopt) {
            if (len < 0) {
                len = strlen(item);
            }
            if (adopt) {
                mpBase = (char*) item;
                mUsed = len;
                mSize = len + 1;
            } else {
                mpBase = 0;
                mUsed = 0;
                mSize = 0;
                appendBytes(item, len);
            }
        }

        String(const String& other) {
            mpBase = 0;
            mUsed = 0;
            mSize = 0;
            appendBytes(other.getUnwrapped(), other.len());
        }

        ~String() {
            if (mpBase) {
                free(mpBase);
            }
        }

        String& operator=(const String& other) {
            clear();
            appendBytes(other.getUnwrapped(), other.len());
            return *this;
        }

        inline char* getUnwrapped() const {
            return mpBase;
        }

        void clear() {
            mUsed = 0;
            if (mSize > 0) {
                mpBase[0] = 0;
            }
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

        void append(String& other) {
            appendBytes(other.getUnwrapped(), other.len());
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

        inline size_t len() const {
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

    void internKeywords() {
        // Note: order has to match TOK_ constants
        static const char* keywords[] = {
            "int",
            "char",
            "void",
            "if",
            "else",
            "while",
            "break",
            "return",
            "for",
            "pragma",
            "define",
            "auto",
            "case",
            "const",
            "continue",
            "default",
            "do",
            "double",
            "enum",
            "extern",
            "float",
            "goto",
            "long",
            "register",
            "short",
            "signed",
            "sizeof",
            "static",
            "struct",
            "switch",
            "typedef",
            "union",
            "unsigned",
            "volatile",
            "_Bool",
            "_Complex",
            "_Imaginary",
            "inline",
            "restrict",
            0};

        for(int i = 0; keywords[i]; i++) {
            mTokenTable.intern(keywords[i], strlen(keywords[i]));
        }
    }

    struct InputState {
        InputStream* pStream;
        int oldCh;
    };

    struct VariableInfo {
        void* pAddress;
        void* pForward; // For a forward direction, linked list of data to fix up
        tokenid_t tok;
        size_t level;
        VariableInfo* pOldDefinition;
        Type* pType;
    };

    class SymbolStack {
    public:
        SymbolStack() {
            mpArena = 0;
            mpTokenTable = 0;
        }

        void setArena(Arena* pArena) {
            mpArena = pArena;
        }

        void setTokenTable(TokenTable* pTokenTable) {
            mpTokenTable = pTokenTable;
        }

        void pushLevel() {
            Mark mark;
            mark.mArenaMark = mpArena->mark();
            mark.mSymbolHead = mStack.size();
            mLevelStack.push_back(mark);
        }

        void popLevel() {
            // Undo any shadowing that was done:
            Mark mark = mLevelStack.back();
            mLevelStack.pop_back();
            while (mStack.size() > mark.mSymbolHead) {
                VariableInfo* pV = mStack.back();
                mStack.pop_back();
                (*mpTokenTable)[pV->tok].mpVariableInfo = pV->pOldDefinition;
            }
            mpArena->freeToMark(mark.mArenaMark);
        }

        bool isDefinedAtCurrentLevel(tokenid_t tok) {
            VariableInfo* pV = (*mpTokenTable)[tok].mpVariableInfo;
            return pV && pV->level == level();
        }

        VariableInfo* add(tokenid_t tok) {
            Token& token = (*mpTokenTable)[tok];
            VariableInfo* pOldV = token.mpVariableInfo;
            VariableInfo* pNewV =
                (VariableInfo*) mpArena->alloc(sizeof(VariableInfo));
            memset(pNewV, 0, sizeof(VariableInfo));
            pNewV->tok = tok;
            pNewV->level = level();
            pNewV->pOldDefinition = pOldV;
            token.mpVariableInfo = pNewV;
            mStack.push_back(pNewV);
            return pNewV;
        }

        VariableInfo* add(Type* pType) {
            VariableInfo* pVI = add(pType->id);
            pVI->pType = pType;
            return pVI;
        }

        void forEach(bool (*fn)(VariableInfo*, void*), void* context) {
            for (size_t i = 0; i < mStack.size(); i++) {
                if (! fn(mStack[i], context)) {
                    break;
                }
            }
        }

    private:
        inline size_t level() {
            return mLevelStack.size();
        }

        struct Mark {
            Arena::Mark mArenaMark;
            size_t mSymbolHead;
        };

        Arena* mpArena;
        TokenTable* mpTokenTable;
        Vector<VariableInfo*> mStack;
        Vector<Mark> mLevelStack;
    };

    int ch; // Current input character, or EOF
    tokenid_t tok;      // token
    intptr_t tokc;    // token extra info
    double tokd;     // floating point constant value
    int tokl;         // token operator level
    intptr_t rsym; // return symbol
    Type* pReturnType; // type of the current function's return.
    intptr_t loc; // local variable index
    char* glo;  // global variable index
    String mTokenString;
    char* dptr; // Macro state: Points to macro text during macro playback.
    int dch;    // Macro state: Saves old value of ch during a macro playback.
    char* pGlobalBase;

    // Arena for the duration of the compile
    Arena mGlobalArena;
    // Arena for data that's only needed when compiling a single function
    Arena mLocalArena;

    TokenTable mTokenTable;
    SymbolStack mGlobals;
    SymbolStack mLocals;

    // Prebuilt types, makes things slightly faster.
    Type* mkpInt;        // int
    Type* mkpChar;       // char
    Type* mkpVoid;       // void
    Type* mkpFloat;
    Type* mkpDouble;
    Type* mkpIntFn;
    Type* mkpIntPtr;
    Type* mkpCharPtr;
    Type* mkpFloatPtr;
    Type* mkpDoublePtr;
    Type* mkpPtrIntFn;

    InputStream* file;

    CodeBuf codeBuf;
    CodeGenerator* pGen;

    String mErrorBuf;

    String mPragmas;
    int mPragmaStringCount;

    static const int ALLOC_SIZE = 99999;

    static const int TOK_DUMMY = 1;
    static const int TOK_NUM = 2;
    static const int TOK_NUM_FLOAT = 3;
    static const int TOK_NUM_DOUBLE = 4;

    // 3..255 are character and/or operators

    // Keywords start at 0x100 and increase by 1
    // Order has to match string list in "internKeywords".
    enum {
        TOK_KEYWORD = TokenTable::TOKEN_BASE,
        TOK_INT = TOK_KEYWORD,
        TOK_CHAR,
        TOK_VOID,
        TOK_IF,
        TOK_ELSE,
        TOK_WHILE,
        TOK_BREAK,
        TOK_RETURN,
        TOK_FOR,
        TOK_PRAGMA,
        TOK_DEFINE,
        TOK_AUTO,
        TOK_CASE,
        TOK_CONST,
        TOK_CONTINUE,
        TOK_DEFAULT,
        TOK_DO,
        TOK_DOUBLE,
        TOK_ENUM,
        TOK_EXTERN,
        TOK_FLOAT,
        TOK_GOTO,
        TOK_LONG,
        TOK_REGISTER,
        TOK_SHORT,
        TOK_SIGNED,
        TOK_SIZEOF,
        TOK_STATIC,
        TOK_STRUCT,
        TOK_SWITCH,
        TOK_TYPEDEF,
        TOK_UNION,
        TOK_UNSIGNED,
        TOK_VOLATILE,
        TOK__BOOL,
        TOK__COMPLEX,
        TOK__IMAGINARY,
        TOK_INLINE,
        TOK_RESTRICT,
        // Symbols start after tokens
        TOK_SYMBOL
    };

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

    /* Called when we detect an internal problem. Does nothing in production.
     *
     */
    void internalError() {
        * (char*) 0 = 0;
    }

    void assert(bool isTrue) {
        if (!isTrue) {
            internalError();
        }
    }

    bool isSymbol(tokenid_t t) {
        return t >= TOK_SYMBOL &&
            ((size_t) (t-TOK_SYMBOL)) < mTokenTable.size();
    }

    bool isSymbolOrKeyword(tokenid_t t) {
        return t >= TOK_KEYWORD &&
            ((size_t) (t-TOK_KEYWORD)) < mTokenTable.size();
    }

    VariableInfo* VI(tokenid_t t) {
        assert(isSymbol(t));
        VariableInfo* pV = mTokenTable[t].mpVariableInfo;
        if (pV && pV->tok != t) {
            internalError();
        }
        return pV;
    }

    inline bool isDefined(tokenid_t t) {
        return t >= TOK_SYMBOL && VI(t) != 0;
    }

    const char* nameof(tokenid_t t) {
        assert(isSymbolOrKeyword(t));
        return mTokenTable[t].pText;
    }

    void pdef(int t) {
        mTokenString.append(t);
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

    /* read a character constant, advances ch to after end of constant */
    int getq() {
        int val = ch;
        if (ch == '\\') {
            inp();
            if (isoctal(ch)) {
                // 1 to 3 octal characters.
                val = 0;
                for(int i = 0; i < 3; i++) {
                    if (isoctal(ch)) {
                        val = (val << 3) + ch - '0';
                        inp();
                    }
                }
                return val;
            } else if (ch == 'x' || ch == 'X') {
                // N hex chars
                inp();
                if (! isxdigit(ch)) {
                    error("'x' character escape requires at least one digit.");
                } else {
                    val = 0;
                    while (isxdigit(ch)) {
                        int d = ch;
                        if (isdigit(d)) {
                            d -= '0';
                        } else if (d <= 'F') {
                            d = d - 'A' + 10;
                        } else {
                            d = d - 'a' + 10;
                        }
                        val = (val << 4) + d;
                        inp();
                    }
                }
            } else {
                int val = ch;
                switch (ch) {
                    case 'a':
                        val = '\a';
                        break;
                    case 'b':
                        val = '\b';
                        break;
                    case 'f':
                        val = '\f';
                        break;
                    case 'n':
                        val = '\n';
                        break;
                    case 'r':
                        val = '\r';
                        break;
                    case 't':
                        val = '\t';
                        break;
                    case 'v':
                        val = '\v';
                        break;
                    case '\\':
                        val = '\\';
                        break;
                    case '\'':
                        val = '\'';
                        break;
                    case '"':
                        val = '"';
                        break;
                    case '?':
                        val = '?';
                        break;
                    default:
                        error("Undefined character escape %c", ch);
                        break;
                }
                inp();
                return val;
            }
        } else {
            inp();
        }
        return val;
    }

    static bool isoctal(int ch) {
        return ch >= '0' && ch <= '7';
    }

    bool acceptCh(int c) {
        bool result = c == ch;
        if (result) {
            pdef(ch);
            inp();
        }
        return result;
    }

    bool acceptDigitsCh() {
        bool result = false;
        while (isdigit(ch)) {
            result = true;
            pdef(ch);
            inp();
        }
        return result;
    }

    void parseFloat() {
        tok = TOK_NUM_DOUBLE;
        // mTokenString already has the integral part of the number.
        acceptCh('.');
        acceptDigitsCh();
        bool doExp = true;
        if (acceptCh('e') || acceptCh('E')) {
            // Don't need to do any extra work
        } else if (ch == 'f' || ch == 'F') {
            pdef('e'); // So it can be parsed by strtof.
            inp();
            tok = TOK_NUM_FLOAT;
        } else {
            doExp = false;
        }
        if (doExp) {
            bool digitsRequired = acceptCh('-');
            bool digitsFound = acceptDigitsCh();
            if (digitsRequired && ! digitsFound) {
                error("malformed exponent");
            }
        }
        char* pText = mTokenString.getUnwrapped();
        if (tok == TOK_NUM_FLOAT) {
            tokd = strtof(pText, 0);
        } else {
            tokd = strtod(pText, 0);
        }
        //fprintf(stderr, "float constant: %s (%d) %g\n", pText, tok, tokd);
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
                    error("Unsupported preprocessor directive \"%s\"",
                          mTokenString.getUnwrapped());
                }
            }
            inp();
        }
        tokl = 0;
        tok = ch;
        /* encode identifiers & numbers */
        if (isid()) {
            mTokenString.clear();
            while (isid()) {
                pdef(ch);
                inp();
            }
            if (isdigit(tok)) {
                // Start of a numeric constant. Could be integer, float, or
                // double, won't know until we look further.
                if (ch == '.' || ch == 'e' || ch == 'e'
                    || ch == 'f' || ch == 'F')  {
                    parseFloat();
                } else {
                    // It's an integer constant
                    tokc = strtol(mTokenString.getUnwrapped(), 0, 0);
                    tok = TOK_NUM;
                }
            } else {
                tok = mTokenTable.intern(mTokenString.getUnwrapped(),
                                         mTokenString.len());
                // Is this a macro?
                char* pMacroDefinition = mTokenTable[tok].mpMacroDefinition;
                if(pMacroDefinition) {
                    // Yes, it is a macro
                    dptr = pMacroDefinition;
                    dch = ch;
                    inp();
                    next();
                }
            }
        } else {
            inp();
            if (tok == '\'') {
                tok = TOK_NUM;
                tokc = getq();
                if (ch != '\'') {
                    error("Expected a ' character, got %c", ch);
                } else {
                  inp();
                }
            } else if ((tok == '/') & (ch == '*')) {
                inp();
                while (ch && ch != EOF) {
                    while (ch != '*' && ch != EOF)
                        inp();
                    inp();
                    if (ch == '/')
                        ch = 0;
                }
                if (ch == EOF) {
                    error("End of file inside comment.");
                }
                inp();
                next();
            } else if ((tok == '/') & (ch == '/')) {
                inp();
                while (ch && (ch != '\n') && (ch != EOF)) {
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
            String buf;
            decodeToken(buf, tok);
            fprintf(stderr, "%s\n", buf.getUnwrapped());
        }
#endif
    }

    void doDefine() {
        next();
        tokenid_t name = tok;
        String* pName = new String();
        while (isspace(ch)) {
            inp();
        }
        if (ch == '(') {
            delete pName;
            error("Defines with arguments not supported");
            return;
        }
        while (isspace(ch)) {
            inp();
        }
        String value;
        while (ch != '\n' && ch != EOF) {
            value.append(ch);
            inp();
        }
        char* pDefn = (char*)mGlobalArena.alloc(value.len() + 1);
        memcpy(pDefn, value.getUnwrapped(), value.len());
        pDefn[value.len()] = 0;
        mTokenTable[name].mpMacroDefinition = pDefn;
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
    }

    void skip(intptr_t c) {
        if (tok != c) {
            error("'%c' expected", c);
        }
        next();
    }

    bool accept(intptr_t c) {
        if (tok == c) {
            next();
            return true;
        }
        return false;
    }

    bool acceptStringLiteral() {
        if (tok == '"') {
            pGen->li((int) glo, mkpCharPtr);
            // This while loop merges multiple adjacent string constants.
            while (tok == '"') {
                while (ch != '"' && ch != EOF) {
                    *allocGlobalSpace(1,1) = getq();
                }
                if (ch != '"') {
                    error("Unterminated string constant.");
                }
                inp();
                next();
            }
            /* Null terminate */
            *glo = 0;
            /* align heap */
            allocGlobalSpace(1,(char*) (((intptr_t) glo + 4) & -4) - glo);

            return true;
        }
        return false;
    }
    /* Parse and evaluate a unary expression.
     * allowAssignment is true if '=' parsing wanted (quick hack)
     */
    void unary(bool allowAssignment) {
        intptr_t n, t, a;
        t = 0;
        n = 1; /* type of expression 0 = forward, 1 = value, other = lvalue */
        if (acceptStringLiteral()) {
            // Nothing else to do.
        } else {
            int c = tokl;
            a = tokc;
            double ad = tokd;
            t = tok;
            next();
            if (t == TOK_NUM) {
                pGen->li(a, mkpInt);
            } else if (t == TOK_NUM_FLOAT) {
                // Align to 4-byte boundary
                glo = (char*) (((intptr_t) glo + 3) & -4);
                * (float*) glo = (float) ad;
                pGen->loadFloat((int) glo, mkpFloat);
                glo += 4;
            } else if (t == TOK_NUM_DOUBLE) {
                // Align to 8-byte boundary
                glo = (char*) (((intptr_t) glo + 7) & -8);
                * (double*) glo = ad;
                pGen->loadFloat((int) glo, mkpDouble);
                glo += 8;
            } else if (c == 2) {
                /* -, +, !, ~ */
                unary(false);
                if (t == '!')
                    pGen->gUnaryCmp(a, mkpInt);
                else if (t == '+') {
                    // ignore unary plus.
                } else {
                    pGen->genUnaryOp(a);
                }
            } else if (t == '(') {
                expr();
                skip(')');
            } else if (t == '*') {
                /* This is a pointer dereference, but we currently only
                 * support a pointer dereference if it's immediately
                 * in front of a cast. So parse the cast right here.
                 */
                skip('(');
                Type* pCast = expectCastTypeDeclaration(mLocalArena);
                // We currently only handle 3 types of cast:
                // (int*), (char*) , (int (*)())
                if(typeEqual(pCast, mkpIntPtr)) {
                    t = TOK_INT;
                } else if (typeEqual(pCast, mkpCharPtr)) {
                    t = TOK_CHAR;
                } else if (typeEqual(pCast, mkpFloatPtr)) {
                    t = TOK_FLOAT;
                } else if (typeEqual(pCast, mkpDoublePtr)) {
                    t = TOK_DOUBLE;
                } else if (typeEqual(pCast, mkpPtrIntFn)){
                    t = 0;
                } else {
                    String buffer;
                    decodeType(buffer, pCast);
                    error("Unsupported cast type %s", buffer.getUnwrapped());
                    decodeType(buffer, mkpPtrIntFn);
                }
                skip(')');
                unary(false);
                if (accept('=')) {
                    pGen->pushR0();
                    expr();
                    pGen->storeR0ToTOS(pCast);
                } else if (t) {
                    pGen->loadR0FromR0(pCast);
                }
                // Else we fall through to the function call below, with
                // t == 0 to trigger an indirect function call. Hack!
            } else if (t == '&') {
                VariableInfo* pVI = VI(tok);
                pGen->leaR0((int) pVI->pAddress,
                            createPtrType(pVI->pType, mLocalArena));
                next();
            } else if (t == EOF ) {
                error("Unexpected EOF.");
            } else if (!checkSymbol(t)) {
                // Don't have to do anything special here, the error
                // message was printed by checkSymbol() above.
            } else {
                if (!isDefined(t)) {
                    mGlobals.add(t);
                    // printf("Adding new global function %s\n", nameof(t));
                }
                VariableInfo* pVI = VI(t);
                n = (intptr_t) pVI->pAddress;
                /* forward reference: try dlsym */
                if (!n) {
                    n = (intptr_t) dlsym(RTLD_DEFAULT, nameof(t));
                    if (tok == '(') {
                        pVI->pType = mkpIntFn;
                    } else {
                        pVI->pType = mkpInt;
                    }
                    pVI->pAddress = (void*) n;
                }
                if ((tok == '=') & allowAssignment) {
                    /* assignment */
                    next();
                    expr();
                    pGen->storeR0(n, pVI->pType);
                } else if (tok != '(') {
                    /* variable */
                    if (!n) {
                        error("Undefined variable %s", nameof(t));
                    }
                    pGen->loadR0(n, tokl == 11, tokc, pVI->pType);
                    if (tokl == 11) {
                        next();
                    }
                }
            }
        }

        /* function call */
        if (accept('(')) {
            Type* pArgList = NULL;
            VariableInfo* pVI = NULL;
            if (n == 1) { // Indirect function call, push address of fn.
                pArgList = pGen->getR0Type()->pTail;
                pGen->pushR0();
            } else {
                pVI = VI(t);
                pArgList = pVI->pType->pTail;
            }
            bool varArgs = pArgList == NULL;
            /* push args and invert order */
            a = pGen->beginFunctionCallArguments();
            int l = 0;
            while (tok != ')' && tok != EOF) {
                if (! varArgs && !pArgList) {
                    error ("Unexpected argument.");
                }
                expr();
                Type* pTargetType;
                if (pArgList) {
                    pTargetType = pArgList->pHead;
                    pArgList = pArgList->pTail;
                } else {
                    pTargetType = pGen->getR0Type();
                    if (pTargetType->tag == TY_FLOAT) {
                        pTargetType = mkpDouble;
                    }
                }
                pGen->convertR0(pTargetType);
                l += pGen->storeR0ToArg(l);
                if (accept(',')) {
                    // fine
                } else if ( tok != ')') {
                    error("Expected ',' or ')'");
                }
            }
            if (! varArgs && pArgList) {
                error ("Expected more argument(s).");
            }
            pGen->endFunctionCallArguments(a, l);
            skip(')');
            if (!n) {
                /* forward reference */
                pVI->pForward = (void*) pGen->callForward((int) pVI->pForward,
                                                          pVI->pType);
            } else if (n == 1) {
                pGen->callIndirect(l, mkpPtrIntFn->pHead);
            } else {
                pGen->callRelative(n - codeBuf.getPC() - pGen->jumpOffset(),
                                   VI(t)->pType);
            }
            pGen->adjustStackAfterCall(l, n == 1);
        }
    }

    /* Recursive descent parser for binary operations.
     */
    void binaryOp(int level) {
        intptr_t t, n, a;
        t = 0;
        if (level-- == 1)
            unary(true);
        else {
            binaryOp(level);
            a = 0;
            while (level == tokl) {
                n = tok;
                t = tokc;
                next();

                if (level > 8) {
                    a = pGen->gtst(t == OP_LOGICAL_OR, a); /* && and || output code generation */
                    binaryOp(level);
                } else {
                    pGen->pushR0();
                    binaryOp(level);

                    if ((level == 4) | (level == 5)) {
                        pGen->gcmp(t, mkpInt);
                    } else {
                        pGen->genOp(t);
                    }
                }
            }
            /* && and || output code generation */
            if (a && level > 8) {
                a = pGen->gtst(t == OP_LOGICAL_OR, a);
                pGen->li(t != OP_LOGICAL_OR, mkpInt);
                pGen->gjmp(5); /* jmp $ + 5 (sizeof li, FIXME for ARM) */
                pGen->gsym(a);
                pGen->li(t == OP_LOGICAL_OR, mkpInt);
            }
        }
    }

    void expr() {
        binaryOp(11);
    }

    int test_expr() {
        expr();
        return pGen->gtst(0, 0);
    }

    void block(intptr_t l, bool outermostFunctionBlock) {
        intptr_t a, n, t;

        Type* pBaseType;
        if ((pBaseType = acceptPrimitiveType(mLocalArena))) {
            /* declarations */
            localDeclarations(pBaseType);
        } else if (tok == TOK_IF) {
            next();
            skip('(');
            a = test_expr();
            skip(')');
            block(l, false);
            if (tok == TOK_ELSE) {
                next();
                n = pGen->gjmp(0); /* jmp */
                pGen->gsym(a);
                block(l, false);
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
            block((intptr_t) &a, false);
            pGen->gjmp(n - codeBuf.getPC() - pGen->jumpOffset()); /* jmp */
            pGen->gsym(a);
        } else if (tok == '{') {
            if (! outermostFunctionBlock) {
                mLocals.pushLevel();
            }
            next();
            while (tok != '}' && tok != EOF)
                block(l, false);
            skip('}');
            if (! outermostFunctionBlock) {
                mLocals.popLevel();
            }
        } else {
            if (accept(TOK_RETURN)) {
                if (tok != ';') {
                    expr();
                    pGen->convertR0(pReturnType);
                }
                rsym = pGen->gjmp(rsym); /* jmp */
            } else if (accept(TOK_BREAK)) {
                *(int *) l = pGen->gjmp(*(int *) l);
            } else if (tok != ';')
                expr();
            skip(';');
        }
    }

    bool typeEqual(Type* a, Type* b) {
        if (a == b) {
            return true;
        }
        if (a == NULL || b == NULL) {
            return false;
        }
        TypeTag at = a->tag;
        if (at != b->tag) {
            return false;
        }
        if (at == TY_POINTER) {
            return typeEqual(a->pHead, b->pHead);
        } else if (at == TY_FUNC || at == TY_PARAM) {
            return typeEqual(a->pHead, b->pHead)
                && typeEqual(a->pTail, b->pTail);
        }
        return true;
    }

    Type* createType(TypeTag tag, Type* pHead, Type* pTail, Arena& arena) {
        assert(tag >= TY_INT && tag <= TY_PARAM);
        Type* pType = (Type*) arena.alloc(sizeof(Type));
        memset(pType, 0, sizeof(*pType));
        pType->tag = tag;
        pType->pHead = pHead;
        pType->pTail = pTail;
        return pType;
    }

    Type* createPtrType(Type* pType, Arena& arena) {
        return createType(TY_POINTER, pType, NULL, arena);
    }

    /**
     * Try to print a type in declaration order
     */
    void decodeType(String& buffer, Type* pType) {
        buffer.clear();
        if (pType == NULL) {
            buffer.appendCStr("null");
            return;
        }
        decodeTypeImp(buffer, pType);
    }

    void decodeTypeImp(String& buffer, Type* pType) {
        decodeTypeImpPrefix(buffer, pType);

        String temp;
        if (pType->id != 0) {
            decodeToken(temp, pType->id);
            buffer.append(temp);
        }

        decodeTypeImpPostfix(buffer, pType);
    }

    void decodeTypeImpPrefix(String& buffer, Type* pType) {
        TypeTag tag = pType->tag;

        if (tag >= TY_INT && tag <= TY_VOID) {
            switch (tag) {
                case TY_INT:
                    buffer.appendCStr("int");
                    break;
                case TY_CHAR:
                    buffer.appendCStr("char");
                    break;
                case TY_VOID:
                    buffer.appendCStr("void");
                    break;
                case TY_FLOAT:
                    buffer.appendCStr("float");
                    break;
                case TY_DOUBLE:
                    buffer.appendCStr("double");
                    break;
                default:
                    break;
            }
            buffer.append(' ');
        }

        switch (tag) {
            case TY_INT:
                break;
            case TY_CHAR:
                break;
            case TY_VOID:
                 break;
            case TY_FLOAT:
                 break;
            case TY_DOUBLE:
                break;
            case TY_POINTER:
                decodeTypeImpPrefix(buffer, pType->pHead);
                if(pType->pHead && pType->pHead->tag == TY_FUNC) {
                    buffer.append('(');
                }
                buffer.append('*');
                break;
            case TY_FUNC:
                decodeTypeImp(buffer, pType->pHead);
                break;
            case TY_PARAM:
                decodeTypeImp(buffer, pType->pHead);
                break;
            default:
                String temp;
                temp.printf("Unknown tag %d", pType->tag);
                buffer.append(temp);
                break;
        }
    }

    void decodeTypeImpPostfix(String& buffer, Type* pType) {
        TypeTag tag = pType->tag;

        switch(tag) {
            case TY_POINTER:
                if(pType->pHead && pType->pHead->tag == TY_FUNC) {
                    buffer.append(')');
                }
                decodeTypeImpPostfix(buffer, pType->pHead);
                break;
            case TY_FUNC:
                buffer.append('(');
                for(Type* pArg = pType->pTail; pArg; pArg = pArg->pTail) {
                    decodeTypeImp(buffer, pArg);
                    if (pArg->pTail) {
                        buffer.appendCStr(", ");
                    }
                }
                buffer.append(')');
                break;
            default:
                break;
        }
    }

    void printType(Type* pType) {
        String buffer;
        decodeType(buffer, pType);
        fprintf(stderr, "%s\n", buffer.getUnwrapped());
    }

    Type* acceptPrimitiveType(Arena& arena) {
        Type* pType;
        if (tok == TOK_INT) {
            pType = mkpInt;
        } else if (tok == TOK_CHAR) {
            pType = mkpChar;
        } else if (tok == TOK_VOID) {
            pType = mkpVoid;
        } else if (tok == TOK_FLOAT) {
            pType = mkpFloat;
        } else if (tok == TOK_DOUBLE) {
            pType = mkpDouble;
        } else {
            return NULL;
        }
        next();
        return pType;
    }

    Type* acceptDeclaration(Type* pType, bool nameAllowed, bool nameRequired,
                            Arena& arena) {
        tokenid_t declName = 0;
        pType = acceptDecl2(pType, declName, nameAllowed,
                                  nameRequired, arena);
        if (declName) {
            // Clone the parent type so we can set a unique ID
            pType = createType(pType->tag, pType->pHead,
                                      pType->pTail, arena);

            pType->id = declName;
        }
        // fprintf(stderr, "Parsed a declaration:       ");
        // printType(pType);
        return pType;
    }

    Type* expectDeclaration(Type* pBaseType, Arena& arena) {
        Type* pType = acceptDeclaration(pBaseType, true, true, arena);
        if (! pType) {
            error("Expected a declaration");
        }
        return pType;
    }

    /* Used for accepting types that appear in casts */
    Type* acceptCastTypeDeclaration(Arena& arena) {
        Type* pType = acceptPrimitiveType(arena);
        if (pType) {
            pType = acceptDeclaration(pType, false, false, arena);
        }
        return pType;
    }

    Type* expectCastTypeDeclaration(Arena& arena) {
        Type* pType = acceptCastTypeDeclaration(arena);
        if (! pType) {
            error("Expected a declaration");
        }
        return pType;
    }

    Type* acceptDecl2(Type* pType, tokenid_t& declName,
                      bool nameAllowed, bool nameRequired, Arena& arena) {
        int ptrCounter = 0;
        while (accept('*')) {
            ptrCounter++;
        }
        pType = acceptDecl3(pType, declName, nameAllowed, nameRequired, arena);
        while (ptrCounter-- > 0) {
            pType = createType(TY_POINTER, pType, NULL, arena);
        }
        return pType;
    }

    Type* acceptDecl3(Type* pType, tokenid_t& declName,
                      bool nameAllowed, bool nameRequired, Arena& arena) {
        // direct-dcl :
        //   name
        //  (dcl)
        //   direct-dcl()
        //   direct-dcl[]
        Type* pNewHead = NULL;
        if (accept('(')) {
            pNewHead = acceptDecl2(pNewHead, declName, nameAllowed,
                                nameRequired, arena);
            skip(')');
        } else if ((declName = acceptSymbol()) != 0) {
            if (nameAllowed == false && declName) {
                error("Symbol %s not allowed here", nameof(declName));
            } else if (nameRequired && ! declName) {
                String temp;
                decodeToken(temp, tok);
                error("Expected symbol. Got %s", temp.getUnwrapped());
            }
        }
        while (accept('(')) {
            // Function declaration
            Type* pTail = acceptArgs(nameAllowed, arena);
            pType = createType(TY_FUNC, pType, pTail, arena);
            skip(')');
        }

        if (pNewHead) {
            Type* pA = pNewHead;
            while (pA->pHead) {
                pA = pA->pHead;
            }
            pA->pHead = pType;
            pType = pNewHead;
        }
        return pType;
    }

    Type* acceptArgs(bool nameAllowed, Arena& arena) {
        Type* pHead = NULL;
        Type* pTail = NULL;
        for(;;) {
            Type* pBaseArg = acceptPrimitiveType(arena);
            if (pBaseArg) {
                Type* pArg = acceptDeclaration(pBaseArg, nameAllowed, false,
                                               arena);
                if (pArg) {
                    Type* pParam = createType(TY_PARAM, pArg, NULL, arena);
                    if (!pHead) {
                        pHead = pParam;
                        pTail = pParam;
                    } else {
                        pTail->pTail = pParam;
                        pTail = pParam;
                    }
                }
            }
            if (! accept(',')) {
                break;
            }
        }
        return pHead;
    }

    Type* expectPrimitiveType(Arena& arena) {
        Type* pType = acceptPrimitiveType(arena);
        if (!pType) {
            String buf;
            decodeToken(buf, tok);
            error("Expected a type, got %s", buf.getUnwrapped());
        }
        return pType;
    }

    void addGlobalSymbol(Type* pDecl) {
        tokenid_t t = pDecl->id;
        VariableInfo* pVI = VI(t);
        if(pVI && pVI->pAddress) {
            reportDuplicate(t);
        }
        mGlobals.add(pDecl);
    }

    void reportDuplicate(tokenid_t t) {
        error("Duplicate definition of %s", nameof(t));
    }

    void addLocalSymbol(Type* pDecl) {
        tokenid_t t = pDecl->id;
        if (mLocals.isDefinedAtCurrentLevel(t)) {
            reportDuplicate(t);
        }
        mLocals.add(pDecl);
    }

    void localDeclarations(Type* pBaseType) {
        intptr_t a;

        while (pBaseType) {
            while (tok != ';' && tok != EOF) {
                Type* pDecl = expectDeclaration(pBaseType, mLocalArena);
                if (!pDecl) {
                    break;
                }
                int variableAddress = 0;
                addLocalSymbol(pDecl);
                loc = loc + pGen->sizeOf(pDecl);
                loc = loc + 4;
                variableAddress = -loc;
                VI(pDecl->id)->pAddress = (void*) variableAddress;
                if (accept('=')) {
                    /* assignment */
                    expr();
                    pGen->storeR0(variableAddress, pDecl);
                }
                if (tok == ',')
                    next();
            }
            skip(';');
            pBaseType = acceptPrimitiveType(mLocalArena);
        }
    }

    bool checkSymbol() {
        return checkSymbol(tok);
    }

    void decodeToken(String& buffer, tokenid_t token) {
        if (token == EOF ) {
            buffer.printf("EOF");
        } else if (token == TOK_NUM) {
            buffer.printf("numeric constant");
        } else if (token >= 0 && token < 256) {
            if (token < 32) {
                buffer.printf("'\\x%02x'", token);
            } else {
                buffer.printf("'%c'", token);
            }
        } else if (token >= TOK_KEYWORD && token < TOK_SYMBOL) {
            buffer.printf("keyword \"%s\"", nameof(token));
        } else {
            buffer.printf("symbol \"%s\"", nameof(token));
        }
    }

    bool checkSymbol(tokenid_t token) {
        bool result = token >= TOK_SYMBOL;
        if (!result) {
            String temp;
            decodeToken(temp, token);
            error("Expected symbol. Got %s", temp.getUnwrapped());
        }
        return result;
    }

    tokenid_t acceptSymbol() {
        tokenid_t result = 0;
        if (tok >= TOK_SYMBOL) {
            result = tok;
            next();
        }
        return result;
    }

    void globalDeclarations() {
        while (tok != EOF) {
            Type* pBaseType = expectPrimitiveType(mGlobalArena);
            if (!pBaseType) {
                break;
            }
            Type* pDecl = expectDeclaration(pBaseType, mGlobalArena);
            if (!pDecl) {
                break;
            }
            if (! isDefined(pDecl->id)) {
                addGlobalSymbol(pDecl);
            }
            VariableInfo* name = VI(pDecl->id);
            if (name && name->pAddress) {
                error("Already defined global %s", nameof(pDecl->id));
            }
            if (pDecl->tag < TY_FUNC) {
                // it's a variable declaration
                for(;;) {
                    if (name && !name->pAddress) {
                        name->pAddress = (int*) allocGlobalSpace(
                                                   pGen->alignment(name->pType),
                                                   pGen->sizeOf(name->pType));
                    }
                    if (accept('=')) {
                        if (tok == TOK_NUM) {
                            if (name) {
                                * (int*) name->pAddress = tokc;
                            }
                            next();
                        } else {
                            error("Expected an integer constant");
                        }
                    }
                    if (!accept(',')) {
                        break;
                    }
                    pDecl = expectDeclaration(pBaseType, mGlobalArena);
                    if (!pDecl) {
                        break;
                    }
                    if (! isDefined(pDecl->id)) {
                        addGlobalSymbol(pDecl);
                    }
                    name = VI(pDecl->id);
                }
                skip(';');
            } else {
                // Function declaration
                if (accept(';')) {
                    // forward declaration.
                } else {
                    if (name) {
                        /* patch forward references (XXX: does not work for function
                         pointers) */
                        pGen->gsym((int) name->pForward);
                        /* put function address */
                        name->pAddress = (void*) codeBuf.getPC();
                    }
                    // Calculate stack offsets for parameters
                    mLocals.pushLevel();
                    intptr_t a = 8;
                    int argCount = 0;
                    for (Type* pP = pDecl->pTail; pP; pP = pP->pTail) {
                        Type* pArg = pP->pHead;
                        addLocalSymbol(pArg);
                        /* read param name and compute offset */
                        VI(pArg->id)->pAddress = (void*) a;
                        a = a + pGen->stackSizeOf(pArg);
                        argCount++;
                    }
                    rsym = loc = 0;
                    pReturnType = pDecl->pHead;
                    a = pGen->functionEntry(argCount);
                    block(0, true);
                    pGen->gsym(rsym);
                    pGen->functionExit(argCount, a, loc);
                    mLocals.popLevel();
                }
            }
        }
    }

    char* allocGlobalSpace(size_t alignment, size_t bytes) {
        size_t base = (((size_t) glo) + alignment - 1) & ~(alignment-1);
        size_t end = base + bytes;
        if ((end - (size_t) pGlobalBase) > (size_t) ALLOC_SIZE) {
            error("Global space exhausted");
            return NULL;
        }
        char* result = (char*) base;
        glo = (char*) end;
        return result;
    }

    void cleanup() {
        if (pGlobalBase != 0) {
            free(pGlobalBase);
            pGlobalBase = 0;
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
        rsym = 0;
        loc = 0;
        glo = 0;
        dptr = 0;
        dch = 0;
        file = 0;
        pGlobalBase = 0;
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
        } else {
            pGen->setErrorSink(this);
        }
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

        cleanup();
        clear();
        mTokenTable.setArena(&mGlobalArena);
        mGlobals.setArena(&mGlobalArena);
        mGlobals.setTokenTable(&mTokenTable);
        mLocals.setArena(&mLocalArena);
        mLocals.setTokenTable(&mTokenTable);

        internKeywords();
        createPrimitiveTypes();
        codeBuf.init(ALLOC_SIZE);
        setArchitecture(NULL);
        if (!pGen) {
            return -1;
        }
#ifdef PROVIDE_TRACE_CODEGEN
            pGen = new TraceCodeGenerator(pGen);
#endif
            pGen->setErrorSink(this);
        pGen->init(&codeBuf);
        file = new TextInputStream(text, textLength);
        pGlobalBase = (char*) calloc(1, ALLOC_SIZE);
        glo = pGlobalBase;
        inp();
        next();
        globalDeclarations();
        checkForUndefinedForwardReferences();
        result = pGen->finishCompile();
        if (result == 0) {
            if (mErrorBuf.len()) {
                result = -2;
            }
        }
        return result;
    }

    void createPrimitiveTypes() {
        mkpInt = createType(TY_INT, NULL, NULL, mGlobalArena);
        mkpChar = createType(TY_CHAR, NULL, NULL, mGlobalArena);
        mkpVoid = createType(TY_VOID, NULL, NULL, mGlobalArena);
        mkpFloat = createType(TY_FLOAT, NULL, NULL, mGlobalArena);
        mkpDouble = createType(TY_DOUBLE, NULL, NULL, mGlobalArena);
        mkpIntFn =  createType(TY_FUNC, mkpInt, NULL, mGlobalArena);
        mkpIntPtr = createPtrType(mkpInt, mGlobalArena);
        mkpCharPtr = createPtrType(mkpChar, mGlobalArena);
        mkpFloatPtr = createPtrType(mkpFloat, mGlobalArena);
        mkpDoublePtr = createPtrType(mkpDouble, mGlobalArena);
        mkpPtrIntFn = createPtrType(mkpIntFn, mGlobalArena);
    }

    void checkForUndefinedForwardReferences() {
        mGlobals.forEach(static_ufrcFn, this);
    }

    static bool static_ufrcFn(VariableInfo* value, void* context) {
        Compiler* pCompiler = (Compiler*) context;
        return pCompiler->undefinedForwardReferenceCheck(value);
    }

    bool undefinedForwardReferenceCheck(VariableInfo* value) {
        if (!value->pAddress && value->pForward) {
            error("Undefined forward reference: %s",
                  mTokenTable[value->tok].pText);
        }
        return true;
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
        tokenid_t tok = mTokenTable.intern(name, strlen(name));
        VariableInfo* pVariableInfo = VI(tok);
        if (pVariableInfo) {
            return pVariableInfo->pAddress;
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

extern "C"
void accDisassemble(ACCscript* script) {
    script->compiler.disassemble(stderr);
}


} // namespace acc

