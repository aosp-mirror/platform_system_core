/*
 * Android "Almost" C Compiler.
 * This is a compiler for a small subset of the C language, intended for use
 * in scripting environments where speed and memory footprint are important.
 *
 * This code is based upon the "unobfuscated" version of the
 * Obfuscated Tiny C compiler, see the file LICENSE for details.
 *
 */

#define LOG_TAG "acc"
#include <cutils/log.h>

#include <ctype.h>
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

#define ENABLE_ARM_DISASSEMBLY
// #define PROVIDE_TRACE_CODEGEN

#define assert(b) assertImpl(b, __LINE__)

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
        TY_INT,       // 0
        TY_CHAR,      // 1
        TY_SHORT,     // 2
        TY_VOID,      // 3
        TY_FLOAT,     // 4
        TY_DOUBLE,    // 5
        TY_POINTER,   // 6
        TY_ARRAY,     // 7
        TY_STRUCT,    // 8
        TY_FUNC,      // 9
        TY_PARAM      // 10
    };

    struct Type {
        TypeTag tag;
        tokenid_t id; // For function arguments, local vars
        int length; // length of array
        Type* pHead;
        Type* pTail;
    };

    enum ExpressionType {
        ET_RVALUE,
        ET_LVALUE
    };

    struct ExpressionValue {
        ExpressionValue() {
            et = ET_RVALUE;
            pType = NULL;
        }
        ExpressionType et;
        Type* pType;
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

        /* Give the code generator some utility types so it can
         * use its own types as needed for the results of some
         * operations like gcmp.
         */

        void setTypes(Type* pInt) {
            mkpInt = pInt;
        }

        /* Emit a function prolog.
         * pDecl is the function declaration, which gives the arguments.
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
        virtual int functionEntry(Type* pDecl) = 0;

        /* Emit a function epilog.
         * Restore the old SP and FP register values.
         * Return to the calling function.
         * argCount - the number of arguments to the function.
         * localVariableAddress - returned from functionEntry()
         * localVariableSize - the size in bytes of the local variables.
         */
        virtual void functionExit(Type* pDecl, int localVariableAddress,
                                  int localVariableSize) = 0;

        /* load immediate value to R0 */
        virtual void li(int i) = 0;

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
        virtual void gcmp(int op) = 0;

        /* Perform the arithmetic op specified by op. TOS is the
         * left argument, R0 is the right argument.
         * Pops TOS.
         */
        virtual void genOp(int op) = 0;

        /* Compare 0 against R0, and store the boolean result in R0.
         * op specifies the comparison.
         */
        virtual void gUnaryCmp(int op) = 0;

        /* Perform the arithmetic op specified by op. 0 is the
         * left argument, R0 is the right argument.
         */
        virtual void genUnaryOp(int op) = 0;

        /* Push R0 onto the stack. (Also known as "dup" for duplicate.)
         */
        virtual void pushR0() = 0;

        /* Turn R0, TOS into R0 TOS R0 */

        virtual void over() = 0;

        /* Pop R0 from the stack. (Also known as "drop")
         */
        virtual void popR0() = 0;

        /* Store R0 to the address stored in TOS.
         * The TOS is popped.
         */
        virtual void storeR0ToTOS() = 0;

        /* Load R0 from the address stored in R0.
         */
        virtual void loadR0FromR0() = 0;

        /* Load the absolute address of a variable to R0.
         * If ea <= LOCAL, then this is a local variable, or an
         * argument, addressed relative to FP.
         * else it is an absolute global address.
         *
         * et is ET_RVALUE for things like string constants, ET_LVALUE for
         * variables.
         */
        virtual void leaR0(int ea, Type* pPointerType, ExpressionType et) = 0;

        /* Load the pc-relative address of a forward-referenced variable to R0.
         * Return the address of the 4-byte constant so that it can be filled
         * in later.
         */
        virtual int leaForward(int ea, Type* pPointerType) = 0;

        /**
         * Convert R0 to the given type.
         */

        void convertR0(Type* pType) {
            convertR0Imp(pType, false);
        }

        void castR0(Type* pType) {
            convertR0Imp(pType, true);
        }

        virtual void convertR0Imp(Type* pType, bool isCast) = 0;

        /* Emit code to adjust the stack for a function call. Return the
         * label for the address of the instruction that adjusts the
         * stack size. This will be passed as argument "a" to
         * endFunctionCallArguments.
         */
        virtual int beginFunctionCallArguments() = 0;

        /* Emit code to store R0 to the stack at byte offset l.
         * Returns stack size of object (typically 4 or 8 bytes)
         */
        virtual size_t storeR0ToArg(int l, Type* pArgType) = 0;

        /* Patch the function call preamble.
         * a is the address returned from beginFunctionCallArguments
         * l is the number of bytes the arguments took on the stack.
         * Typically you would also emit code to convert the argument
         * list into whatever the native function calling convention is.
         * On ARM for example you would pop the first 5 arguments into
         * R0..R4
         */
        virtual void endFunctionCallArguments(Type* pDecl, int a, int l) = 0;

        /* Emit a call to an unknown function. The argument "symbol" needs to
         * be stored in the location where the address should go. It forms
         * a chain. The address will be patched later.
         * Return the address of the word that has to be patched.
         */
        virtual int callForward(int symbol, Type* pFunc) = 0;

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
        virtual void adjustStackAfterCall(Type* pDecl, int l, bool isIndirect) = 0;

        /* Print a disassembly of the assembled code to out. Return
         * non-zero if there is an error.
         */
        virtual int disassemble(FILE* out) = 0;

        /* Generate a symbol at the current PC. t is the head of a
         * linked list of addresses to patch.
         */
        virtual void gsym(int t) = 0;

        /* Resolve a forward reference function at the current PC.
         * t is the head of a
         * linked list of addresses to patch.
         * (Like gsym, but using absolute address, not PC relative address.)
         */
        virtual void resolveForward(int t) = 0;

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
        virtual size_t alignmentOf(Type* type) = 0;

        /**
         * Array element alignment (in bytes) for this type of data.
         */
        virtual size_t sizeOf(Type* type) = 0;

        /**
         * Stack alignment of this type of data
         */
        virtual size_t stackAlignmentOf(Type* pType) = 0;

        /**
         * Argument stack argument size of this data type.
         */
        virtual size_t stackSizeOf(Type* pType) = 0;

        virtual Type* getR0Type() {
            return mExpressionStack.back().pType;
        }

        virtual ExpressionType getR0ExpressionType() {
            return mExpressionStack.back().et;
        }

        virtual void setR0ExpressionType(ExpressionType et) {
            mExpressionStack.back().et = et;
        }

        virtual size_t getExpressionStackDepth() {
            return mExpressionStack.size();
        }

        virtual void forceR0RVal() {
            if (getR0ExpressionType() == ET_LVALUE) {
                loadR0FromR0();
            }
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

        void assertImpl(bool test, int line) {
            if (!test) {
                error("code generator assertion failed at line %s:%d.", __FILE__, line);
                LOGD("code generator assertion failed at line %s:%d.", __FILE__, line);
                * (char*) 0 = 0;
            }
        }

        void setR0Type(Type* pType) {
            assert(pType != NULL);
            mExpressionStack.back().pType = pType;
            mExpressionStack.back().et = ET_RVALUE;
        }

        void setR0Type(Type* pType, ExpressionType et) {
            assert(pType != NULL);
            mExpressionStack.back().pType = pType;
            mExpressionStack.back().et = et;
        }

        Type* getTOSType() {
            return mExpressionStack[mExpressionStack.size()-2].pType;
        }

        void pushType() {
            if (mExpressionStack.size()) {
                mExpressionStack.push_back(mExpressionStack.back());
            } else {
                mExpressionStack.push_back(ExpressionValue());
            }

        }

        void overType() {
            size_t size = mExpressionStack.size();
            if (size >= 2) {
                mExpressionStack.push_back(mExpressionStack.back());
                mExpressionStack[size-1] = mExpressionStack[size-2];
                mExpressionStack[size-2] = mExpressionStack[size];
            }
        }

        void popType() {
            mExpressionStack.pop_back();
        }

        bool bitsSame(Type* pA, Type* pB) {
            return collapseType(pA->tag) == collapseType(pB->tag);
        }

        TypeTag collapseType(TypeTag tag) {
            static const TypeTag collapsedTag[] = {
                    TY_INT,
                    TY_INT,
                    TY_INT,
                    TY_VOID,
                    TY_FLOAT,
                    TY_DOUBLE,
                    TY_INT,
                    TY_INT,
                    TY_VOID,
                    TY_VOID,
                    TY_VOID
                };
            return collapsedTag[tag];
        }

        TypeTag collapseTypeR0() {
            return collapseType(getR0Type()->tag);
        }

        static bool isFloatType(Type* pType) {
            return isFloatTag(pType->tag);
        }

        static bool isFloatTag(TypeTag tag) {
            return tag == TY_FLOAT || tag == TY_DOUBLE;
        }

        static bool isPointerType(Type* pType) {
            return isPointerTag(pType->tag);
        }

        static bool isPointerTag(TypeTag tag) {
            return tag == TY_POINTER || tag == TY_ARRAY;
        }

        Type* getPointerArithmeticResultType(Type* a, Type* b) {
            TypeTag aTag = a->tag;
            TypeTag bTag = b->tag;
            if (aTag == TY_POINTER) {
                return a;
            }
            if (bTag == TY_POINTER) {
                return b;
            }
            if (aTag == TY_ARRAY) {
                return a->pTail;
            }
            if (bTag == TY_ARRAY) {
                return b->pTail;
            }
            return NULL;
        }

        Type* mkpInt;

    private:
        Vector<ExpressionValue> mExpressionStack;
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
        virtual int functionEntry(Type* pDecl) {
            mStackUse = 0;
            // sp -> arg4 arg5 ...
            // Push our register-based arguments back on the stack
            int regArgCount = calcRegArgCount(pDecl);
            if (regArgCount > 0) {
                mStackUse += regArgCount * 4;
                o4(0xE92D0000 | ((1 << regArgCount) - 1)); // stmfd    sp!, {}
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

        virtual void functionExit(Type* pDecl, int localVariableAddress, int localVariableSize) {
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

            // We store the PC into the lr so we can adjust the sp before
            // returning. We need to pull off the registers we pushed
            // earlier. We don't need to actually store them anywhere,
            // just adjust the stack.
            int regArgCount = calcRegArgCount(pDecl);
            if (regArgCount) {
                o4(0xE28DD000 | (regArgCount << 2)); // add sp, sp, #argCount << 2
            }
            o4(0xE12FFF1E); // bx lr
        }

        /* load immediate value */
        virtual void li(int t) {
            liReg(t, 0);
            setR0Type(mkpInt);
        }

        virtual void loadFloat(int address, Type* pType) {
            setR0Type(pType);
            // Global, absolute address
            o4(0xE59F0000); //        ldr r0, .L1
            o4(0xEA000000); //        b .L99
            o4(address);         // .L1:   .word ea
                                 // .L99:

            switch (pType->tag) {
            case TY_FLOAT:
                o4(0xE5900000);      // ldr r0, [r0]
                break;
            case TY_DOUBLE:
                o4(0xE1C000D0);      // ldrd r0, [r0]
                break;
            default:
                assert(false);
                break;
            }
        }

        virtual int gjmp(int t) {
            return o4(0xEA000000 | encodeAddress(t)); // b .L33
        }

        /* l = 0: je, l == 1: jne */
        virtual int gtst(bool l, int t) {
            Type* pR0Type = getR0Type();
            TypeTag tagR0 = pR0Type->tag;
            switch(tagR0) {
                case TY_FLOAT:
                    callRuntime((void*) runtime_is_non_zero_f);
                    break;
                case TY_DOUBLE:
                    callRuntime((void*) runtime_is_non_zero_d);
                    break;
                default:
                    break;
            }
            o4(0xE3500000); // cmp r0,#0
            int branch = l ? 0x1A000000 : 0x0A000000; // bne : beq
            return o4(branch | encodeAddress(t));
        }

        virtual void gcmp(int op) {
            Type* pR0Type = getR0Type();
            Type* pTOSType = getTOSType();
            TypeTag tagR0 = collapseType(pR0Type->tag);
            TypeTag tagTOS = collapseType(pTOSType->tag);
            if (tagR0 == TY_INT && tagTOS == TY_INT) {
                setupIntPtrArgs();
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
            } else if (tagR0 == TY_DOUBLE || tagTOS == TY_DOUBLE) {
                setupDoubleArgs();
                switch(op) {
                    case OP_EQUALS:
                        callRuntime((void*) runtime_cmp_eq_dd);
                        break;
                    case OP_NOT_EQUALS:
                        callRuntime((void*) runtime_cmp_ne_dd);
                        break;
                    case OP_LESS_EQUAL:
                        callRuntime((void*) runtime_cmp_le_dd);
                        break;
                    case OP_GREATER:
                        callRuntime((void*) runtime_cmp_gt_dd);
                        break;
                    case OP_GREATER_EQUAL:
                        callRuntime((void*) runtime_cmp_ge_dd);
                        break;
                    case OP_LESS:
                        callRuntime((void*) runtime_cmp_lt_dd);
                        break;
                    default:
                        error("Unknown comparison op %d", op);
                        break;
                }
            } else {
                setupFloatArgs();
                switch(op) {
                    case OP_EQUALS:
                        callRuntime((void*) runtime_cmp_eq_ff);
                        break;
                    case OP_NOT_EQUALS:
                        callRuntime((void*) runtime_cmp_ne_ff);
                        break;
                    case OP_LESS_EQUAL:
                        callRuntime((void*) runtime_cmp_le_ff);
                        break;
                    case OP_GREATER:
                        callRuntime((void*) runtime_cmp_gt_ff);
                        break;
                    case OP_GREATER_EQUAL:
                        callRuntime((void*) runtime_cmp_ge_ff);
                        break;
                    case OP_LESS:
                        callRuntime((void*) runtime_cmp_lt_ff);
                        break;
                    default:
                        error("Unknown comparison op %d", op);
                        break;
                }
            }
            setR0Type(mkpInt);
        }

        virtual void genOp(int op) {
            Type* pR0Type = getR0Type();
            Type* pTOSType = getTOSType();
            TypeTag tagR0 = pR0Type->tag;
            TypeTag tagTOS = pTOSType->tag;
            bool isFloatR0 = isFloatTag(tagR0);
            bool isFloatTOS = isFloatTag(tagTOS);
            if (!isFloatR0 && !isFloatTOS) {
                setupIntPtrArgs();
                bool isPtrR0 = isPointerTag(tagR0);
                bool isPtrTOS = isPointerTag(tagTOS);
                if (isPtrR0 || isPtrTOS) {
                    if (isPtrR0 && isPtrTOS) {
                        if (op != OP_MINUS) {
                            error("Unsupported pointer-pointer operation %d.", op);
                        }
                        if (! typeEqual(pR0Type, pTOSType)) {
                            error("Incompatible pointer types for subtraction.");
                        }
                        o4(0xE0410000); // sub     r0,r1,r0
                        setR0Type(mkpInt);
                        int size = sizeOf(pR0Type->pHead);
                        if (size != 1) {
                            pushR0();
                            li(size);
                            // TODO: Optimize for power-of-two.
                            genOp(OP_DIV);
                        }
                    } else {
                        if (! (op == OP_PLUS || (op == OP_MINUS && isPtrR0))) {
                            error("Unsupported pointer-scalar operation %d", op);
                        }
                        Type* pPtrType = getPointerArithmeticResultType(
                                pR0Type, pTOSType);
                        int size = sizeOf(pPtrType->pHead);
                        if (size != 1) {
                            // TODO: Optimize for power-of-two.
                            liReg(size, 2);
                            if (isPtrR0) {
                                o4(0x0E0010192); // mul     r1,r2,r1
                            } else {
                                o4(0x0E0000092); // mul     r0,r2,r0
                            }
                        }
                        switch(op) {
                            case OP_PLUS:
                            o4(0xE0810000); // add     r0,r1,r0
                            break;
                            case OP_MINUS:
                            o4(0xE0410000); // sub     r0,r1,r0
                            break;
                        }
                        setR0Type(pPtrType);
                    }
                } else {
                    switch(op) {
                        case OP_MUL:
                        o4(0x0E0000091); // mul     r0,r1,r0
                        break;
                        case OP_DIV:
                        callRuntime((void*) runtime_DIV);
                        break;
                        case OP_MOD:
                        callRuntime((void*) runtime_MOD);
                        break;
                        case OP_PLUS:
                        o4(0xE0810000); // add     r0,r1,r0
                        break;
                        case OP_MINUS:
                        o4(0xE0410000); // sub     r0,r1,r0
                        break;
                        case OP_SHIFT_LEFT:
                        o4(0xE1A00011); // lsl     r0,r1,r0
                        break;
                        case OP_SHIFT_RIGHT:
                        o4(0xE1A00051); // asr     r0,r1,r0
                        break;
                        case OP_BIT_AND:
                        o4(0xE0010000); // and     r0,r1,r0
                        break;
                        case OP_BIT_XOR:
                        o4(0xE0210000); // eor     r0,r1,r0
                        break;
                        case OP_BIT_OR:
                        o4(0xE1810000); // orr     r0,r1,r0
                        break;
                        case OP_BIT_NOT:
                        o4(0xE1E00000); // mvn     r0, r0
                        break;
                        default:
                        error("Unimplemented op %d\n", op);
                        break;
                    }
                }
            } else {
                Type* pResultType = tagR0 > tagTOS ? pR0Type : pTOSType;
                if (pResultType->tag == TY_DOUBLE) {
                    setupDoubleArgs();
                    switch(op) {
                    case OP_MUL:
                        callRuntime((void*) runtime_op_mul_dd);
                        break;
                    case OP_DIV:
                        callRuntime((void*) runtime_op_div_dd);
                        break;
                    case OP_PLUS:
                        callRuntime((void*) runtime_op_add_dd);
                        break;
                    case OP_MINUS:
                        callRuntime((void*) runtime_op_sub_dd);
                        break;
                    default:
                        error("Unsupported binary floating operation %d\n", op);
                        break;
                    }
                } else {
                    setupFloatArgs();
                    switch(op) {
                    case OP_MUL:
                        callRuntime((void*) runtime_op_mul_ff);
                        break;
                    case OP_DIV:
                        callRuntime((void*) runtime_op_div_ff);
                        break;
                    case OP_PLUS:
                        callRuntime((void*) runtime_op_add_ff);
                        break;
                    case OP_MINUS:
                        callRuntime((void*) runtime_op_sub_ff);
                        break;
                    default:
                        error("Unsupported binary floating operation %d\n", op);
                        break;
                    }
                }
                setR0Type(pResultType);
            }
        }

        virtual void gUnaryCmp(int op) {
            if (op != OP_LOGICAL_NOT) {
                error("Unknown unary cmp %d", op);
            } else {
                Type* pR0Type = getR0Type();
                TypeTag tag = collapseType(pR0Type->tag);
                switch(tag) {
                    case TY_INT:
                        o4(0xE3A01000); // mov    r1, #0
                        o4(0xE1510000); // cmp r1, r0
                        o4(0x03A00001); // moveq r0,#1
                        o4(0x13A00000); // movne r0,#0
                        break;
                    case TY_FLOAT:
                        callRuntime((void*) runtime_is_zero_f);
                        break;
                    case TY_DOUBLE:
                        callRuntime((void*) runtime_is_zero_d);
                        break;
                    default:
                        error("gUnaryCmp unsupported type");
                        break;
                }
            }
            setR0Type(mkpInt);
        }

        virtual void genUnaryOp(int op) {
            Type* pR0Type = getR0Type();
            TypeTag tag = collapseType(pR0Type->tag);
            switch(tag) {
                case TY_INT:
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
                    break;
                case TY_FLOAT:
                case TY_DOUBLE:
                    switch (op) {
                        case OP_MINUS:
                            if (tag == TY_FLOAT) {
                                callRuntime((void*) runtime_op_neg_f);
                            } else {
                                callRuntime((void*) runtime_op_neg_d);
                            }
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
            if (r0ct != TY_DOUBLE) {
                    o4(0xE92D0001);  // stmfd   sp!,{r0}
                    mStackUse += 4;
            } else {
                    o4(0xE92D0003);  // stmfd   sp!,{r0,r1}
                    mStackUse += 8;
            }
            pushType();
            LOG_STACK("pushR0: %d\n", mStackUse);
        }

        virtual void over() {
            // We know it's only used for int-ptr ops (++/--)

            Type* pR0Type = getR0Type();
            TypeTag r0ct = collapseType(pR0Type->tag);

            Type* pTOSType = getTOSType();
            TypeTag tosct = collapseType(pTOSType->tag);

            assert (r0ct == TY_INT  && tosct == TY_INT);

            o4(0xE8BD0002);  // ldmfd   sp!,{r1}
            o4(0xE92D0001);  // stmfd   sp!,{r0}
            o4(0xE92D0002);  // stmfd   sp!,{r1}
            overType();
            mStackUse += 4;
        }

        virtual void popR0() {
            Type* pTOSType = getTOSType();
            switch (collapseType(pTOSType->tag)){
                case TY_INT:
                case TY_FLOAT:
                    o4(0xE8BD0001);  // ldmfd   sp!,{r0}
                    mStackUse -= 4;
                    break;
                case TY_DOUBLE:
                    o4(0xE8BD0003);  // ldmfd   sp!,{r0, r1}  // Restore R0
                        mStackUse -= 8;
                    break;
                default:
                    error("Can't pop this type.");
                    break;
            }
            popType();
            LOG_STACK("popR0: %d\n", mStackUse);
        }

        virtual void storeR0ToTOS() {
            Type* pPointerType = getTOSType();
            assert(pPointerType->tag == TY_POINTER);
            Type* pDestType = pPointerType->pHead;
            convertR0(pDestType);
            o4(0xE8BD0004);  // ldmfd   sp!,{r2}
            popType();
            mStackUse -= 4;
            switch (pDestType->tag) {
                case TY_POINTER:
                case TY_INT:
                case TY_FLOAT:
                    o4(0xE5820000); // str r0, [r2]
                    break;
                case TY_SHORT:
                    o4(0xE1C200B0); // strh r0, [r2]
                    break;
                case TY_CHAR:
                    o4(0xE5C20000); // strb r0, [r2]
                    break;
                case TY_DOUBLE:
                    o4(0xE1C200F0); // strd r0, [r2]
                    break;
                default:
                    error("storeR0ToTOS: unimplemented type %d",
                            pDestType->tag);
                    break;
            }
        }

        virtual void loadR0FromR0() {
            Type* pPointerType = getR0Type();
            assert(pPointerType->tag == TY_POINTER);
            Type* pNewType = pPointerType->pHead;
            TypeTag tag = pNewType->tag;
            switch (tag) {
                case TY_POINTER:
                case TY_INT:
                case TY_FLOAT:
                    o4(0xE5900000); // ldr r0, [r0]
                    break;
                case TY_SHORT:
                    o4(0xE1D000F0); // ldrsh r0, [r0]
                    break;
                case TY_CHAR:
                    o4(0xE5D00000); // ldrb r0, [r0]
                    break;
                case TY_DOUBLE:
                    o4(0xE1C000D0); // ldrd   r0, [r0]
                    break;
                case TY_ARRAY:
                    pNewType = pNewType->pTail;
                    break;
                default:
                    error("loadR0FromR0: unimplemented type %d", tag);
                    break;
            }
            setR0Type(pNewType);
        }

        virtual void leaR0(int ea, Type* pPointerType, ExpressionType et) {
            if (ea > -LOCAL && ea < LOCAL) {
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
            setR0Type(pPointerType, et);
        }

        virtual int leaForward(int ea, Type* pPointerType) {
            setR0Type(pPointerType);
            int result = ea;
            int pc = getPC();
            int offset = 0;
            if (ea) {
                offset = (pc - ea - 8) >> 2;
                if ((offset & 0xffff) != offset) {
                    error("function forward reference out of bounds");
                }
            } else {
                offset = 0;
            }
            o4(0xE59F0000 | offset); //        ldr    r0, .L1

            if (ea == 0) {
                o4(0xEA000000); //        b .L99
                result = o4(ea);         // .L1:   .word 0
                            // .L99:
            }
            return result;
        }

        virtual void convertR0Imp(Type* pType, bool isCast){
            Type* pR0Type = getR0Type();
            if (isPointerType(pType) && isPointerType(pR0Type)) {
                Type* pA = pR0Type;
                Type* pB = pType;
                // Array decays to pointer
                if (pA->tag == TY_ARRAY && pB->tag == TY_POINTER) {
                    pA = pA->pTail;
                }
                if (typeEqual(pA, pB)) {
                    return; // OK
                }
                if (pB->pHead->tag == TY_VOID) {
                    return; // convert to void* is OK.
                }
                if (pA->tag == TY_POINTER && pB->tag == TY_POINTER
                        && isCast) {
                    return; // OK
                }
                error("Incompatible pointer or array types");
            } else if (bitsSame(pType, pR0Type)) {
                // do nothing special
            } else {
                TypeTag r0Tag = collapseType(pR0Type->tag);
                TypeTag destTag = collapseType(pType->tag);
                if (r0Tag == TY_INT) {
                    if (destTag == TY_FLOAT) {
                        callRuntime((void*) runtime_int_to_float);
                    } else {
                        assert(destTag == TY_DOUBLE);
                        callRuntime((void*) runtime_int_to_double);
                    }
                } else if (r0Tag == TY_FLOAT) {
                    if (destTag == TY_INT) {
                        callRuntime((void*) runtime_float_to_int);
                    } else {
                        assert(destTag == TY_DOUBLE);
                        callRuntime((void*) runtime_float_to_double);
                    }
                } else {
                    assert (r0Tag == TY_DOUBLE);
                    if (destTag == TY_INT) {
                        callRuntime((void*) runtime_double_to_int);
                    } else {
                        assert(destTag == TY_FLOAT);
                        callRuntime((void*) runtime_double_to_float);
                    }
                }
            }
            setR0Type(pType);
        }

        virtual int beginFunctionCallArguments() {
            return o4(0xE24DDF00); // Placeholder
        }

        virtual size_t storeR0ToArg(int l, Type* pArgType) {
            convertR0(pArgType);
            Type* pR0Type = getR0Type();
            TypeTag r0ct = collapseType(pR0Type->tag);
            switch(r0ct) {
                case TY_INT:
                case TY_FLOAT:
                    if (l < 0 || l > 4096-4) {
                        error("l out of range for stack offset: 0x%08x", l);
                    }
                    o4(0xE58D0000 + l); // str r0, [sp, #l]
                    return 4;
                case TY_DOUBLE: {
                    // Align to 8 byte boundary
                    int l2 = (l + 7) & ~7;
                    if (l2 < 0 || l2 > 4096-8) {
                        error("l out of range for stack offset: 0x%08x", l);
                    }
                    o4(0xE58D0000 + l2); // str r0, [sp, #l]
                    o4(0xE58D1000 + l2 + 4); // str r1, [sp, #l+4]
                    return (l2 - l) + 8;
                }
                default:
                    assert(false);
                    return 0;
            }
        }

        virtual void endFunctionCallArguments(Type* pDecl, int a, int l) {
            int argumentStackUse = l;
            // Have to calculate register arg count from actual stack size,
            // in order to properly handle ... functions.
            int regArgCount = l >> 2;
            if (regArgCount > 4) {
                regArgCount = 4;
            }
            if (regArgCount > 0) {
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
            setR0Type(pFunc->pHead);
            // Forward calls are always short (local)
            return o4(0xEB000000 | encodeAddress(symbol));
        }

        virtual void callIndirect(int l, Type* pFunc) {
            assert(pFunc->tag == TY_FUNC);
            popType(); // Get rid of indirect fn pointer type
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

        virtual void adjustStackAfterCall(Type* pDecl, int l, bool isIndirect) {
            int argCount = l >> 2;
            // Have to calculate register arg count from actual stack size,
            // in order to properly handle ... functions.
            int regArgCount = l >> 2;
            if (regArgCount > 4) {
                regArgCount = 4;
            }
            int stackArgs = argCount - regArgCount;
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
            int n;
            int base = getBase();
            int pc = getPC();
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

        /* output a symbol and patch all calls to it */
        virtual void resolveForward(int t) {
            if (t) {
                int pc = getPC();
                *(int *) t = pc;
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
        virtual size_t alignmentOf(Type* pType){
            switch(pType->tag) {
                case TY_CHAR:
                    return 1;
                case TY_SHORT:
                    return 1;
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
                case TY_SHORT:
                    return 2;
                case TY_CHAR:
                    return 1;
                case TY_FLOAT:
                    return 4;
                case TY_DOUBLE:
                    return 8;
                case TY_POINTER:
                    return 4;
                case TY_ARRAY:
                    return pType->length * sizeOf(pType->pHead);
                default:
                    error("Unsupported type %d", pType->tag);
                    return 0;
            }
        }

        virtual size_t stackAlignmentOf(Type* pType) {
            switch(pType->tag) {
                case TY_DOUBLE:
                    return 8;
                case TY_ARRAY:
                    return stackAlignmentOf(pType->pHead);
                default:
                    return 4;
            }
        }

        virtual size_t stackSizeOf(Type* pType) {
            switch(pType->tag) {
                case TY_DOUBLE:
                    return 8;
                case TY_ARRAY:
                    return sizeOf(pType);
                case TY_FUNC:
                    error("stackSizeOf func not supported");
                    return 4;
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

        int calcRegArgCount(Type* pDecl) {
            int reg = 0;
            Type* pArgs = pDecl->pTail;
            while (pArgs && reg < 4) {
                Type* pArg = pArgs->pHead;
                if ( pArg->tag == TY_DOUBLE) {
                    int evenReg = (reg + 1) & ~1;
                    if (evenReg >= 4) {
                        break;
                    }
                    reg = evenReg + 2;
                } else {
                    reg++;
                }
                pArgs = pArgs->pTail;
            }
            return reg;
        }

        void setupIntPtrArgs() {
            o4(0xE8BD0002);  // ldmfd   sp!,{r1}
            mStackUse -= 4;
            popType();
        }

        /* Pop TOS to R1
         * Make sure both R0 and TOS are floats. (Could be ints)
         * We know that at least one of R0 and TOS is already a float
         */
        void setupFloatArgs() {
            Type* pR0Type = getR0Type();
            Type* pTOSType = getTOSType();
            TypeTag tagR0 = collapseType(pR0Type->tag);
            TypeTag tagTOS = collapseType(pTOSType->tag);
            if (tagR0 != TY_FLOAT) {
                assert(tagR0 == TY_INT);
                callRuntime((void*) runtime_int_to_float);
            }
            if (tagTOS != TY_FLOAT) {
                assert(tagTOS == TY_INT);
                assert(tagR0 == TY_FLOAT);
                o4(0xE92D0001);  // stmfd   sp!,{r0}  // push R0
                o4(0xE59D0004);  // ldr     r0, [sp, #4]
                callRuntime((void*) runtime_int_to_float);
                o4(0xE1A01000);  // mov r1, r0
                o4(0xE8BD0001);  // ldmfd   sp!,{r0}  // pop R0
                o4(0xE28DD004);  // add sp, sp, #4 // Pop sp
            } else {
                // Pop TOS
                o4(0xE8BD0002);  // ldmfd   sp!,{r1}
            }
            mStackUse -= 4;
            popType();
        }

        /* Pop TOS into R2..R3
         * Make sure both R0 and TOS are doubles. Could be floats or ints.
         * We know that at least one of R0 and TOS are already a double.
         */

        void setupDoubleArgs() {
            Type* pR0Type = getR0Type();
            Type* pTOSType = getTOSType();
            TypeTag tagR0 = collapseType(pR0Type->tag);
            TypeTag tagTOS = collapseType(pTOSType->tag);
            if (tagR0 != TY_DOUBLE) {
                if (tagR0 == TY_INT) {
                    callRuntime((void*) runtime_int_to_double);
                } else {
                    assert(tagR0 == TY_FLOAT);
                    callRuntime((void*) runtime_float_to_double);
                }
            }
            if (tagTOS != TY_DOUBLE) {
                o4(0xE92D0003);  // stmfd   sp!,{r0,r1}  // push r0,r1
                o4(0xE59D0008);  // ldr     r0, [sp, #8]
                if (tagTOS == TY_INT) {
                    callRuntime((void*) runtime_int_to_double);
                } else {
                    assert(tagTOS == TY_FLOAT);
                    callRuntime((void*) runtime_float_to_double);
                }
                o4(0xE1A02000);  // mov r2, r0
                o4(0xE1A03001);  // mov r3, r1
                o4(0xE8BD0003);  // ldmfd   sp!,{r0, r1}  // Restore R0
                o4(0xE28DD004);  // add sp, sp, #4 // Pop sp
                mStackUse -= 4;
            } else {
                o4(0xE8BD000C);  // ldmfd   sp!,{r2,r3}
                mStackUse -= 8;
            }
            popType();
        }

        void liReg(int t, int reg) {
            assert(reg >= 0 && reg < 16);
            int rN = (reg & 0xf) << 12;
            if (t >= 0 && t < 255) {
                 o4((0xE3A00000 + t) | rN); // mov    rN, #0
            } else if (t >= -256 && t < 0) {
                // mvn means move constant ^ ~0
                o4((0xE3E00000 - (t+1)) | rN); // mvn    rN, #0
            } else {
                  o4(0xE51F0000 | rN); //         ldr    rN, .L3
                  o4(0xEA000000); //         b .L99
                  o4(t);          // .L3:   .word 0
                                  // .L99:
            }
        }

        void callRuntime(void* fn) {
            o4(0xE59FC000); // ldr    r12, .L1
            o4(0xEA000000); // b      .L99
            o4((int) fn);   //.L1:  .word  fn
            o4(0xE12FFF3C); //.L99: blx    r12
        }

        // Integer math:

        static int runtime_DIV(int b, int a) {
            return a / b;
        }

        static int runtime_MOD(int b, int a) {
            return a % b;
        }

        // Comparison to zero

        static int runtime_is_non_zero_f(float a) {
            return a != 0;
        }

        static int runtime_is_non_zero_d(double a) {
            return a != 0;
        }

        // Comparison to zero

        static int runtime_is_zero_f(float a) {
            return a == 0;
        }

        static int runtime_is_zero_d(double a) {
            return a == 0;
        }

        // Type conversion

        static int runtime_float_to_int(float a) {
            return (int) a;
        }

        static double runtime_float_to_double(float a) {
            return (double) a;
        }

        static int runtime_double_to_int(double a) {
            return (int) a;
        }

        static float runtime_double_to_float(double a) {
            return (float) a;
        }

        static float runtime_int_to_float(int a) {
            return (float) a;
        }

        static double runtime_int_to_double(int a) {
            return (double) a;
        }

        // Comparisons float

        static int runtime_cmp_eq_ff(float b, float a) {
            return a == b;
        }

        static int runtime_cmp_ne_ff(float b, float a) {
            return a != b;
        }

        static int runtime_cmp_lt_ff(float b, float a) {
            return a < b;
        }

        static int runtime_cmp_le_ff(float b, float a) {
            return a <= b;
        }

        static int runtime_cmp_ge_ff(float b, float a) {
            return a >= b;
        }

        static int runtime_cmp_gt_ff(float b, float a) {
            return a > b;
        }

        // Comparisons double

        static int runtime_cmp_eq_dd(double b, double a) {
            return a == b;
        }

        static int runtime_cmp_ne_dd(double b, double a) {
            return a != b;
        }

        static int runtime_cmp_lt_dd(double b, double a) {
            return a < b;
        }

        static int runtime_cmp_le_dd(double b, double a) {
            return a <= b;
        }

        static int runtime_cmp_ge_dd(double b, double a) {
            return a >= b;
        }

        static int runtime_cmp_gt_dd(double b, double a) {
            return a > b;
        }

        // Math float

        static float runtime_op_add_ff(float b, float a) {
            return a + b;
        }

        static float runtime_op_sub_ff(float b, float a) {
            return a - b;
        }

        static float runtime_op_mul_ff(float b, float a) {
            return a * b;
        }

        static float runtime_op_div_ff(float b, float a) {
            return a / b;
        }

        static float runtime_op_neg_f(float a) {
            return -a;
        }

        // Math double

        static double runtime_op_add_dd(double b, double a) {
            return a + b;
        }

        static double runtime_op_sub_dd(double b, double a) {
            return a - b;
        }

        static double runtime_op_mul_dd(double b, double a) {
            return a * b;
        }

        static double runtime_op_div_dd(double b, double a) {
            return a / b;
        }

        static double runtime_op_neg_d(double a) {
            return -a;
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
        virtual int functionEntry(Type* pDecl) {
            o(0xe58955); /* push   %ebp, mov %esp, %ebp */
            return oad(0xec81, 0); /* sub $xxx, %esp */
        }

        virtual void functionExit(Type* pDecl, int localVariableAddress, int localVariableSize) {
            o(0xc3c9); /* leave, ret */
            *(int *) localVariableAddress = localVariableSize; /* save local variables */
        }

        /* load immediate value */
        virtual void li(int i) {
            oad(0xb8, i); /* mov $xx, %eax */
            setR0Type(mkpInt);
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
            Type* pR0Type = getR0Type();
            TypeTag tagR0 = pR0Type->tag;
            bool isFloatR0 = isFloatTag(tagR0);
            if (isFloatR0) {
                o(0xeed9); // fldz
                o(0xe9da); // fucompp
                o(0xe0df); // fnstsw %ax
                o(0x9e);   // sahf
            } else {
                o(0xc085); // test %eax, %eax
            }
            // Use two output statements to generate one instruction.
            o(0x0f);   // je/jne xxx
            return psym(0x84 + l, t);
        }

        virtual void gcmp(int op) {
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
                li(0);
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
            setR0Type(mkpInt);
        }

        virtual void genOp(int op) {
            Type* pR0Type = getR0Type();
            Type* pTOSType = getTOSType();
            TypeTag tagR0 = pR0Type->tag;
            TypeTag tagTOS = pTOSType->tag;
            bool isFloatR0 = isFloatTag(tagR0);
            bool isFloatTOS = isFloatTag(tagTOS);
            if (!isFloatR0 && !isFloatTOS) {
                bool isPtrR0 = isPointerTag(tagR0);
                bool isPtrTOS = isPointerTag(tagTOS);
                if (isPtrR0 || isPtrTOS) {
                    if (isPtrR0 && isPtrTOS) {
                        if (op != OP_MINUS) {
                            error("Unsupported pointer-pointer operation %d.", op);
                        }
                        if (! typeEqual(pR0Type, pTOSType)) {
                            error("Incompatible pointer types for subtraction.");
                        }
                        o(0x59); /* pop %ecx */
                        o(decodeOp(op));
                        popType();
                        setR0Type(mkpInt);
                        int size = sizeOf(pR0Type->pHead);
                        if (size != 1) {
                            pushR0();
                            li(size);
                            // TODO: Optimize for power-of-two.
                            genOp(OP_DIV);
                        }
                    } else {
                        if (! (op == OP_PLUS || (op == OP_MINUS && isPtrR0))) {
                            error("Unsupported pointer-scalar operation %d", op);
                        }
                        Type* pPtrType = getPointerArithmeticResultType(
                                pR0Type, pTOSType);
                        o(0x59); /* pop %ecx */
                        int size = sizeOf(pPtrType->pHead);
                        if (size != 1) {
                            // TODO: Optimize for power-of-two.
                            if (isPtrR0) {
                                oad(0xC969, size); // imull $size, %ecx
                            } else {
                                oad(0xC069, size); // mul $size, %eax
                            }
                        }
                        o(decodeOp(op));
                        popType();
                        setR0Type(pPtrType);
                    }
                } else {
                    o(0x59); /* pop %ecx */
                    o(decodeOp(op));
                    if (op == OP_MOD)
                        o(0x92); /* xchg %edx, %eax */
                    popType();
                }
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
                setR0Type(pResultType);
            }
        }

        virtual void gUnaryCmp(int op) {
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
                            li(0);
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
                        error("gUnaryCmp unsupported type");
                        break;
                }
            }
            setR0Type(mkpInt);
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
                    error("pushR0 unsupported type %d", r0ct);
                    break;
            }
            pushType();
        }

        virtual void over() {
            // We know it's only used for int-ptr ops (++/--)

            Type* pR0Type = getR0Type();
            TypeTag r0ct = collapseType(pR0Type->tag);

            Type* pTOSType = getTOSType();
            TypeTag tosct = collapseType(pTOSType->tag);

            assert (r0ct == TY_INT && tosct == TY_INT);

            o(0x59); /* pop %ecx */
            o(0x50); /* push %eax */
            o(0x51); /* push %ecx */

            overType();
        }

        virtual void popR0() {
            Type* pR0Type = getR0Type();
            TypeTag r0ct = collapseType(pR0Type->tag);
            switch(r0ct) {
                case TY_INT:
                    o(0x58); /* popl %eax */
                    break;
                case TY_FLOAT:
                    o(0x2404d9); // flds (%esp)
                    o(0x58); /* popl %eax */
                    break;
                case TY_DOUBLE:
                    o(0x2404dd); // fldl (%esp)
                    o(0x58); /* popl %eax */
                    o(0x58); /* popl %eax */
                    break;
                default:
                    error("popR0 unsupported type %d", r0ct);
                    break;
            }
            popType();
        }

        virtual void storeR0ToTOS() {
            Type* pPointerType = getTOSType();
            assert(pPointerType->tag == TY_POINTER);
            Type* pTargetType = pPointerType->pHead;
            convertR0(pTargetType);
            o(0x59); /* pop %ecx */
            popType();
            switch (pTargetType->tag) {
                case TY_POINTER:
                case TY_INT:
                    o(0x0189); /* movl %eax/%al, (%ecx) */
                    break;
                case TY_SHORT:
                    o(0x018966); /* movw %ax, (%ecx) */
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
                    error("storeR0ToTOS: unsupported type %d",
                            pTargetType->tag);
                    break;
            }
        }

        virtual void loadR0FromR0() {
            Type* pPointerType = getR0Type();
            assert(pPointerType->tag == TY_POINTER);
            Type* pNewType = pPointerType->pHead;
            TypeTag tag = pNewType->tag;
            switch (tag) {
                case TY_POINTER:
                case TY_INT:
                    o2(0x008b); /* mov (%eax), %eax */
                    break;
                case TY_SHORT:
                    o(0xbf0f); /* movswl (%eax), %eax */
                    ob(0);
                    break;
                case TY_CHAR:
                    o(0xbe0f); /* movsbl (%eax), %eax */
                    ob(0); /* add zero in code */
                    break;
                case TY_FLOAT:
                    o2(0x00d9); // flds (%eax)
                    break;
                case TY_DOUBLE:
                    o2(0x00dd); // fldl (%eax)
                    break;
                case TY_ARRAY:
                    pNewType = pNewType->pTail;
                    break;
                default:
                    error("loadR0FromR0: unsupported type %d", tag);
                    break;
            }
            setR0Type(pNewType);
        }

        virtual void leaR0(int ea, Type* pPointerType, ExpressionType et) {
            gmov(10, ea); /* leal EA, %eax */
            setR0Type(pPointerType, et);
        }

        virtual int leaForward(int ea, Type* pPointerType) {
            oad(0xb8, ea); /* mov $xx, %eax */
            setR0Type(pPointerType);
            return getPC() - 4;
        }

        virtual void convertR0Imp(Type* pType, bool isCast){
            Type* pR0Type = getR0Type();
            if (pR0Type == NULL) {
                assert(false);
                setR0Type(pType);
                return;
            }
            if (isPointerType(pType) && isPointerType(pR0Type)) {
                Type* pA = pR0Type;
                Type* pB = pType;
                // Array decays to pointer
                if (pA->tag == TY_ARRAY && pB->tag == TY_POINTER) {
                    pA = pA->pTail;
                }
                if (typeEqual(pA, pB)) {
                    return; // OK
                }
                if (pB->pHead->tag == TY_VOID) {
                    return; // convert to void* is OK.
                }
                if (pA->tag == TY_POINTER && pB->tag == TY_POINTER
                        && isCast) {
                    return; // OK
                }
                error("Incompatible pointer or array types");
            } else if (bitsSame(pType, pR0Type)) {
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

        virtual size_t storeR0ToArg(int l, Type* pArgType) {
            convertR0(pArgType);
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

        virtual void endFunctionCallArguments(Type* pDecl, int a, int l) {
            * (int*) a = l;
        }

        virtual int callForward(int symbol, Type* pFunc) {
            assert(pFunc->tag == TY_FUNC);
            setR0Type(pFunc->pHead);
            return psym(0xe8, symbol); /* call xxx */
        }

        virtual void callIndirect(int l, Type* pFunc) {
            assert(pFunc->tag == TY_FUNC);
            popType(); // Get rid of indirect fn pointer type
            setR0Type(pFunc->pHead);
            oad(0x2494ff, l); /* call *xxx(%esp) */
        }

        virtual void adjustStackAfterCall(Type* pDecl, int l, bool isIndirect) {
            assert(pDecl->tag == TY_FUNC);
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

        /* output a symbol and patch all calls to it, using absolute address */
        virtual void resolveForward(int t) {
            int n;
            int pc = getPC();
            while (t) {
                n = *(int *) t; /* next value */
                *(int *) t = pc;
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
        virtual size_t alignmentOf(Type* pType){
            switch (pType->tag) {
            case TY_CHAR:
                return 1;
            case TY_SHORT:
                return 2;
            case TY_ARRAY:
                return alignmentOf(pType->pHead);
            case TY_FUNC:
                error("alignment of func not supported");
                return 1;
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
                case TY_SHORT:
                    return 2;
                case TY_CHAR:
                    return 1;
                case TY_FLOAT:
                    return 4;
                case TY_DOUBLE:
                    return 8;
                case TY_POINTER:
                    return 4;
                case TY_ARRAY:
                    return pType->length * sizeOf(pType->pHead);
                default:
                    error("Unsupported type %d", pType->tag);
                    return 0;
            }
        }

        virtual size_t stackAlignmentOf(Type* pType){
            return 4;
        }

        virtual size_t stackSizeOf(Type* pType) {
            switch(pType->tag) {
                case TY_DOUBLE:
                    return 8;
                case TY_ARRAY:
                    return sizeOf(pType);
                case TY_FUNC:
                    error("stackSizeOf func not supported");
                    return 4;
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

        /* Output exactly 2 bytes
         */
        void o2(int n) {
            ob(n & 0xff);
            ob(0xff & (n >> 8));
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
            popType();
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
        virtual int functionEntry(Type* pDecl) {
            int result = mpBase->functionEntry(pDecl);
            fprintf(stderr, "functionEntry(pDecl) -> %d\n", result);
            return result;
        }

        virtual void functionExit(Type* pDecl, int localVariableAddress, int localVariableSize) {
            fprintf(stderr, "functionExit(pDecl, %d, %d)\n",
                    localVariableAddress, localVariableSize);
            mpBase->functionExit(pDecl, localVariableAddress, localVariableSize);
        }

        /* load immediate value */
        virtual void li(int t) {
            fprintf(stderr, "li(%d)\n", t);
            mpBase->li(t);
        }

        virtual void loadFloat(int address, Type* pType) {
            fprintf(stderr, "loadFloat(%d, type=%d)\n", address, pType->tag);
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

        virtual void gcmp(int op) {
            fprintf(stderr, "gcmp(%d)\n", op);
            mpBase->gcmp(op);
        }

        virtual void genOp(int op) {
            fprintf(stderr, "genOp(%d)\n", op);
            mpBase->genOp(op);
        }


        virtual void gUnaryCmp(int op) {
            fprintf(stderr, "gUnaryCmp(%d)\n", op);
            mpBase->gUnaryCmp(op);
        }

        virtual void genUnaryOp(int op) {
            fprintf(stderr, "genUnaryOp(%d)\n", op);
            mpBase->genUnaryOp(op);
        }

        virtual void pushR0() {
            fprintf(stderr, "pushR0()\n");
            mpBase->pushR0();
        }

        virtual void over() {
            fprintf(stderr, "over()\n");
            mpBase->over();
        }

        virtual void popR0() {
            fprintf(stderr, "popR0()\n");
            mpBase->popR0();
        }

        virtual void storeR0ToTOS() {
            fprintf(stderr, "storeR0ToTOS()\n");
            mpBase->storeR0ToTOS();
        }

        virtual void loadR0FromR0() {
            fprintf(stderr, "loadR0FromR0()\n");
            mpBase->loadR0FromR0();
        }

        virtual void leaR0(int ea, Type* pPointerType, ExpressionType et) {
            fprintf(stderr, "leaR0(%d, %d, %d)\n", ea,
                    pPointerType->pHead->tag, et);
            mpBase->leaR0(ea, pPointerType, et);
        }

        virtual int leaForward(int ea, Type* pPointerType) {
            fprintf(stderr, "leaForward(%d)\n", ea);
            return mpBase->leaForward(ea, pPointerType);
        }

        virtual void convertR0(Type* pType){
            fprintf(stderr, "convertR0(pType tag=%d)\n",  pType->tag);
            mpBase->convertR0(pType);
        }

        virtual int beginFunctionCallArguments() {
            int result = mpBase->beginFunctionCallArguments();
            fprintf(stderr, "beginFunctionCallArguments() = %d\n", result);
            return result;
        }

        virtual size_t storeR0ToArg(int l, Type* pArgType) {
            fprintf(stderr, "storeR0ToArg(%d, pArgType=%d)\n", l,
                    pArgType->tag);
            return mpBase->storeR0ToArg(l, pArgType);
        }

        virtual void endFunctionCallArguments(Type* pDecl, int a, int l) {
            fprintf(stderr, "endFunctionCallArguments(%d, %d)\n", a, l);
            mpBase->endFunctionCallArguments(pDecl, a, l);
        }

        virtual int callForward(int symbol, Type* pFunc) {
            int result = mpBase->callForward(symbol, pFunc);
            fprintf(stderr, "callForward(%d) = %d\n", symbol, result);
            return result;
        }

        virtual void callIndirect(int l, Type* pFunc) {
            fprintf(stderr, "callIndirect(%d returntype = %d)\n", l,
                    pFunc->pHead->tag);
            mpBase->callIndirect(l, pFunc);
        }

        virtual void adjustStackAfterCall(Type* pDecl, int l, bool isIndirect) {
            fprintf(stderr, "adjustStackAfterCall(pType, %d, %d)\n", l, isIndirect);
            mpBase->adjustStackAfterCall(pDecl, l, isIndirect);
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

        virtual void resolveForward(int t) {
            mpBase->resolveForward(t);
        }

        virtual int finishCompile() {
            int result = mpBase->finishCompile();
            fprintf(stderr, "finishCompile() = %d\n", result);
            return result;
        }

        /**
         * Alignment (in bytes) for this type of data
         */
        virtual size_t alignmentOf(Type* pType){
            return mpBase->alignmentOf(pType);
        }

        /**
         * Array element alignment (in bytes) for this type of data.
         */
        virtual size_t sizeOf(Type* pType){
            return mpBase->sizeOf(pType);
        }


        virtual size_t stackAlignmentOf(Type* pType) {
            return mpBase->stackAlignmentOf(pType);
        }


        virtual size_t stackSizeOf(Type* pType) {
            return mpBase->stackSizeOf(pType);
        }

        virtual Type* getR0Type() {
            return mpBase->getR0Type();
        }

        virtual ExpressionType getR0ExpressionType() {
            return mpBase->getR0ExpressionType();
        }

        virtual void setR0ExpressionType(ExpressionType et) {
            mpBase->setR0ExpressionType(et);
        }

        virtual size_t getExpressionStackDepth() {
            return mpBase->getExpressionStackDepth();
        }

        virtual void forceR0RVal() {
            return mpBase->forceR0RVal();
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
        virtual int getChar() = 0;
    };

    class TextInputStream : public InputStream {
    public:
        TextInputStream(const char* text, size_t textLength)
            : pText(text), mTextLength(textLength), mPosition(0) {
        }

        virtual int getChar() {
            return mPosition < mTextLength ? pText[mPosition++] : EOF;
        }

    private:
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

            // predefined tokens that can also be symbols start here:
            "pragma",
            "define",
            "line",
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
    bool mbSuppressMacroExpansion;
    char* dptr; // Macro state: Points to macro text during macro playback.
    int dch;    // Macro state: Saves old value of ch during a macro playback.
    char* pGlobalBase;
    ACCSymbolLookupFn mpSymbolLookupFn;
    void* mpSymbolLookupContext;

    // Arena for the duration of the compile
    Arena mGlobalArena;
    // Arena for data that's only needed when compiling a single function
    Arena mLocalArena;

    Arena* mpCurrentArena;

    TokenTable mTokenTable;
    SymbolStack mGlobals;
    SymbolStack mLocals;

    // Prebuilt types, makes things slightly faster.
    Type* mkpInt;        // int
    Type* mkpShort;      // short
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
    int mLineNumber;
    bool mbBumpLine;

    CodeBuf codeBuf;
    CodeGenerator* pGen;

    String mErrorBuf;

    String mPragmas;
    int mPragmaStringCount;
    int mCompileResult;

    static const int ALLOC_SIZE = 99999;

    static const int TOK_DUMMY = 1;
    static const int TOK_NUM = 2;
    static const int TOK_NUM_FLOAT = 3;
    static const int TOK_NUM_DOUBLE = 4;
    static const int TOK_OP_ASSIGNMENT = 5;

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

        // Symbols start after keywords

        TOK_SYMBOL,
        TOK_PRAGMA = TOK_SYMBOL,
        TOK_DEFINE,
        TOK_LINE
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

    void assertImpl(bool isTrue, int line) {
        if (!isTrue) {
            LOGD("assertion failed at line %s:%d.", __FILE__, line);
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
        } else {
            if (mbBumpLine) {
                mLineNumber++;
                mbBumpLine = false;
            }
            ch = file->getChar();
            if (ch == '\n') {
                mbBumpLine = true;
            }
        }
#if 0
        printf("ch='%c' 0x%x\n", ch, ch);
#endif
    }

    int isid() {
        return isalnum(ch) | (ch == '_');
    }

    int decodeHex(int c) {
        if (isdigit(c)) {
            c -= '0';
        } else if (c <= 'F') {
            c = c - 'A' + 10;
        } else {
            c =c - 'a' + 10;
        }
        return c;
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
                        val = (val << 4) + decodeHex(ch);
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
        if(mTokenString.len() == 0) {
            mTokenString.append('0');
        }
        acceptCh('.');
        acceptDigitsCh();
        if (acceptCh('e') || acceptCh('E')) {
            acceptCh('-') || acceptCh('+');
            acceptDigitsCh();
        }
        if (ch == 'f' || ch == 'F') {
            tok = TOK_NUM_FLOAT;
            inp();
        } else if (ch == 'l' || ch == 'L') {
            inp();
            error("Long floating point constants not supported.");
        }
        char* pText = mTokenString.getUnwrapped();
        char* pEnd = pText + strlen(pText);
        char* pEndPtr = 0;
        errno = 0;
        if (tok == TOK_NUM_FLOAT) {
            tokd = strtof(pText, &pEndPtr);
        } else {
            tokd = strtod(pText, &pEndPtr);
        }
        if (errno || pEndPtr != pEnd) {
            error("Can't parse constant: %s", pText);
        }
        // fprintf(stderr, "float constant: %s (%d) %g\n", pText, tok, tokd);
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
                } else if (tok == TOK_LINE) {
                    doLine();
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
        if (isdigit(ch) || ch == '.') {
            // Start of a numeric constant. Could be integer, float, or
            // double, won't know until we look further.
            mTokenString.clear();
            pdef(ch);
            inp();
            int base = 10;
            if (tok == '0') {
                if (ch == 'x' || ch == 'X') {
                    base = 16;
                    tok = TOK_NUM;
                    tokc = 0;
                    inp();
                    while ( isxdigit(ch) ) {
                        tokc = (tokc << 4) + decodeHex(ch);
                        inp();
                    }
                } else if (isoctal(ch)){
                    base = 8;
                    tok = TOK_NUM;
                    tokc = 0;
                    while ( isoctal(ch) ) {
                        tokc = (tokc << 3) + (ch - '0');
                        inp();
                    }
                }
            } else if (isdigit(tok)){
                acceptDigitsCh();
            }
            if (base == 10) {
                if (tok == '.' || ch == '.' || ch == 'e' || ch == 'E') {
                    parseFloat();
                } else {
                    // It's an integer constant
                    char* pText = mTokenString.getUnwrapped();
                    char* pEnd = pText + strlen(pText);
                    char* pEndPtr = 0;
                    errno = 0;
                    tokc = strtol(pText, &pEndPtr, base);
                    if (errno || pEndPtr != pEnd) {
                        error("Can't parse constant: %s %d %d", pText, base, errno);
                    }
                    tok = TOK_NUM;
                }
            }
        } else if (isid()) {
            mTokenString.clear();
            while (isid()) {
                pdef(ch);
                inp();
            }
            tok = mTokenTable.intern(mTokenString.getUnwrapped(), mTokenString.len());
            if (! mbSuppressMacroExpansion) {
                // Is this a macro?
                char* pMacroDefinition = mTokenTable[tok].mpMacroDefinition;
                if (pMacroDefinition) {
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
                        /* check for op=, valid for * / % + - << >> & ^ | */
                        if (ch == '=' &&
                                ((tokl >= 1 && tokl <= 3)
                                        || (tokl >=6 && tokl <= 8)) ) {
                            inp();
                            tok = TOK_OP_ASSIGNMENT;
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
            decodeToken(buf, tok, true);
            fprintf(stderr, "%s\n", buf.getUnwrapped());
        }
#endif
    }

    void doDefine() {
        mbSuppressMacroExpansion = true;
        next();
        mbSuppressMacroExpansion = false;
        tokenid_t name = tok;
        String* pName = new String();
        if (ch == '(') {
            delete pName;
            error("Defines with arguments not supported");
            return;
        }
        while (isspace(ch)) {
            inp();
        }
        String value;
        bool appendToValue = true;
        while (ch != '\n' && ch != EOF) {
            // Check for '//' comments.
            if (appendToValue && ch == '/') {
                inp();
                if (ch == '/') {
                    appendToValue = false;
                } else {
                    value.append('/');
                }
            }
            if (appendToValue && ch != EOF) {
                value.append(ch);
            }
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

    void doLine() {
        // # line number { "filename "}
        next();
        if (tok != TOK_NUM) {
            error("Expected a line-number");
        } else {
            mLineNumber = tokc-1; // The end-of-line will increment it.
        }
        while(ch != EOF && ch != '\n') {
            inp();
        }
    }

    virtual void verror(const char* fmt, va_list ap) {
        mErrorBuf.printf("%ld: ", mLineNumber);
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
            pGen->leaR0((int) glo, mkpCharPtr, ET_RVALUE);
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

    void linkGlobal(tokenid_t t, bool isFunction) {
        VariableInfo* pVI = VI(t);
        void* n = NULL;
        if (mpSymbolLookupFn) {
            n = mpSymbolLookupFn(mpSymbolLookupContext, nameof(t));
        }
        if (pVI->pType == NULL) {
            if (isFunction) {
                pVI->pType = mkpIntFn;
            } else {
                pVI->pType = mkpInt;
            }
        }
        pVI->pAddress = n;
    }

    void unaryOrAssignment() {
        unary();
        if (accept('=')) {
            checkLVal();
            pGen->pushR0();
            expr();
            pGen->forceR0RVal();
            pGen->storeR0ToTOS();
        } else if (tok == TOK_OP_ASSIGNMENT) {
            int t = tokc;
            next();
            checkLVal();
            pGen->pushR0();
            pGen->forceR0RVal();
            pGen->pushR0();
            expr();
            pGen->forceR0RVal();
            pGen->genOp(t);
            pGen->storeR0ToTOS();
        }
    }

    /* Parse and evaluate a unary expression.
     */
    void unary() {
        tokenid_t t;
        intptr_t a;
        t = 0;
        if (acceptStringLiteral()) {
            // Nothing else to do.
        } else {
            int c = tokl;
            a = tokc;
            double ad = tokd;
            t = tok;
            next();
            if (t == TOK_NUM) {
                pGen->li(a);
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
                unary();
                pGen->forceR0RVal();
                if (t == '!')
                    pGen->gUnaryCmp(a);
                else if (t == '+') {
                    // ignore unary plus.
                } else {
                    pGen->genUnaryOp(a);
                }
            } else if (c == 11) {
                // pre increment / pre decrement
                unary();
                doIncDec(a == OP_INCREMENT, 0);
            }
            else if (t == '(') {
                // It's either a cast or an expression
                Type* pCast = acceptCastTypeDeclaration();
                if (pCast) {
                    skip(')');
                    unary();
                    pGen->forceR0RVal();
                    pGen->castR0(pCast);
                } else {
                    commaExpr();
                    skip(')');
                }
            } else if (t == '*') {
                /* This is a pointer dereference.
                 */
                unary();
                doPointer();
            } else if (t == '&') {
                VariableInfo* pVI = VI(tok);
                pGen->leaR0((int) pVI->pAddress, createPtrType(pVI->pType),
                        ET_RVALUE);
                next();
            } else if (t == EOF ) {
                error("Unexpected EOF.");
            } else if (t == ';') {
                error("Unexpected ';'");
            } else if (!checkSymbol(t)) {
                // Don't have to do anything special here, the error
                // message was printed by checkSymbol() above.
            } else {
                if (!isDefined(t)) {
                    mGlobals.add(t);
                    // printf("Adding new global function %s\n", nameof(t));
                }
                VariableInfo* pVI = VI(t);
                int n = (intptr_t) pVI->pAddress;
                /* forward reference: try our lookup function */
                if (!n) {
                    linkGlobal(t, tok == '(');
                    n = (intptr_t) pVI->pAddress;
                    if (!n && tok != '(') {
                        error("Undeclared variable %s\n", nameof(t));
                    }
                }
                if (tok != '(') {
                    /* variable or function name */
                    if (!n) {
                        linkGlobal(t, false);
                        n = (intptr_t) pVI->pAddress;
                        if (!n) {
                            error("Undeclared variable %s\n", nameof(t));
                        }
                    }
                }
                // load a variable
                Type* pVal;
                ExpressionType et;
                if (pVI->pType->tag == TY_ARRAY) {
                    pVal = pVI->pType;
                    et = ET_RVALUE;
                } else {
                    pVal = createPtrType(pVI->pType);
                    et = ET_LVALUE;
                }
                if (n) {
                    int tag = pVal->pHead->tag;
                    if (tag == TY_FUNC) {
                        et = ET_RVALUE;
                    }
                    pGen->leaR0(n, pVal, et);
                } else {
                    pVI->pForward = (void*) pGen->leaForward(
                            (int) pVI->pForward, pVal);
                }
            }
        }

        /* Now handle postfix operators */
        for(;;) {
            if (tokl == 11) {
                // post inc / post dec
                doIncDec(tokc == OP_INCREMENT, true);
                next();
            } else if (accept('[')) {
                // Array reference
                pGen->forceR0RVal();
                pGen->pushR0();
                commaExpr();
                pGen->forceR0RVal();
                pGen->genOp(OP_PLUS);
                doPointer();
                skip(']');
            } else  if (accept('(')) {
                /* function call */
                Type* pDecl = NULL;
                VariableInfo* pVI = NULL;
                Type* pFn = pGen->getR0Type();
                assert(pFn->tag == TY_POINTER);
                assert(pFn->pHead->tag == TY_FUNC);
                pDecl = pFn->pHead;
                pGen->pushR0();
                Type* pArgList = pDecl->pTail;
                bool varArgs = pArgList == NULL;
                /* push args and invert order */
                a = pGen->beginFunctionCallArguments();
                int l = 0;
                int argCount = 0;
                while (tok != ')' && tok != EOF) {
                    if (! varArgs && !pArgList) {
                        error("Unexpected argument.");
                    }
                    expr();
                    pGen->forceR0RVal();
                    Type* pTargetType;
                    if (pArgList) {
                        pTargetType = pArgList->pHead;
                        pArgList = pArgList->pTail;
                    } else {
                        // This is a ... function, just pass arguments in their
                        // natural type.
                        pTargetType = pGen->getR0Type();
                        if (pTargetType->tag == TY_FLOAT) {
                            pTargetType = mkpDouble;
                        } else if (pTargetType->tag == TY_ARRAY) {
                            // Pass arrays by pointer.
                            pTargetType = pTargetType->pTail;
                        }
                    }
                    if (pTargetType->tag == TY_VOID) {
                        error("Can't pass void value for argument %d",
                              argCount + 1);
                    } else {
                        l += pGen->storeR0ToArg(l, pTargetType);
                    }
                    if (accept(',')) {
                        // fine
                    } else if ( tok != ')') {
                        error("Expected ',' or ')'");
                    }
                    argCount += 1;
                }
                if (! varArgs && pArgList) {
                    error("Expected more argument(s). Saw %d", argCount);
                }
                pGen->endFunctionCallArguments(pDecl, a, l);
                skip(')');
                pGen->callIndirect(l, pDecl);
                pGen->adjustStackAfterCall(pDecl, l, true);
            } else {
                break;
            }
        }
    }

    void doIncDec(int isInc, int isPost) {
        // R0 already has the lval
        checkLVal();
        int lit = isInc ? 1 : -1;
        pGen->pushR0();
        pGen->loadR0FromR0();
        int tag = pGen->getR0Type()->tag;
        if (!(tag == TY_INT || tag == TY_SHORT || tag == TY_CHAR ||
                tag == TY_POINTER)) {
            error("++/-- illegal for this type. %d", tag);
        }
        if (isPost) {
            pGen->over();
            pGen->pushR0();
            pGen->li(lit);
            pGen->genOp(OP_PLUS);
            pGen->storeR0ToTOS();
            pGen->popR0();
        } else {
            pGen->pushR0();
            pGen->li(lit);
            pGen->genOp(OP_PLUS);
            pGen->over();
            pGen->storeR0ToTOS();
            pGen->popR0();
        }
    }

    void doPointer() {
        pGen->forceR0RVal();
        Type* pR0Type = pGen->getR0Type();
        if (pR0Type->tag != TY_POINTER) {
            error("Expected a pointer type.");
        } else {
            if (pR0Type->pHead->tag != TY_FUNC) {
                pGen->setR0ExpressionType(ET_LVALUE);
            }
        }
    }

    /* Recursive descent parser for binary operations.
     */
    void binaryOp(int level) {
        intptr_t t, a;
        t = 0;
        if (level-- == 1)
            unaryOrAssignment();
        else {
            binaryOp(level);
            a = 0;
            while (level == tokl) {
                t = tokc;
                next();
                pGen->forceR0RVal();
                if (level > 8) {
                    a = pGen->gtst(t == OP_LOGICAL_OR, a); /* && and || output code generation */
                    binaryOp(level);
                } else {
                    pGen->pushR0();
                    binaryOp(level);
                    // Check for syntax error.
                    if (pGen->getR0Type() == NULL) {
                        // We failed to parse a right-hand argument.
                        // Push a dummy value so we don't fail
                        pGen->li(0);
                    }
                    pGen->forceR0RVal();
                    if ((level == 4) | (level == 5)) {
                        pGen->gcmp(t);
                    } else {
                        pGen->genOp(t);
                    }
                }
            }
            /* && and || output code generation */
            if (a && level > 8) {
                pGen->forceR0RVal();
                a = pGen->gtst(t == OP_LOGICAL_OR, a);
                pGen->li(t != OP_LOGICAL_OR);
                int b = pGen->gjmp(0);
                pGen->gsym(a);
                pGen->li(t == OP_LOGICAL_OR);
                pGen->gsym(b);
            }
        }
    }

    void commaExpr() {
        for(;;) {
            expr();
            if (!accept(',')) {
                break;
            }
        }
    }

    void expr() {
        binaryOp(11);
    }

    int test_expr() {
        commaExpr();
        pGen->forceR0RVal();
        return pGen->gtst(0, 0);
    }

    void block(intptr_t l, bool outermostFunctionBlock) {
        intptr_t a, n, t;

        Type* pBaseType;
        if ((pBaseType = acceptPrimitiveType())) {
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
                    commaExpr();
                skip(';');
                n = codeBuf.getPC();
                a = 0;
                if (tok != ';')
                    a = test_expr();
                skip(';');
                if (tok != ')') {
                    t = pGen->gjmp(0);
                    commaExpr();
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
                    commaExpr();
                    pGen->forceR0RVal();
                    if (pReturnType->tag == TY_VOID) {
                        error("Must not return a value from a void function");
                    } else {
                        pGen->convertR0(pReturnType);
                    }
                } else {
                    if (pReturnType->tag != TY_VOID) {
                        error("Must specify a value here");
                    }
                }
                rsym = pGen->gjmp(rsym); /* jmp */
            } else if (accept(TOK_BREAK)) {
                *(int *) l = pGen->gjmp(*(int *) l);
            } else if (tok != ';')
                commaExpr();
            skip(';');
        }
    }

    static bool typeEqual(Type* a, Type* b) {
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
        } else if (at == TY_ARRAY) {
            return a->length == b->length && typeEqual(a->pHead, b->pHead);
        } else if (at == TY_FUNC || at == TY_PARAM) {
            return typeEqual(a->pHead, b->pHead)
                && typeEqual(a->pTail, b->pTail);
        }
        return true;
    }

    Type* createType(TypeTag tag, Type* pHead, Type* pTail) {
        assert(tag >= TY_INT && tag <= TY_PARAM);
        Type* pType = (Type*) mpCurrentArena->alloc(sizeof(Type));
        memset(pType, 0, sizeof(*pType));
        pType->tag = tag;
        pType->pHead = pHead;
        pType->pTail = pTail;
        return pType;
    }

    Type* createPtrType(Type* pType) {
        return createType(TY_POINTER, pType, NULL);
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
            decodeToken(temp, pType->id, false);
            buffer.append(temp);
        }

        decodeTypeImpPostfix(buffer, pType);
    }

    void decodeTypeImpPrefix(String& buffer, Type* pType) {
        TypeTag tag = pType->tag;

        if (tag >= TY_INT && tag <= TY_DOUBLE) {
            switch (tag) {
                case TY_INT:
                    buffer.appendCStr("int");
                    break;
                case TY_SHORT:
                    buffer.appendCStr("short");
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
            case TY_SHORT:
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
            case TY_ARRAY:
                decodeTypeImpPrefix(buffer, pType->pHead);
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
            case TY_ARRAY:
                {
                    String temp;
                    temp.printf("[%d]", pType->length);
                    buffer.append(temp);
                }
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

    Type* acceptPrimitiveType() {
        Type* pType;
        if (tok == TOK_INT) {
            pType = mkpInt;
        } else if (tok == TOK_SHORT) {
            pType = mkpShort;
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

    Type* acceptDeclaration(Type* pType, bool nameAllowed, bool nameRequired) {
        tokenid_t declName = 0;
        bool reportFailure = false;
        pType = acceptDecl2(pType, declName, nameAllowed,
                                  nameRequired, reportFailure);
        if (declName) {
            // Clone the parent type so we can set a unique ID
            Type* pOldType = pType;
            pType = createType(pType->tag, pType->pHead, pType->pTail);

            pType->id = declName;
            pType->length = pOldType->length;
        } else if (nameRequired) {
            error("Expected a variable name");
        }
        // fprintf(stderr, "Parsed a declaration:       ");
        // printType(pType);
        if (reportFailure) {
            return NULL;
        }
        return pType;
    }

    Type* expectDeclaration(Type* pBaseType) {
        Type* pType = acceptDeclaration(pBaseType, true, true);
        if (! pType) {
            error("Expected a declaration");
        }
        return pType;
    }

    /* Used for accepting types that appear in casts */
    Type* acceptCastTypeDeclaration() {
        Type* pType = acceptPrimitiveType();
        if (pType) {
            pType = acceptDeclaration(pType, false, false);
        }
        return pType;
    }

    Type* expectCastTypeDeclaration() {
        Type* pType = acceptCastTypeDeclaration();
        if (! pType) {
            error("Expected a declaration");
        }
        return pType;
    }

    Type* acceptDecl2(Type* pType, tokenid_t& declName,
                      bool nameAllowed, bool nameRequired,
                      bool& reportFailure) {
        while (accept('*')) {
            pType = createType(TY_POINTER, pType, NULL);
        }
        pType = acceptDecl3(pType, declName, nameAllowed, nameRequired,
                            reportFailure);
        return pType;
    }

    Type* acceptDecl3(Type* pType, tokenid_t& declName,
                      bool nameAllowed, bool nameRequired,
                      bool& reportFailure) {
        // direct-dcl :
        //   name
        //  (dcl)
        //   direct-dcl()
        //   direct-dcl[]
        Type* pNewHead = NULL;
        if (accept('(')) {
            pNewHead = acceptDecl2(pNewHead, declName, nameAllowed,
                                nameRequired, reportFailure);
            skip(')');
        } else if ((declName = acceptSymbol()) != 0) {
            if (nameAllowed == false && declName) {
                error("Symbol %s not allowed here", nameof(declName));
                reportFailure = true;
            }
        } else if (nameRequired && ! declName) {
            String temp;
            decodeToken(temp, tok, true);
            error("Expected name. Got %s", temp.getUnwrapped());
            reportFailure = true;
        }
        for(;;) {
            if (accept('(')) {
                // Function declaration
                Type* pTail = acceptArgs(nameAllowed);
                pType = createType(TY_FUNC, pType, pTail);
                skip(')');
            } if (accept('[')) {
                if (tok != ']') {
                    if (tok != TOK_NUM || tokc <= 0) {
                        error("Expected positive integer constant");
                    } else {
                        Type* pDecayType = createPtrType(pType);
                        pType = createType(TY_ARRAY, pType, pDecayType);
                        pType->length = tokc;
                    }
                    next();
                }
                skip(']');
            } else {
                break;
            }
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

    Type* acceptArgs(bool nameAllowed) {
        Type* pHead = NULL;
        Type* pTail = NULL;
        for(;;) {
            Type* pBaseArg = acceptPrimitiveType();
            if (pBaseArg) {
                Type* pArg = acceptDeclaration(pBaseArg, nameAllowed, false);
                if (pArg) {
                    Type* pParam = createType(TY_PARAM, pArg, NULL);
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

    Type* expectPrimitiveType() {
        Type* pType = acceptPrimitiveType();
        if (!pType) {
            String buf;
            decodeToken(buf, tok, true);
            error("Expected a type, got %s", buf.getUnwrapped());
        }
        return pType;
    }

    void checkLVal() {
        if (pGen->getR0ExpressionType() != ET_LVALUE) {
            error("Expected an lval");
        }
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
                Type* pDecl = expectDeclaration(pBaseType);
                if (!pDecl) {
                    break;
                }
                int variableAddress = 0;
                addLocalSymbol(pDecl);
                size_t alignment = pGen->stackAlignmentOf(pDecl);
                size_t alignmentMask = ~ (alignment - 1);
                size_t sizeOf = pGen->sizeOf(pDecl);
                loc = (loc + alignment - 1) & alignmentMask;
                size_t alignedSize = (sizeOf + alignment - 1) & alignmentMask;
                loc = loc + alignedSize;
                variableAddress = -loc;
                VI(pDecl->id)->pAddress = (void*) variableAddress;
                if (accept('=')) {
                    /* assignment */
                    pGen->leaR0(variableAddress, createPtrType(pDecl), ET_LVALUE);
                    pGen->pushR0();
                    expr();
                    pGen->forceR0RVal();
                    pGen->storeR0ToTOS();
                }
                if (tok == ',')
                    next();
            }
            skip(';');
            pBaseType = acceptPrimitiveType();
        }
    }

    bool checkSymbol() {
        return checkSymbol(tok);
    }

    void decodeToken(String& buffer, tokenid_t token, bool quote) {
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
        } else {
            if (quote) {
                if (token >= TOK_KEYWORD && token < TOK_SYMBOL) {
                    buffer.printf("keyword \"%s\"", nameof(token));
                } else {
                    buffer.printf("symbol \"%s\"", nameof(token));
                }
            } else {
                buffer.printf("%s", nameof(token));
            }
        }
    }

    bool checkSymbol(tokenid_t token) {
        bool result = token >= TOK_SYMBOL;
        if (!result) {
            String temp;
            decodeToken(temp, token, true);
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
            Type* pBaseType = expectPrimitiveType();
            if (!pBaseType) {
                break;
            }
            Type* pDecl = expectDeclaration(pBaseType);
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
                                                   pGen->alignmentOf(name->pType),
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
                    pDecl = expectDeclaration(pBaseType);
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
                } else if (tok != '{') {
                    error("expected '{'");
                } else {
                    mpCurrentArena = &mLocalArena;
                    if (name) {
                        /* patch forward references */
                        pGen->resolveForward((int) name->pForward);
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
                        size_t alignment = pGen->stackAlignmentOf(pArg);
                        a = (a + alignment - 1) & ~ (alignment-1);
                        VI(pArg->id)->pAddress = (void*) a;
                        a = a + pGen->stackSizeOf(pArg);
                        argCount++;
                    }
                    rsym = loc = 0;
                    pReturnType = pDecl->pHead;
                    a = pGen->functionEntry(pDecl);
                    block(0, true);
                    pGen->gsym(rsym);
                    pGen->functionExit(pDecl, a, loc);
                    mLocals.popLevel();
                    mpCurrentArena = &mGlobalArena;
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

    // One-time initialization, when class is constructed.
    void init() {
        mpSymbolLookupFn = 0;
        mpSymbolLookupContext = 0;
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
        mCompileResult = 0;
        mLineNumber = 1;
        mbBumpLine = false;
        mbSuppressMacroExpansion = false;
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
            pGen->setTypes(mkpInt);
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
        init();
        clear();
    }

    ~Compiler() {
        cleanup();
    }

    void registerSymbolCallback(ACCSymbolLookupFn pFn, ACCvoid* pContext) {
        mpSymbolLookupFn = pFn;
        mpSymbolLookupContext = pContext;
    }

    int compile(const char* text, size_t textLength) {
        int result;

        mpCurrentArena = &mGlobalArena;
        createPrimitiveTypes();
        cleanup();
        clear();
        mTokenTable.setArena(&mGlobalArena);
        mGlobals.setArena(&mGlobalArena);
        mGlobals.setTokenTable(&mTokenTable);
        mLocals.setArena(&mLocalArena);
        mLocals.setTokenTable(&mTokenTable);

        internKeywords();
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
        mCompileResult = result;
        return result;
    }

    void createPrimitiveTypes() {
        mkpInt = createType(TY_INT, NULL, NULL);
        mkpShort = createType(TY_SHORT, NULL, NULL);
        mkpChar = createType(TY_CHAR, NULL, NULL);
        mkpVoid = createType(TY_VOID, NULL, NULL);
        mkpFloat = createType(TY_FLOAT, NULL, NULL);
        mkpDouble = createType(TY_DOUBLE, NULL, NULL);
        mkpIntFn =  createType(TY_FUNC, mkpInt, NULL);
        mkpIntPtr = createPtrType(mkpInt);
        mkpCharPtr = createPtrType(mkpChar);
        mkpFloatPtr = createPtrType(mkpFloat);
        mkpDoublePtr = createPtrType(mkpDouble);
        mkpPtrIntFn = createPtrType(mkpIntFn);
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
        if (mCompileResult == 0) {
            tokenid_t tok = mTokenTable.intern(name, strlen(name));
            VariableInfo* pVariableInfo = VI(tok);
            if (pVariableInfo) {
                return pVariableInfo->pAddress;
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

    void registerSymbolCallback(ACCSymbolLookupFn pFn, ACCvoid* pContext) {
        compiler.registerSymbolCallback(pFn, pContext);
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
void accRegisterSymbolCallback(ACCscript* script, ACCSymbolLookupFn pFn,
                               ACCvoid* pContext) {
    script->registerSymbolCallback(pFn, pContext);
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

