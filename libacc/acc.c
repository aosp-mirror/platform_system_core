/*
 **
 ** Copyright 2009, The Android Open Source Project
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

/* Based upon the freeware version of the Obfuscated Tiny C Compiler
 * by Francis Bellard. <francis@bellard.org>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TOKEN_OPERATOR 1
#define TOKEN_NUMBER 2

#define TOKEN_SYMBOL_BASE     256
#define TOKEN_INT             256
#define TOKEN_IF              288
#define TOKEN_ELSE            312
#define TOKEN_WHILE           352
#define TOKEN_BREAK           400
#define TOKEN_RETURN          448
#define TOKEN_FOR             504
#define TOKEN_DEFINE          536

static int currentToken;
static int currentTokenData;
static int gCurrentTokenOperatorLevel;
static int currentChar;
static int gEndOfFunctionTarget;
static int gProgramCounter;
static int gFunctionStackSize;
static int savedChar;
static char* pInProgressMacro;
static char* P;
static char* ac;
static char* gStringTable;
static char* pSymbolTable;
static char* M;
static char* R;
static FILE* pInput;

static void parseDeclarations (int isLocal);
static void parseExpression();

static void addToSymbolTable(char e) {
    *pSymbolTable++ = e;
}

static void nextChar() {
    if (pInProgressMacro) {
        currentChar = *(char*) pInProgressMacro++;
        if (currentChar == 2) {
            pInProgressMacro = NULL;
            currentChar = savedChar;
        }
    } else
        currentChar = fgetc(pInput);
}

static int isSymbolChar() {
    return isalnum(currentChar) || currentChar == '_';
}

static void unescapeCurrentChar() {
    if (currentChar == '\\') {
        nextChar();
        if (currentChar == 'n')
            currentChar = '\n';
    }
}

static void nextToken() {
    int j, m;
    while (isspace(currentChar) || currentChar == '#') {
        if (currentChar == '#') {
            nextChar();
            nextToken();
            if (currentToken == TOKEN_DEFINE) {
                nextToken();
                addToSymbolTable(' ');
                *(int*) currentToken = 1;
                *(int*) (currentToken + 4) = (int) pSymbolTable;
            }
            while (currentChar != '\n') {
                addToSymbolTable(currentChar);
                nextChar();
            }
            addToSymbolTable(currentChar);
            addToSymbolTable(2);
        }
        nextChar();
    }
    gCurrentTokenOperatorLevel = 0;
    currentToken = currentChar;
    if (isSymbolChar()) {
        addToSymbolTable(' ');
        M = pSymbolTable;
        while (isSymbolChar()) {
            addToSymbolTable(currentChar);
            nextChar();
        }
        if (isdigit(currentToken)) {
            currentTokenData = strtol(M, 0, 0);
            currentToken = TOKEN_NUMBER;
        } else {
            *(char*) pSymbolTable = ' ';
            currentToken = strstr(R, M - 1) - R;
            *(char*) pSymbolTable = 0;
            currentToken = currentToken * 8 + TOKEN_SYMBOL_BASE;
            if (currentToken > TOKEN_DEFINE) {
                currentToken = ((int) P) + currentToken;
                if (*(int*) currentToken == 1) {
                    pInProgressMacro = (char*) (*(int*) (currentToken + 4));
                    savedChar = currentChar;
                    nextChar();
                    nextToken();
                }
            }
        }
    } else {
        nextChar();
        if (currentToken == '\'') {
            currentToken = TOKEN_NUMBER;
            unescapeCurrentChar();
            currentTokenData = currentChar;
            nextChar();
            nextChar();
        } else if (currentToken == '/' & currentChar == '*') {
            nextChar();
            while (currentChar) {
                while (currentChar != '*')
                    nextChar();
                nextChar();
                if (currentChar == '/')
                    currentChar = 0;
            }
            nextChar();
            nextToken();
        } else {
            char* e = "++#m--%am*@R<^1c/@%[_[H3c%@%[_[H3c+@.B#d-@%:_^BKd<<Z/03e>>`/03e<=0f>=/f<@.f>@1f==&g!='g&&k||#l&@.BCh^@.BSi|@.B+j~@/%Yd!@&d*@b";
            while (j = *(char*) e++) {
                m = *(char*) e++;
                currentTokenData = 0;
                while ((gCurrentTokenOperatorLevel = *(char*) e++ - 98) < 0)
                    currentTokenData = currentTokenData * 64 + gCurrentTokenOperatorLevel + 64;
                if (j == currentToken && (m == currentChar || m == 64)) {
                    if (m == currentChar) {
                        nextChar();
                        currentToken = TOKEN_OPERATOR;
                    }
                    break;
                }
            }
        }
    }
}

/*
 * Emit 1 to 4 bytes of code. Little-endian, doesn't emit high bytes that
 * are 0x00 or 0xff
 */
static void emitCode(int g) {
    while( g && g != -1) {
        *(char*) gProgramCounter++=g;
        g=g>>8;
    }
}

static void fixupAddress(e) {
    int g;
    while( e) {
        g=*(int*) e;
        *(int*) e=gProgramCounter-e-4;
        e=g;
    }
}

static int emitCodeWithImmediate( g, e) {
    emitCode(g);
    *(int*) gProgramCounter = e;
    e = gProgramCounter;
    gProgramCounter = gProgramCounter + 4;
    return e;
}

static int emitLoadAccumulatorImmediate(e) {
    emitCodeWithImmediate(0xb8,e); /* Move immediate a, e */
}

static int emitBranch(e) {
    return emitCodeWithImmediate(0xe9,e); /* Jump relative */
}

static int emitTest( j, e) {
    emitCode(0x0FC085); /* 85 C0 FC TEST */
    return emitCodeWithImmediate(0x84 + j, e); /* TEST */
}

static void emitSetCC(int condition) {
    emitCode( 0xC139); /* 39 C1 CMP */
    emitLoadAccumulatorImmediate(0);
    emitCode( 0x0F); /* Two byte opcode prefix */
    emitCode( condition+0x90); /* Set byte on condition (controlled by e) */
    emitCode( 0xC0); /* I think this is part of the SETcc instruction */
}

static void emitNumericOp( int op, int e) {
    emitCode(op + 0x83);
    emitCodeWithImmediate((e < 512) << 7 | 5, e);
}

static void parseTerminal (int level) {
    int g,e,m,aa;
    g=1;
    if( currentToken == '"') {
        emitLoadAccumulatorImmediate(gStringTable);
        while( currentChar != '"') {
            unescapeCurrentChar ();
            *(char*) gStringTable++=currentChar;
            nextChar ();
        }
        *(char*) gStringTable=0;
        gStringTable= (char*) (((int)gStringTable) +4&-4);
        nextChar();
        nextToken();
    }
    else {
        aa=gCurrentTokenOperatorLevel;
        m= currentTokenData;
        e=currentToken;
        nextToken();
        if( e == TOKEN_NUMBER) {
            emitLoadAccumulatorImmediate(m);
        }
        else if( aa == 2) {
            parseTerminal(0);
            emitCodeWithImmediate(0xB9,0); /* MOV r1, immediate */
            if( e == '!')emitSetCC(m);
            else emitCode( m);
        }
        else if( e == '(') {
            parseExpression ();
            nextToken();
        }
        else if( e == '*') {
            nextToken();
            e=currentToken;
            nextToken();
            nextToken();
            if( currentToken == '*') {
                nextToken();
                nextToken();
                nextToken();
                nextToken();
                e=0;
            }
            nextToken();
            parseTerminal(0);
            if( currentToken == '=') {
                nextToken();
                emitCode( 0x50); /* PUSH r0 */
                parseExpression ();
                emitCode( 0x59); /* POP r1 */
                emitCode( 0x188 + (e == TOKEN_INT)); /* 88 01 MOV */
            }
            else if( e) {
                if( e == TOKEN_INT)emitCode( 0x8B); /* MOV */
                else emitCode( 0xBE0F); /* 0F BE MOVSX move with sign extension */
                gProgramCounter++;
            }
        }
        else if( e == '&') {
            emitNumericOp(10,*(int*) currentToken); /* 8D LEA */
            nextToken();
        }
        else {
            g=*(int*) e;
            if(!g)g=dlsym(0,M);
            if( currentToken == '=' & level) {
                nextToken();
                parseExpression ();
                emitNumericOp(6,g); /* 89 MOV */
            }
            else if( currentToken!= '(') {
                emitNumericOp(8,g); /* 8B MOV sreg */
                if( gCurrentTokenOperatorLevel == 11) {
                    emitNumericOp(0,g); /* 83 ADD */
                    emitCode( currentTokenData);
                    nextToken();
                }
            }
        }
    }
    if( currentToken == '(') {
        if( g == 1)emitCode( 0x50); /* push */
        m= emitCodeWithImmediate(0xEC81,0); /* 81 EC Cmp ?? */
        nextToken();
        level=0;
        while( currentToken!= ')') {
            parseExpression ();
            emitCodeWithImmediate(0x248489,level); /* 89 84 24 MOV sp + level*/
            if( currentToken == ',')nextToken();
            level=level +4;
        }
        *(int*) m= level;
        nextToken();
        if(!g) {
            e=e +4;
            *(int*) e=emitCodeWithImmediate(0xE8,*(int*) e); /* Call */
        }
        else if( g == 1) {
            emitCodeWithImmediate(0x2494FF,level); /* FF 94 24 */
            level=level +4;
        }
        else {
            emitCodeWithImmediate(0xE8,g-gProgramCounter-5); /* CALL */
        }
        if( level)emitCodeWithImmediate(0xC481,level); /* 81 C4 adjust stack pointer */
    }
}

static void parseBinaryOp (int level) {
    int e,g,m;
    if( level--== 1)parseTerminal(1);
    else {
        parseBinaryOp (level);
        m= 0;
        while( level == gCurrentTokenOperatorLevel) {
            g=currentToken;
            e=currentTokenData;
            nextToken();
            if( level>8) {
                m= emitTest(e,m);
                parseBinaryOp (level);
            }
            else {
                emitCode( 0x50);
                parseBinaryOp (level);
                emitCode( 0x59);
                if( level == 4 | level == 5) {
                    emitSetCC(e);
                }
                else {
                    emitCode( e);
                    if( g == '%')emitCode( 0x92); /* XCHG */
                }
            }
        }
        if( m&&level>8) {
            m= emitTest(e,m);
            emitLoadAccumulatorImmediate(e^1);
            emitBranch(5); /* Jump relative +5 */
            fixupAddress(m);
            emitLoadAccumulatorImmediate(e);
        }
    }
}

static void parseExpression() {
    parseBinaryOp(11);
}

static int parseExpressionEmitTest() {
    parseExpression();
    return emitTest(0, 0);
}

static void parseStatement (int* pBreakTarget) {
    int m,g,e;
    if( currentToken == TOKEN_IF) {
        nextToken();
        nextToken();
        m= parseExpressionEmitTest ();
        nextToken();
        parseStatement (pBreakTarget);
        if( currentToken == TOKEN_ELSE) {
            nextToken();
            g=emitBranch(0);
            fixupAddress(m);
            parseStatement (pBreakTarget);
            fixupAddress(g);
        }
        else {
            fixupAddress(m);
        }
    }
    else if ( currentToken == TOKEN_WHILE || currentToken == TOKEN_FOR) {
        e = currentToken;
        nextToken();
        nextToken();
        if( e == TOKEN_WHILE) {
            g=gProgramCounter;
            m= parseExpressionEmitTest ();
        }
        else {
            if( currentToken != ';')parseExpression ();
            nextToken();
            g=gProgramCounter;
            m= 0;
            if( currentToken != ';')m= parseExpressionEmitTest ();
            nextToken();
            if( currentToken!= ')') {
                e=emitBranch(0);
                parseExpression ();
                emitBranch(g-gProgramCounter-5);
                fixupAddress(e);
                g=e +4;
            }
        }
        nextToken();
        parseStatement(&m);
        emitBranch(g-gProgramCounter-5);
        fixupAddress(m);
    }
    else if( currentToken == '{') {
        nextToken();
        parseDeclarations(1);
        while( currentToken != '}') parseStatement(pBreakTarget);
        nextToken();
    }
    else {
        if( currentToken == TOKEN_RETURN) {
            nextToken();
            if( currentToken != ';') parseExpression();
            gEndOfFunctionTarget=emitBranch(gEndOfFunctionTarget);
        }
        else if( currentToken == TOKEN_BREAK) {
            nextToken();
            *pBreakTarget = emitBranch(*pBreakTarget);
        }
        else if( currentToken != ';') parseExpression();
        nextToken();
    }
}

static void parseDeclarations (int isLocal) {
    int m;
    while( currentToken == TOKEN_INT | currentToken != -1 & !isLocal ) {
        if( currentToken == TOKEN_INT) {
            nextToken();
            while( currentToken != ';') {
                if( isLocal ) {
                    gFunctionStackSize=gFunctionStackSize +4;
                    *(int*) currentToken=-gFunctionStackSize;
                }
                else {
                    *(char**) currentToken = gStringTable;
                    gStringTable=gStringTable +4;
                }
                nextToken();
                if( currentToken == ',')nextToken();
            }
            nextToken();
        }
        else {
            fixupAddress(*(int*)(currentToken + 4));
            *(int*) currentToken=gProgramCounter;
            nextToken();
            nextToken();
            m= 8;
            while( currentToken != ')') {
                *(int*) currentToken=m;
                m= m +4;
                nextToken();
                if( currentToken == ',')nextToken();
            }
            nextToken();
            gEndOfFunctionTarget=gFunctionStackSize=0;
            emitCode( 0xE58955); /* 55 89 E5 PUSH */
            m= emitCodeWithImmediate(0xEC81,0); /* 81 EC */
            parseStatement(0);
            fixupAddress(gEndOfFunctionTarget);
            emitCode( 0xC3C9); /* C9 C3 LEAVE */
            *(int*) m= gFunctionStackSize;
        }
    }
}

int main( int argc, char** argv) {
    pInput = stdin;
    if (argc-- > 1) {
        char* file = argv[1];
        argv += 1;
        pInput = fopen(file, "r");
        if (pInput == NULL) {
            fprintf(stderr, "Could not open file \"%s\"\n", file);
            return -1;
        }
    }
    pSymbolTable = strcpy(R = calloc(1, 99999),
            " int if else while break return for define main ") + 48;
    gStringTable = calloc(1, 99999);
    ac = calloc(1, 99999);
    gProgramCounter = (int) ac;
    P = calloc(1, 99999);
    nextChar();
    nextToken();
    parseDeclarations(0);
#if 1
    fwrite(R, 1, 99999, stdout);
    fwrite(ac, 1, 99999, stdout);
    fwrite(P, 1, 99999, stdout);
    return 0;
#else
    /* Look up the address of "main" in the symbol table and call it.
     * We put main in at a known offset, so we know the address.
     */
    return (*(int(*)()) *(int*) (P + 592))(argc, argv);
#endif
}

