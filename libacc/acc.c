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
static int C;
static int currentChar;
static int K;
static int q;
static int G;
static int savedChar;
static char* pInProgressMacro;
static char* P;
static char* ac;
static char* v;
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
    C = 0;
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
                while ((C = *(char*) e++ - 98) < 0)
                    currentTokenData = currentTokenData * 64 + C + 64;
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
 * are 0x0 or 0xff
 */
static void emitCode(int g) {
    while( g && g != -1) {
        *(char*) q++=g;
        g=g>>8;
    }
}

static void fixupAddress(e) {
    int g;
    while( e) {
        g=*(int*) e;
        *(int*) e=q-e-4;
        e=g;
    }
}

static int emitCodeWithImmediate( g, e) {
    emitCode(g);
    *(int*) q = e;
    e = q;
    q = q + 4;
    return e;
}

static int emitLoadAccumulatorImmediate(e) {
    emitCodeWithImmediate(0xb8,e); /* Move immediate a, e */
}

static int emitBranch(e) {
    return emitCodeWithImmediate(0xe9,e); /* Jump relative */
}

static int S( j, e) {
    emitCode(0x0FC085); /* XADD 85 r/m8, r8  exchange and add */
    return emitCodeWithImmediate(0x84 + j, e); /* TEST */
}

static void Z(e) {
    emitCode( 0xC139);
    emitLoadAccumulatorImmediate(0);
    emitCode( 0x0F);
    emitCode( e+0x90);
    emitCode( 0xC0);
}

static void N( j, e) {
    emitCode(j + 0x83);
    emitCodeWithImmediate((e < 512) << 7 | 5, e);
}

static void T (int j) {
    int g,e,m,aa;
    g=1;
    if( currentToken == '"') {
        emitLoadAccumulatorImmediate(v);
        while( currentChar != '"') {
            unescapeCurrentChar ();
            *(char*) v++=currentChar;
            nextChar ();
        }
        *(char*) v=0;
        v= (char*) (((int)v) +4&-4);
        nextChar();
        nextToken();
    }
    else {
        aa=C;
        m= currentTokenData;
        e=currentToken;
        nextToken();
        if( e == TOKEN_NUMBER) {
            emitLoadAccumulatorImmediate(m);
        }
        else if( aa == 2) {
            T(0);
            emitCodeWithImmediate(0xB9,0);
            if( e == '!')Z(m);
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
            T(0);
            if( currentToken == '=') {
                nextToken();
                emitCode( 0x50);
                parseExpression ();
                emitCode( 0x59);
                emitCode( 0x188 + (e == TOKEN_INT));
            }
            else if( e) {
                if( e == TOKEN_INT)emitCode( 0x8B);
                else emitCode( 0xBE0F);
                q++;
            }
        }
        else if( e == '&') {
            N(10,*(int*) currentToken);
            nextToken();
        }
        else {
            g=*(int*) e;
            if(!g)g=dlsym(0,M);
            if( currentToken == '=' & j) {
                nextToken();
                parseExpression ();
                N(6,g);
            }
            else if( currentToken!= '(') {
                N(8,g);
                if( C == 11) {
                    N(0,g);
                    emitCode( currentTokenData);
                    nextToken();
                }
            }
        }
    }
    if( currentToken == '(') {
        if( g == 1)emitCode( 0x50);
        m= emitCodeWithImmediate(0xEC81,0);
        nextToken();
        j=0;
        while( currentToken!= ')') {
            parseExpression ();
            emitCodeWithImmediate(0x248489,j);
            if( currentToken == ',')nextToken();
            j=j +4;
        }
        *(int*) m= j;
        nextToken();
        if(!g) {
            e=e +4;
            *(int*) e=emitCodeWithImmediate(0xE8,*(int*) e);
        }
        else if( g == 1) {
            emitCodeWithImmediate(0x2494FF,j);
            j=j +4;
        }
        else {
            emitCodeWithImmediate(0xE8,g-q-5);
        }
        if( j)emitCodeWithImmediate(0xC481,j);
    }
}

static void parseBinaryOp (int level) {
    int e,g,m;
    if( level--== 1)T(1);
    else {
        parseBinaryOp (level);
        m= 0;
        while( level == C) {
            g=currentToken;
            e=currentTokenData;
            nextToken();
            if( level>8) {
                m= S(e,m);
                parseBinaryOp (level);
            }
            else {
                emitCode( 0x50);
                parseBinaryOp (level);
                emitCode( 0x59);
                if( level == 4 | level == 5) {
                    Z(e);
                }
                else {
                    emitCode( e);
                    if( g == '%')emitCode( 0x92);
                }
            }
        }
        if( m&&level>8) {
            m= S(e,m);
            emitLoadAccumulatorImmediate(e^1);
            emitBranch(5);
            fixupAddress(m);
            emitLoadAccumulatorImmediate(e);
        }
    }
}

static void parseExpression() {
    parseBinaryOp(11);
}

static int U() {
    parseExpression();
    return S(0, 0);
}

static void parseStatement (int* pBreakTarget) {
    int m,g,e;
    if( currentToken == TOKEN_IF) {
        nextToken();
        nextToken();
        m= U ();
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
            g=q;
            m= U ();
        }
        else {
            if( currentToken != ';')parseExpression ();
            nextToken();
            g=q;
            m= 0;
            if( currentToken != ';')m= U ();
            nextToken();
            if( currentToken!= ')') {
                e=emitBranch(0);
                parseExpression ();
                emitBranch(g-q-5);
                fixupAddress(e);
                g=e +4;
            }
        }
        nextToken();
        parseStatement(&m);
        emitBranch(g-q-5);
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
            K=emitBranch(K);
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
                    G=G +4;
                    *(int*) currentToken=-G;
                }
                else {
                    *(char**) currentToken = v;
                    v=v +4;
                }
                nextToken();
                if( currentToken == ',')nextToken();
            }
            nextToken();
        }
        else {
            fixupAddress(*(int*)(currentToken + 4));
            *(int*) currentToken=q;
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
            K=G=0;
            emitCode( 0xE58955);
            m= emitCodeWithImmediate(0xEC81,0);
            parseStatement(0);
            fixupAddress(K);
            emitCode( 0xC3C9);
            *(int*) m= G;
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
    v = calloc(1, 99999);
    ac = calloc(1, 99999);
    q = (int) ac;
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
    return (*(int(*)()) *(int*) (P + 592))(argc, argv);
#endif
}

