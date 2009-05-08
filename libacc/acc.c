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
#define TOKEN_DEFINE 536

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

static void ab (int j);
static void w();

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
            currentToken = currentToken * 8 + 256;
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

static void ae( g) {
    while( g && g != -1) {
        *(char*) q++=g;
        g=g>>8;
    }
}

static void A(e) {
    int g;
    while( e) {
        g=*(int*) e;
        *(int*) e=q-e-4;
        e=g;
    }
}

static int s( g, e) {
    ae(g);
    *(int*) q = e;
    e = q;
    q = q + 4;
    return e;
}

static int H(e) {
    s(184,e);
}

static int B(e) {
    return s(233,e);
}

static int S( j, e) {
    ae(1032325);
    return s(132 + j, e);
}

static void Z(e) {
    ae( 49465);
    H(0);
    ae( 15);
    ae( e+144);
    ae( 192);
}

static void N( j, e) {
    ae(j + 131);
    s((e < 512) << 7 | 5, e);
}

static void T (j) {
    int g,e,m,aa;
    g=1;
    if( currentToken == 34) {
        H(v);
        while( currentChar!=34) {
            unescapeCurrentChar ();
            *(char*) v++=currentChar;
            nextChar ();
        }
        *(char*) v=0;
        v= (char*) (((int)v) +4&-4);
        nextChar ();
        nextToken();
    }
    else {
        aa=C;
        m= currentTokenData;
        e=currentToken;
        nextToken();
        if( e == 2) {
            H(m);
        }
        else if( aa == 2) {
            T(0);
            s(185,0);
            if( e == 33)Z(m);
            else ae( m);
        }
        else if( e == 40) {
            w ();
            nextToken();
        }
        else if( e == 42) {
            nextToken();
            e=currentToken;
            nextToken();
            nextToken();
            if( currentToken == 42) {
                nextToken();
                nextToken();
                nextToken();
                nextToken();
                e=0;
            }
            nextToken();
            T(0);
            if( currentToken == 61) {
                nextToken();
                ae( 80);
                w ();
                ae( 89);
                ae( 392+(e == 256));
            }
            else if( e) {
                if( e == 256)ae( 139);
                else ae( 48655);
                q++;
            }
        }
        else if( e == 38) {
            N(10,*(int*) currentToken);
            nextToken();
        }
        else {
            g=*(int*) e;
            if(!g)g=dlsym(0,M);
            if( currentToken == 61&j) {
                nextToken();
                w ();
                N(6,g);
            }
            else if( currentToken!= 40) {
                N(8,g);
                if( C == 11) {
                    N(0,g);
                    ae( currentTokenData);
                    nextToken();
                }
            }
        }
    }
    if( currentToken == 40) {
        if( g == 1)ae( 80);
        m= s(60545,0);
        nextToken();
        j=0;
        while( currentToken!= 41) {
            w ();
            s(2393225,j);
            if( currentToken == 44)nextToken();
            j=j +4;
        }
        *(int*) m= j;
        nextToken();
        if(!g) {
            e=e +4;
            *(int*) e=s(232,*(int*) e);
        }
        else if( g == 1) {
            s(2397439,j);
            j=j +4;
        }
        else {
            s(232,g-q-5);
        }
        if( j)s(50305,j);
    }
}

static void O (j) {
    int e,g,m;
    if( j--== 1)T(1);
    else {
        O (j);
        m= 0;
        while( j == C) {
            g=currentToken;
            e=currentTokenData;
            nextToken();
            if( j>8) {
                m= S(e,m);
                O (j);
            }
            else {
                ae( 80);
                O (j);
                ae( 89);
                if( j == 4|j == 5) {
                    Z(e);
                }
                else {
                    ae( e);
                    if( g == 37)ae( 146);
                }
            }
        }
        if( m&&j>8) {
            m= S(e,m);
            H(e^1);
            B(5);
            A(m);
            H(e);
        }
    }
}

static void w() {
    O(11);
}

static int U() {
    w();
    return S(0, 0);
}

static void I (j) {
    int m,g,e;
    if( currentToken == 288) {
        nextToken();
        nextToken();
        m= U ();
        nextToken();
        I (j);
        if( currentToken == 312) {
            nextToken();
            g=B(0);
            A(m);
            I (j);
            A(g);
        }
        else {
            A(m);
        }
    }
    else if( currentToken == 352|currentToken == 504) {
        e=currentToken;
        nextToken();
        nextToken();
        if( e == 352) {
            g=q;
            m= U ();
        }
        else {
            if( currentToken!= 59)w ();
            nextToken();
            g=q;
            m= 0;
            if( currentToken!= 59)m= U ();
            nextToken();
            if( currentToken!= 41) {
                e=B(0);
                w ();
                B(g-q-5);
                A(e);
                g=e +4;
            }
        }
        nextToken();
        I(&m);
        B(g-q-5);
        A(m);
    }
    else if( currentToken == 123) {
        nextToken();
        ab(1);
        while( currentToken!= 125)I (j);
        nextToken();
    }
    else {
        if( currentToken == 448) {
            nextToken();
            if( currentToken!= 59)w ();
            K=B(K);
        }
        else if( currentToken == 400) {
            nextToken();
            *(int*) j=B(*(int*) j);
        }
        else if( currentToken!= 59)w ();
        nextToken();
    }
}

static void ab (int j) {
    int m;
    while( currentToken == 256 | currentToken != -1 & !j ) {
        if( currentToken == 256) {
            nextToken();
            while( currentToken!= 59) {
                if( j ) {
                    G=G +4;
                    *(int*) currentToken=-G;
                }
                else {
                    *(char**) currentToken = v;
                    v=v +4;
                }
                nextToken();
                if( currentToken == 44)nextToken();
            }
            nextToken();
        }
        else {
            A(*(int*)(currentToken +4));
            *(int*) currentToken=q;
            nextToken();
            nextToken();
            m= 8;
            while( currentToken!= 41) {
                *(int*) currentToken=m;
                m= m +4;
                nextToken();
                if( currentToken == 44)nextToken();
            }
            nextToken();
            K=G=0;
            ae( 15042901);
            m= s(60545,0);
            I(0);
            A(K);
            ae( 50121);
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
    ab(0);
#if 1
    fwrite(R, 1, 99999, stdout);
    fwrite(ac, 1, 99999, stdout);
    fwrite(P, 1, 99999, stdout);
    return 0;
#else
    return (*(int(*)()) *(int*) (P + 592))(argc, argv);
#endif
}

