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

static int d, z, C, h, K, q, G, W;
static char* L;
static char* P;
static char* ac;
static char* v;
static char* D;
static char* M;
static char* R;
static FILE* Q;

static void ab (int j);
static void w();

static void addToSymbolTable(char e) {
    *D++ = e;
}

static void next() {
    if (L) {
        h = *(char*) L++;
        if (h == 2) {
            L = 0;
            h = W;
        }
    } else
        h = fgetc(Q);
}

static int X() {
    return isalnum(h) || h == '_';
}

static void Y() {
    if (h == 92) {
        next();
        if (h == 110)
            h = 10;
    }
}

static void ad() {
    int j, m;
    while (isspace(h) | h == 35) {
        if (h == 35) {
            next();
            ad();
            if (d == 536) {
                ad();
                addToSymbolTable(32);
                *(int*) d = 1;
                *(int*) (d + 4) = (int) D;
            }
            while (h != '\n') {
                addToSymbolTable(h);
                next();
            }
            addToSymbolTable(h);
            addToSymbolTable(2);
        }
        next();
    }
    C = 0;
    d = h;
    if (X()) {
        addToSymbolTable(32);
        M = D;
        while (X()) {
            addToSymbolTable(h);
            next();
        }
        if (isdigit(d)) {
            z = strtol(M, 0, 0);
            d = 2;
        } else {
            *(char*) D = 32;
            d = strstr(R, M - 1) - R;
            *(char*) D = 0;
            d = d * 8 + 256;
            if (d > 536) {
                d = ((int) P) + d;
                if (*(int*) d == 1) {
                    L = (char*) (*(int*) (d + 4));
                    W = h;
                    next();
                    ad();
                }
            }
        }
    } else {
        next();
        if (d == 39) {
            d = 2;
            Y();
            z = h;
            next();
            next();
        } else if (d == 47 & h == 42) {
            next();
            while (h) {
                while (h != 42)
                    next();
                next();
                if (h == 47)
                    h = 0;
            }
            next();
            ad();
        } else {
            char* e = "++#m--%am*@R<^1c/@%[_[H3c%@%[_[H3c+@.B#d-@%:_^BKd<<Z/03e>>`/03e<=0f>=/f<@.f>@1f==&g!='g&&k||#l&@.BCh^@.BSi|@.B+j~@/%Yd!@&d*@b";
            while (j = *(char*) e++) {
                m = *(char*) e++;
                z = 0;
                while ((C = *(char*) e++ - 98) < 0)
                    z = z * 64 + C + 64;
                if (j == d & (m == h | m == 64)) {
                    if (m == h) {
                        next();
                        d = 1;
                    }
                    break;
                }
            }
        }
    }
}

static void ae( g) {
    while( g&&g!=-1) {
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
    if( d == 34) {
        H(v);
        while( h!=34) {
            Y ();
            *(char*) v++=h;
            next ();
        }
        *(char*) v=0;
        v= (char*) (((int)v) +4&-4);
        next ();
        ad();
    }
    else {
        aa=C;
        m= z;
        e=d;
        ad();
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
            ad();
        }
        else if( e == 42) {
            ad();
            e=d;
            ad();
            ad();
            if( d == 42) {
                ad();
                ad();
                ad();
                ad();
                e=0;
            }
            ad();
            T(0);
            if( d == 61) {
                ad();
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
            N(10,*(int*) d);
            ad();
        }
        else {
            g=*(int*) e;
            if(!g)g=dlsym(0,M);
            if( d == 61&j) {
                ad();
                w ();
                N(6,g);
            }
            else if( d!= 40) {
                N(8,g);
                if( C == 11) {
                    N(0,g);
                    ae( z);
                    ad();
                }
            }
        }
    }
    if( d == 40) {
        if( g == 1)ae( 80);
        m= s(60545,0);
        ad();
        j=0;
        while( d!= 41) {
            w ();
            s(2393225,j);
            if( d == 44)ad();
            j=j +4;
        }
        *(int*) m= j;
        ad();
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
            g=d;
            e=z;
            ad();
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
    if( d == 288) {
        ad();
        ad();
        m= U ();
        ad();
        I (j);
        if( d == 312) {
            ad();
            g=B(0);
            A(m);
            I (j);
            A(g);
        }
        else {
            A(m);
        }
    }
    else if( d == 352|d == 504) {
        e=d;
        ad();
        ad();
        if( e == 352) {
            g=q;
            m= U ();
        }
        else {
            if( d!= 59)w ();
            ad();
            g=q;
            m= 0;
            if( d!= 59)m= U ();
            ad();
            if( d!= 41) {
                e=B(0);
                w ();
                B(g-q-5);
                A(e);
                g=e +4;
            }
        }
        ad();
        I(&m);
        B(g-q-5);
        A(m);
    }
    else if( d == 123) {
        ad();
        ab(1);
        while( d!= 125)I (j);
        ad();
    }
    else {
        if( d == 448) {
            ad();
            if( d!= 59)w ();
            K=B(K);
        }
        else if( d == 400) {
            ad();
            *(int*) j=B(*(int*) j);
        }
        else if( d!= 59)w ();
        ad();
    }
}

static void ab (int j) {
    int m;
    while( d == 256 | d != -1 & !j ) {
        if( d == 256) {
            ad();
            while( d!= 59) {
                if( j ) {
                    G=G +4;
                    *(int*) d=-G;
                }
                else {
                    *(char**) d = v;
                    v=v +4;
                }
                ad();
                if( d == 44)ad();
            }
            ad();
        }
        else {
            A(*(int*)(d +4));
            *(int*) d=q;
            ad();
            ad();
            m= 8;
            while( d!= 41) {
                *(int*) d=m;
                m= m +4;
                ad();
                if( d == 44)ad();
            }
            ad();
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
    Q = stdin;
    if (argc-- > 1) {
        char* file = argv[1];
        argv += 1;
        Q = fopen(file, "r");
        if (Q == NULL) {
            fprintf(stderr, "Could not open file \"%s\"\n", file);
            return -1;
        }
    }
    D = strcpy(R = calloc(1, 99999),
            " int if else while break return for define main ") + 48;
    v = calloc(1, 99999);
    ac = calloc(1, 99999);
    q = (int) ac;
    P = calloc(1, 99999);
    next();
    ad();
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

