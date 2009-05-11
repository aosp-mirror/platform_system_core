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

namespace acc {

class compiler {
/* vars: value of variables
   loc : local variable index
   glo : global variable index
   ind : output code ptr
   rsym: return symbol
   prog: output code
   dstk: define stack
   dptr, dch: macro state
*/
int tok, tokc, tokl, ch, vars, rsym, prog, ind, loc, glo, sym_stk, dstk, dptr, dch, last_id;
FILE* file;

#define ALLOC_SIZE 99999

/* depends on the init string */
#define TOK_STR_SIZE 48
#define TOK_IDENT    0x100
#define TOK_INT      0x100
#define TOK_IF       0x120
#define TOK_ELSE     0x138
#define TOK_WHILE    0x160
#define TOK_BREAK    0x190
#define TOK_RETURN   0x1c0
#define TOK_FOR      0x1f8
#define TOK_DEFINE   0x218
#define TOK_MAIN     0x250

#define TOK_DUMMY   1
#define TOK_NUM     2

#define LOCAL   0x200

#define SYM_FORWARD 0
#define SYM_DEFINE  1

/* tokens in string heap */
#define TAG_TOK    ' '
#define TAG_MACRO  2

void pdef(int t)
{
    *(char *)dstk++ = t;
}

void inp()
{
    if (dptr) {
        ch = *(char *)dptr++;
        if (ch == TAG_MACRO) {
            dptr = 0;
            ch = dch;
        }
    } else
        ch = fgetc(file);
    /*    printf("ch=%c 0x%x\n", ch, ch); */
}

int isid()
{
    return isalnum(ch) | ch == '_';
}

/* read a character constant */
void getq()
{
    if (ch == '\\') {
        inp();
        if (ch == 'n')
            ch = '\n';
    }
}

void next()
{
    int l, a;

    while (isspace(ch) | ch == '#') {
        if (ch == '#') {
            inp();
            next();
            if (tok == TOK_DEFINE) {
                next();
                pdef(TAG_TOK); /* fill last ident tag */
                *(int *)tok = SYM_DEFINE;
                *(int *)(tok + 4) = dstk; /* define stack */
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
            *(char *)dstk = TAG_TOK; /* no need to mark end of string (we
                                        suppose data is initied to zero */
            tok = (int) (strstr((char*) sym_stk, (char*) (last_id - 1)) - sym_stk);
            *(char *)dstk = 0;   /* mark real end of ident for dlsym() */
            tok = tok * 8 + TOK_IDENT;
            if (tok > TOK_DEFINE) {
                tok = vars + tok;
                /*        printf("tok=%s %x\n", last_id, tok); */
                /* define handling */
                if (*(int *)tok == SYM_DEFINE) {
                    dptr = *(int *)(tok + 4);
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
        } else if (tok == '/' & ch == '*') {
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
        } else
        {
            const char* t = "++#m--%am*@R<^1c/@%[_[H3c%@%[_[H3c+@.B#d-@%:_^BKd<<Z/03e>>`/03e<=0f>=/f<@.f>@1f==&g!=\'g&&k||#l&@.BCh^@.BSi|@.B+j~@/%Yd!@&d*@b";
            while (l = *t++) {
                a = *t++;
                tokc = 0;
                while ((tokl = *t++ - 'b') < 0)
                    tokc = tokc * 64 + tokl + 64;
                if (l == tok & (a == ch | a == '@')) {
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
            }
        }
    }
#if 0
    {
        int p;

        printf("tok=0x%x ", tok);
        if (tok >= TOK_IDENT) {
            printf("'");
            if (tok > TOK_DEFINE)
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

void error(const char *fmt,...)
{
    va_list ap;

    va_start(ap, fmt);
    fprintf(stderr, "%ld: ", ftell((FILE *)file));
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    exit(1);
}

void skip(int c)
{
    if (tok != c) {
        error("'%c' expected", c);
    }
    next();
}

void o(int n)
{
    /* cannot use unsigned, so we must do a hack */
    while (n && n != -1) {
        *(char *)ind++ = n;
        n = n >> 8;
    }
}

/* output a symbol and patch all calls to it */
void gsym(int t)
{
    int n;
    while (t) {
        n = *(int *)t; /* next value */
        *(int *)t = ind - t - 4;
        t = n;
    }
}

/* psym is used to put an instruction with a data field which is a
   reference to a symbol. It is in fact the same as oad ! */
#define psym oad

/* instruction + address */
int oad(int n, int t)
{
    o(n);
    *(int *)ind = t;
    t = ind;
    ind = ind + 4;
    return t;
}

/* load immediate value */
int li(int t)
{
    oad(0xb8, t); /* mov $xx, %eax */
}

int gjmp(int t)
{
    return psym(0xe9, t);
}

/* l = 0: je, l == 1: jne */
int gtst(int l, int t)
{
    o(0x0fc085); /* test %eax, %eax, je/jne xxx */
    return psym(0x84 + l, t);
}

int gcmp(int t)
{
    o(0xc139); /* cmp %eax,%ecx */
    li(0);
    o(0x0f); /* setxx %al */
    o(t + 0x90);
    o(0xc0);
}

int gmov(int l, int t)
{
    o(l + 0x83);
    oad((t < LOCAL) << 7 | 5, t);
}

/* l is one if '=' parsing wanted (quick hack) */
void unary(int l)
{
    int n, t, a, c;

    n = 1; /* type of expression 0 = forward, 1 = value, other =
              lvalue */
    if (tok == '\"') {
        li(glo);
        while (ch != '\"') {
            getq();
            *(char *)glo++ = ch;
            inp();
        }
        *(char *)glo = 0;
        glo = glo + 4 & -4; /* align heap */
        inp();
        next();
    } else {
        c = tokl;
        a = tokc;
        t = tok;
        next();
        if (t == TOK_NUM) {
            li(a);
        } else if (c == 2) {
            /* -, +, !, ~ */
            unary(0);
            oad(0xb9, 0); /* movl $0, %ecx */
            if (t == '!')
                gcmp(a);
            else
                o(a);
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
                o(0x50); /* push %eax */
                expr();
                o(0x59); /* pop %ecx */
                o(0x0188 + (t == TOK_INT)); /* movl %eax/%al, (%ecx) */
            } else if (t) {
                if (t == TOK_INT)
                    o(0x8b); /* mov (%eax), %eax */
                else
                    o(0xbe0f); /* movsbl (%eax), %eax */
                ind++; /* add zero in code */
            }
        } else if (t == '&') {
            gmov(10, *(int *)tok); /* leal EA, %eax */
            next();
        } else {
            n = *(int *)t;
            /* forward reference: try dlsym */
            if (!n)
                n = (int) dlsym(0, (char*) last_id);
            if (tok == '=' & l) {
                /* assignment */
                next();
                expr();
                gmov(6, n); /* mov %eax, EA */
            } else if (tok != '(') {
                /* variable */
                gmov(8, n); /* mov EA, %eax */
                if (tokl == 11) {
                    gmov(0, n);
                    o(tokc);
                    next();
                }
            }
        }
    }

    /* function call */
    if (tok == '(') {
        if (n == 1)
            o(0x50); /* push %eax */

        /* push args and invert order */
        a = oad(0xec81, 0); /* sub $xxx, %esp */
        next();
        l = 0;
        while(tok != ')') {
            expr();
            oad(0x248489, l); /* movl %eax, xxx(%esp) */
            if (tok == ',')
                next();
            l = l + 4;
        }
        *(int *)a = l;
        next();
        if (!n) {
            /* forward reference */
            t = t + 4;
            *(int *)t = psym(0xe8, *(int *)t);
        } else if (n == 1) {
            oad(0x2494ff, l); /* call *xxx(%esp) */
            l = l + 4;
        } else {
            oad(0xe8, n - ind - 5); /* call xxx */
        }
        if (l)
            oad(0xc481, l); /* add $xxx, %esp */
    }
}

void sum(int l)
{
    int t, n, a;

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
                a = gtst(t, a); /* && and || output code generation */
                sum(l);
            } else {
                o(0x50); /* push %eax */
                sum(l);
                o(0x59); /* pop %ecx */

                if (l == 4 | l == 5) {
                    gcmp(t);
                } else {
                    o(t);
                    if (n == '%')
                        o(0x92); /* xchg %edx, %eax */
                }
            }
        }
        /* && and || output code generation */
        if (a && l > 8) {
            a = gtst(t, a);
            li(t ^ 1);
            gjmp(5); /* jmp $ + 5 */
            gsym(a);
            li(t);
        }
    }
}

void expr()
{
    sum(11);
}


int test_expr()
{
    expr();
    return gtst(0, 0);
}


void block(int l)
{
    int a, n, t;

    if (tok == TOK_IF) {
        next();
        skip('(');
        a = test_expr();
        skip(')');
        block(l);
        if (tok == TOK_ELSE) {
            next();
            n = gjmp(0); /* jmp */
            gsym(a);
            block(l);
            gsym(n); /* patch else jmp */
        } else {
            gsym(a); /* patch if test */
        }
    } else if (tok == TOK_WHILE | tok == TOK_FOR) {
        t = tok;
        next();
        skip('(');
        if (t == TOK_WHILE) {
            n = ind;
            a = test_expr();
        } else {
            if (tok != ';')
                expr();
            skip(';');
            n = ind;
            a = 0;
            if (tok != ';')
                a = test_expr();
            skip(';');
            if (tok != ')') {
                t = gjmp(0);
                expr();
                gjmp(n - ind - 5);
                gsym(t);
                n = t + 4;
            }
        }
        skip(')');
        block((int) &a);
        gjmp(n - ind - 5); /* jmp */
        gsym(a);
    } else if (tok == '{') {
        next();
        /* declarations */
        decl(1);
        while(tok != '}')
            block(l);
        next();
    } else {
        if (tok == TOK_RETURN) {
            next();
            if (tok != ';')
                expr();
            rsym = gjmp(rsym); /* jmp */
        } else if (tok == TOK_BREAK) {
            next();
            *(int *)l = gjmp(*(int *)l);
        } else if (tok != ';')
            expr();
        skip(';');
    }
}

/* 'l' is true if local declarations */
void decl(int l)
{
    int a;

    while (tok == TOK_INT | tok != -1 & !l) {
        if (tok == TOK_INT) {
            next();
            while (tok != ';') {
                if (l) {
                    loc = loc + 4;
                    *(int *)tok = -loc;
                } else {
                    *(int *)tok = glo;
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
            gsym(*(int *)(tok + 4));
            /* put function address */
            *(int *)tok = ind;
            next();
            skip('(');
            a = 8;
            while (tok != ')') {
                /* read param name and compute offset */
                *(int *)tok = a;
                a = a + 4;
                next();
                if (tok == ',')
                    next();
            }
            next(); /* skip ')' */
            rsym = loc = 0;
            o(0xe58955); /* push   %ebp, mov %esp, %ebp */
            a = oad(0xec81, 0); /* sub $xxx, %esp */
            block(0);
            gsym(rsym);
            o(0xc3c9); /* leave, ret */
            *(int *)a = loc; /* save local variables */
        }
    }
}

public:
compiler() :
    tok(0), tokc(0), tokl(0), ch(0),
    vars(0), rsym(0), prog(0), ind(0), loc(0), glo(0), sym_stk(0),
    dstk(0), dptr(0), dch(0), last_id(0), file(0)
{
}

int compile(FILE* in) {

    file = in;
    sym_stk = (int) calloc(1, ALLOC_SIZE);
    dstk = (int) strcpy((char*) sym_stk,
                  " int if else while break return for define main ") + TOK_STR_SIZE;
    glo = (int) calloc(1, ALLOC_SIZE);
    ind = prog = (int) calloc(1, ALLOC_SIZE);
    vars = (int) calloc(1, ALLOC_SIZE);
    inp();
    next();
    decl(0);
    return 0;
}

int run(int argc, char** argv)
{
    typedef int (*mainPtr)(int argc, char** argv);
    mainPtr aMain = (mainPtr) * (int*) (vars + TOK_MAIN);
    if (! aMain) {
        fprintf(stderr, "Could not find main");
        return -1;
    }
    return aMain(argc, argv);
}

int dump(FILE* out) {
    fwrite((void *)prog, 1, ind - prog, out);
    return 0;
}

};


} // namespace acc

int main(int argc, char** argv) {
    bool doTest = false;
    const char* inFile = NULL;
    const char* outFile = NULL;
    int i;
    for(i = 1; i < argc; i++) {
        char* arg = argv[i];
        if (arg[0] == '-') {
            switch (arg[1]) {
            case 'T':
                if (i + 1 >= argc) {
                    fprintf(stderr, "Expected filename after -T\n");
                    return 2;
                }
                doTest = true;
                outFile = argv[i + 1];
                i += 1;
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
        if (! in) {
            fprintf(stderr, "Could not open input file %s\n", inFile);
            return 1;
        }
    }
    acc::compiler compiler;
    int compileResult = compiler.compile(in);
    if (in != stdin) {
        fclose(in);
    }
    if (compileResult) {
        fprintf(stderr, "Compile failed: %d\n", compileResult);
        return 6;
    }
    if (doTest) {
        FILE* save = fopen(outFile, "w");
        if (! save) {
            fprintf(stderr, "Could not open output file %s\n", outFile);
            return 5;
        }
        compiler.dump(save);
        fclose(save);
    } else {
        int codeArgc = argc-i+1;
        char** codeArgv=argv + i - 1;
        codeArgv[0] = (char*) (inFile ? inFile : "stdin");
        return compiler.run(codeArgc, codeArgv);
    }

    return 0;
}
