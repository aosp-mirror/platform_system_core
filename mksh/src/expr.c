/*	$OpenBSD: expr.c,v 1.21 2009/06/01 19:00:57 deraadt Exp $	*/

/*-
 * Copyright (c) 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010
 *	Thorsten Glaser <tg@mirbsd.org>
 *
 * Provided that these terms and disclaimer and all copyright notices
 * are retained or reproduced in an accompanying document, permission
 * is granted to deal in this work without restriction, including un-
 * limited rights to use, publicly perform, distribute, sell, modify,
 * merge, give away, or sublicence.
 *
 * This work is provided "AS IS" and WITHOUT WARRANTY of any kind, to
 * the utmost extent permitted by applicable law, neither express nor
 * implied; without malicious intent or gross negligence. In no event
 * may a licensor, author or contributor be held liable for indirect,
 * direct, other damage, loss, or other issues arising in any way out
 * of dealing in the work, even if advised of the possibility of such
 * damage or existence of a defect, except proven that it results out
 * of said person's immediate fault when using the work as intended.
 */

#include "sh.h"

__RCSID("$MirOS: src/bin/mksh/expr.c,v 1.44 2010/08/14 21:35:13 tg Exp $");

/* The order of these enums is constrained by the order of opinfo[] */
enum token {
	/* some (long) unary operators */
	O_PLUSPLUS = 0, O_MINUSMINUS,
	/* binary operators */
	O_EQ, O_NE,
	/* assignments are assumed to be in range O_ASN .. O_BORASN */
	O_ASN, O_TIMESASN, O_DIVASN, O_MODASN, O_PLUSASN, O_MINUSASN,
	O_LSHIFTASN, O_RSHIFTASN, O_BANDASN, O_BXORASN, O_BORASN,
	O_LSHIFT, O_RSHIFT,
	O_LE, O_GE, O_LT, O_GT,
	O_LAND,
	O_LOR,
	O_TIMES, O_DIV, O_MOD,
	O_PLUS, O_MINUS,
	O_BAND,
	O_BXOR,
	O_BOR,
	O_TERN,
	O_COMMA,
	/* things after this aren't used as binary operators */
	/* unary that are not also binaries */
	O_BNOT, O_LNOT,
	/* misc */
	OPEN_PAREN, CLOSE_PAREN, CTERN,
	/* things that don't appear in the opinfo[] table */
	VAR, LIT, END, BAD
};
#define IS_BINOP(op) (((int)op) >= (int)O_EQ && ((int)op) <= (int)O_COMMA)
#define IS_ASSIGNOP(op)	((int)(op) >= (int)O_ASN && (int)(op) <= (int)O_BORASN)

/* precisions; used to be enum prec but we do arithmetics on it */
#define P_PRIMARY	0	/* VAR, LIT, (), ~ ! - + */
#define P_MULT		1	/* * / % */
#define P_ADD		2	/* + - */
#define P_SHIFT		3	/* << >> */
#define P_RELATION	4	/* < <= > >= */
#define P_EQUALITY	5	/* == != */
#define P_BAND		6	/* & */
#define P_BXOR		7	/* ^ */
#define P_BOR		8	/* | */
#define P_LAND		9	/* && */
#define P_LOR		10	/* || */
#define P_TERN		11	/* ?: */
#define P_ASSIGN	12	/* = *= /= %= += -= <<= >>= &= ^= |= */
#define P_COMMA		13	/* , */
#define MAX_PREC	P_COMMA

struct opinfo {
	char		name[4];
	int		len;	/* name length */
	int		prec;	/* precedence: lower is higher */
};

/* Tokens in this table must be ordered so the longest are first
 * (eg, += before +). If you change something, change the order
 * of enum token too.
 */
static const struct opinfo opinfo[] = {
	{ "++",	 2, P_PRIMARY },	/* before + */
	{ "--",	 2, P_PRIMARY },	/* before - */
	{ "==",	 2, P_EQUALITY },	/* before = */
	{ "!=",	 2, P_EQUALITY },	/* before ! */
	{ "=",	 1, P_ASSIGN },		/* keep assigns in a block */
	{ "*=",	 2, P_ASSIGN },
	{ "/=",	 2, P_ASSIGN },
	{ "%=",	 2, P_ASSIGN },
	{ "+=",	 2, P_ASSIGN },
	{ "-=",	 2, P_ASSIGN },
	{ "<<=", 3, P_ASSIGN },
	{ ">>=", 3, P_ASSIGN },
	{ "&=",	 2, P_ASSIGN },
	{ "^=",	 2, P_ASSIGN },
	{ "|=",	 2, P_ASSIGN },
	{ "<<",	 2, P_SHIFT },
	{ ">>",	 2, P_SHIFT },
	{ "<=",	 2, P_RELATION },
	{ ">=",	 2, P_RELATION },
	{ "<",	 1, P_RELATION },
	{ ">",	 1, P_RELATION },
	{ "&&",	 2, P_LAND },
	{ "||",	 2, P_LOR },
	{ "*",	 1, P_MULT },
	{ "/",	 1, P_MULT },
	{ "%",	 1, P_MULT },
	{ "+",	 1, P_ADD },
	{ "-",	 1, P_ADD },
	{ "&",	 1, P_BAND },
	{ "^",	 1, P_BXOR },
	{ "|",	 1, P_BOR },
	{ "?",	 1, P_TERN },
	{ ",",	 1, P_COMMA },
	{ "~",	 1, P_PRIMARY },
	{ "!",	 1, P_PRIMARY },
	{ "(",	 1, P_PRIMARY },
	{ ")",	 1, P_PRIMARY },
	{ ":",	 1, P_PRIMARY },
	{ "",	 0, P_PRIMARY }
};

typedef struct expr_state Expr_state;
struct expr_state {
	const char *expression;		/* expression being evaluated */
	const char *tokp;		/* lexical position */
	struct tbl *val;		/* value from token() */
	struct tbl *evaling;		/* variable that is being recursively
					 * expanded (EXPRINEVAL flag set) */
	int noassign;			/* don't do assigns (for ?:,&&,||) */
	enum token tok;			/* token from token() */
	bool arith;			/* evaluating an $(()) expression? */
	bool natural;			/* unsigned arithmetic calculation */
};

#define bivui(x, op, y)	(es->natural ?			\
	(mksh_ari_t)((x)->val.u op (y)->val.u) :	\
	(mksh_ari_t)((x)->val.i op (y)->val.i)		\
)
#define chvui(x, op)	do {			\
	if (es->natural)			\
		(x)->val.u = op (x)->val.u;	\
	else					\
		(x)->val.i = op (x)->val.i;	\
} while (/* CONSTCOND */ 0)
#define stvui(x, n)	do {			\
	if (es->natural)			\
		(x)->val.u = (n);		\
	else					\
		(x)->val.i = (n);		\
} while (/* CONSTCOND */ 0)

enum error_type {
	ET_UNEXPECTED, ET_BADLIT, ET_RECURSIVE,
	ET_LVALUE, ET_RDONLY, ET_STR
};

static void evalerr(Expr_state *, enum error_type, const char *)
    MKSH_A_NORETURN;
static struct tbl *evalexpr(Expr_state *, int);
static void exprtoken(Expr_state *);
static struct tbl *do_ppmm(Expr_state *, enum token, struct tbl *, bool);
static void assign_check(Expr_state *, enum token, struct tbl *);
static struct tbl *tempvar(void);
static struct tbl *intvar(Expr_state *, struct tbl *);

/*
 * parse and evaluate expression
 */
int
evaluate(const char *expr, mksh_ari_t *rval, int error_ok, bool arith)
{
	struct tbl v;
	int ret;

	v.flag = DEFINED|INTEGER;
	v.type = 0;
	ret = v_evaluate(&v, expr, error_ok, arith);
	*rval = v.val.i;
	return (ret);
}

/*
 * parse and evaluate expression, storing result in vp.
 */
int
v_evaluate(struct tbl *vp, const char *expr, volatile int error_ok,
    bool arith)
{
	struct tbl *v;
	Expr_state curstate;
	Expr_state * const es = &curstate;
	int i;

	/* save state to allow recursive calls */
	curstate.expression = curstate.tokp = expr;
	curstate.noassign = 0;
	curstate.arith = arith;
	curstate.evaling = NULL;
	curstate.natural = false;

	newenv(E_ERRH);
	i = sigsetjmp(e->jbuf, 0);
	if (i) {
		/* Clear EXPRINEVAL in of any variables we were playing with */
		if (curstate.evaling)
			curstate.evaling->flag &= ~EXPRINEVAL;
		quitenv(NULL);
		if (i == LAEXPR) {
			if (error_ok == KSH_RETURN_ERROR)
				return (0);
			errorfz();
		}
		unwind(i);
		/* NOTREACHED */
	}

	exprtoken(es);
	if (es->tok == END) {
		es->tok = LIT;
		es->val = tempvar();
	}
	v = intvar(es, evalexpr(es, MAX_PREC));

	if (es->tok != END)
		evalerr(es, ET_UNEXPECTED, NULL);

	if (es->arith && es->natural)
		vp->flag |= INT_U;
	if (vp->flag & INTEGER)
		setint_v(vp, v, es->arith);
	else
		/* can fail if readonly */
		setstr(vp, str_val(v), error_ok);

	quitenv(NULL);

	return (1);
}

static void
evalerr(Expr_state *es, enum error_type type, const char *str)
{
	char tbuf[2];
	const char *s;

	es->arith = false;
	switch (type) {
	case ET_UNEXPECTED:
		switch (es->tok) {
		case VAR:
			s = es->val->name;
			break;
		case LIT:
			s = str_val(es->val);
			break;
		case END:
			s = "end of expression";
			break;
		case BAD:
			tbuf[0] = *es->tokp;
			tbuf[1] = '\0';
			s = tbuf;
			break;
		default:
			s = opinfo[(int)es->tok].name;
		}
		warningf(true, "%s: unexpected '%s'", es->expression, s);
		break;

	case ET_BADLIT:
		warningf(true, "%s: bad number '%s'", es->expression, str);
		break;

	case ET_RECURSIVE:
		warningf(true, "%s: expression recurses on parameter '%s'",
		    es->expression, str);
		break;

	case ET_LVALUE:
		warningf(true, "%s: %s requires lvalue",
		    es->expression, str);
		break;

	case ET_RDONLY:
		warningf(true, "%s: %s applied to read only variable",
		    es->expression, str);
		break;

	default: /* keep gcc happy */
	case ET_STR:
		warningf(true, "%s: %s", es->expression, str);
		break;
	}
	unwind(LAEXPR);
}

static struct tbl *
evalexpr(Expr_state *es, int prec)
{
	struct tbl *vl, *vr = NULL, *vasn;
	enum token op;
	mksh_ari_t res = 0;

	if (prec == P_PRIMARY) {
		op = es->tok;
		if (op == O_BNOT || op == O_LNOT || op == O_MINUS ||
		    op == O_PLUS) {
			exprtoken(es);
			vl = intvar(es, evalexpr(es, P_PRIMARY));
			if (op == O_BNOT)
				chvui(vl, ~);
			else if (op == O_LNOT)
				chvui(vl, !);
			else if (op == O_MINUS)
				chvui(vl, -);
			/* op == O_PLUS is a no-op */
		} else if (op == OPEN_PAREN) {
			exprtoken(es);
			vl = evalexpr(es, MAX_PREC);
			if (es->tok != CLOSE_PAREN)
				evalerr(es, ET_STR, "missing )");
			exprtoken(es);
		} else if (op == O_PLUSPLUS || op == O_MINUSMINUS) {
			exprtoken(es);
			vl = do_ppmm(es, op, es->val, true);
			exprtoken(es);
		} else if (op == VAR || op == LIT) {
			vl = es->val;
			exprtoken(es);
		} else {
			evalerr(es, ET_UNEXPECTED, NULL);
			/* NOTREACHED */
		}
		if (es->tok == O_PLUSPLUS || es->tok == O_MINUSMINUS) {
			vl = do_ppmm(es, es->tok, vl, false);
			exprtoken(es);
		}
		return (vl);
	}
	vl = evalexpr(es, prec - 1);
	for (op = es->tok; IS_BINOP(op) && opinfo[(int)op].prec == prec;
	    op = es->tok) {
		exprtoken(es);
		vasn = vl;
		if (op != O_ASN) /* vl may not have a value yet */
			vl = intvar(es, vl);
		if (IS_ASSIGNOP(op)) {
			assign_check(es, op, vasn);
			vr = intvar(es, evalexpr(es, P_ASSIGN));
		} else if (op != O_TERN && op != O_LAND && op != O_LOR)
			vr = intvar(es, evalexpr(es, prec - 1));
		if ((op == O_DIV || op == O_MOD || op == O_DIVASN ||
		    op == O_MODASN) && vr->val.i == 0) {
			if (es->noassign)
				vr->val.i = 1;
			else
				evalerr(es, ET_STR, "zero divisor");
		}
		switch ((int)op) {
		case O_TIMES:
		case O_TIMESASN:
			res = bivui(vl, *, vr);
			break;
		case O_DIV:
		case O_DIVASN:
			res = bivui(vl, /, vr);
			break;
		case O_MOD:
		case O_MODASN:
			res = bivui(vl, %, vr);
			break;
		case O_PLUS:
		case O_PLUSASN:
			res = bivui(vl, +, vr);
			break;
		case O_MINUS:
		case O_MINUSASN:
			res = bivui(vl, -, vr);
			break;
		case O_LSHIFT:
		case O_LSHIFTASN:
			res = bivui(vl, <<, vr);
			break;
		case O_RSHIFT:
		case O_RSHIFTASN:
			res = bivui(vl, >>, vr);
			break;
		case O_LT:
			res = bivui(vl, <, vr);
			break;
		case O_LE:
			res = bivui(vl, <=, vr);
			break;
		case O_GT:
			res = bivui(vl, >, vr);
			break;
		case O_GE:
			res = bivui(vl, >=, vr);
			break;
		case O_EQ:
			res = bivui(vl, ==, vr);
			break;
		case O_NE:
			res = bivui(vl, !=, vr);
			break;
		case O_BAND:
		case O_BANDASN:
			res = bivui(vl, &, vr);
			break;
		case O_BXOR:
		case O_BXORASN:
			res = bivui(vl, ^, vr);
			break;
		case O_BOR:
		case O_BORASN:
			res = bivui(vl, |, vr);
			break;
		case O_LAND:
			if (!vl->val.i)
				es->noassign++;
			vr = intvar(es, evalexpr(es, prec - 1));
			res = bivui(vl, &&, vr);
			if (!vl->val.i)
				es->noassign--;
			break;
		case O_LOR:
			if (vl->val.i)
				es->noassign++;
			vr = intvar(es, evalexpr(es, prec - 1));
			res = bivui(vl, ||, vr);
			if (vl->val.i)
				es->noassign--;
			break;
		case O_TERN:
			{
				bool ev = vl->val.i != 0;

				if (!ev)
					es->noassign++;
				vl = evalexpr(es, MAX_PREC);
				if (!ev)
					es->noassign--;
				if (es->tok != CTERN)
					evalerr(es, ET_STR, "missing :");
				exprtoken(es);
				if (ev)
					es->noassign++;
				vr = evalexpr(es, P_TERN);
				if (ev)
					es->noassign--;
				vl = ev ? vl : vr;
			}
			break;
		case O_ASN:
			res = vr->val.i;
			break;
		case O_COMMA:
			res = vr->val.i;
			break;
		}
		if (IS_ASSIGNOP(op)) {
			stvui(vr, res);
			if (!es->noassign) {
				if (vasn->flag & INTEGER)
					setint_v(vasn, vr, es->arith);
				else
					setint(vasn, res);
			}
			vl = vr;
		} else if (op != O_TERN)
			stvui(vl, res);
	}
	return (vl);
}

static void
exprtoken(Expr_state *es)
{
	const char *cp = es->tokp;
	int c;
	char *tvar;

	/* skip white space */
 skip_spaces:
	while ((c = *cp), ksh_isspace(c))
		++cp;
	if (es->tokp == es->expression && c == '#') {
		/* expression begins with # */
		es->natural = true;	/* switch to unsigned */
		++cp;
		goto skip_spaces;
	}
	es->tokp = cp;

	if (c == '\0')
		es->tok = END;
	else if (ksh_isalphx(c)) {
		for (; ksh_isalnux(c); c = *cp)
			cp++;
		if (c == '[') {
			int len;

			len = array_ref_len(cp);
			if (len == 0)
				evalerr(es, ET_STR, "missing ]");
			cp += len;
		} else if (c == '(' /*)*/ ) {
			/* todo: add math functions (all take single argument):
			 * abs acos asin atan cos cosh exp int log sin sinh sqrt
			 * tan tanh
			 */
			;
		}
		if (es->noassign) {
			es->val = tempvar();
			es->val->flag |= EXPRLVALUE;
		} else {
			strndupx(tvar, es->tokp, cp - es->tokp, ATEMP);
			es->val = global(tvar);
			afree(tvar, ATEMP);
		}
		es->tok = VAR;
	} else if (c == '1' && cp[1] == '#') {
		cp += 2;
		cp += utf_ptradj(cp);
		strndupx(tvar, es->tokp, cp - es->tokp, ATEMP);
		goto process_tvar;
#ifndef MKSH_SMALL
	} else if (c == '\'') {
		++cp;
		cp += utf_ptradj(cp);
		if (*cp++ != '\'')
			evalerr(es, ET_STR,
			    "multi-character character constant");
		/* 'x' -> 1#x (x = one multibyte character) */
		c = cp - es->tokp;
		tvar = alloc(c + /* NUL */ 1, ATEMP);
		tvar[0] = '1';
		tvar[1] = '#';
		memcpy(tvar + 2, es->tokp + 1, c - 2);
		tvar[c] = '\0';
		goto process_tvar;
#endif
	} else if (ksh_isdigit(c)) {
		while (c != '_' && (ksh_isalnux(c) || c == '#'))
			c = *cp++;
		strndupx(tvar, es->tokp, --cp - es->tokp, ATEMP);
 process_tvar:
		es->val = tempvar();
		es->val->flag &= ~INTEGER;
		es->val->type = 0;
		es->val->val.s = tvar;
		if (setint_v(es->val, es->val, es->arith) == NULL)
			evalerr(es, ET_BADLIT, tvar);
		afree(tvar, ATEMP);
		es->tok = LIT;
	} else {
		int i, n0;

		for (i = 0; (n0 = opinfo[i].name[0]); i++)
			if (c == n0 && strncmp(cp, opinfo[i].name,
			    (size_t)opinfo[i].len) == 0) {
				es->tok = (enum token)i;
				cp += opinfo[i].len;
				break;
			}
		if (!n0)
			es->tok = BAD;
	}
	es->tokp = cp;
}

/* Do a ++ or -- operation */
static struct tbl *
do_ppmm(Expr_state *es, enum token op, struct tbl *vasn, bool is_prefix)
{
	struct tbl *vl;
	mksh_ari_t oval;

	assign_check(es, op, vasn);

	vl = intvar(es, vasn);
	oval = vl->val.i;
	if (op == O_PLUSPLUS) {
		if (es->natural)
			++vl->val.u;
		else
			++vl->val.i;
	} else {
		if (es->natural)
			--vl->val.u;
		else
			--vl->val.i;
	}
	if (vasn->flag & INTEGER)
		setint_v(vasn, vl, es->arith);
	else
		setint(vasn, vl->val.i);
	if (!is_prefix)		/* undo the inc/dec */
		vl->val.i = oval;

	return (vl);
}

static void
assign_check(Expr_state *es, enum token op, struct tbl *vasn)
{
	if (es->tok == END ||
	    (vasn->name[0] == '\0' && !(vasn->flag & EXPRLVALUE)))
		evalerr(es, ET_LVALUE, opinfo[(int)op].name);
	else if (vasn->flag & RDONLY)
		evalerr(es, ET_RDONLY, opinfo[(int)op].name);
}

static struct tbl *
tempvar(void)
{
	struct tbl *vp;

	vp = alloc(sizeof(struct tbl), ATEMP);
	vp->flag = ISSET|INTEGER;
	vp->type = 0;
	vp->areap = ATEMP;
	vp->ua.hval = 0;
	vp->val.i = 0;
	vp->name[0] = '\0';
	return (vp);
}

/* cast (string) variable to temporary integer variable */
static struct tbl *
intvar(Expr_state *es, struct tbl *vp)
{
	struct tbl *vq;

	/* try to avoid replacing a temp var with another temp var */
	if (vp->name[0] == '\0' &&
	    (vp->flag & (ISSET|INTEGER|EXPRLVALUE)) == (ISSET|INTEGER))
		return (vp);

	vq = tempvar();
	if (setint_v(vq, vp, es->arith) == NULL) {
		if (vp->flag & EXPRINEVAL)
			evalerr(es, ET_RECURSIVE, vp->name);
		es->evaling = vp;
		vp->flag |= EXPRINEVAL;
		v_evaluate(vq, str_val(vp), KSH_UNWIND_ERROR, es->arith);
		vp->flag &= ~EXPRINEVAL;
		es->evaling = NULL;
	}
	return (vq);
}


/*
 * UTF-8 support code: high-level functions
 */

int
utf_widthadj(const char *src, const char **dst)
{
	size_t len;
	unsigned int wc;
	int width;

	if (!UTFMODE || (len = utf_mbtowc(&wc, src)) == (size_t)-1 ||
	    wc == 0)
		len = width = 1;
	else if ((width = utf_wcwidth(wc)) < 0)
		/* XXX use 2 for x_zotc3 here? */
		width = 1;

	if (dst)
		*dst = src + len;
	return (width);
}

int
utf_mbswidth(const char *s)
{
	size_t len;
	unsigned int wc;
	int width = 0, cw;

	if (!UTFMODE)
		return (strlen(s));

	while (*s)
		if (((len = utf_mbtowc(&wc, s)) == (size_t)-1) ||
		    ((cw = utf_wcwidth(wc)) == -1)) {
			s++;
			width += 1;
		} else {
			s += len;
			width += cw;
		}
	return (width);
}

const char *
utf_skipcols(const char *p, int cols)
{
	int c = 0;

	while (c < cols) {
		if (!*p)
			return (p + cols - c);
		c += utf_widthadj(p, &p);
	}
	return (p);
}

size_t
utf_ptradj(const char *src)
{
	register size_t n;

	if (!UTFMODE ||
	    *(const unsigned char *)(src) < 0xC2 ||
	    (n = utf_mbtowc(NULL, src)) == (size_t)-1)
		n = 1;
	return (n);
}

/*
 * UTF-8 support code: low-level functions
 */

/* CESU-8 multibyte and wide character conversion crafted for mksh */

size_t
utf_mbtowc(unsigned int *dst, const char *src)
{
	const unsigned char *s = (const unsigned char *)src;
	unsigned int c, wc;

	if ((wc = *s++) < 0x80) {
 out:
		if (dst != NULL)
			*dst = wc;
		return (wc ? ((const char *)s - src) : 0);
	}
	if (wc < 0xC2 || wc >= 0xF0)
		/* < 0xC0: spurious second byte */
		/* < 0xC2: non-minimalistic mapping error in 2-byte seqs */
		/* > 0xEF: beyond BMP */
		goto ilseq;

	if (wc < 0xE0) {
		wc = (wc & 0x1F) << 6;
		if (((c = *s++) & 0xC0) != 0x80)
			goto ilseq;
		wc |= c & 0x3F;
		goto out;
	}

	wc = (wc & 0x0F) << 12;

	if (((c = *s++) & 0xC0) != 0x80)
		goto ilseq;
	wc |= (c & 0x3F) << 6;

	if (((c = *s++) & 0xC0) != 0x80)
		goto ilseq;
	wc |= c & 0x3F;

	/* Check for non-minimalistic mapping error in 3-byte seqs */
	if (wc >= 0x0800 && wc <= 0xFFFD)
		goto out;
 ilseq:
	return ((size_t)(-1));
}

size_t
utf_wctomb(char *dst, unsigned int wc)
{
	unsigned char *d;

	if (wc < 0x80) {
		*dst = wc;
		return (1);
	}

	d = (unsigned char *)dst;
	if (wc < 0x0800)
		*d++ = (wc >> 6) | 0xC0;
	else {
		*d++ = ((wc = wc > 0xFFFD ? 0xFFFD : wc) >> 12) | 0xE0;
		*d++ = ((wc >> 6) & 0x3F) | 0x80;
	}
	*d++ = (wc & 0x3F) | 0x80;
	return ((char *)d - dst);
}


#ifndef MKSH_mirbsd_wcwidth
/* --- begin of wcwidth.c excerpt --- */
/*-
 * Markus Kuhn -- 2007-05-26 (Unicode 5.0)
 *
 * Permission to use, copy, modify, and distribute this software
 * for any purpose and without fee is hereby granted. The author
 * disclaims all warranties with regard to this software.
 */

__RCSID("$miros: src/lib/libc/i18n/wcwidth.c,v 1.8 2008/09/20 12:01:18 tg Exp $");

int
utf_wcwidth(unsigned int c)
{
	static const struct cbset {
		unsigned short first;
		unsigned short last;
	} comb[] = {
		{ 0x0300, 0x036F }, { 0x0483, 0x0486 }, { 0x0488, 0x0489 },
		{ 0x0591, 0x05BD }, { 0x05BF, 0x05BF }, { 0x05C1, 0x05C2 },
		{ 0x05C4, 0x05C5 }, { 0x05C7, 0x05C7 }, { 0x0600, 0x0603 },
		{ 0x0610, 0x0615 }, { 0x064B, 0x065E }, { 0x0670, 0x0670 },
		{ 0x06D6, 0x06E4 }, { 0x06E7, 0x06E8 }, { 0x06EA, 0x06ED },
		{ 0x070F, 0x070F }, { 0x0711, 0x0711 }, { 0x0730, 0x074A },
		{ 0x07A6, 0x07B0 }, { 0x07EB, 0x07F3 }, { 0x0901, 0x0902 },
		{ 0x093C, 0x093C }, { 0x0941, 0x0948 }, { 0x094D, 0x094D },
		{ 0x0951, 0x0954 }, { 0x0962, 0x0963 }, { 0x0981, 0x0981 },
		{ 0x09BC, 0x09BC }, { 0x09C1, 0x09C4 }, { 0x09CD, 0x09CD },
		{ 0x09E2, 0x09E3 }, { 0x0A01, 0x0A02 }, { 0x0A3C, 0x0A3C },
		{ 0x0A41, 0x0A42 }, { 0x0A47, 0x0A48 }, { 0x0A4B, 0x0A4D },
		{ 0x0A70, 0x0A71 }, { 0x0A81, 0x0A82 }, { 0x0ABC, 0x0ABC },
		{ 0x0AC1, 0x0AC5 }, { 0x0AC7, 0x0AC8 }, { 0x0ACD, 0x0ACD },
		{ 0x0AE2, 0x0AE3 }, { 0x0B01, 0x0B01 }, { 0x0B3C, 0x0B3C },
		{ 0x0B3F, 0x0B3F }, { 0x0B41, 0x0B43 }, { 0x0B4D, 0x0B4D },
		{ 0x0B56, 0x0B56 }, { 0x0B82, 0x0B82 }, { 0x0BC0, 0x0BC0 },
		{ 0x0BCD, 0x0BCD }, { 0x0C3E, 0x0C40 }, { 0x0C46, 0x0C48 },
		{ 0x0C4A, 0x0C4D }, { 0x0C55, 0x0C56 }, { 0x0CBC, 0x0CBC },
		{ 0x0CBF, 0x0CBF }, { 0x0CC6, 0x0CC6 }, { 0x0CCC, 0x0CCD },
		{ 0x0CE2, 0x0CE3 }, { 0x0D41, 0x0D43 }, { 0x0D4D, 0x0D4D },
		{ 0x0DCA, 0x0DCA }, { 0x0DD2, 0x0DD4 }, { 0x0DD6, 0x0DD6 },
		{ 0x0E31, 0x0E31 }, { 0x0E34, 0x0E3A }, { 0x0E47, 0x0E4E },
		{ 0x0EB1, 0x0EB1 }, { 0x0EB4, 0x0EB9 }, { 0x0EBB, 0x0EBC },
		{ 0x0EC8, 0x0ECD }, { 0x0F18, 0x0F19 }, { 0x0F35, 0x0F35 },
		{ 0x0F37, 0x0F37 }, { 0x0F39, 0x0F39 }, { 0x0F71, 0x0F7E },
		{ 0x0F80, 0x0F84 }, { 0x0F86, 0x0F87 }, { 0x0F90, 0x0F97 },
		{ 0x0F99, 0x0FBC }, { 0x0FC6, 0x0FC6 }, { 0x102D, 0x1030 },
		{ 0x1032, 0x1032 }, { 0x1036, 0x1037 }, { 0x1039, 0x1039 },
		{ 0x1058, 0x1059 }, { 0x1160, 0x11FF }, { 0x135F, 0x135F },
		{ 0x1712, 0x1714 }, { 0x1732, 0x1734 }, { 0x1752, 0x1753 },
		{ 0x1772, 0x1773 }, { 0x17B4, 0x17B5 }, { 0x17B7, 0x17BD },
		{ 0x17C6, 0x17C6 }, { 0x17C9, 0x17D3 }, { 0x17DD, 0x17DD },
		{ 0x180B, 0x180D }, { 0x18A9, 0x18A9 }, { 0x1920, 0x1922 },
		{ 0x1927, 0x1928 }, { 0x1932, 0x1932 }, { 0x1939, 0x193B },
		{ 0x1A17, 0x1A18 }, { 0x1B00, 0x1B03 }, { 0x1B34, 0x1B34 },
		{ 0x1B36, 0x1B3A }, { 0x1B3C, 0x1B3C }, { 0x1B42, 0x1B42 },
		{ 0x1B6B, 0x1B73 }, { 0x1DC0, 0x1DCA }, { 0x1DFE, 0x1DFF },
		{ 0x200B, 0x200F }, { 0x202A, 0x202E }, { 0x2060, 0x2063 },
		{ 0x206A, 0x206F }, { 0x20D0, 0x20EF }, { 0x302A, 0x302F },
		{ 0x3099, 0x309A }, { 0xA806, 0xA806 }, { 0xA80B, 0xA80B },
		{ 0xA825, 0xA826 }, { 0xFB1E, 0xFB1E }, { 0xFE00, 0xFE0F },
		{ 0xFE20, 0xFE23 }, { 0xFEFF, 0xFEFF }, { 0xFFF9, 0xFFFB }
	};
	size_t min = 0, mid, max = NELEM(comb) - 1;

	/* test for 8-bit control characters */
	if (c < 32 || (c >= 0x7f && c < 0xa0))
		return (c ? -1 : 0);

	/* binary search in table of non-spacing characters */
	if (c >= comb[0].first && c <= comb[max].last)
		while (max >= min) {
			mid = (min + max) / 2;
			if (c > comb[mid].last)
				min = mid + 1;
			else if (c < comb[mid].first)
				max = mid - 1;
			else
				return (0);
		}

	/* if we arrive here, c is not a combining or C0/C1 control char */
	return ((c >= 0x1100 && (
	    c <= 0x115f || /* Hangul Jamo init. consonants */
	    c == 0x2329 || c == 0x232a ||
	    (c >= 0x2e80 && c <= 0xa4cf && c != 0x303f) || /* CJK ... Yi */
	    (c >= 0xac00 && c <= 0xd7a3) || /* Hangul Syllables */
	    (c >= 0xf900 && c <= 0xfaff) || /* CJK Compatibility Ideographs */
	    (c >= 0xfe10 && c <= 0xfe19) || /* Vertical forms */
	    (c >= 0xfe30 && c <= 0xfe6f) || /* CJK Compatibility Forms */
	    (c >= 0xff00 && c <= 0xff60) || /* Fullwidth Forms */
	    (c >= 0xffe0 && c <= 0xffe6))) ? 2 : 1);
}
/* --- end of wcwidth.c excerpt --- */
#endif
