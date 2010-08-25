/*	$OpenBSD: tree.c,v 1.19 2008/08/11 21:50:35 jaredy Exp $	*/

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

__RCSID("$MirOS: src/bin/mksh/tree.c,v 1.30 2010/02/25 20:18:19 tg Exp $");

#define INDENT	4

#define tputc(c, shf) shf_putchar(c, shf);
static void ptree(struct op *, int, struct shf *);
static void pioact(struct shf *, int, struct ioword *);
static void tputC(int, struct shf *);
static void tputS(char *, struct shf *);
static void vfptreef(struct shf *, int, const char *, va_list);
static struct ioword **iocopy(struct ioword **, Area *);
static void iofree(struct ioword **, Area *);

/*
 * print a command tree
 */
static void
ptree(struct op *t, int indent, struct shf *shf)
{
	const char **w;
	struct ioword **ioact;
	struct op *t1;

 Chain:
	if (t == NULL)
		return;
	switch (t->type) {
	case TCOM:
		if (t->vars)
			for (w = (const char **)t->vars; *w != NULL; )
				fptreef(shf, indent, "%S ", *w++);
		else
			shf_puts("#no-vars# ", shf);
		if (t->args)
			for (w = t->args; *w != NULL; )
				fptreef(shf, indent, "%S ", *w++);
		else
			shf_puts("#no-args# ", shf);
		break;
	case TEXEC:
		t = t->left;
		goto Chain;
	case TPAREN:
		fptreef(shf, indent + 2, "( %T) ", t->left);
		break;
	case TPIPE:
		fptreef(shf, indent, "%T| ", t->left);
		t = t->right;
		goto Chain;
	case TLIST:
		fptreef(shf, indent, "%T%;", t->left);
		t = t->right;
		goto Chain;
	case TOR:
	case TAND:
		fptreef(shf, indent, "%T%s %T",
		    t->left, (t->type==TOR) ? "||" : "&&", t->right);
		break;
	case TBANG:
		shf_puts("! ", shf);
		t = t->right;
		goto Chain;
	case TDBRACKET: {
		int i;

		shf_puts("[[", shf);
		for (i = 0; t->args[i]; i++)
			fptreef(shf, indent, " %S", t->args[i]);
		shf_puts(" ]] ", shf);
		break;
	}
	case TSELECT:
		fptreef(shf, indent, "select %s ", t->str);
		/* FALLTHROUGH */
	case TFOR:
		if (t->type == TFOR)
			fptreef(shf, indent, "for %s ", t->str);
		if (t->vars != NULL) {
			shf_puts("in ", shf);
			for (w = (const char **)t->vars; *w; )
				fptreef(shf, indent, "%S ", *w++);
			fptreef(shf, indent, "%;");
		}
		fptreef(shf, indent + INDENT, "do%N%T", t->left);
		fptreef(shf, indent, "%;done ");
		break;
	case TCASE:
		fptreef(shf, indent, "case %S in", t->str);
		for (t1 = t->left; t1 != NULL; t1 = t1->right) {
			fptreef(shf, indent, "%N(");
			for (w = (const char **)t1->vars; *w != NULL; w++)
				fptreef(shf, indent, "%S%c", *w,
				    (w[1] != NULL) ? '|' : ')');
			fptreef(shf, indent + INDENT, "%;%T%N;;", t1->left);
		}
		fptreef(shf, indent, "%Nesac ");
		break;
	case TIF:
	case TELIF:
		/* 3 == strlen("if ") */
		fptreef(shf, indent + 3, "if %T", t->left);
		for (;;) {
			t = t->right;
			if (t->left != NULL) {
				fptreef(shf, indent, "%;");
				fptreef(shf, indent + INDENT, "then%N%T",
				    t->left);
			}
			if (t->right == NULL || t->right->type != TELIF)
				break;
			t = t->right;
			fptreef(shf, indent, "%;");
			/* 5 == strlen("elif ") */
			fptreef(shf, indent + 5, "elif %T", t->left);
		}
		if (t->right != NULL) {
			fptreef(shf, indent, "%;");
			fptreef(shf, indent + INDENT, "else%;%T", t->right);
		}
		fptreef(shf, indent, "%;fi ");
		break;
	case TWHILE:
	case TUNTIL:
		/* 6 == strlen("while"/"until") */
		fptreef(shf, indent + 6, "%s %T",
		    (t->type==TWHILE) ? "while" : "until",
		    t->left);
		fptreef(shf, indent, "%;do");
		fptreef(shf, indent + INDENT, "%;%T", t->right);
		fptreef(shf, indent, "%;done ");
		break;
	case TBRACE:
		fptreef(shf, indent + INDENT, "{%;%T", t->left);
		fptreef(shf, indent, "%;} ");
		break;
	case TCOPROC:
		fptreef(shf, indent, "%T|& ", t->left);
		break;
	case TASYNC:
		fptreef(shf, indent, "%T& ", t->left);
		break;
	case TFUNCT:
		fptreef(shf, indent,
		    t->u.ksh_func ? "function %s %T" : "%s() %T",
		    t->str, t->left);
		break;
	case TTIME:
		fptreef(shf, indent, "time %T", t->left);
		break;
	default:
		shf_puts("<botch>", shf);
		break;
	}
	if ((ioact = t->ioact) != NULL) {
		int	need_nl = 0;

		while (*ioact != NULL)
			pioact(shf, indent, *ioact++);
		/* Print here documents after everything else... */
		for (ioact = t->ioact; *ioact != NULL; ) {
			struct ioword *iop = *ioact++;

			/* heredoc is 0 when tracing (set -x) */
			if ((iop->flag & IOTYPE) == IOHERE && iop->heredoc &&
			    /* iop->delim[1] == '<' means here string */
			    (!iop->delim || iop->delim[1] != '<')) {
				tputc('\n', shf);
				shf_puts(iop->heredoc, shf);
				fptreef(shf, indent, "%s",
				    evalstr(iop->delim, 0));
				need_nl = 1;
			}
		}
		/* Last delimiter must be followed by a newline (this often
		 * leads to an extra blank line, but its not worth worrying
		 * about)
		 */
		if (need_nl)
			tputc('\n', shf);
	}
}

static void
pioact(struct shf *shf, int indent, struct ioword *iop)
{
	int flag = iop->flag;
	int type = flag & IOTYPE;
	int expected;

	expected = (type == IOREAD || type == IORDWR || type == IOHERE) ? 0 :
	    (type == IOCAT || type == IOWRITE) ? 1 :
	    (type == IODUP && (iop->unit == !(flag & IORDUP))) ? iop->unit :
	    iop->unit + 1;
	if (iop->unit != expected)
		shf_fprintf(shf, "%d", iop->unit);

	switch (type) {
	case IOREAD:
		shf_puts("< ", shf);
		break;
	case IOHERE:
		shf_puts(flag & IOSKIP ? "<<-" : "<<", shf);
		break;
	case IOCAT:
		shf_puts(">> ", shf);
		break;
	case IOWRITE:
		shf_puts(flag & IOCLOB ? ">| " : "> ", shf);
		break;
	case IORDWR:
		shf_puts("<> ", shf);
		break;
	case IODUP:
		shf_puts(flag & IORDUP ? "<&" : ">&", shf);
		break;
	}
	/* name/delim are 0 when printing syntax errors */
	if (type == IOHERE) {
		if (iop->delim)
			fptreef(shf, indent, "%s%S ",
			    /* here string */ iop->delim[1] == '<' ? "" : " ",
			    iop->delim);
		else
			tputc(' ', shf);
	} else if (iop->name)
		fptreef(shf, indent, (iop->flag & IONAMEXP) ? "%s " : "%S ",
		    iop->name);
}


/*
 * variants of fputc, fputs for ptreef and snptreef
 */
static void
tputC(int c, struct shf *shf)
{
	if ((c&0x60) == 0) {		/* C0|C1 */
		tputc((c&0x80) ? '$' : '^', shf);
		tputc(((c&0x7F)|0x40), shf);
	} else if ((c&0x7F) == 0x7F) {	/* DEL */
		tputc((c&0x80) ? '$' : '^', shf);
		tputc('?', shf);
	} else
		tputc(c, shf);
}

static void
tputS(char *wp, struct shf *shf)
{
	int c, quotelevel = 0;

	/* problems:
	 *	`...` -> $(...)
	 *	'foo' -> "foo"
	 * could change encoding to:
	 *	OQUOTE ["'] ... CQUOTE ["']
	 *	COMSUB [(`] ...\0	(handle $ ` \ and maybe " in `...` case)
	 */
	while (1)
		switch (*wp++) {
		case EOS:
			return;
		case ADELIM:
		case CHAR:
			tputC(*wp++, shf);
			break;
		case QCHAR:
			c = *wp++;
			if (!quotelevel || (c == '"' || c == '`' || c == '$'))
				tputc('\\', shf);
			tputC(c, shf);
			break;
		case COMSUB:
			shf_puts("$(", shf);
			while (*wp != 0)
				tputC(*wp++, shf);
			tputc(')', shf);
			wp++;
			break;
		case EXPRSUB:
			shf_puts("$((", shf);
			while (*wp != 0)
				tputC(*wp++, shf);
			shf_puts("))", shf);
			wp++;
			break;
		case OQUOTE:
			quotelevel++;
			tputc('"', shf);
			break;
		case CQUOTE:
			if (quotelevel)
				quotelevel--;
			tputc('"', shf);
			break;
		case OSUBST:
			tputc('$', shf);
			if (*wp++ == '{')
				tputc('{', shf);
			while ((c = *wp++) != 0)
				tputC(c, shf);
			break;
		case CSUBST:
			if (*wp++ == '}')
				tputc('}', shf);
			break;
		case OPAT:
			tputc(*wp++, shf);
			tputc('(', shf);
			break;
		case SPAT:
			tputc('|', shf);
			break;
		case CPAT:
			tputc(')', shf);
			break;
		}
}

/*
 * this is the _only_ way to reliably handle
 * variable args with an ANSI compiler
 */
/* VARARGS */
int
fptreef(struct shf *shf, int indent, const char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);

	vfptreef(shf, indent, fmt, va);
	va_end(va);
	return (0);
}

/* VARARGS */
char *
snptreef(char *s, int n, const char *fmt, ...)
{
	va_list va;
	struct shf shf;

	shf_sopen(s, n, SHF_WR | (s ? 0 : SHF_DYNAMIC), &shf);

	va_start(va, fmt);
	vfptreef(&shf, 0, fmt, va);
	va_end(va);

	return (shf_sclose(&shf)); /* null terminates */
}

static void
vfptreef(struct shf *shf, int indent, const char *fmt, va_list va)
{
	int c;

	while ((c = *fmt++)) {
		if (c == '%') {
			switch ((c = *fmt++)) {
			case 'c':
				tputc(va_arg(va, int), shf);
				break;
			case 's':
				shf_puts(va_arg(va, char *), shf);
				break;
			case 'S':	/* word */
				tputS(va_arg(va, char *), shf);
				break;
			case 'd':	/* decimal */
				shf_fprintf(shf, "%d", va_arg(va, int));
				break;
			case 'u':	/* decimal */
				shf_fprintf(shf, "%u", va_arg(va, unsigned int));
				break;
			case 'T':	/* format tree */
				ptree(va_arg(va, struct op *), indent, shf);
				break;
			case ';':	/* newline or ; */
			case 'N':	/* newline or space */
				if (shf->flags & SHF_STRING) {
					if (c == ';')
						tputc(';', shf);
					tputc(' ', shf);
				} else {
					int i;

					tputc('\n', shf);
					for (i = indent; i >= 8; i -= 8)
						tputc('\t', shf);
					for (; i > 0; --i)
						tputc(' ', shf);
				}
				break;
			case 'R':
				pioact(shf, indent, va_arg(va, struct ioword *));
				break;
			default:
				tputc(c, shf);
				break;
			}
		} else
			tputc(c, shf);
	}
}

/*
 * copy tree (for function definition)
 */
struct op *
tcopy(struct op *t, Area *ap)
{
	struct op *r;
	const char **tw;
	char **rw;

	if (t == NULL)
		return (NULL);

	r = alloc(sizeof(struct op), ap);

	r->type = t->type;
	r->u.evalflags = t->u.evalflags;

	if (t->type == TCASE)
		r->str = wdcopy(t->str, ap);
	else
		strdupx(r->str, t->str, ap);

	if (t->vars == NULL)
		r->vars = NULL;
	else {
		for (tw = (const char **)t->vars; *tw++ != NULL; )
			;
		rw = r->vars = alloc((tw - (const char **)t->vars + 1) *
		    sizeof(*tw), ap);
		for (tw = (const char **)t->vars; *tw != NULL; )
			*rw++ = wdcopy(*tw++, ap);
		*rw = NULL;
	}

	if (t->args == NULL)
		r->args = NULL;
	else {
		for (tw = t->args; *tw++ != NULL; )
			;
		r->args = (const char **)(rw = alloc((tw - t->args + 1) *
		    sizeof(*tw), ap));
		for (tw = t->args; *tw != NULL; )
			*rw++ = wdcopy(*tw++, ap);
		*rw = NULL;
	}

	r->ioact = (t->ioact == NULL) ? NULL : iocopy(t->ioact, ap);

	r->left = tcopy(t->left, ap);
	r->right = tcopy(t->right, ap);
	r->lineno = t->lineno;

	return (r);
}

char *
wdcopy(const char *wp, Area *ap)
{
	size_t len = wdscan(wp, EOS) - wp;
	return (memcpy(alloc(len, ap), wp, len));
}

/* return the position of prefix c in wp plus 1 */
const char *
wdscan(const char *wp, int c)
{
	int nest = 0;

	while (1)
		switch (*wp++) {
		case EOS:
			return (wp);
		case ADELIM:
			if (c == ADELIM)
				return (wp + 1);
			/* FALLTHROUGH */
		case CHAR:
		case QCHAR:
			wp++;
			break;
		case COMSUB:
		case EXPRSUB:
			while (*wp++ != 0)
				;
			break;
		case OQUOTE:
		case CQUOTE:
			break;
		case OSUBST:
			nest++;
			while (*wp++ != '\0')
				;
			break;
		case CSUBST:
			wp++;
			if (c == CSUBST && nest == 0)
				return (wp);
			nest--;
			break;
		case OPAT:
			nest++;
			wp++;
			break;
		case SPAT:
		case CPAT:
			if (c == wp[-1] && nest == 0)
				return (wp);
			if (wp[-1] == CPAT)
				nest--;
			break;
		default:
			internal_warningf(
			    "wdscan: unknown char 0x%x (carrying on)",
			    wp[-1]);
		}
}

/* return a copy of wp without any of the mark up characters and
 * with quote characters (" ' \) stripped.
 * (string is allocated from ATEMP)
 */
char *
wdstrip(const char *wp, bool keepq, bool make_magic)
{
	struct shf shf;
	int c;

	shf_sopen(NULL, 32, SHF_WR | SHF_DYNAMIC, &shf);

	/* problems:
	 *	`...` -> $(...)
	 *	x${foo:-"hi"} -> x${foo:-hi}
	 *	x${foo:-'hi'} -> x${foo:-hi} unless keepq
	 */
	while (1)
		switch (*wp++) {
		case EOS:
			return (shf_sclose(&shf)); /* null terminates */
		case ADELIM:
		case CHAR:
			c = *wp++;
			if (make_magic && (ISMAGIC(c) || c == '[' || c == NOT ||
			    c == '-' || c == ']' || c == '*' || c == '?'))
				shf_putchar(MAGIC, &shf);
			shf_putchar(c, &shf);
			break;
		case QCHAR:
			c = *wp++;
			if (keepq && (c == '"' || c == '`' || c == '$' || c == '\\'))
				shf_putchar('\\', &shf);
			shf_putchar(c, &shf);
			break;
		case COMSUB:
			shf_puts("$(", &shf);
			while (*wp != 0)
				shf_putchar(*wp++, &shf);
			shf_putchar(')', &shf);
			break;
		case EXPRSUB:
			shf_puts("$((", &shf);
			while (*wp != 0)
				shf_putchar(*wp++, &shf);
			shf_puts("))", &shf);
			break;
		case OQUOTE:
			break;
		case CQUOTE:
			break;
		case OSUBST:
			shf_putchar('$', &shf);
			if (*wp++ == '{')
			    shf_putchar('{', &shf);
			while ((c = *wp++) != 0)
				shf_putchar(c, &shf);
			break;
		case CSUBST:
			if (*wp++ == '}')
				shf_putchar('}', &shf);
			break;
		case OPAT:
			if (make_magic) {
				shf_putchar(MAGIC, &shf);
				shf_putchar(*wp++ | 0x80, &shf);
			} else {
				shf_putchar(*wp++, &shf);
				shf_putchar('(', &shf);
			}
			break;
		case SPAT:
			if (make_magic)
				shf_putchar(MAGIC, &shf);
			shf_putchar('|', &shf);
			break;
		case CPAT:
			if (make_magic)
				shf_putchar(MAGIC, &shf);
			shf_putchar(')', &shf);
			break;
		}
}

static struct ioword **
iocopy(struct ioword **iow, Area *ap)
{
	struct ioword **ior;
	int i;

	for (ior = iow; *ior++ != NULL; )
		;
	ior = alloc((ior - iow + 1) * sizeof(struct ioword *), ap);

	for (i = 0; iow[i] != NULL; i++) {
		struct ioword *p, *q;

		p = iow[i];
		q = alloc(sizeof(struct ioword), ap);
		ior[i] = q;
		*q = *p;
		if (p->name != NULL)
			q->name = wdcopy(p->name, ap);
		if (p->delim != NULL)
			q->delim = wdcopy(p->delim, ap);
		if (p->heredoc != NULL)
			strdupx(q->heredoc, p->heredoc, ap);
	}
	ior[i] = NULL;

	return (ior);
}

/*
 * free tree (for function definition)
 */
void
tfree(struct op *t, Area *ap)
{
	char **w;

	if (t == NULL)
		return;

	if (t->str != NULL)
		afree(t->str, ap);

	if (t->vars != NULL) {
		for (w = t->vars; *w != NULL; w++)
			afree(*w, ap);
		afree(t->vars, ap);
	}

	if (t->args != NULL) {
		union mksh_ccphack cw;
		/* XXX we assume the caller is right */
		cw.ro = t->args;
		for (w = cw.rw; *w != NULL; w++)
			afree(*w, ap);
		afree(t->args, ap);
	}

	if (t->ioact != NULL)
		iofree(t->ioact, ap);

	tfree(t->left, ap);
	tfree(t->right, ap);

	afree(t, ap);
}

static void
iofree(struct ioword **iow, Area *ap)
{
	struct ioword **iop;
	struct ioword *p;

	for (iop = iow; (p = *iop++) != NULL; ) {
		if (p->name != NULL)
			afree(p->name, ap);
		if (p->delim != NULL)
			afree(p->delim, ap);
		if (p->heredoc != NULL)
			afree(p->heredoc, ap);
		afree(p, ap);
	}
	afree(iow, ap);
}
