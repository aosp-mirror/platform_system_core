/*	$OpenBSD: eval.c,v 1.35 2010/03/24 08:27:26 fgsch Exp $	*/

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

__RCSID("$MirOS: src/bin/mksh/eval.c,v 1.90 2010/07/17 22:09:33 tg Exp $");

/*
 * string expansion
 *
 * first pass: quoting, IFS separation, ~, ${}, $() and $(()) substitution.
 * second pass: alternation ({,}), filename expansion (*?[]).
 */

/* expansion generator state */
typedef struct Expand {
	/* int type; */			/* see expand() */
	const char *str;		/* string */
	union {
		const char **strv;	/* string[] */
		struct shf *shf;	/* file */
	} u;				/* source */
	struct tbl *var;		/* variable in ${var..} */
	short split;			/* split "$@" / call waitlast $() */
} Expand;

#define	XBASE		0	/* scanning original */
#define	XSUB		1	/* expanding ${} string */
#define	XARGSEP		2	/* ifs0 between "$*" */
#define	XARG		3	/* expanding $*, $@ */
#define	XCOM		4	/* expanding $() */
#define XNULLSUB	5	/* "$@" when $# is 0 (don't generate word) */
#define XSUBMID		6	/* middle of expanding ${} */

/* States used for field splitting */
#define IFS_WORD	0	/* word has chars (or quotes) */
#define IFS_WS		1	/* have seen IFS white-space */
#define IFS_NWS		2	/* have seen IFS non-white-space */

static int varsub(Expand *, const char *, const char *, int *, int *);
static int comsub(Expand *, const char *);
static char *trimsub(char *, char *, int);
static void glob(char *, XPtrV *, int);
static void globit(XString *, char **, char *, XPtrV *, int);
static const char *maybe_expand_tilde(const char *, XString *, char **, int);
static char *tilde(char *);
#ifndef MKSH_NOPWNAM
static char *homedir(char *);
#endif
static void alt_expand(XPtrV *, char *, char *, char *, int);
static size_t utflen(const char *);
static void utfincptr(const char *, mksh_ari_t *);

/* UTFMODE functions */
static size_t
utflen(const char *s)
{
	size_t n;

	if (UTFMODE) {
		n = 0;
		while (*s) {
			s += utf_ptradj(s);
			++n;
		}
	} else
		n = strlen(s);
	return (n);
}

static void
utfincptr(const char *s, mksh_ari_t *lp)
{
	const char *cp = s;

	while ((*lp)--)
		cp += utf_ptradj(cp);
	*lp = cp - s;
}

/* compile and expand word */
char *
substitute(const char *cp, int f)
{
	struct source *s, *sold;

	sold = source;
	s = pushs(SWSTR, ATEMP);
	s->start = s->str = cp;
	source = s;
	if (yylex(ONEWORD) != LWORD)
		internal_errorf("substitute");
	source = sold;
	afree(s, ATEMP);
	return (evalstr(yylval.cp, f));
}

/*
 * expand arg-list
 */
char **
eval(const char **ap, int f)
{
	XPtrV w;

	if (*ap == NULL) {
		union mksh_ccphack vap;

		vap.ro = ap;
		return (vap.rw);
	}
	XPinit(w, 32);
	XPput(w, NULL);		/* space for shell name */
	while (*ap != NULL)
		expand(*ap++, &w, f);
	XPput(w, NULL);
	return ((char **)XPclose(w) + 1);
}

/*
 * expand string
 */
char *
evalstr(const char *cp, int f)
{
	XPtrV w;
	char *dp = null;

	XPinit(w, 1);
	expand(cp, &w, f);
	if (XPsize(w))
		dp = *XPptrv(w);
	XPfree(w);
	return (dp);
}

/*
 * expand string - return only one component
 * used from iosetup to expand redirection files
 */
char *
evalonestr(const char *cp, int f)
{
	XPtrV w;
	char *rv;

	XPinit(w, 1);
	expand(cp, &w, f);
	switch (XPsize(w)) {
	case 0:
		rv = null;
		break;
	case 1:
		rv = (char *) *XPptrv(w);
		break;
	default:
		rv = evalstr(cp, f&~DOGLOB);
		break;
	}
	XPfree(w);
	return (rv);
}

/* for nested substitution: ${var:=$var2} */
typedef struct SubType {
	struct tbl *var;	/* variable for ${var..} */
	struct SubType *prev;	/* old type */
	struct SubType *next;	/* poped type (to avoid re-allocating) */
	short	stype;		/* [=+-?%#] action after expanded word */
	short	base;		/* begin position of expanded word */
	short	f;		/* saved value of f (DOPAT, etc) */
	uint8_t	quotep;		/* saved value of quote (for ${..[%#]..}) */
	uint8_t	quotew;		/* saved value of quote (for ${..[+-=]..}) */
} SubType;

void
expand(const char *cp,	/* input word */
    XPtrV *wp,		/* output words */
    int f)		/* DO* flags */
{
	int c = 0;
	int type;		/* expansion type */
	int quote = 0;		/* quoted */
	XString ds;		/* destination string */
	char *dp;		/* destination */
	const char *sp;		/* source */
	int fdo, word;		/* second pass flags; have word */
	int doblank;		/* field splitting of parameter/command subst */
	Expand x = {		/* expansion variables */
		NULL, { NULL }, NULL, 0
	};
	SubType st_head, *st;
	int newlines = 0; /* For trailing newlines in COMSUB */
	int saw_eq, tilde_ok;
	int make_magic;
	size_t len;

	if (cp == NULL)
		internal_errorf("expand(NULL)");
	/* for alias, readonly, set, typeset commands */
	if ((f & DOVACHECK) && is_wdvarassign(cp)) {
		f &= ~(DOVACHECK|DOBLANK|DOGLOB|DOTILDE);
		f |= DOASNTILDE;
	}
	if (Flag(FNOGLOB))
		f &= ~DOGLOB;
	if (Flag(FMARKDIRS))
		f |= DOMARKDIRS;
	if (Flag(FBRACEEXPAND) && (f & DOGLOB))
		f |= DOBRACE_;

	Xinit(ds, dp, 128, ATEMP);	/* init dest. string */
	type = XBASE;
	sp = cp;
	fdo = 0;
	saw_eq = 0;
	tilde_ok = (f & (DOTILDE|DOASNTILDE)) ? 1 : 0; /* must be 1/0 */
	doblank = 0;
	make_magic = 0;
	word = (f&DOBLANK) ? IFS_WS : IFS_WORD;
	/* clang doesn't know OSUBST comes before CSUBST */
	memset(&st_head, 0, sizeof(st_head));
	st = &st_head;

	while (1) {
		Xcheck(ds, dp);

		switch (type) {
		case XBASE:	/* original prefixed string */
			c = *sp++;
			switch (c) {
			case EOS:
				c = 0;
				break;
			case CHAR:
				c = *sp++;
				break;
			case QCHAR:
				quote |= 2; /* temporary quote */
				c = *sp++;
				break;
			case OQUOTE:
				word = IFS_WORD;
				tilde_ok = 0;
				quote = 1;
				continue;
			case CQUOTE:
				quote = st->quotew;
				continue;
			case COMSUB:
				tilde_ok = 0;
				if (f & DONTRUNCOMMAND) {
					word = IFS_WORD;
					*dp++ = '$'; *dp++ = '(';
					while (*sp != '\0') {
						Xcheck(ds, dp);
						*dp++ = *sp++;
					}
					*dp++ = ')';
				} else {
					type = comsub(&x, sp);
					if (type == XCOM && (f&DOBLANK))
						doblank++;
					sp = strnul(sp) + 1;
					newlines = 0;
				}
				continue;
			case EXPRSUB:
				word = IFS_WORD;
				tilde_ok = 0;
				if (f & DONTRUNCOMMAND) {
					*dp++ = '$'; *dp++ = '('; *dp++ = '(';
					while (*sp != '\0') {
						Xcheck(ds, dp);
						*dp++ = *sp++;
					}
					*dp++ = ')'; *dp++ = ')';
				} else {
					struct tbl v;
					char *p;

					v.flag = DEFINED|ISSET|INTEGER;
					v.type = 10; /* not default */
					v.name[0] = '\0';
					v_evaluate(&v, substitute(sp, 0),
					    KSH_UNWIND_ERROR, true);
					sp = strnul(sp) + 1;
					for (p = str_val(&v); *p; ) {
						Xcheck(ds, dp);
						*dp++ = *p++;
					}
				}
				continue;
			case OSUBST: {	/* ${{#}var{:}[=+-?#%]word} */
			/* format is:
			 *	OSUBST [{x] plain-variable-part \0
			 *	    compiled-word-part CSUBST [}x]
			 * This is where all syntax checking gets done...
			 */
				const char *varname = ++sp; /* skip the { or x (}) */
				int stype;
				int slen = 0;

				sp = cstrchr(sp, '\0') + 1; /* skip variable */
				type = varsub(&x, varname, sp, &stype, &slen);
				if (type < 0) {
					char *beg, *end, *str;

 unwind_substsyn:
					sp = varname - 2; /* restore sp */
					end = (beg = wdcopy(sp, ATEMP)) +
					    (wdscan(sp, CSUBST) - sp);
					/* ({) the } or x is already skipped */
					if (end < wdscan(beg, EOS))
						*end = EOS;
					str = snptreef(NULL, 64, "%S", beg);
					afree(beg, ATEMP);
					errorf("%s: bad substitution", str);
				}
				if (f & DOBLANK)
					doblank++;
				tilde_ok = 0;
				if (type == XBASE) {	/* expand? */
					if (!st->next) {
						SubType *newst;

						newst = alloc(sizeof(SubType), ATEMP);
						newst->next = NULL;
						newst->prev = st;
						st->next = newst;
					}
					st = st->next;
					st->stype = stype;
					st->base = Xsavepos(ds, dp);
					st->f = f;
					st->var = x.var;
					st->quotew = st->quotep = quote;
					/* skip qualifier(s) */
					if (stype)
						sp += slen;
					switch (stype & 0x7f) {
					case '0': {
						char *beg, *mid, *end, *stg;
						mksh_ari_t from = 0, num = -1, flen, finc = 0;

						beg = wdcopy(sp, ATEMP);
						mid = beg + (wdscan(sp, ADELIM) - sp);
						stg = beg + (wdscan(sp, CSUBST) - sp);
						if (mid >= stg)
							goto unwind_substsyn;
						mid[-2] = EOS;
						if (mid[-1] == /*{*/'}') {
							sp += mid - beg - 1;
							end = NULL;
						} else {
							end = mid +
							    (wdscan(mid, ADELIM) - mid);
							if (end >= stg)
								goto unwind_substsyn;
							end[-2] = EOS;
							sp += end - beg - 1;
						}
						evaluate(substitute(stg = wdstrip(beg, false, false), 0),
						    &from, KSH_UNWIND_ERROR, true);
						afree(stg, ATEMP);
						if (end) {
							evaluate(substitute(stg = wdstrip(mid, false, false), 0),
							    &num, KSH_UNWIND_ERROR, true);
							afree(stg, ATEMP);
						}
						afree(beg, ATEMP);
						beg = str_val(st->var);
						flen = utflen(beg);
						if (from < 0) {
							if (-from < flen)
								finc = flen + from;
						} else
							finc = from < flen ? from : flen;
						if (UTFMODE)
							utfincptr(beg, &finc);
						beg += finc;
						flen = utflen(beg);
						if (num < 0 || num > flen)
							num = flen;
						if (UTFMODE)
							utfincptr(beg, &num);
						strndupx(x.str, beg, num, ATEMP);
						goto do_CSUBST;
					}
					case '/': {
						char *s, *p, *d, *sbeg, *end;
						char *pat, *rrep;
						char *tpat0, *tpat1, *tpat2;

						s = wdcopy(sp, ATEMP);
						p = s + (wdscan(sp, ADELIM) - sp);
						d = s + (wdscan(sp, CSUBST) - sp);
						if (p >= d)
							goto unwind_substsyn;
						p[-2] = EOS;
						if (p[-1] == /*{*/'}')
							d = NULL;
						else
							d[-2] = EOS;
						sp += (d ? d : p) - s - 1;
						tpat0 = wdstrip(s, true, true);
						pat = substitute(tpat0, 0);
						if (d) {
							d = wdstrip(p, true, false);
							rrep = substitute(d, 0);
							afree(d, ATEMP);
						} else
							rrep = null;
						afree(s, ATEMP);
						s = d = pat;
						while (*s)
							if (*s != '\\' ||
							    s[1] == '%' ||
							    s[1] == '#' ||
							    s[1] == '\0' ||
				/* XXX really? */	    s[1] == '\\' ||
							    s[1] == '/')
								*d++ = *s++;
							else
								s++;
						*d = '\0';
						afree(tpat0, ATEMP);

						/* reject empty pattern */
						if (!*pat || gmatchx("", pat, false))
							goto no_repl;

						/* prepare string on which to work */
						strdupx(s, str_val(st->var), ATEMP);
						sbeg = s;

						/* first see if we have any match at all */
						tpat0 = pat;
						if (*pat == '#') {
							/* anchor at the beginning */
							tpat1 = shf_smprintf("%s%c*", ++tpat0, MAGIC);
							tpat2 = tpat1;
						} else if (*pat == '%') {
							/* anchor at the end */
							tpat1 = shf_smprintf("%c*%s", MAGIC, ++tpat0);
							tpat2 = tpat0;
						} else {
							/* float */
							tpat1 = shf_smprintf("%c*%s%c*", MAGIC, pat, MAGIC);
							tpat2 = tpat1 + 2;
						}
 again_repl:
						/* this would not be necessary if gmatchx would return
						 * the start and end values of a match found, like re*
						 */
						if (!gmatchx(sbeg, tpat1, false))
							goto end_repl;
						end = strnul(s);
						/* now anchor the beginning of the match */
						if (*pat != '#')
							while (sbeg <= end) {
								if (gmatchx(sbeg, tpat2, false))
									break;
								else
									sbeg++;
							}
						/* now anchor the end of the match */
						p = end;
						if (*pat != '%')
							while (p >= sbeg) {
								bool gotmatch;

								c = *p; *p = '\0';
								gotmatch = gmatchx(sbeg, tpat0, false);
								*p = c;
								if (gotmatch)
									break;
								p--;
							}
						strndupx(end, s, sbeg - s, ATEMP);
						d = shf_smprintf("%s%s%s", end, rrep, p);
						afree(end, ATEMP);
						sbeg = d + (sbeg - s) + strlen(rrep);
						afree(s, ATEMP);
						s = d;
						if (stype & 0x80)
							goto again_repl;
 end_repl:
						afree(tpat1, ATEMP);
						x.str = s;
 no_repl:
						afree(pat, ATEMP);
						if (rrep != null)
							afree(rrep, ATEMP);
						goto do_CSUBST;
					}
					case '#':
					case '%':
						/* ! DOBLANK,DOBRACE_,DOTILDE */
						f = DOPAT | (f&DONTRUNCOMMAND) |
						    DOTEMP_;
						st->quotew = quote = 0;
						/* Prepend open pattern (so |
						 * in a trim will work as
						 * expected)
						 */
						*dp++ = MAGIC;
						*dp++ = (char)('@' | 0x80);
						break;
					case '=':
						/* Enabling tilde expansion
						 * after :s here is
						 * non-standard ksh, but is
						 * consistent with rules for
						 * other assignments. Not
						 * sure what POSIX thinks of
						 * this.
						 * Not doing tilde expansion
						 * for integer variables is a
						 * non-POSIX thing - makes
						 * sense though, since ~ is
						 * a arithmetic operator.
						 */
						if (!(x.var->flag & INTEGER))
							f |= DOASNTILDE|DOTILDE;
						f |= DOTEMP_;
						/* These will be done after the
						 * value has been assigned.
						 */
						f &= ~(DOBLANK|DOGLOB|DOBRACE_);
						tilde_ok = 1;
						break;
					case '?':
						f &= ~DOBLANK;
						f |= DOTEMP_;
						/* FALLTHROUGH */
					default:
						/* Enable tilde expansion */
						tilde_ok = 1;
						f |= DOTILDE;
					}
				} else
					/* skip word */
					sp += wdscan(sp, CSUBST) - sp;
				continue;
			}
			case CSUBST: /* only get here if expanding word */
 do_CSUBST:
				sp++; /* ({) skip the } or x */
				tilde_ok = 0;	/* in case of ${unset:-} */
				*dp = '\0';
				quote = st->quotep;
				f = st->f;
				if (f&DOBLANK)
					doblank--;
				switch (st->stype&0x7f) {
				case '#':
				case '%':
					/* Append end-pattern */
					*dp++ = MAGIC; *dp++ = ')'; *dp = '\0';
					dp = Xrestpos(ds, dp, st->base);
					/* Must use st->var since calling
					 * global would break things
					 * like x[i+=1].
					 */
					x.str = trimsub(str_val(st->var),
						dp, st->stype);
					if (x.str[0] != '\0' || st->quotep)
						type = XSUB;
					else
						type = XNULLSUB;
					if (f&DOBLANK)
						doblank++;
					st = st->prev;
					continue;
				case '=':
					/* Restore our position and substitute
					 * the value of st->var (may not be
					 * the assigned value in the presence
					 * of integer/right-adj/etc attributes).
					 */
					dp = Xrestpos(ds, dp, st->base);
					/* Must use st->var since calling
					 * global would cause with things
					 * like x[i+=1] to be evaluated twice.
					 */
					/* Note: not exported by FEXPORT
					 * in AT&T ksh.
					 */
					/* XXX POSIX says readonly is only
					 * fatal for special builtins (setstr
					 * does readonly check).
					 */
					len = strlen(dp) + 1;
					setstr(st->var,
					    debunk(alloc(len, ATEMP),
					    dp, len), KSH_UNWIND_ERROR);
					x.str = str_val(st->var);
					type = XSUB;
					if (f&DOBLANK)
						doblank++;
					st = st->prev;
					continue;
				case '?': {
					char *s = Xrestpos(ds, dp, st->base);

					errorf("%s: %s", st->var->name,
					    dp == s ?
					    "parameter null or not set" :
					    (debunk(s, s, strlen(s) + 1), s));
				}
				case '0':
				case '/':
					dp = Xrestpos(ds, dp, st->base);
					type = XSUB;
					if (f&DOBLANK)
						doblank++;
					st = st->prev;
					continue;
				}
				st = st->prev;
				type = XBASE;
				continue;

			case OPAT: /* open pattern: *(foo|bar) */
				/* Next char is the type of pattern */
				make_magic = 1;
				c = *sp++ + 0x80;
				break;

			case SPAT: /* pattern separator (|) */
				make_magic = 1;
				c = '|';
				break;

			case CPAT: /* close pattern */
				make_magic = 1;
				c = /*(*/ ')';
				break;
			}
			break;

		case XNULLSUB:
			/* Special case for "$@" (and "${foo[@]}") - no
			 * word is generated if $# is 0 (unless there is
			 * other stuff inside the quotes).
			 */
			type = XBASE;
			if (f&DOBLANK) {
				doblank--;
				/* not really correct: x=; "$x$@" should
				 * generate a null argument and
				 * set A; "${@:+}" shouldn't.
				 */
				if (dp == Xstring(ds, dp))
					word = IFS_WS;
			}
			continue;

		case XSUB:
		case XSUBMID:
			if ((c = *x.str++) == 0) {
				type = XBASE;
				if (f&DOBLANK)
					doblank--;
				continue;
			}
			break;

		case XARGSEP:
			type = XARG;
			quote = 1;
		case XARG:
			if ((c = *x.str++) == '\0') {
				/* force null words to be created so
				 * set -- '' 2 ''; foo "$@" will do
				 * the right thing
				 */
				if (quote && x.split)
					word = IFS_WORD;
				if ((x.str = *x.u.strv++) == NULL) {
					type = XBASE;
					if (f&DOBLANK)
						doblank--;
					continue;
				}
				c = ifs0;
				if (c == 0) {
					if (quote && !x.split)
						continue;
					c = ' ';
				}
				if (quote && x.split) {
					/* terminate word for "$@" */
					type = XARGSEP;
					quote = 0;
				}
			}
			break;

		case XCOM:
			if (newlines) {		/* Spit out saved NLs */
				c = '\n';
				--newlines;
			} else {
				while ((c = shf_getc(x.u.shf)) == 0 || c == '\n')
					if (c == '\n')
						/* Save newlines */
						newlines++;
				if (newlines && c != EOF) {
					shf_ungetc(c, x.u.shf);
					c = '\n';
					--newlines;
				}
			}
			if (c == EOF) {
				newlines = 0;
				shf_close(x.u.shf);
				if (x.split)
					subst_exstat = waitlast();
				type = XBASE;
				if (f&DOBLANK)
					doblank--;
				continue;
			}
			break;
		}

		/* check for end of word or IFS separation */
		if (c == 0 || (!quote && (f & DOBLANK) && doblank &&
		    !make_magic && ctype(c, C_IFS))) {
			/* How words are broken up:
			 *			|	value of c
			 *	word		|	ws	nws	0
			 *	-----------------------------------
			 *	IFS_WORD		w/WS	w/NWS	w
			 *	IFS_WS			-/WS	w/NWS	-
			 *	IFS_NWS			-/NWS	w/NWS	w
			 * (w means generate a word)
			 * Note that IFS_NWS/0 generates a word (AT&T ksh
			 * doesn't do this, but POSIX does).
			 */
			if (word == IFS_WORD ||
			    (!ctype(c, C_IFSWS) && c && word == IFS_NWS)) {
				char *p;

				*dp++ = '\0';
				p = Xclose(ds, dp);
				if (fdo & DOBRACE_)
					/* also does globbing */
					alt_expand(wp, p, p,
					    p + Xlength(ds, (dp - 1)),
					    fdo | (f & DOMARKDIRS));
				else if (fdo & DOGLOB)
					glob(p, wp, f & DOMARKDIRS);
				else if ((f & DOPAT) || !(fdo & DOMAGIC_))
					XPput(*wp, p);
				else
					XPput(*wp, debunk(p, p, strlen(p) + 1));
				fdo = 0;
				saw_eq = 0;
				tilde_ok = (f & (DOTILDE|DOASNTILDE)) ? 1 : 0;
				if (c != 0)
					Xinit(ds, dp, 128, ATEMP);
			}
			if (c == 0)
				return;
			if (word != IFS_NWS)
				word = ctype(c, C_IFSWS) ? IFS_WS : IFS_NWS;
		} else {
			if (type == XSUB) {
				if (word == IFS_NWS &&
				    Xlength(ds, dp) == 0) {
					char *p;

					*(p = alloc(1, ATEMP)) = '\0';
					XPput(*wp, p);
				}
				type = XSUBMID;
			}

			/* age tilde_ok info - ~ code tests second bit */
			tilde_ok <<= 1;
			/* mark any special second pass chars */
			if (!quote)
				switch (c) {
				case '[':
				case NOT:
				case '-':
				case ']':
					/* For character classes - doesn't hurt
					 * to have magic !,-,]s outside of
					 * [...] expressions.
					 */
					if (f & (DOPAT | DOGLOB)) {
						fdo |= DOMAGIC_;
						if (c == '[')
							fdo |= f & DOGLOB;
						*dp++ = MAGIC;
					}
					break;
				case '*':
				case '?':
					if (f & (DOPAT | DOGLOB)) {
						fdo |= DOMAGIC_ | (f & DOGLOB);
						*dp++ = MAGIC;
					}
					break;
				case OBRACE:
				case ',':
				case CBRACE:
					if ((f & DOBRACE_) && (c == OBRACE ||
					    (fdo & DOBRACE_))) {
						fdo |= DOBRACE_|DOMAGIC_;
						*dp++ = MAGIC;
					}
					break;
				case '=':
					/* Note first unquoted = for ~ */
					if (!(f & DOTEMP_) && !saw_eq &&
					    (Flag(FBRACEEXPAND) ||
					    (f & DOASNTILDE))) {
						saw_eq = 1;
						tilde_ok = 1;
					}
					break;
				case ':': /* : */
					/* Note unquoted : for ~ */
					if (!(f & DOTEMP_) && (f & DOASNTILDE))
						tilde_ok = 1;
					break;
				case '~':
					/* tilde_ok is reset whenever
					 * any of ' " $( $(( ${ } are seen.
					 * Note that tilde_ok must be preserved
					 * through the sequence ${A=a=}~
					 */
					if (type == XBASE &&
					    (f & (DOTILDE|DOASNTILDE)) &&
					    (tilde_ok & 2)) {
						const char *p;
						char *dp_x;

						dp_x = dp;
						p = maybe_expand_tilde(sp,
						    &ds, &dp_x,
						    f & DOASNTILDE);
						if (p) {
							if (dp != dp_x)
								word = IFS_WORD;
							dp = dp_x;
							sp = p;
							continue;
						}
					}
					break;
				}
			else
				quote &= ~2; /* undo temporary */

			if (make_magic) {
				make_magic = 0;
				fdo |= DOMAGIC_ | (f & DOGLOB);
				*dp++ = MAGIC;
			} else if (ISMAGIC(c)) {
				fdo |= DOMAGIC_;
				*dp++ = MAGIC;
			}
			*dp++ = c; /* save output char */
			word = IFS_WORD;
		}
	}
}

/*
 * Prepare to generate the string returned by ${} substitution.
 */
static int
varsub(Expand *xp, const char *sp, const char *word,
    int *stypep,	/* becomes qualifier type */
    int *slenp)		/* " " len (=, :=, etc.) valid iff *stypep != 0 */
{
	int c;
	int state;	/* next state: XBASE, XARG, XSUB, XNULLSUB */
	int stype;	/* substitution type */
	int slen;
	const char *p;
	struct tbl *vp;
	bool zero_ok = false;

	if ((stype = sp[0]) == '\0')	/* Bad variable name */
		return (-1);

	xp->var = NULL;

	/*-
	 * ${#var}, string length (-U: characters, +U: octets) or array size
	 * ${%var}, string width (-U: screen columns, +U: octets)
	 */
	c = sp[1];
	if (stype == '%' && c == '\0')
		return (-1);
	if ((stype == '#' || stype == '%') && c != '\0') {
		/* Can't have any modifiers for ${#...} or ${%...} */
		if (*word != CSUBST)
			return (-1);
		sp++;
		/* Check for size of array */
		if ((p = cstrchr(sp, '[')) && (p[1] == '*' || p[1] == '@') &&
		    p[2] == ']') {
			int n = 0;

			if (stype != '#')
				return (-1);
			vp = global(arrayname(sp));
			if (vp->flag & (ISSET|ARRAY))
				zero_ok = true;
			for (; vp; vp = vp->u.array)
				if (vp->flag & ISSET)
					n++;
			c = n;
		} else if (c == '*' || c == '@') {
			if (stype != '#')
				return (-1);
			c = e->loc->argc;
		} else {
			p = str_val(global(sp));
			zero_ok = p != null;
			if (stype == '#')
				c = utflen(p);
			else {
				/* partial utf_mbswidth reimplementation */
				const char *s = p;
				unsigned int wc;
				size_t len;
				int cw;

				c = 0;
				while (*s) {
					if (!UTFMODE || (len = utf_mbtowc(&wc,
					    s)) == (size_t)-1)
						/* not UTFMODE or not UTF-8 */
						wc = (unsigned char)(*s++);
					else
						/* UTFMODE and UTF-8 */
						s += len;
					/* wc == char or wchar at s++ */
					if ((cw = utf_wcwidth(wc)) == -1) {
						/* 646, 8859-1, 10646 C0/C1 */
						c = -1;
						break;
					}
					c += cw;
				}
			}
		}
		if (Flag(FNOUNSET) && c == 0 && !zero_ok)
			errorf("%s: parameter not set", sp);
		*stypep = 0; /* unqualified variable/string substitution */
		xp->str = shf_smprintf("%d", c);
		return (XSUB);
	}

	/* Check for qualifiers in word part */
	stype = 0;
	c = word[slen = 0] == CHAR ? word[1] : 0;
	if (c == ':') {
		slen += 2;
		stype = 0x80;
		c = word[slen + 0] == CHAR ? word[slen + 1] : 0;
	}
	if (!stype && c == '/') {
		slen += 2;
		stype = c;
		if (word[slen] == ADELIM) {
			slen += 2;
			stype |= 0x80;
		}
	} else if (stype == 0x80 && (c == ' ' || c == '0')) {
		stype |= '0';
	} else if (ctype(c, C_SUBOP1)) {
		slen += 2;
		stype |= c;
	} else if (ctype(c, C_SUBOP2)) { /* Note: ksh88 allows :%, :%%, etc */
		slen += 2;
		stype = c;
		if (word[slen + 0] == CHAR && c == word[slen + 1]) {
			stype |= 0x80;
			slen += 2;
		}
	} else if (stype)	/* : is not ok */
		return (-1);
	if (!stype && *word != CSUBST)
		return (-1);
	*stypep = stype;
	*slenp = slen;

	c = sp[0];
	if (c == '*' || c == '@') {
		switch (stype & 0x7f) {
		case '=':	/* can't assign to a vector */
		case '%':	/* can't trim a vector (yet) */
		case '#':
		case '0':
		case '/':
			return (-1);
		}
		if (e->loc->argc == 0) {
			xp->str = null;
			xp->var = global(sp);
			state = c == '@' ? XNULLSUB : XSUB;
		} else {
			xp->u.strv = (const char **)e->loc->argv + 1;
			xp->str = *xp->u.strv++;
			xp->split = c == '@'; /* $@ */
			state = XARG;
		}
		zero_ok = true;	/* POSIX 2009? */
	} else {
		if ((p = cstrchr(sp, '[')) && (p[1] == '*' || p[1] == '@') &&
		    p[2] == ']') {
			XPtrV wv;

			switch (stype & 0x7f) {
			case '=':	/* can't assign to a vector */
			case '%':	/* can't trim a vector (yet) */
			case '#':
			case '?':
			case '0':
			case '/':
				return (-1);
			}
			XPinit(wv, 32);
			if ((c = sp[0]) == '!')
				++sp;
			vp = global(arrayname(sp));
			for (; vp; vp = vp->u.array) {
				if (!(vp->flag&ISSET))
					continue;
				XPput(wv, c == '!' ? shf_smprintf("%lu",
				    arrayindex(vp)) :
				    str_val(vp));
			}
			if (XPsize(wv) == 0) {
				xp->str = null;
				state = p[1] == '@' ? XNULLSUB : XSUB;
				XPfree(wv);
			} else {
				XPput(wv, 0);
				xp->u.strv = (const char **)XPptrv(wv);
				xp->str = *xp->u.strv++;
				xp->split = p[1] == '@'; /* ${foo[@]} */
				state = XARG;
			}
		} else {
			/* Can't assign things like $! or $1 */
			if ((stype & 0x7f) == '=' &&
			    ctype(*sp, C_VAR1 | C_DIGIT))
				return (-1);
			if (*sp == '!' && sp[1]) {
				++sp;
				xp->var = global(sp);
				if (cstrchr(sp, '[')) {
					if (xp->var->flag & ISSET)
						xp->str = shf_smprintf("%lu",
						    arrayindex(xp->var));
					else
						xp->str = null;
				} else if (xp->var->flag & ISSET)
					xp->str = xp->var->name;
				else
					xp->str = "0";	/* ksh93 compat */
			} else {
				xp->var = global(sp);
				xp->str = str_val(xp->var);
			}
			state = XSUB;
		}
	}

	c = stype&0x7f;
	/* test the compiler's code generator */
	if (ctype(c, C_SUBOP2) || stype == (0x80 | '0') || c == '/' ||
	    (((stype&0x80) ? *xp->str=='\0' : xp->str==null) ? /* undef? */
	    c == '=' || c == '-' || c == '?' : c == '+'))
		state = XBASE;	/* expand word instead of variable value */
	if (Flag(FNOUNSET) && xp->str == null && !zero_ok &&
	    (ctype(c, C_SUBOP2) || (state != XBASE && c != '+')))
		errorf("%s: parameter not set", sp);
	return (state);
}

/*
 * Run the command in $(...) and read its output.
 */
static int
comsub(Expand *xp, const char *cp)
{
	Source *s, *sold;
	struct op *t;
	struct shf *shf;

	s = pushs(SSTRING, ATEMP);
	s->start = s->str = cp;
	sold = source;
	t = compile(s);
	afree(s, ATEMP);
	source = sold;

	if (t == NULL)
		return (XBASE);

	if (t != NULL && t->type == TCOM && /* $(<file) */
	    *t->args == NULL && *t->vars == NULL && t->ioact != NULL) {
		struct ioword *io = *t->ioact;
		char *name;

		if ((io->flag&IOTYPE) != IOREAD)
			errorf("funny $() command: %s",
			    snptreef(NULL, 32, "%R", io));
		shf = shf_open(name = evalstr(io->name, DOTILDE), O_RDONLY, 0,
			SHF_MAPHI|SHF_CLEXEC);
		if (shf == NULL)
			errorf("%s: cannot open $() input", name);
		xp->split = 0;	/* no waitlast() */
	} else {
		int ofd1, pv[2];
		openpipe(pv);
		shf = shf_fdopen(pv[0], SHF_RD, NULL);
		ofd1 = savefd(1);
		if (pv[1] != 1) {
			ksh_dup2(pv[1], 1, false);
			close(pv[1]);
		}
		execute(t, XFORK|XXCOM|XPIPEO, NULL);
		restfd(1, ofd1);
		startlast();
		xp->split = 1;	/* waitlast() */
	}

	xp->u.shf = shf;
	return (XCOM);
}

/*
 * perform #pattern and %pattern substitution in ${}
 */

static char *
trimsub(char *str, char *pat, int how)
{
	char *end = strnul(str);
	char *p, c;

	switch (how & 0xFF) {
	case '#':		/* shortest at beginning */
		for (p = str; p <= end; p += utf_ptradj(p)) {
			c = *p; *p = '\0';
			if (gmatchx(str, pat, false)) {
				*p = c;
				return (p);
			}
			*p = c;
		}
		break;
	case '#'|0x80:		/* longest match at beginning */
		for (p = end; p >= str; p--) {
			c = *p; *p = '\0';
			if (gmatchx(str, pat, false)) {
				*p = c;
				return (p);
			}
			*p = c;
		}
		break;
	case '%':		/* shortest match at end */
		p = end;
		while (p >= str) {
			if (gmatchx(p, pat, false))
				goto trimsub_match;
			if (UTFMODE) {
				char *op = p;
				while ((p-- > str) && ((*p & 0xC0) == 0x80))
					;
				if ((p < str) || (p + utf_ptradj(p) != op))
					p = op - 1;
			} else
				--p;
		}
		break;
	case '%'|0x80:		/* longest match at end */
		for (p = str; p <= end; p++)
			if (gmatchx(p, pat, false)) {
 trimsub_match:
				strndupx(end, str, p - str, ATEMP);
				return (end);
			}
		break;
	}

	return (str);		/* no match, return string */
}

/*
 * glob
 * Name derived from V6's /etc/glob, the program that expanded filenames.
 */

/* XXX cp not const 'cause slashes are temporarily replaced with NULs... */
static void
glob(char *cp, XPtrV *wp, int markdirs)
{
	int oldsize = XPsize(*wp);

	if (glob_str(cp, wp, markdirs) == 0)
		XPput(*wp, debunk(cp, cp, strlen(cp) + 1));
	else
		qsort(XPptrv(*wp) + oldsize, XPsize(*wp) - oldsize,
		    sizeof(void *), xstrcmp);
}

#define GF_NONE		0
#define GF_EXCHECK	BIT(0)		/* do existence check on file */
#define GF_GLOBBED	BIT(1)		/* some globbing has been done */
#define GF_MARKDIR	BIT(2)		/* add trailing / to directories */

/* Apply file globbing to cp and store the matching files in wp. Returns
 * the number of matches found.
 */
int
glob_str(char *cp, XPtrV *wp, int markdirs)
{
	int oldsize = XPsize(*wp);
	XString xs;
	char *xp;

	Xinit(xs, xp, 256, ATEMP);
	globit(&xs, &xp, cp, wp, markdirs ? GF_MARKDIR : GF_NONE);
	Xfree(xs, xp);

	return (XPsize(*wp) - oldsize);
}

static void
globit(XString *xs,	/* dest string */
    char **xpp,		/* ptr to dest end */
    char *sp,		/* source path */
    XPtrV *wp,		/* output list */
    int check)		/* GF_* flags */
{
	char *np;		/* next source component */
	char *xp = *xpp;
	char *se;
	char odirsep;

	/* This to allow long expansions to be interrupted */
	intrcheck();

	if (sp == NULL) {	/* end of source path */
		/* We only need to check if the file exists if a pattern
		 * is followed by a non-pattern (eg, foo*x/bar; no check
		 * is needed for foo* since the match must exist) or if
		 * any patterns were expanded and the markdirs option is set.
		 * Symlinks make things a bit tricky...
		 */
		if ((check & GF_EXCHECK) ||
		    ((check & GF_MARKDIR) && (check & GF_GLOBBED))) {
#define stat_check()	(stat_done ? stat_done : \
			    (stat_done = stat(Xstring(*xs, xp), &statb) < 0 \
				? -1 : 1))
			struct stat lstatb, statb;
			int stat_done = 0;	 /* -1: failed, 1 ok */

			if (lstat(Xstring(*xs, xp), &lstatb) < 0)
				return;
			/* special case for systems which strip trailing
			 * slashes from regular files (eg, /etc/passwd/).
			 * SunOS 4.1.3 does this...
			 */
			if ((check & GF_EXCHECK) && xp > Xstring(*xs, xp) &&
			    xp[-1] == '/' && !S_ISDIR(lstatb.st_mode) &&
			    (!S_ISLNK(lstatb.st_mode) ||
			    stat_check() < 0 || !S_ISDIR(statb.st_mode)))
				return;
			/* Possibly tack on a trailing / if there isn't already
			 * one and if the file is a directory or a symlink to a
			 * directory
			 */
			if (((check & GF_MARKDIR) && (check & GF_GLOBBED)) &&
			    xp > Xstring(*xs, xp) && xp[-1] != '/' &&
			    (S_ISDIR(lstatb.st_mode) ||
			    (S_ISLNK(lstatb.st_mode) && stat_check() > 0 &&
			    S_ISDIR(statb.st_mode)))) {
				*xp++ = '/';
				*xp = '\0';
			}
		}
		strndupx(np, Xstring(*xs, xp), Xlength(*xs, xp), ATEMP);
		XPput(*wp, np);
		return;
	}

	if (xp > Xstring(*xs, xp))
		*xp++ = '/';
	while (*sp == '/') {
		Xcheck(*xs, xp);
		*xp++ = *sp++;
	}
	np = strchr(sp, '/');
	if (np != NULL) {
		se = np;
		odirsep = *np;	/* don't assume '/', can be multiple kinds */
		*np++ = '\0';
	} else {
		odirsep = '\0'; /* keep gcc quiet */
		se = sp + strlen(sp);
	}


	/* Check if sp needs globbing - done to avoid pattern checks for strings
	 * containing MAGIC characters, open [s without the matching close ],
	 * etc. (otherwise opendir() will be called which may fail because the
	 * directory isn't readable - if no globbing is needed, only execute
	 * permission should be required (as per POSIX)).
	 */
	if (!has_globbing(sp, se)) {
		XcheckN(*xs, xp, se - sp + 1);
		debunk(xp, sp, Xnleft(*xs, xp));
		xp += strlen(xp);
		*xpp = xp;
		globit(xs, xpp, np, wp, check);
	} else {
		DIR *dirp;
		struct dirent *d;
		char *name;
		int len;
		int prefix_len;

		/* xp = *xpp;	copy_non_glob() may have re-alloc'd xs */
		*xp = '\0';
		prefix_len = Xlength(*xs, xp);
		dirp = opendir(prefix_len ? Xstring(*xs, xp) : ".");
		if (dirp == NULL)
			goto Nodir;
		while ((d = readdir(dirp)) != NULL) {
			name = d->d_name;
			if (name[0] == '.' &&
			    (name[1] == 0 || (name[1] == '.' && name[2] == 0)))
				continue; /* always ignore . and .. */
			if ((*name == '.' && *sp != '.') ||
			    !gmatchx(name, sp, true))
				continue;

			len = strlen(d->d_name) + 1;
			XcheckN(*xs, xp, len);
			memcpy(xp, name, len);
			*xpp = xp + len - 1;
			globit(xs, xpp, np, wp,
				(check & GF_MARKDIR) | GF_GLOBBED
				| (np ? GF_EXCHECK : GF_NONE));
			xp = Xstring(*xs, xp) + prefix_len;
		}
		closedir(dirp);
 Nodir:
		;
	}

	if (np != NULL)
		*--np = odirsep;
}

/* remove MAGIC from string */
char *
debunk(char *dp, const char *sp, size_t dlen)
{
	char *d;
	const char *s;

	if ((s = cstrchr(sp, MAGIC))) {
		if (s - sp >= (ssize_t)dlen)
			return (dp);
		memmove(dp, sp, s - sp);
		for (d = dp + (s - sp); *s && (d - dp < (ssize_t)dlen); s++)
			if (!ISMAGIC(*s) || !(*++s & 0x80) ||
			    !vstrchr("*+?@! ", *s & 0x7f))
				*d++ = *s;
			else {
				/* extended pattern operators: *+?@! */
				if ((*s & 0x7f) != ' ')
					*d++ = *s & 0x7f;
				if (d - dp < (ssize_t)dlen)
					*d++ = '(';
			}
		*d = '\0';
	} else if (dp != sp)
		strlcpy(dp, sp, dlen);
	return (dp);
}

/* Check if p is an unquoted name, possibly followed by a / or :. If so
 * puts the expanded version in *dcp,dp and returns a pointer in p just
 * past the name, otherwise returns 0.
 */
static const char *
maybe_expand_tilde(const char *p, XString *dsp, char **dpp, int isassign)
{
	XString ts;
	char *dp = *dpp;
	char *tp;
	const char *r;

	Xinit(ts, tp, 16, ATEMP);
	/* : only for DOASNTILDE form */
	while (p[0] == CHAR && p[1] != '/' && (!isassign || p[1] != ':'))
	{
		Xcheck(ts, tp);
		*tp++ = p[1];
		p += 2;
	}
	*tp = '\0';
	r = (p[0] == EOS || p[0] == CHAR || p[0] == CSUBST) ?
	    tilde(Xstring(ts, tp)) : NULL;
	Xfree(ts, tp);
	if (r) {
		while (*r) {
			Xcheck(*dsp, dp);
			if (ISMAGIC(*r))
				*dp++ = MAGIC;
			*dp++ = *r++;
		}
		*dpp = dp;
		r = p;
	}
	return (r);
}

/*
 * tilde expansion
 *
 * based on a version by Arnold Robbins
 */

static char *
tilde(char *cp)
{
	char *dp = null;

	if (cp[0] == '\0')
		dp = str_val(global("HOME"));
	else if (cp[0] == '+' && cp[1] == '\0')
		dp = str_val(global("PWD"));
	else if (cp[0] == '-' && cp[1] == '\0')
		dp = str_val(global("OLDPWD"));
#ifndef MKSH_NOPWNAM
	else
		dp = homedir(cp);
#endif
	/* If HOME, PWD or OLDPWD are not set, don't expand ~ */
	return (dp == null ? NULL : dp);
}

#ifndef MKSH_NOPWNAM
/*
 * map userid to user's home directory.
 * note that 4.3's getpw adds more than 6K to the shell,
 * and the YP version probably adds much more.
 * we might consider our own version of getpwnam() to keep the size down.
 */
static char *
homedir(char *name)
{
	struct tbl *ap;

	ap = ktenter(&homedirs, name, hash(name));
	if (!(ap->flag & ISSET)) {
		struct passwd *pw;

		pw = getpwnam(name);
		if (pw == NULL)
			return (NULL);
		strdupx(ap->val.s, pw->pw_dir, APERM);
		ap->flag |= DEFINED|ISSET|ALLOC;
	}
	return (ap->val.s);
}
#endif

static void
alt_expand(XPtrV *wp, char *start, char *exp_start, char *end, int fdo)
{
	int count = 0;
	char *brace_start, *brace_end, *comma = NULL;
	char *field_start;
	char *p;

	/* search for open brace */
	for (p = exp_start; (p = strchr(p, MAGIC)) && p[1] != OBRACE; p += 2)
		;
	brace_start = p;

	/* find matching close brace, if any */
	if (p) {
		comma = NULL;
		count = 1;
		for (p += 2; *p && count; p++) {
			if (ISMAGIC(*p)) {
				if (*++p == OBRACE)
					count++;
				else if (*p == CBRACE)
					--count;
				else if (*p == ',' && count == 1)
					comma = p;
			}
		}
	}
	/* no valid expansions... */
	if (!p || count != 0) {
		/* Note that given a{{b,c} we do not expand anything (this is
		 * what AT&T ksh does. This may be changed to do the {b,c}
		 * expansion. }
		 */
		if (fdo & DOGLOB)
			glob(start, wp, fdo & DOMARKDIRS);
		else
			XPput(*wp, debunk(start, start, end - start));
		return;
	}
	brace_end = p;
	if (!comma) {
		alt_expand(wp, start, brace_end, end, fdo);
		return;
	}

	/* expand expression */
	field_start = brace_start + 2;
	count = 1;
	for (p = brace_start + 2; p != brace_end; p++) {
		if (ISMAGIC(*p)) {
			if (*++p == OBRACE)
				count++;
			else if ((*p == CBRACE && --count == 0) ||
			    (*p == ',' && count == 1)) {
				char *news;
				int l1, l2, l3;

				l1 = brace_start - start;
				l2 = (p - 1) - field_start;
				l3 = end - brace_end;
				news = alloc(l1 + l2 + l3 + 1, ATEMP);
				memcpy(news, start, l1);
				memcpy(news + l1, field_start, l2);
				memcpy(news + l1 + l2, brace_end, l3);
				news[l1 + l2 + l3] = '\0';
				alt_expand(wp, news, news + l1,
				    news + l1 + l2 + l3, fdo);
				field_start = p + 1;
			}
		}
	}
	return;
}
