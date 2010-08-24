/*	$OpenBSD: misc.c,v 1.37 2009/04/19 20:34:05 sthen Exp $	*/
/*	$OpenBSD: path.c,v 1.12 2005/03/30 17:16:37 deraadt Exp $	*/

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
#if !HAVE_GETRUSAGE
#include <sys/times.h>
#endif
#if HAVE_GRP_H
#include <grp.h>
#endif

__RCSID("$MirOS: src/bin/mksh/misc.c,v 1.141 2010/07/17 22:09:36 tg Exp $");

unsigned char chtypes[UCHAR_MAX + 1];	/* type bits for unsigned char */

#if !HAVE_SETRESUGID
uid_t kshuid;
gid_t kshgid, kshegid;
#endif

static int do_gmatch(const unsigned char *, const unsigned char *,
    const unsigned char *, const unsigned char *);
static const unsigned char *cclass(const unsigned char *, int);
#ifdef TIOCSCTTY
static void chvt(const char *);
#endif

/*
 * Fast character classes
 */
void
setctypes(const char *s, int t)
{
	unsigned int i;

	if (t & C_IFS) {
		for (i = 0; i < UCHAR_MAX + 1; i++)
			chtypes[i] &= ~C_IFS;
		chtypes[0] |= C_IFS; /* include \0 in C_IFS */
	}
	while (*s != 0)
		chtypes[(unsigned char)*s++] |= t;
}

void
initctypes(void)
{
	int c;

	for (c = 'a'; c <= 'z'; c++)
		chtypes[c] |= C_ALPHA;
	for (c = 'A'; c <= 'Z'; c++)
		chtypes[c] |= C_ALPHA;
	chtypes['_'] |= C_ALPHA;
	setctypes("0123456789", C_DIGIT);
	setctypes(" \t\n|&;<>()", C_LEX1); /* \0 added automatically */
	setctypes("*@#!$-?", C_VAR1);
	setctypes(" \t\n", C_IFSWS);
	setctypes("=-+?", C_SUBOP1);
	setctypes("\t\n \"#$&'()*;<=>?[\\]`|", C_QUOTE);
}

/* called from XcheckN() to grow buffer */
char *
Xcheck_grow_(XString *xsp, const char *xp, unsigned int more)
{
	const char *old_beg = xsp->beg;

	xsp->len += more > xsp->len ? more : xsp->len;
	xsp->beg = aresize(xsp->beg, xsp->len + 8, xsp->areap);
	xsp->end = xsp->beg + xsp->len;
	return (xsp->beg + (xp - old_beg));
}

#define SHFLAGS_DEFNS
#include "sh_flags.h"

const struct shoption options[] = {
#define SHFLAGS_ITEMS
#include "sh_flags.h"
};

/*
 * translate -o option into F* constant (also used for test -o option)
 */
size_t
option(const char *n)
{
	size_t i;

	if ((n[0] == '-' || n[0] == '+') && n[1] && !n[2]) {
		for (i = 0; i < NELEM(options); i++)
			if (options[i].c == n[1])
				return (i);
	} else for (i = 0; i < NELEM(options); i++)
		if (options[i].name && strcmp(options[i].name, n) == 0)
			return (i);

	return ((size_t)-1);
}

struct options_info {
	int opt_width;
	int opts[NELEM(options)];
};

static char *options_fmt_entry(char *, int, int, const void *);
static void printoptions(bool);

/* format a single select menu item */
static char *
options_fmt_entry(char *buf, int buflen, int i, const void *arg)
{
	const struct options_info *oi = (const struct options_info *)arg;

	shf_snprintf(buf, buflen, "%-*s %s",
	    oi->opt_width, options[oi->opts[i]].name,
	    Flag(oi->opts[i]) ? "on" : "off");
	return (buf);
}

static void
printoptions(bool verbose)
{
	int i = 0;

	if (verbose) {
		int n = 0, len, octs = 0;
		struct options_info oi;

		/* verbose version */
		shf_puts("Current option settings\n", shl_stdout);

		oi.opt_width = 0;
		while (i < (int)NELEM(options)) {
			if (options[i].name) {
				oi.opts[n++] = i;
				len = strlen(options[i].name);
				if (len > octs)
					octs = len;
				len = utf_mbswidth(options[i].name);
				if (len > oi.opt_width)
					oi.opt_width = len;
			}
			++i;
		}
		print_columns(shl_stdout, n, options_fmt_entry, &oi,
		    octs + 4, oi.opt_width + 4, true);
	} else {
		/* short version á la AT&T ksh93 */
		shf_puts("set", shl_stdout);
		while (i < (int)NELEM(options)) {
			if (Flag(i) && options[i].name)
				shprintf(" -o %s", options[i].name);
			++i;
		}
		shf_putc('\n', shl_stdout);
	}
}

char *
getoptions(void)
{
	unsigned int i;
	char m[(int) FNFLAGS + 1];
	char *cp = m;

	for (i = 0; i < NELEM(options); i++)
		if (options[i].c && Flag(i))
			*cp++ = options[i].c;
	strndupx(cp, m, cp - m, ATEMP);
	return (cp);
}

/* change a Flag(*) value; takes care of special actions */
void
change_flag(enum sh_flag f, int what, unsigned int newval)
{
	unsigned char oldval;

	oldval = Flag(f);
	Flag(f) = newval ? 1 : 0;	/* needed for tristates */
#ifndef MKSH_UNEMPLOYED
	if (f == FMONITOR) {
		if (what != OF_CMDLINE && newval != oldval)
			j_change();
	} else
#endif
	  if ((
#if !MKSH_S_NOVI
	    f == FVI ||
#endif
	    f == FEMACS || f == FGMACS) && newval) {
#if !MKSH_S_NOVI
		Flag(FVI) =
#endif
		    Flag(FEMACS) = Flag(FGMACS) = 0;
		Flag(f) = (unsigned char)newval;
	} else if (f == FPRIVILEGED && oldval && !newval) {
		/* Turning off -p? */
#if HAVE_SETRESUGID
		gid_t kshegid = getgid();

		setresgid(kshegid, kshegid, kshegid);
#if HAVE_SETGROUPS
		setgroups(1, &kshegid);
#endif
		setresuid(ksheuid, ksheuid, ksheuid);
#else
		seteuid(ksheuid = kshuid = getuid());
		setuid(ksheuid);
		setegid(kshegid = kshgid = getgid());
		setgid(kshegid);
#endif
	} else if ((f == FPOSIX || f == FSH) && newval) {
		Flag(FPOSIX) = Flag(FSH) = Flag(FBRACEEXPAND) = 0;
		Flag(f) = (unsigned char)newval;
	}
	/* Changing interactive flag? */
	if (f == FTALKING) {
		if ((what == OF_CMDLINE || what == OF_SET) && procpid == kshpid)
			Flag(FTALKING_I) = (unsigned char)newval;
	}
}

/* Parse command line & set command arguments. Returns the index of
 * non-option arguments, -1 if there is an error.
 */
int
parse_args(const char **argv,
    int what,			/* OF_CMDLINE or OF_SET */
    bool *setargsp)
{
	static char cmd_opts[NELEM(options) + 5]; /* o:T:\0 */
	static char set_opts[NELEM(options) + 6]; /* A:o;s\0 */
	char set, *opts;
	const char *array = NULL;
	Getopt go;
	size_t i;
	int optc, sortargs = 0, arrayset = 0;

	/* First call? Build option strings... */
	if (cmd_opts[0] == '\0') {
		char *p = cmd_opts, *q = set_opts;

		/* see cmd_opts[] declaration */
		*p++ = 'o';
		*p++ = ':';
#if !defined(MKSH_SMALL) || defined(TIOCSCTTY)
		*p++ = 'T';
		*p++ = ':';
#endif
		/* see set_opts[] declaration */
		*q++ = 'A';
		*q++ = ':';
		*q++ = 'o';
		*q++ = ';';
		*q++ = 's';

		for (i = 0; i < NELEM(options); i++) {
			if (options[i].c) {
				if (options[i].flags & OF_CMDLINE)
					*p++ = options[i].c;
				if (options[i].flags & OF_SET)
					*q++ = options[i].c;
			}
		}
		*p = '\0';
		*q = '\0';
	}

	if (what == OF_CMDLINE) {
		const char *p = argv[0], *q;
		/* Set FLOGIN before parsing options so user can clear
		 * flag using +l.
		 */
		if (*p != '-')
			for (q = p; *q; )
				if (*q++ == '/')
					p = q;
		Flag(FLOGIN) = (*p == '-');
		opts = cmd_opts;
	} else if (what == OF_FIRSTTIME) {
		opts = cmd_opts;
	} else
		opts = set_opts;
	ksh_getopt_reset(&go, GF_ERROR|GF_PLUSOPT);
	while ((optc = ksh_getopt(argv, &go, opts)) != -1) {
		set = (go.info & GI_PLUS) ? 0 : 1;
		switch (optc) {
		case 'A':
			if (what == OF_FIRSTTIME)
				break;
			arrayset = set ? 1 : -1;
			array = go.optarg;
			break;

		case 'o':
			if (what == OF_FIRSTTIME)
				break;
			if (go.optarg == NULL) {
				/* lone -o: print options
				 *
				 * Note that on the command line, -o requires
				 * an option (ie, can't get here if what is
				 * OF_CMDLINE).
				 */
				printoptions(set);
				break;
			}
			i = option(go.optarg);
			if ((enum sh_flag)i == FARC4RANDOM) {
				warningf(true, "Do not use set ±o arc4random,"
				    " it will be removed in the next version"
				    " of mksh!");
				return (0);
			}
			if ((i != (size_t)-1) && set == Flag(i))
				/* Don't check the context if the flag
				 * isn't changing - makes "set -o interactive"
				 * work if you're already interactive. Needed
				 * if the output of "set +o" is to be used.
				 */
				;
			else if ((i != (size_t)-1) && (options[i].flags & what))
				change_flag((enum sh_flag)i, what, set);
			else {
				bi_errorf("%s: bad option", go.optarg);
				return (-1);
			}
			break;

#if !defined(MKSH_SMALL) || defined(TIOCSCTTY)
		case 'T':
			if (what != OF_FIRSTTIME)
				break;
#ifndef TIOCSCTTY
			errorf("no TIOCSCTTY ioctl");
#else
			change_flag(FTALKING, OF_CMDLINE, 1);
			chvt(go.optarg);
			break;
#endif
#endif

		case '?':
			return (-1);

		default:
			if (what == OF_FIRSTTIME)
				break;
			/* -s: sort positional params (AT&T ksh stupidity) */
			if (what == OF_SET && optc == 's') {
				sortargs = 1;
				break;
			}
			for (i = 0; i < NELEM(options); i++)
				if (optc == options[i].c &&
				    (what & options[i].flags)) {
					change_flag((enum sh_flag)i, what, set);
					break;
				}
			if (i == NELEM(options))
				internal_errorf("parse_args: '%c'", optc);
		}
	}
	if (!(go.info & GI_MINUSMINUS) && argv[go.optind] &&
	    (argv[go.optind][0] == '-' || argv[go.optind][0] == '+') &&
	    argv[go.optind][1] == '\0') {
		/* lone - clears -v and -x flags */
		if (argv[go.optind][0] == '-')
			Flag(FVERBOSE) = Flag(FXTRACE) = 0;
		/* set skips lone - or + option */
		go.optind++;
	}
	if (setargsp)
		/* -- means set $#/$* even if there are no arguments */
		*setargsp = !arrayset && ((go.info & GI_MINUSMINUS) ||
		    argv[go.optind]);

	if (arrayset && (!*array || *skip_varname(array, false))) {
		bi_errorf("%s: is not an identifier", array);
		return (-1);
	}
	if (sortargs) {
		for (i = go.optind; argv[i]; i++)
			;
		qsort(&argv[go.optind], i - go.optind, sizeof(void *),
		    xstrcmp);
	}
	if (arrayset)
		go.optind += set_array(array, arrayset > 0 ? true : false,
		    argv + go.optind);

	return (go.optind);
}

/* parse a decimal number: returns 0 if string isn't a number, 1 otherwise */
int
getn(const char *s, int *ai)
{
	int i, c, rv = 0;
	bool neg = false;

	do {
		c = *s++;
	} while (ksh_isspace(c));
	if (c == '-') {
		neg = true;
		c = *s++;
	} else if (c == '+')
		c = *s++;
	*ai = i = 0;
	do {
		if (!ksh_isdigit(c))
			goto getn_out;
		i *= 10;
		if (i < *ai)
			/* overflow */
			goto getn_out;
		i += c - '0';
		*ai = i;
	} while ((c = *s++));
	rv = 1;

 getn_out:
	if (neg)
		*ai = -*ai;
	return (rv);
}

/* getn() that prints error */
int
bi_getn(const char *as, int *ai)
{
	int rv;

	if (!(rv = getn(as, ai)))
		bi_errorf("%s: bad number", as);
	return (rv);
}

/* -------- gmatch.c -------- */

/*
 * int gmatch(string, pattern)
 * char *string, *pattern;
 *
 * Match a pattern as in sh(1).
 * pattern character are prefixed with MAGIC by expand.
 */

int
gmatchx(const char *s, const char *p, bool isfile)
{
	const char *se, *pe;

	if (s == NULL || p == NULL)
		return (0);

	se = s + strlen(s);
	pe = p + strlen(p);
	/* isfile is false iff no syntax check has been done on
	 * the pattern. If check fails, just to a strcmp().
	 */
	if (!isfile && !has_globbing(p, pe)) {
		size_t len = pe - p + 1;
		char tbuf[64];
		char *t = len <= sizeof(tbuf) ? tbuf : alloc(len, ATEMP);
		debunk(t, p, len);
		return (!strcmp(t, s));
	}
	return (do_gmatch((const unsigned char *) s, (const unsigned char *) se,
	    (const unsigned char *) p, (const unsigned char *) pe));
}

/* Returns if p is a syntacticly correct globbing pattern, false
 * if it contains no pattern characters or if there is a syntax error.
 * Syntax errors are:
 *	- [ with no closing ]
 *	- imbalanced $(...) expression
 *	- [...] and *(...) not nested (eg, [a$(b|]c), *(a[b|c]d))
 */
/*XXX
- if no magic,
	if dest given, copy to dst
	return ?
- if magic && (no globbing || syntax error)
	debunk to dst
	return ?
- return ?
*/
int
has_globbing(const char *xp, const char *xpe)
{
	const unsigned char *p = (const unsigned char *) xp;
	const unsigned char *pe = (const unsigned char *) xpe;
	int c;
	int nest = 0, bnest = 0;
	int saw_glob = 0;
	int in_bracket = 0; /* inside [...] */

	for (; p < pe; p++) {
		if (!ISMAGIC(*p))
			continue;
		if ((c = *++p) == '*' || c == '?')
			saw_glob = 1;
		else if (c == '[') {
			if (!in_bracket) {
				saw_glob = 1;
				in_bracket = 1;
				if (ISMAGIC(p[1]) && p[2] == NOT)
					p += 2;
				if (ISMAGIC(p[1]) && p[2] == ']')
					p += 2;
			}
			/* XXX Do we need to check ranges here? POSIX Q */
		} else if (c == ']') {
			if (in_bracket) {
				if (bnest)		/* [a*(b]) */
					return (0);
				in_bracket = 0;
			}
		} else if ((c & 0x80) && vstrchr("*+?@! ", c & 0x7f)) {
			saw_glob = 1;
			if (in_bracket)
				bnest++;
			else
				nest++;
		} else if (c == '|') {
			if (in_bracket && !bnest)	/* *(a[foo|bar]) */
				return (0);
		} else if (c == /*(*/ ')') {
			if (in_bracket) {
				if (!bnest--)		/* *(a[b)c] */
					return (0);
			} else if (nest)
				nest--;
		}
		/*
		 * else must be a MAGIC-MAGIC, or MAGIC-!,
		 * MAGIC--, MAGIC-], MAGIC-{, MAGIC-, MAGIC-}
		 */
	}
	return (saw_glob && !in_bracket && !nest);
}

/* Function must return either 0 or 1 (assumed by code for 0x80|'!') */
static int
do_gmatch(const unsigned char *s, const unsigned char *se,
    const unsigned char *p, const unsigned char *pe)
{
	int sc, pc;
	const unsigned char *prest, *psub, *pnext;
	const unsigned char *srest;

	if (s == NULL || p == NULL)
		return (0);
	while (p < pe) {
		pc = *p++;
		sc = s < se ? *s : '\0';
		s++;
		if (!ISMAGIC(pc)) {
			if (sc != pc)
				return (0);
			continue;
		}
		switch (*p++) {
		case '[':
			if (sc == 0 || (p = cclass(p, sc)) == NULL)
				return (0);
			break;

		case '?':
			if (sc == 0)
				return (0);
			if (UTFMODE) {
				--s;
				s += utf_ptradj((const void *)s);
			}
			break;

		case '*':
			if (p == pe)
				return (1);
			s--;
			do {
				if (do_gmatch(s, se, p, pe))
					return (1);
			} while (s++ < se);
			return (0);

		/**
		 * [*+?@!](pattern|pattern|..)
		 * This is also needed for ${..%..}, etc.
		 */
		case 0x80|'+': /* matches one or more times */
		case 0x80|'*': /* matches zero or more times */
			if (!(prest = pat_scan(p, pe, 0)))
				return (0);
			s--;
			/* take care of zero matches */
			if (p[-1] == (0x80 | '*') &&
			    do_gmatch(s, se, prest, pe))
				return (1);
			for (psub = p; ; psub = pnext) {
				pnext = pat_scan(psub, pe, 1);
				for (srest = s; srest <= se; srest++) {
					if (do_gmatch(s, srest, psub, pnext - 2) &&
					    (do_gmatch(srest, se, prest, pe) ||
					    (s != srest && do_gmatch(srest,
					    se, p - 2, pe))))
						return (1);
				}
				if (pnext == prest)
					break;
			}
			return (0);

		case 0x80|'?': /* matches zero or once */
		case 0x80|'@': /* matches one of the patterns */
		case 0x80|' ': /* simile for @ */
			if (!(prest = pat_scan(p, pe, 0)))
				return (0);
			s--;
			/* Take care of zero matches */
			if (p[-1] == (0x80 | '?') &&
			    do_gmatch(s, se, prest, pe))
				return (1);
			for (psub = p; ; psub = pnext) {
				pnext = pat_scan(psub, pe, 1);
				srest = prest == pe ? se : s;
				for (; srest <= se; srest++) {
					if (do_gmatch(s, srest, psub, pnext - 2) &&
					    do_gmatch(srest, se, prest, pe))
						return (1);
				}
				if (pnext == prest)
					break;
			}
			return (0);

		case 0x80|'!': /* matches none of the patterns */
			if (!(prest = pat_scan(p, pe, 0)))
				return (0);
			s--;
			for (srest = s; srest <= se; srest++) {
				int matched = 0;

				for (psub = p; ; psub = pnext) {
					pnext = pat_scan(psub, pe, 1);
					if (do_gmatch(s, srest, psub,
					    pnext - 2)) {
						matched = 1;
						break;
					}
					if (pnext == prest)
						break;
				}
				if (!matched &&
				    do_gmatch(srest, se, prest, pe))
					return (1);
			}
			return (0);

		default:
			if (sc != p[-1])
				return (0);
			break;
		}
	}
	return (s == se);
}

static const unsigned char *
cclass(const unsigned char *p, int sub)
{
	int c, d, notp, found = 0;
	const unsigned char *orig_p = p;

	if ((notp = (ISMAGIC(*p) && *++p == NOT)))
		p++;
	do {
		c = *p++;
		if (ISMAGIC(c)) {
			c = *p++;
			if ((c & 0x80) && !ISMAGIC(c)) {
				c &= 0x7f;/* extended pattern matching: *+?@! */
				/* XXX the ( char isn't handled as part of [] */
				if (c == ' ') /* simile for @: plain (..) */
					c = '(' /*)*/;
			}
		}
		if (c == '\0')
			/* No closing ] - act as if the opening [ was quoted */
			return (sub == '[' ? orig_p : NULL);
		if (ISMAGIC(p[0]) && p[1] == '-' &&
		    (!ISMAGIC(p[2]) || p[3] != ']')) {
			p += 2; /* MAGIC- */
			d = *p++;
			if (ISMAGIC(d)) {
				d = *p++;
				if ((d & 0x80) && !ISMAGIC(d))
					d &= 0x7f;
			}
			/* POSIX says this is an invalid expression */
			if (c > d)
				return (NULL);
		} else
			d = c;
		if (c == sub || (c <= sub && sub <= d))
			found = 1;
	} while (!(ISMAGIC(p[0]) && p[1] == ']'));

	return ((found != notp) ? p+2 : NULL);
}

/* Look for next ) or | (if match_sep) in *(foo|bar) pattern */
const unsigned char *
pat_scan(const unsigned char *p, const unsigned char *pe, int match_sep)
{
	int nest = 0;

	for (; p < pe; p++) {
		if (!ISMAGIC(*p))
			continue;
		if ((*++p == /*(*/ ')' && nest-- == 0) ||
		    (*p == '|' && match_sep && nest == 0))
			return (p + 1);
		if ((*p & 0x80) && vstrchr("*+?@! ", *p & 0x7f))
			nest++;
	}
	return (NULL);
}

int
xstrcmp(const void *p1, const void *p2)
{
	return (strcmp(*(const char * const *)p1, *(const char * const *)p2));
}

/* Initialise a Getopt structure */
void
ksh_getopt_reset(Getopt *go, int flags)
{
	go->optind = 1;
	go->optarg = NULL;
	go->p = 0;
	go->flags = flags;
	go->info = 0;
	go->buf[1] = '\0';
}


/* getopt() used for shell built-in commands, the getopts command, and
 * command line options.
 * A leading ':' in options means don't print errors, instead return '?'
 * or ':' and set go->optarg to the offending option character.
 * If GF_ERROR is set (and option doesn't start with :), errors result in
 * a call to bi_errorf().
 *
 * Non-standard features:
 *	- ';' is like ':' in options, except the argument is optional
 *	  (if it isn't present, optarg is set to 0).
 *	  Used for 'set -o'.
 *	- ',' is like ':' in options, except the argument always immediately
 *	  follows the option character (optarg is set to the null string if
 *	  the option is missing).
 *	  Used for 'read -u2', 'print -u2' and fc -40.
 *	- '#' is like ':' in options, expect that the argument is optional
 *	  and must start with a digit. If the argument doesn't start with a
 *	  digit, it is assumed to be missing and normal option processing
 *	  continues (optarg is set to 0 if the option is missing).
 *	  Used for 'typeset -LZ4'.
 *	- accepts +c as well as -c IF the GF_PLUSOPT flag is present. If an
 *	  option starting with + is accepted, the GI_PLUS flag will be set
 *	  in go->info.
 */
int
ksh_getopt(const char **argv, Getopt *go, const char *optionsp)
{
	char c;
	const char *o;

	if (go->p == 0 || (c = argv[go->optind - 1][go->p]) == '\0') {
		const char *arg = argv[go->optind], flag = arg ? *arg : '\0';

		go->p = 1;
		if (flag == '-' && arg[1] == '-' && arg[2] == '\0') {
			go->optind++;
			go->p = 0;
			go->info |= GI_MINUSMINUS;
			return (-1);
		}
		if (arg == NULL ||
		    ((flag != '-' ) && /* neither a - nor a + (if + allowed) */
		    (!(go->flags & GF_PLUSOPT) || flag != '+')) ||
		    (c = arg[1]) == '\0') {
			go->p = 0;
			return (-1);
		}
		go->optind++;
		go->info &= ~(GI_MINUS|GI_PLUS);
		go->info |= flag == '-' ? GI_MINUS : GI_PLUS;
	}
	go->p++;
	if (c == '?' || c == ':' || c == ';' || c == ',' || c == '#' ||
	    !(o = cstrchr(optionsp, c))) {
		if (optionsp[0] == ':') {
			go->buf[0] = c;
			go->optarg = go->buf;
		} else {
			warningf(true, "%s%s-%c: unknown option",
			    (go->flags & GF_NONAME) ? "" : argv[0],
			    (go->flags & GF_NONAME) ? "" : ": ", c);
			if (go->flags & GF_ERROR)
				bi_errorfz();
		}
		return ('?');
	}
	/* : means argument must be present, may be part of option argument
	 *   or the next argument
	 * ; same as : but argument may be missing
	 * , means argument is part of option argument, and may be null.
	 */
	if (*++o == ':' || *o == ';') {
		if (argv[go->optind - 1][go->p])
			go->optarg = argv[go->optind - 1] + go->p;
		else if (argv[go->optind])
			go->optarg = argv[go->optind++];
		else if (*o == ';')
			go->optarg = NULL;
		else {
			if (optionsp[0] == ':') {
				go->buf[0] = c;
				go->optarg = go->buf;
				return (':');
			}
			warningf(true, "%s%s-'%c' requires argument",
			    (go->flags & GF_NONAME) ? "" : argv[0],
			    (go->flags & GF_NONAME) ? "" : ": ", c);
			if (go->flags & GF_ERROR)
				bi_errorfz();
			return ('?');
		}
		go->p = 0;
	} else if (*o == ',') {
		/* argument is attached to option character, even if null */
		go->optarg = argv[go->optind - 1] + go->p;
		go->p = 0;
	} else if (*o == '#') {
		/* argument is optional and may be attached or unattached
		 * but must start with a digit. optarg is set to 0 if the
		 * argument is missing.
		 */
		if (argv[go->optind - 1][go->p]) {
			if (ksh_isdigit(argv[go->optind - 1][go->p])) {
				go->optarg = argv[go->optind - 1] + go->p;
				go->p = 0;
			} else
				go->optarg = NULL;
		} else {
			if (argv[go->optind] && ksh_isdigit(argv[go->optind][0])) {
				go->optarg = argv[go->optind++];
				go->p = 0;
			} else
				go->optarg = NULL;
		}
	}
	return (c);
}

/* print variable/alias value using necessary quotes
 * (POSIX says they should be suitable for re-entry...)
 * No trailing newline is printed.
 */
void
print_value_quoted(const char *s)
{
	const char *p;
	int inquote = 0;

	/* Test if any quotes are needed */
	for (p = s; *p; p++)
		if (ctype(*p, C_QUOTE))
			break;
	if (!*p) {
		shf_puts(s, shl_stdout);
		return;
	}
	for (p = s; *p; p++) {
		if (*p == '\'') {
			if (inquote)
				shf_putc('\'', shl_stdout);
			shf_putc('\\', shl_stdout);
			inquote = 0;
		} else if (!inquote) {
			shf_putc('\'', shl_stdout);
			inquote = 1;
		}
		shf_putc(*p, shl_stdout);
	}
	if (inquote)
		shf_putc('\'', shl_stdout);
}

/*
 * Print things in columns and rows - func() is called to format
 * the i-th element
 */
void
print_columns(struct shf *shf, int n,
    char *(*func)(char *, int, int, const void *),
    const void *arg, int max_oct, int max_col, bool prefcol)
{
	int i, r, c, rows, cols, nspace;
	char *str;

	if (n <= 0) {
#ifndef MKSH_SMALL
		internal_warningf("print_columns called with n=%d <= 0", n);
#endif
		return;
	}

	++max_oct;
	str = alloc(max_oct, ATEMP);

	/* ensure x_cols is valid first */
	if (x_cols < MIN_COLS)
		change_winsz();

	/*
	 * We use (max_col + 1) to consider the space separator.
	 * Note that no space is printed after the last column
	 * to avoid problems with terminals that have auto-wrap.
	 */
	cols = x_cols / (max_col + 1);

	/* if we can only print one column anyway, skip the goo */
	if (cols < 2) {
		for (i = 0; i < n; ++i)
			shf_fprintf(shf, "%s \n",
			    (*func)(str, max_oct, i, arg));
		goto out;
	}

	rows = (n + cols - 1) / cols;
	if (prefcol && cols > rows) {
		i = rows;
		rows = cols > n ? n : cols;
		cols = i;
	}

	max_col = -max_col;
	nspace = (x_cols + max_col * cols) / cols;
	if (nspace <= 0)
		nspace = 1;
	for (r = 0; r < rows; r++) {
		for (c = 0; c < cols; c++) {
			i = c * rows + r;
			if (i < n) {
				shf_fprintf(shf, "%*s", max_col,
				    (*func)(str, max_oct, i, arg));
				if (c + 1 < cols)
					shf_fprintf(shf, "%*s", nspace, null);
			}
		}
		shf_putchar('\n', shf);
	}
 out:
	afree(str, ATEMP);
}

/* Strip any nul bytes from buf - returns new length (nbytes - # of nuls) */
void
strip_nuls(char *buf, int nbytes)
{
	char *dst;

	/* nbytes check because some systems (older FreeBSDs) have a buggy
	 * memchr()
	 */
	if (nbytes && (dst = memchr(buf, '\0', nbytes))) {
		char *end = buf + nbytes;
		char *p, *q;

		for (p = dst; p < end; p = q) {
			/* skip a block of nulls */
			while (++p < end && *p == '\0')
				;
			/* find end of non-null block */
			if (!(q = memchr(p, '\0', end - p)))
				q = end;
			memmove(dst, p, q - p);
			dst += q - p;
		}
		*dst = '\0';
	}
}

/* Like read(2), but if read fails due to non-blocking flag, resets flag
 * and restarts read.
 */
int
blocking_read(int fd, char *buf, int nbytes)
{
	int ret;
	int tried_reset = 0;

	while ((ret = read(fd, buf, nbytes)) < 0) {
		if (!tried_reset && errno == EAGAIN) {
			if (reset_nonblock(fd) > 0) {
				tried_reset = 1;
				continue;
			}
			errno = EAGAIN;
		}
		break;
	}
	return (ret);
}

/* Reset the non-blocking flag on the specified file descriptor.
 * Returns -1 if there was an error, 0 if non-blocking wasn't set,
 * 1 if it was.
 */
int
reset_nonblock(int fd)
{
	int flags;

	if ((flags = fcntl(fd, F_GETFL, 0)) < 0)
		return (-1);
	if (!(flags & O_NONBLOCK))
		return (0);
	flags &= ~O_NONBLOCK;
	if (fcntl(fd, F_SETFL, flags) < 0)
		return (-1);
	return (1);
}


/* Like getcwd(), except bsize is ignored if buf is 0 (PATH_MAX is used) */
char *
ksh_get_wd(size_t *dlen)
{
	char *ret, *b;
	size_t len = 1;

#ifdef NO_PATH_MAX
	if ((b = get_current_dir_name())) {
		len = strlen(b) + 1;
		strndupx(ret, b, len - 1, ATEMP);
		free(b);
	} else
		ret = NULL;
#else
	if ((ret = getcwd((b = alloc(PATH_MAX + 1, ATEMP)), PATH_MAX)))
		ret = aresize(b, len = (strlen(b) + 1), ATEMP);
	else
		afree(b, ATEMP);
#endif

	if (dlen)
		*dlen = len;
	return (ret);
}

/*
 *	Makes a filename into result using the following algorithm.
 *	- make result NULL
 *	- if file starts with '/', append file to result & set cdpathp to NULL
 *	- if file starts with ./ or ../ append cwd and file to result
 *	  and set cdpathp to NULL
 *	- if the first element of cdpathp doesnt start with a '/' xx or '.' xx
 *	  then cwd is appended to result.
 *	- the first element of cdpathp is appended to result
 *	- file is appended to result
 *	- cdpathp is set to the start of the next element in cdpathp (or NULL
 *	  if there are no more elements.
 *	The return value indicates whether a non-null element from cdpathp
 *	was appended to result.
 */
int
make_path(const char *cwd, const char *file,
    char **cdpathp,		/* & of : separated list */
    XString *xsp,
    int *phys_pathp)
{
	int rval = 0;
	bool use_cdpath = true;
	char *plist;
	int len, plen = 0;
	char *xp = Xstring(*xsp, xp);

	if (!file)
		file = null;

	if (file[0] == '/') {
		*phys_pathp = 0;
		use_cdpath = false;
	} else {
		if (file[0] == '.') {
			char c = file[1];

			if (c == '.')
				c = file[2];
			if (c == '/' || c == '\0')
				use_cdpath = false;
		}

		plist = *cdpathp;
		if (!plist)
			use_cdpath = false;
		else if (use_cdpath) {
			char *pend;

			for (pend = plist; *pend && *pend != ':'; pend++)
				;
			plen = pend - plist;
			*cdpathp = *pend ? pend + 1 : NULL;
		}

		if ((!use_cdpath || !plen || plist[0] != '/') &&
		    (cwd && *cwd)) {
			len = strlen(cwd);
			XcheckN(*xsp, xp, len);
			memcpy(xp, cwd, len);
			xp += len;
			if (cwd[len - 1] != '/')
				Xput(*xsp, xp, '/');
		}
		*phys_pathp = Xlength(*xsp, xp);
		if (use_cdpath && plen) {
			XcheckN(*xsp, xp, plen);
			memcpy(xp, plist, plen);
			xp += plen;
			if (plist[plen - 1] != '/')
				Xput(*xsp, xp, '/');
			rval = 1;
		}
	}

	len = strlen(file) + 1;
	XcheckN(*xsp, xp, len);
	memcpy(xp, file, len);

	if (!use_cdpath)
		*cdpathp = NULL;

	return (rval);
}

/*
 * Simplify pathnames containing "." and ".." entries.
 * ie, simplify_path("/a/b/c/./../d/..") returns "/a/b"
 */
void
simplify_path(char *pathl)
{
	char *cur, *t;
	bool isrooted;
	char *very_start = pathl, *start;

	if (!*pathl)
		return;

	if ((isrooted = pathl[0] == '/'))
		very_start++;

	/* Before			After
	 * /foo/			/foo
	 * /foo/../../bar		/bar
	 * /foo/./blah/..		/foo
	 * .				.
	 * ..				..
	 * ./foo			foo
	 * foo/../../../bar		../../bar
	 */

	for (cur = t = start = very_start; ; ) {
		/* treat multiple '/'s as one '/' */
		while (*t == '/')
			t++;

		if (*t == '\0') {
			if (cur == pathl)
				/* convert empty path to dot */
				*cur++ = '.';
			*cur = '\0';
			break;
		}

		if (t[0] == '.') {
			if (!t[1] || t[1] == '/') {
				t += 1;
				continue;
			} else if (t[1] == '.' && (!t[2] || t[2] == '/')) {
				if (!isrooted && cur == start) {
					if (cur != very_start)
						*cur++ = '/';
					*cur++ = '.';
					*cur++ = '.';
					start = cur;
				} else if (cur != start)
					while (--cur > start && *cur != '/')
						;
				t += 2;
				continue;
			}
		}

		if (cur != very_start)
			*cur++ = '/';

		/* find/copy next component of pathname */
		while (*t && *t != '/')
			*cur++ = *t++;
	}
}


void
set_current_wd(char *pathl)
{
	size_t len = 1;
	char *p = pathl;

	if (p == NULL) {
		if ((p = ksh_get_wd(&len)) == NULL)
			p = null;
	} else
		len = strlen(p) + 1;

	if (len > current_wd_size) {
		afree(current_wd, APERM);
		current_wd = alloc(current_wd_size = len, APERM);
	}
	memcpy(current_wd, p, len);
	if (p != pathl && p != null)
		afree(p, ATEMP);
}

#ifdef TIOCSCTTY
extern void chvt_reinit(void);

static void
chvt(const char *fn)
{
	char dv[20];
	struct stat sb;
	int fd;

	/* for entropy */
	kshstate_f.h = evilhash(fn);

	if (*fn == '-') {
		memcpy(dv, "-/dev/null", sizeof("-/dev/null"));
		fn = dv + 1;
	} else {
		if (stat(fn, &sb)) {
			memcpy(dv, "/dev/ttyC", 9);
			strlcpy(dv + 9, fn, sizeof(dv) - 9);
			if (stat(dv, &sb)) {
				strlcpy(dv + 8, fn, sizeof(dv) - 8);
				if (stat(dv, &sb))
					errorf("chvt: can't find tty %s", fn);
			}
			fn = dv;
		}
		if (!(sb.st_mode & S_IFCHR))
			errorf("chvt: not a char device: %s", fn);
		if ((sb.st_uid != 0) && chown(fn, 0, 0))
			warningf(false, "chvt: cannot chown root %s", fn);
		if (((sb.st_mode & 07777) != 0600) && chmod(fn, (mode_t)0600))
			warningf(false, "chvt: cannot chmod 0600 %s", fn);
#if HAVE_REVOKE
		if (revoke(fn))
#endif
			warningf(false, "chvt: cannot revoke %s, new shell is"
			    " potentially insecure", fn);
	}
	if ((fd = open(fn, O_RDWR)) == -1) {
		sleep(1);
		if ((fd = open(fn, O_RDWR)) == -1)
			errorf("chvt: cannot open %s", fn);
	}
	switch (fork()) {
	case -1:
		errorf("chvt: %s failed", "fork");
	case 0:
		break;
	default:
		exit(0);
	}
	if (setsid() == -1)
		errorf("chvt: %s failed", "setsid");
	if (fn != dv + 1) {
		if (ioctl(fd, TIOCSCTTY, NULL) == -1)
			errorf("chvt: %s failed", "TIOCSCTTY");
		if (tcflush(fd, TCIOFLUSH))
			errorf("chvt: %s failed", "TCIOFLUSH");
	}
	ksh_dup2(fd, 0, false);
	ksh_dup2(fd, 1, false);
	ksh_dup2(fd, 2, false);
	if (fd > 2)
		close(fd);
	chvt_reinit();
}
#endif

#ifdef DEBUG
char longsizes_are_okay[sizeof(long) == sizeof(unsigned long) ? 1 : -1];
char arisize_is_okay[sizeof(mksh_ari_t) == 4 ? 1 : -1];
char uarisize_is_okay[sizeof(mksh_uari_t) == 4 ? 1 : -1];

char *
strchr(char *p, int ch)
{
	for (;; ++p) {
		if (*p == ch)
			return (p);
		if (!*p)
			return (NULL);
	}
	/* NOTREACHED */
}

char *
strstr(char *b, const char *l)
{
	char first, c;
	size_t n;

	if ((first = *l++) == '\0')
		return (b);
	n = strlen(l);
 strstr_look:
	while ((c = *b++) != first)
		if (c == '\0')
			return (NULL);
	if (strncmp(b, l, n))
		goto strstr_look;
	return (b - 1);
}
#endif

#ifndef MKSH_ASSUME_UTF8
#if !HAVE_STRCASESTR
const char *
stristr(const char *b, const char *l)
{
	char first, c;
	size_t n;

	if ((first = *l++), ((first = ksh_tolower(first)) == '\0'))
		return (b);
	n = strlen(l);
 stristr_look:
	while ((c = *b++), ((c = ksh_tolower(c)) != first))
		if (c == '\0')
			return (NULL);
	if (strncasecmp(b, l, n))
		goto stristr_look;
	return (b - 1);
}
#endif
#endif

#ifdef MKSH_SMALL
char *
strndup_(const char *src, size_t len, Area *ap)
{
	char *dst = NULL;

	if (src != NULL) {
		dst = alloc(len + 1, ap);
		memcpy(dst, src, len);
		dst[len] = '\0';
	}
	return (dst);
}

char *
strdup_(const char *src, Area *ap)
{
	return (src == NULL ? NULL : strndup_(src, strlen(src), ap));
}
#endif

#if !HAVE_GETRUSAGE
#define INVTCK(r,t)	do {						\
	r.tv_usec = ((t) % (1000000 / CLK_TCK)) * (1000000 / CLK_TCK);	\
	r.tv_sec = (t) / CLK_TCK;					\
} while (/* CONSTCOND */ 0)

int
getrusage(int what, struct rusage *ru)
{
	struct tms tms;
	clock_t u, s;

	if (/* ru == NULL || */ times(&tms) == (clock_t)-1)
		return (-1);

	switch (what) {
	case RUSAGE_SELF:
		u = tms.tms_utime;
		s = tms.tms_stime;
		break;
	case RUSAGE_CHILDREN:
		u = tms.tms_cutime;
		s = tms.tms_cstime;
		break;
	default:
		errno = EINVAL;
		return (-1);
	}
	INVTCK(ru->ru_utime, u);
	INVTCK(ru->ru_stime, s);
	return (0);
}
#endif

/*
 * process the string available via fg (get a char)
 * and fp (put back a char) for backslash escapes,
 * assuming the first call to *fg gets the char di-
 * rectly after the backslash; return the character
 * (0..0xFF), Unicode (wc + 0x100), or -1 if no known
 * escape sequence was found
 */
int
unbksl(bool cstyle, int (*fg)(void), void (*fp)(int))
{
	int wc, i, c, fc;

	fc = (*fg)();
	switch (fc) {
	case 'a':
		/*
		 * according to the comments in pdksh, \007 seems
		 * to be more portable than \a (due to HP-UX cc,
		 * Ultrix cc, old pcc, etc.) so we avoid the escape
		 * sequence altogether in mksh and assume ASCII
		 */
		wc = 7;
		break;
	case 'b':
		wc = '\b';
		break;
	case 'c':
		if (!cstyle)
			goto unknown_escape;
		c = (*fg)();
		wc = CTRL(c);
		break;
	case 'E':
	case 'e':
		wc = 033;
		break;
	case 'f':
		wc = '\f';
		break;
	case 'n':
		wc = '\n';
		break;
	case 'r':
		wc = '\r';
		break;
	case 't':
		wc = '\t';
		break;
	case 'v':
		/* assume ASCII here as well */
		wc = 11;
		break;
	case '1':
	case '2':
	case '3':
	case '4':
	case '5':
	case '6':
	case '7':
		if (!cstyle)
			goto unknown_escape;
		/* FALLTHROUGH */
	case '0':
		if (cstyle)
			(*fp)(fc);
		/*
		 * look for an octal number with up to three
		 * digits, not counting the leading zero;
		 * convert it to a raw octet
		 */
		wc = 0;
		i = 3;
		while (i--)
			if ((c = (*fg)()) >= '0' && c <= '7')
				wc = (wc << 3) + (c - '0');
			else {
				(*fp)(c);
				break;
			}
		break;
	case 'U':
		i = 8;
		if (0)
		/* FALLTHROUGH */
	case 'u':
		i = 4;
		if (0)
		/* FALLTHROUGH */
	case 'x':
		i = cstyle ? -1 : 2;
		/*
		 * x:	look for a hexadecimal number with up to
		 *	two (C style: arbitrary) digits; convert
		 *	to raw octet (C style: Unicode if >0xFF)
		 * u/U:	look for a hexadecimal number with up to
		 *	four (U: eight) digits; convert to Unicode
		 */
		wc = 0;
		while (i--) {
			wc <<= 4;
			if ((c = (*fg)()) >= '0' && c <= '9')
				wc += c - '0';
			else if (c >= 'A' && c <= 'F')
				wc += c - 'A' + 10;
			else if (c >= 'a' && c <= 'f')
				wc += c - 'a' + 10;
			else {
				wc >>= 4;
				(*fp)(c);
				break;
			}
		}
		if ((cstyle && wc > 0xFF) || fc != 'x')
			/* Unicode marker */
			wc += 0x100;
		break;
	case '\'':
		if (!cstyle)
			goto unknown_escape;
		wc = '\'';
		break;
	case '\\':
		wc = '\\';
		break;
	default:
 unknown_escape:
		(*fp)(fc);
		return (-1);
	}

	return (wc);
}
