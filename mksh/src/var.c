/*	$OpenBSD: var.c,v 1.34 2007/10/15 02:16:35 deraadt Exp $	*/

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

#if defined(__OpenBSD__)
#include <sys/sysctl.h>
#endif

__RCSID("$MirOS: src/bin/mksh/var.c,v 1.110 2010/07/25 11:35:43 tg Exp $");

/*
 * Variables
 *
 * WARNING: unreadable code, needs a rewrite
 *
 * if (flag&INTEGER), val.i contains integer value, and type contains base.
 * otherwise, (val.s + type) contains string value.
 * if (flag&EXPORT), val.s contains "name=value" for E-Z exporting.
 */
static struct tbl vtemp;
static struct table specials;
static char *formatstr(struct tbl *, const char *);
static void exportprep(struct tbl *, const char *);
static int special(const char *);
static void unspecial(const char *);
static void getspec(struct tbl *);
static void setspec(struct tbl *);
static void unsetspec(struct tbl *);
static int getint(struct tbl *, mksh_ari_t *, bool);
static mksh_ari_t intval(struct tbl *);
static struct tbl *arraysearch(struct tbl *, uint32_t);
static const char *array_index_calc(const char *, bool *, uint32_t *);
static uint32_t oaathash_update(register uint32_t, register const uint8_t *,
    register size_t);
static uint32_t oaathash_finalise(register uint32_t);

uint8_t set_refflag = 0;

/*
 * create a new block for function calls and simple commands
 * assume caller has allocated and set up e->loc
 */
void
newblock(void)
{
	struct block *l;
	static const char *empty[] = { null };

	l = alloc(sizeof(struct block), ATEMP);
	l->flags = 0;
	ainit(&l->area); /* todo: could use e->area (l->area => l->areap) */
	if (!e->loc) {
		l->argc = 0;
		l->argv = empty;
	} else {
		l->argc = e->loc->argc;
		l->argv = e->loc->argv;
	}
	l->exit = l->error = NULL;
	ktinit(&l->vars, &l->area, 0);
	ktinit(&l->funs, &l->area, 0);
	l->next = e->loc;
	e->loc = l;
}

/*
 * pop a block handling special variables
 */
void
popblock(void)
{
	struct block *l = e->loc;
	struct tbl *vp, **vpp = l->vars.tbls, *vq;
	int i;

	e->loc = l->next;	/* pop block */
	for (i = l->vars.size; --i >= 0; )
		if ((vp = *vpp++) != NULL && (vp->flag&SPECIAL)) {
			if ((vq = global(vp->name))->flag & ISSET)
				setspec(vq);
			else
				unsetspec(vq);
		}
	if (l->flags & BF_DOGETOPTS)
		user_opt = l->getopts_state;
	afreeall(&l->area);
	afree(l, ATEMP);
}

/* called by main() to initialise variable data structures */
#define VARSPEC_DEFNS
#include "var_spec.h"

enum var_specs {
#define VARSPEC_ENUMS
#include "var_spec.h"
	V_MAX
};

static const char * const initvar_names[] = {
#define VARSPEC_ITEMS
#include "var_spec.h"
};

void
initvar(void)
{
	int i = 0;
	struct tbl *tp;

	ktinit(&specials, APERM,
	    /* must be 80% of 2^n (currently 12 specials) */ 16);
	while (i < V_MAX - 1) {
		tp = ktenter(&specials, initvar_names[i],
		    hash(initvar_names[i]));
		tp->flag = DEFINED|ISSET;
		tp->type = ++i;
	}
}

/* Used to calculate an array index for global()/local(). Sets *arrayp to
 * true if this is an array, sets *valp to the array index, returns
 * the basename of the array.
 */
static const char *
array_index_calc(const char *n, bool *arrayp, uint32_t *valp)
{
	const char *p;
	int len;
	char *ap = NULL;

	*arrayp = false;
 redo_from_ref:
	p = skip_varname(n, false);
	if (!set_refflag && (p != n) && ksh_isalphx(n[0])) {
		struct block *l = e->loc;
		struct tbl *vp;
		char *vn;
		uint32_t h;

		strndupx(vn, n, p - n, ATEMP);
		h = hash(vn);
		/* check if this is a reference */
		do {
			vp = ktsearch(&l->vars, vn, h);
		} while (!vp && (l = l->next));
		afree(vn, ATEMP);
		if (vp && (vp->flag & (DEFINED|ASSOC|ARRAY)) ==
		    (DEFINED|ASSOC)) {
			char *cp;

			/* gotcha! */
			cp = shf_smprintf("%s%s", str_val(vp), p);
			afree(ap, ATEMP);
			n = ap = cp;
			goto redo_from_ref;
		}
	}

	if (p != n && *p == '[' && (len = array_ref_len(p))) {
		char *sub, *tmp;
		mksh_ari_t rval;

		/* Calculate the value of the subscript */
		*arrayp = true;
		strndupx(tmp, p + 1, len - 2, ATEMP);
		sub = substitute(tmp, 0);
		afree(tmp, ATEMP);
		strndupx(n, n, p - n, ATEMP);
		evaluate(sub, &rval, KSH_UNWIND_ERROR, true);
		*valp = (uint32_t)rval;
		afree(sub, ATEMP);
	}
	return (n);
}

/*
 * Search for variable, if not found create globally.
 */
struct tbl *
global(const char *n)
{
	struct block *l = e->loc;
	struct tbl *vp;
	int c;
	bool array;
	uint32_t h, val;

	/* Check to see if this is an array */
	n = array_index_calc(n, &array, &val);
	h = hash(n);
	c = n[0];
	if (!ksh_isalphx(c)) {
		if (array)
			errorf("bad substitution");
		vp = &vtemp;
		vp->flag = DEFINED;
		vp->type = 0;
		vp->areap = ATEMP;
		*vp->name = c;
		if (ksh_isdigit(c)) {
			for (c = 0; ksh_isdigit(*n); n++)
				c = c*10 + *n-'0';
			if (c <= l->argc)
				/* setstr can't fail here */
				setstr(vp, l->argv[c], KSH_RETURN_ERROR);
			vp->flag |= RDONLY;
			return (vp);
		}
		vp->flag |= RDONLY;
		if (n[1] != '\0')
			return (vp);
		vp->flag |= ISSET|INTEGER;
		switch (c) {
		case '$':
			vp->val.i = kshpid;
			break;
		case '!':
			/* If no job, expand to nothing */
			if ((vp->val.i = j_async()) == 0)
				vp->flag &= ~(ISSET|INTEGER);
			break;
		case '?':
			vp->val.i = exstat;
			break;
		case '#':
			vp->val.i = l->argc;
			break;
		case '-':
			vp->flag &= ~INTEGER;
			vp->val.s = getoptions();
			break;
		default:
			vp->flag &= ~(ISSET|INTEGER);
		}
		return (vp);
	}
	for (l = e->loc; ; l = l->next) {
		vp = ktsearch(&l->vars, n, h);
		if (vp != NULL) {
			if (array)
				return (arraysearch(vp, val));
			else
				return (vp);
		}
		if (l->next == NULL)
			break;
	}
	vp = ktenter(&l->vars, n, h);
	if (array)
		vp = arraysearch(vp, val);
	vp->flag |= DEFINED;
	if (special(n))
		vp->flag |= SPECIAL;
	return (vp);
}

/*
 * Search for local variable, if not found create locally.
 */
struct tbl *
local(const char *n, bool copy)
{
	struct block *l = e->loc;
	struct tbl *vp;
	bool array;
	uint32_t h, val;

	/* Check to see if this is an array */
	n = array_index_calc(n, &array, &val);
	h = hash(n);
	if (!ksh_isalphx(*n)) {
		vp = &vtemp;
		vp->flag = DEFINED|RDONLY;
		vp->type = 0;
		vp->areap = ATEMP;
		return (vp);
	}
	vp = ktenter(&l->vars, n, h);
	if (copy && !(vp->flag & DEFINED)) {
		struct block *ll = l;
		struct tbl *vq = NULL;

		while ((ll = ll->next) && !(vq = ktsearch(&ll->vars, n, h)))
			;
		if (vq) {
			vp->flag |= vq->flag &
			    (EXPORT | INTEGER | RDONLY | LJUST | RJUST |
			    ZEROFIL | LCASEV | UCASEV_AL | INT_U | INT_L);
			if (vq->flag & INTEGER)
				vp->type = vq->type;
			vp->u2.field = vq->u2.field;
		}
	}
	if (array)
		vp = arraysearch(vp, val);
	vp->flag |= DEFINED;
	if (special(n))
		vp->flag |= SPECIAL;
	return (vp);
}

/* get variable string value */
char *
str_val(struct tbl *vp)
{
	char *s;

	if ((vp->flag&SPECIAL))
		getspec(vp);
	if (!(vp->flag&ISSET))
		s = null;		/* special to dollar() */
	else if (!(vp->flag&INTEGER))	/* string source */
		s = vp->val.s + vp->type;
	else {				/* integer source */
		/* worst case number length is when base=2 */
		/* 1 (minus) + 2 (base, up to 36) + 1 ('#') + number of bits
		 * in the mksh_uari_t + 1 (NUL) */
		char strbuf[1 + 2 + 1 + 8 * sizeof(mksh_uari_t) + 1];
		const char *digits = (vp->flag & UCASEV_AL) ?
		    digits_uc : digits_lc;
		mksh_uari_t n;
		int base;

		s = strbuf + sizeof(strbuf);
		if (vp->flag & INT_U)
			n = vp->val.u;
		else
			n = (vp->val.i < 0) ? -vp->val.i : vp->val.i;
		base = (vp->type == 0) ? 10 : vp->type;

		if (base == 1) {
			size_t sz = 1;

			*(s = strbuf) = '1';
			s[1] = '#';
			if (!UTFMODE || ((n & 0xFF80) == 0xEF80))
				/* OPTU-16 -> raw octet */
				s[2] = n & 0xFF;
			else
				sz = utf_wctomb(s + 2, n);
			s[2 + sz] = '\0';
		} else {
			*--s = '\0';
			do {
				*--s = digits[n % base];
				n /= base;
			} while (n != 0);
			if (base != 10) {
				*--s = '#';
				*--s = digits[base % 10];
				if (base >= 10)
					*--s = digits[base / 10];
			}
			if (!(vp->flag & INT_U) && vp->val.i < 0)
				*--s = '-';
		}
		if (vp->flag & (RJUST|LJUST)) /* case already dealt with */
			s = formatstr(vp, s);
		else
			strdupx(s, s, ATEMP);
	}
	return (s);
}

/* get variable integer value, with error checking */
static mksh_ari_t
intval(struct tbl *vp)
{
	mksh_ari_t num;
	int base;

	base = getint(vp, &num, false);
	if (base == -1)
		/* XXX check calls - is error here ok by POSIX? */
		errorf("%s: bad number", str_val(vp));
	return (num);
}

/* set variable to string value */
int
setstr(struct tbl *vq, const char *s, int error_ok)
{
	char *salloc = NULL;
	int no_ro_check = error_ok & 0x4;

	error_ok &= ~0x4;
	if ((vq->flag & RDONLY) && !no_ro_check) {
		warningf(true, "%s: is read only", vq->name);
		if (!error_ok)
			errorfz();
		return (0);
	}
	if (!(vq->flag&INTEGER)) { /* string dest */
		if ((vq->flag&ALLOC)) {
			/* debugging */
			if (s >= vq->val.s &&
			    s <= vq->val.s + strlen(vq->val.s))
				internal_errorf(
				    "setstr: %s=%s: assigning to self",
				    vq->name, s);
			afree(vq->val.s, vq->areap);
		}
		vq->flag &= ~(ISSET|ALLOC);
		vq->type = 0;
		if (s && (vq->flag & (UCASEV_AL|LCASEV|LJUST|RJUST)))
			s = salloc = formatstr(vq, s);
		if ((vq->flag&EXPORT))
			exportprep(vq, s);
		else {
			strdupx(vq->val.s, s, vq->areap);
			vq->flag |= ALLOC;
		}
	} else {		/* integer dest */
		if (!v_evaluate(vq, s, error_ok, true))
			return (0);
	}
	vq->flag |= ISSET;
	if ((vq->flag&SPECIAL))
		setspec(vq);
	afree(salloc, ATEMP);
	return (1);
}

/* set variable to integer */
void
setint(struct tbl *vq, mksh_ari_t n)
{
	if (!(vq->flag&INTEGER)) {
		struct tbl *vp = &vtemp;
		vp->flag = (ISSET|INTEGER);
		vp->type = 0;
		vp->areap = ATEMP;
		vp->val.i = n;
		/* setstr can't fail here */
		setstr(vq, str_val(vp), KSH_RETURN_ERROR);
	} else
		vq->val.i = n;
	vq->flag |= ISSET;
	if ((vq->flag&SPECIAL))
		setspec(vq);
}

static int
getint(struct tbl *vp, mksh_ari_t *nump, bool arith)
{
	char *s;
	int c, base, neg;
	bool have_base = false;
	mksh_ari_t num;

	if (vp->flag&SPECIAL)
		getspec(vp);
	/* XXX is it possible for ISSET to be set and val.s to be 0? */
	if (!(vp->flag&ISSET) || (!(vp->flag&INTEGER) && vp->val.s == NULL))
		return (-1);
	if (vp->flag&INTEGER) {
		*nump = vp->val.i;
		return (vp->type);
	}
	s = vp->val.s + vp->type;
	if (s == NULL)	/* redundant given initial test */
		s = null;
	base = 10;
	num = 0;
	neg = 0;
	if (arith && *s == '0' && *(s+1)) {
		s++;
		if (*s == 'x' || *s == 'X') {
			s++;
			base = 16;
		} else if (vp->flag & ZEROFIL) {
			while (*s == '0')
				s++;
		} else
			base = 8;
		have_base = true;
	}
	for (c = *s++; c ; c = *s++) {
		if (c == '-') {
			neg++;
			continue;
		} else if (c == '#') {
			base = (int)num;
			if (have_base || base < 1 || base > 36)
				return (-1);
			if (base == 1) {
				unsigned int wc;

				if (!UTFMODE)
					wc = *(unsigned char *)s;
				else if (utf_mbtowc(&wc, s) == (size_t)-1)
					/* OPTU-8 -> OPTU-16 */
					/*
					 * (with a twist: 1#\uEF80 converts
					 * the same as 1#\x80 does, thus is
					 * not round-tripping correctly XXX)
					 */
					wc = 0xEF00 + *(unsigned char *)s;
				*nump = (mksh_ari_t)wc;
				return (1);
			}
			num = 0;
			have_base = true;
			continue;
		} else if (ksh_isdigit(c))
			c -= '0';
		else if (ksh_islower(c))
			c -= 'a' - 10;
		else if (ksh_isupper(c))
			c -= 'A' - 10;
		else
			return (-1);
		if (c < 0 || c >= base)
			return (-1);
		num = num * base + c;
	}
	if (neg)
		num = -num;
	*nump = num;
	return (base);
}

/* convert variable vq to integer variable, setting its value from vp
 * (vq and vp may be the same)
 */
struct tbl *
setint_v(struct tbl *vq, struct tbl *vp, bool arith)
{
	int base;
	mksh_ari_t num;

	if ((base = getint(vp, &num, arith)) == -1)
		return (NULL);
	if (!(vq->flag & INTEGER) && (vq->flag & ALLOC)) {
		vq->flag &= ~ALLOC;
		afree(vq->val.s, vq->areap);
	}
	vq->val.i = num;
	if (vq->type == 0) /* default base */
		vq->type = base;
	vq->flag |= ISSET|INTEGER;
	if (vq->flag&SPECIAL)
		setspec(vq);
	return (vq);
}

static char *
formatstr(struct tbl *vp, const char *s)
{
	int olen, nlen;
	char *p, *q;
	size_t psiz;

	olen = utf_mbswidth(s);

	if (vp->flag & (RJUST|LJUST)) {
		if (!vp->u2.field)	/* default field width */
			vp->u2.field = olen;
		nlen = vp->u2.field;
	} else
		nlen = olen;

	p = alloc((psiz = nlen * /* MB_LEN_MAX */ 3 + 1), ATEMP);
	if (vp->flag & (RJUST|LJUST)) {
		int slen = olen, i = 0;

		if (vp->flag & RJUST) {
			const char *qq = s;
			int n = 0;

			while (i < slen)
				i += utf_widthadj(qq, &qq);
			/* strip trailing spaces (AT&T uses qq[-1] == ' ') */
			while (qq > s && ksh_isspace(qq[-1])) {
				--qq;
				--slen;
			}
			if (vp->flag & ZEROFIL && vp->flag & INTEGER) {
				if (s[1] == '#')
					n = 2;
				else if (s[2] == '#')
					n = 3;
				if (vp->u2.field <= n)
					n = 0;
			}
			if (n) {
				memcpy(p, s, n);
				s += n;
			}
			while (slen > vp->u2.field)
				slen -= utf_widthadj(s, &s);
			if (vp->u2.field - slen)
				memset(p + n, (vp->flag & ZEROFIL) ? '0' : ' ',
				    vp->u2.field - slen);
			slen -= n;
			shf_snprintf(p + vp->u2.field - slen,
			    psiz - (vp->u2.field - slen),
			    "%.*s", slen, s);
		} else {
			/* strip leading spaces/zeros */
			while (ksh_isspace(*s))
				s++;
			if (vp->flag & ZEROFIL)
				while (*s == '0')
					s++;
			shf_snprintf(p, nlen + 1, "%-*.*s",
				vp->u2.field, vp->u2.field, s);
		}
	} else
		memcpy(p, s, strlen(s) + 1);

	if (vp->flag & UCASEV_AL) {
		for (q = p; *q; q++)
			*q = ksh_toupper(*q);
	} else if (vp->flag & LCASEV) {
		for (q = p; *q; q++)
			*q = ksh_tolower(*q);
	}

	return (p);
}

/*
 * make vp->val.s be "name=value" for quick exporting.
 */
static void
exportprep(struct tbl *vp, const char *val)
{
	char *xp;
	char *op = (vp->flag&ALLOC) ? vp->val.s : NULL;
	int namelen = strlen(vp->name);
	int vallen = strlen(val) + 1;

	vp->flag |= ALLOC;
	xp = alloc(namelen + 1 + vallen, vp->areap);
	memcpy(vp->val.s = xp, vp->name, namelen);
	xp += namelen;
	*xp++ = '=';
	vp->type = xp - vp->val.s; /* offset to value */
	memcpy(xp, val, vallen);
	if (op != NULL)
		afree(op, vp->areap);
}

/*
 * lookup variable (according to (set&LOCAL)),
 * set its attributes (INTEGER, RDONLY, EXPORT, TRACE, LJUST, RJUST, ZEROFIL,
 * LCASEV, UCASEV_AL), and optionally set its value if an assignment.
 */
struct tbl *
typeset(const char *var, Tflag set, Tflag clr, int field, int base)
{
	struct tbl *vp;
	struct tbl *vpbase, *t;
	char *tvar;
	const char *val;
	int len;

	/* check for valid variable name, search for value */
	val = skip_varname(var, false);
	if (val == var)
		return (NULL);
	mkssert(var != NULL);
	mkssert(*var != 0);
	if (*val == '[') {
		if (set_refflag)
			errorf("%s: reference variable cannot be an array",
			    var);
		len = array_ref_len(val);
		if (len == 0)
			return (NULL);
		/* IMPORT is only used when the shell starts up and is
		 * setting up its environment. Allow only simple array
		 * references at this time since parameter/command substitution
		 * is preformed on the [expression] which would be a major
		 * security hole.
		 */
		if (set & IMPORT) {
			int i;
			for (i = 1; i < len - 1; i++)
				if (!ksh_isdigit(val[i]))
					return (NULL);
		}
		val += len;
	}
	if (*val == '=')
		strndupx(tvar, var, val++ - var, ATEMP);
	else {
		/* Importing from original environment: must have an = */
		if (set & IMPORT)
			return (NULL);
		strdupx(tvar, var, ATEMP);
		val = NULL;
		/* handle foo[*] ⇒ foo (whole array) mapping for R39b */
		len = strlen(tvar);
		if (len > 3 && tvar[len-3] == '[' && tvar[len-2] == '*' &&
		    tvar[len-1] == ']')
			tvar[len-3] = '\0';
	}

	/* Prevent typeset from creating a local PATH/ENV/SHELL */
	if (Flag(FRESTRICTED) && (strcmp(tvar, "PATH") == 0 ||
	    strcmp(tvar, "ENV") == 0 || strcmp(tvar, "SHELL") == 0))
		errorf("%s: restricted", tvar);

	vp = (set&LOCAL) ? local(tvar, (set & LOCAL_COPY) ? true : false) :
	    global(tvar);
	if (set_refflag == 2 && (vp->flag & (ARRAY|ASSOC)) == ASSOC)
		vp->flag &= ~ASSOC;
	else if (set_refflag == 1) {
		if (vp->flag & ARRAY) {
			struct tbl *a, *tmp;

			/* Free up entire array */
			for (a = vp->u.array; a; ) {
				tmp = a;
				a = a->u.array;
				if (tmp->flag & ALLOC)
					afree(tmp->val.s, tmp->areap);
				afree(tmp, tmp->areap);
			}
			vp->u.array = NULL;
			vp->flag &= ~ARRAY;
		}
		vp->flag |= ASSOC;
	}

	set &= ~(LOCAL|LOCAL_COPY);

	vpbase = (vp->flag & ARRAY) ? global(arrayname(var)) : vp;

	/* only allow export flag to be set. AT&T ksh allows any attribute to
	 * be changed which means it can be truncated or modified (-L/-R/-Z/-i)
	 */
	if ((vpbase->flag&RDONLY) &&
	    (val || clr || (set & ~EXPORT)))
		/* XXX check calls - is error here ok by POSIX? */
		errorf("%s: is read only", tvar);
	afree(tvar, ATEMP);

	/* most calls are with set/clr == 0 */
	if (set | clr) {
		bool ok = true;

		/* XXX if x[0] isn't set, there will be problems: need to have
		 * one copy of attributes for arrays...
		 */
		for (t = vpbase; t; t = t->u.array) {
			bool fake_assign;
			char *s = NULL;
			char *free_me = NULL;

			fake_assign = (t->flag & ISSET) && (!val || t != vp) &&
			    ((set & (UCASEV_AL|LCASEV|LJUST|RJUST|ZEROFIL)) ||
			    ((t->flag & INTEGER) && (clr & INTEGER)) ||
			    (!(t->flag & INTEGER) && (set & INTEGER)));
			if (fake_assign) {
				if (t->flag & INTEGER) {
					s = str_val(t);
					free_me = NULL;
				} else {
					s = t->val.s + t->type;
					free_me = (t->flag & ALLOC) ? t->val.s :
					    NULL;
				}
				t->flag &= ~ALLOC;
			}
			if (!(t->flag & INTEGER) && (set & INTEGER)) {
				t->type = 0;
				t->flag &= ~ALLOC;
			}
			t->flag = (t->flag | set) & ~clr;
			/* Don't change base if assignment is to be done,
			 * in case assignment fails.
			 */
			if ((set & INTEGER) && base > 0 && (!val || t != vp))
				t->type = base;
			if (set & (LJUST|RJUST|ZEROFIL))
				t->u2.field = field;
			if (fake_assign) {
				if (!setstr(t, s, KSH_RETURN_ERROR)) {
					/* Somewhat arbitrary action here:
					 * zap contents of variable, but keep
					 * the flag settings.
					 */
					ok = false;
					if (t->flag & INTEGER)
						t->flag &= ~ISSET;
					else {
						if (t->flag & ALLOC)
							afree(t->val.s, t->areap);
						t->flag &= ~(ISSET|ALLOC);
						t->type = 0;
					}
				}
				if (free_me)
					afree(free_me, t->areap);
			}
		}
		if (!ok)
			errorfz();
	}

	if (val != NULL) {
		if (vp->flag&INTEGER) {
			/* do not zero base before assignment */
			setstr(vp, val, KSH_UNWIND_ERROR | 0x4);
			/* Done after assignment to override default */
			if (base > 0)
				vp->type = base;
		} else
			/* setstr can't fail (readonly check already done) */
			setstr(vp, val, KSH_RETURN_ERROR | 0x4);
	}

	/* only x[0] is ever exported, so use vpbase */
	if ((vpbase->flag&EXPORT) && !(vpbase->flag&INTEGER) &&
	    vpbase->type == 0)
		exportprep(vpbase, (vpbase->flag&ISSET) ? vpbase->val.s : null);

	return (vp);
}

/**
 * Unset a variable. The flags can be:
 * |1	= tear down entire array
 * |2	= keep attributes, only unset content
 */
void
unset(struct tbl *vp, int flags)
{
	if (vp->flag & ALLOC)
		afree(vp->val.s, vp->areap);
	if ((vp->flag & ARRAY) && (flags & 1)) {
		struct tbl *a, *tmp;

		/* Free up entire array */
		for (a = vp->u.array; a; ) {
			tmp = a;
			a = a->u.array;
			if (tmp->flag & ALLOC)
				afree(tmp->val.s, tmp->areap);
			afree(tmp, tmp->areap);
		}
		vp->u.array = NULL;
	}
	if (flags & 2) {
		vp->flag &= ~(ALLOC|ISSET);
		return;
	}
	/* If foo[0] is being unset, the remainder of the array is kept... */
	vp->flag &= SPECIAL | ((flags & 1) ? 0 : ARRAY|DEFINED);
	if (vp->flag & SPECIAL)
		unsetspec(vp);	/* responsible for 'unspecial'ing var */
}

/* return a pointer to the first char past a legal variable name (returns the
 * argument if there is no legal name, returns a pointer to the terminating
 * NUL if whole string is legal).
 */
const char *
skip_varname(const char *s, int aok)
{
	int alen;

	if (s && ksh_isalphx(*s)) {
		while (*++s && ksh_isalnux(*s))
			;
		if (aok && *s == '[' && (alen = array_ref_len(s)))
			s += alen;
	}
	return (s);
}

/* Return a pointer to the first character past any legal variable name */
const char *
skip_wdvarname(const char *s,
    int aok)				/* skip array de-reference? */
{
	if (s[0] == CHAR && ksh_isalphx(s[1])) {
		do {
			s += 2;
		} while (s[0] == CHAR && ksh_isalnux(s[1]));
		if (aok && s[0] == CHAR && s[1] == '[') {
			/* skip possible array de-reference */
			const char *p = s;
			char c;
			int depth = 0;

			while (1) {
				if (p[0] != CHAR)
					break;
				c = p[1];
				p += 2;
				if (c == '[')
					depth++;
				else if (c == ']' && --depth == 0) {
					s = p;
					break;
				}
			}
		}
	}
	return (s);
}

/* Check if coded string s is a variable name */
int
is_wdvarname(const char *s, int aok)
{
	const char *p = skip_wdvarname(s, aok);

	return (p != s && p[0] == EOS);
}

/* Check if coded string s is a variable assignment */
int
is_wdvarassign(const char *s)
{
	const char *p = skip_wdvarname(s, true);

	return (p != s && p[0] == CHAR && p[1] == '=');
}

/*
 * Make the exported environment from the exported names in the dictionary.
 */
char **
makenv(void)
{
	struct block *l;
	XPtrV denv;
	struct tbl *vp, **vpp;
	int i;

	XPinit(denv, 64);
	for (l = e->loc; l != NULL; l = l->next)
		for (vpp = l->vars.tbls, i = l->vars.size; --i >= 0; )
			if ((vp = *vpp++) != NULL &&
			    (vp->flag&(ISSET|EXPORT)) == (ISSET|EXPORT)) {
				struct block *l2;
				struct tbl *vp2;
				uint32_t h = hash(vp->name);

				/* unexport any redefined instances */
				for (l2 = l->next; l2 != NULL; l2 = l2->next) {
					vp2 = ktsearch(&l2->vars, vp->name, h);
					if (vp2 != NULL)
						vp2->flag &= ~EXPORT;
				}
				if ((vp->flag&INTEGER)) {
					/* integer to string */
					char *val;
					val = str_val(vp);
					vp->flag &= ~(INTEGER|RDONLY|SPECIAL);
					/* setstr can't fail here */
					setstr(vp, val, KSH_RETURN_ERROR);
				}
				XPput(denv, vp->val.s);
			}
	XPput(denv, NULL);
	return ((char **)XPclose(denv));
}

/* Bob Jenkins' one-at-a-time hash */
static uint32_t
oaathash_update(register uint32_t h, register const uint8_t *cp,
    register size_t n)
{
	while (n--) {
		h += *cp++;
		h += h << 10;
		h ^= h >> 6;
	}

	return (h);
}

static uint32_t
oaathash_finalise(register uint32_t h)
{
	h += h << 3;
	h ^= h >> 11;
	h += h << 15;

	return (h);
}

uint32_t
oaathash_full(register const uint8_t *bp)
{
	register uint32_t h = 0;
	register uint8_t c;

	while ((c = *bp++)) {
		h += c;
		h += h << 10;
		h ^= h >> 6;
	}

	return (oaathash_finalise(h));
}

void
change_random(const void *vp, size_t n)
{
	register uint32_t h = 0x100;
#if defined(__OpenBSD__)
	int mib[2];
	uint8_t k[3];
	size_t klen;
#endif

	kshstate_v.cr_dp = vp;
	kshstate_v.cr_dsz = n;
	gettimeofday(&kshstate_v.cr_tv, NULL);
	h = oaathash_update(oaathash_update(h, (void *)&kshstate_v,
	    sizeof(kshstate_v)), vp, n);
	kshstate_v.lcg_state_ = oaathash_finalise(h);

#if defined(__OpenBSD__)
	/* OpenBSD, MirBSD: proper kernel entropy comes at zero cost */

	mib[0] = CTL_KERN;
	mib[1] = KERN_ARND;
	klen = sizeof(k);
	sysctl(mib, 2, k, &klen, &kshstate_v.lcg_state_,
	    sizeof(kshstate_v.lcg_state_));
	/* we ignore failures and take in k anyway */
	h = oaathash_update(h, k, sizeof(k));
	kshstate_v.lcg_state_ = oaathash_finalise(h);
#elif defined(MKSH_A4PB)
	/* forced by the user to use arc4random_pushb(3) • Cygwin? */
	{
		uint32_t prv;

		prv = arc4random_pushb(&kshstate_v.lcg_state_,
		    sizeof(kshstate_v.lcg_state_));
		h = oaathash_update(h, &prv, sizeof(prv));
	}
	kshstate_v.lcg_state_ = oaathash_finalise(h);
#endif
}

/*
 * handle special variables with side effects - PATH, SECONDS.
 */

/* Test if name is a special parameter */
static int
special(const char *name)
{
	struct tbl *tp;

	tp = ktsearch(&specials, name, hash(name));
	return (tp && (tp->flag & ISSET) ? tp->type : V_NONE);
}

/* Make a variable non-special */
static void
unspecial(const char *name)
{
	struct tbl *tp;

	tp = ktsearch(&specials, name, hash(name));
	if (tp)
		ktdelete(tp);
}

static time_t seconds;		/* time SECONDS last set */
static int user_lineno;		/* what user set $LINENO to */

static void
getspec(struct tbl *vp)
{
	register mksh_ari_t i;
	int st;

	switch ((st = special(vp->name))) {
	case V_SECONDS:
		/*
		 * On start up the value of SECONDS is used before
		 * it has been set - don't do anything in this case
		 * (see initcoms[] in main.c).
		 */
		if (vp->flag & ISSET) {
			struct timeval tv;

			gettimeofday(&tv, NULL);
			i = tv.tv_sec - seconds;
		} else
			return;
		break;
	case V_RANDOM:
		/*
		 * this is the same Linear Congruential PRNG as Borland
		 * C/C++ allegedly uses in its built-in rand() function
		 */
		i = ((kshstate_v.lcg_state_ =
		    22695477 * kshstate_v.lcg_state_ + 1) >> 16) & 0x7FFF;
		break;
	case V_HISTSIZE:
		i = histsize;
		break;
	case V_OPTIND:
		i = user_opt.uoptind;
		break;
	case V_LINENO:
		i = current_lineno + user_lineno;
		break;
	case V_COLUMNS:
	case V_LINES:
		/*
		 * Do NOT export COLUMNS/LINES. Many applications
		 * check COLUMNS/LINES before checking ws.ws_col/row,
		 * so if the app is started with C/L in the environ
		 * and the window is then resized, the app won't
		 * see the change cause the environ doesn't change.
		 */
		change_winsz();
		i = st == V_COLUMNS ? x_cols : x_lins;
		break;
	default:
		/* do nothing, do not touch vp at all */
		return;
	}
	vp->flag &= ~SPECIAL;
	setint(vp, i);
	vp->flag |= SPECIAL;
}

static void
setspec(struct tbl *vp)
{
	mksh_ari_t i;
	char *s;
	int st;

	switch ((st = special(vp->name))) {
	case V_PATH:
		if (path)
			afree(path, APERM);
		s = str_val(vp);
		strdupx(path, s, APERM);
		flushcom(1);	/* clear tracked aliases */
		return;
	case V_IFS:
		setctypes(s = str_val(vp), C_IFS);
		ifs0 = *s;
		return;
	case V_TMPDIR:
		if (tmpdir) {
			afree(tmpdir, APERM);
			tmpdir = NULL;
		}
		/* Use tmpdir iff it is an absolute path, is writable and
		 * searchable and is a directory...
		 */
		{
			struct stat statb;

			s = str_val(vp);
			if (s[0] == '/' && access(s, W_OK|X_OK) == 0 &&
			    stat(s, &statb) == 0 && S_ISDIR(statb.st_mode))
				strdupx(tmpdir, s, APERM);
		}
		break;
#if HAVE_PERSISTENT_HISTORY
	case V_HISTFILE:
		sethistfile(str_val(vp));
		break;
#endif
	case V_TMOUT:
		/* AT&T ksh seems to do this (only listen if integer) */
		if (vp->flag & INTEGER)
			ksh_tmout = vp->val.i >= 0 ? vp->val.i : 0;
		break;

	/* common sub-cases */
	case V_OPTIND:
	case V_HISTSIZE:
	case V_COLUMNS:
	case V_LINES:
	case V_RANDOM:
	case V_SECONDS:
	case V_LINENO:
		vp->flag &= ~SPECIAL;
		i = intval(vp);
		vp->flag |= SPECIAL;
		break;
	default:
		/* do nothing, do not touch vp at all */
		return;
	}

	/* process the singular parts of the common cases */

	switch (st) {
	case V_OPTIND:
		getopts_reset((int)i);
		break;
	case V_HISTSIZE:
		sethistsize((int)i);
		break;
	case V_COLUMNS:
		if (i >= MIN_COLS)
			x_cols = i;
		break;
	case V_LINES:
		if (i >= MIN_LINS)
			x_lins = i;
		break;
	case V_RANDOM:
		/*
		 * mksh R39d+ no longer has the traditional repeatability
		 * of $RANDOM sequences, but always retains state
		 */
		change_random(&i, sizeof(i));
		break;
	case V_SECONDS:
		{
			struct timeval tv;

			gettimeofday(&tv, NULL);
			seconds = tv.tv_sec - i;
		}
		break;
	case V_LINENO:
		/* The -1 is because line numbering starts at 1. */
		user_lineno = (unsigned int)i - current_lineno - 1;
		break;
	}
}

static void
unsetspec(struct tbl *vp)
{
	switch (special(vp->name)) {
	case V_PATH:
		if (path)
			afree(path, APERM);
		strdupx(path, def_path, APERM);
		flushcom(1);	/* clear tracked aliases */
		break;
	case V_IFS:
		setctypes(" \t\n", C_IFS);
		ifs0 = ' ';
		break;
	case V_TMPDIR:
		/* should not become unspecial */
		if (tmpdir) {
			afree(tmpdir, APERM);
			tmpdir = NULL;
		}
		break;
	case V_LINENO:
	case V_RANDOM:
	case V_SECONDS:
	case V_TMOUT:		/* AT&T ksh leaves previous value in place */
		unspecial(vp->name);
		break;

	/*
	 * AT&T ksh man page says OPTIND, OPTARG and _ lose special
	 * meaning, but OPTARG does not (still set by getopts) and _ is
	 * also still set in various places. Don't know what AT&T does
	 * for HISTSIZE, HISTFILE. Unsetting these in AT&T ksh does not
	 * loose the 'specialness': IFS, COLUMNS, PATH, TMPDIR
	 */
	}
}

/*
 * Search for (and possibly create) a table entry starting with
 * vp, indexed by val.
 */
static struct tbl *
arraysearch(struct tbl *vp, uint32_t val)
{
	struct tbl *prev, *curr, *news;
	size_t len;

	vp->flag = (vp->flag | (ARRAY|DEFINED)) & ~ASSOC;
	/* The table entry is always [0] */
	if (val == 0)
		return (vp);
	prev = vp;
	curr = vp->u.array;
	while (curr && curr->ua.index < val) {
		prev = curr;
		curr = curr->u.array;
	}
	if (curr && curr->ua.index == val) {
		if (curr->flag&ISSET)
			return (curr);
		news = curr;
	} else
		news = NULL;
	len = strlen(vp->name) + 1;
	if (!news) {
		news = alloc(offsetof(struct tbl, name[0]) + len, vp->areap);
		memcpy(news->name, vp->name, len);
	}
	news->flag = (vp->flag & ~(ALLOC|DEFINED|ISSET|SPECIAL)) | AINDEX;
	news->type = vp->type;
	news->areap = vp->areap;
	news->u2.field = vp->u2.field;
	news->ua.index = val;

	if (curr != news) {		/* not reusing old array entry */
		prev->u.array = news;
		news->u.array = curr;
	}
	return (news);
}

/* Return the length of an array reference (eg, [1+2]) - cp is assumed
 * to point to the open bracket. Returns 0 if there is no matching closing
 * bracket.
 */
int
array_ref_len(const char *cp)
{
	const char *s = cp;
	int c;
	int depth = 0;

	while ((c = *s++) && (c != ']' || --depth))
		if (c == '[')
			depth++;
	if (!c)
		return (0);
	return (s - cp);
}

/*
 * Make a copy of the base of an array name
 */
char *
arrayname(const char *str)
{
	const char *p;
	char *rv;

	if ((p = cstrchr(str, '[')) == 0)
		/* Shouldn't happen, but why worry? */
		strdupx(rv, str, ATEMP);
	else
		strndupx(rv, str, p - str, ATEMP);

	return (rv);
}

/* set (or overwrite, if reset) the array variable var to the values in vals */
mksh_uari_t
set_array(const char *var, bool reset, const char **vals)
{
	struct tbl *vp, *vq;
	mksh_uari_t i;
	const char *ccp;
#ifndef MKSH_SMALL
	char *cp;
	mksh_uari_t j;
#endif

	/* to get local array, use "typeset foo; set -A foo" */
	vp = global(var);

	/* Note: AT&T ksh allows set -A but not set +A of a read-only var */
	if ((vp->flag&RDONLY))
		errorf("%s: is read only", var);
	/* This code is quite non-optimal */
	if (reset)
		/* trash existing values and attributes */
		unset(vp, 1);
	/* todo: would be nice for assignment to completely succeed or
	 * completely fail. Only really effects integer arrays:
	 * evaluation of some of vals[] may fail...
	 */
	i = 0;
#ifndef MKSH_SMALL
	j = 0;
#else
#define j i
#endif
	while ((ccp = vals[i])) {
#ifndef MKSH_SMALL
		if (*ccp == '[') {
			int level = 0;

			while (*ccp) {
				if (*ccp == ']' && --level == 0)
					break;
				if (*ccp == '[')
					++level;
				++ccp;
			}
			if (*ccp == ']' && level == 0 && ccp[1] == '=') {
				strndupx(cp, vals[i] + 1, ccp - (vals[i] + 1),
				    ATEMP);
				evaluate(substitute(cp, 0), (mksh_ari_t *)&j,
				    KSH_UNWIND_ERROR, true);
				afree(cp, ATEMP);
				ccp += 2;
			} else
				ccp = vals[i];
		}
#endif

		vq = arraysearch(vp, j);
		/* would be nice to deal with errors here... (see above) */
		setstr(vq, ccp, KSH_RETURN_ERROR);
		i++;
#ifndef MKSH_SMALL
		j++;
#endif
	}

	return (i);
}

void
change_winsz(void)
{
	if (x_lins < 0) {
		/* first time initialisation */
#ifdef TIOCGWINSZ
		if (tty_fd < 0)
			/* non-FTALKING, try to get an fd anyway */
			tty_init(false, false);
#endif
		x_cols = -1;
	}

#ifdef TIOCGWINSZ
	/* check if window size has changed */
	if (tty_fd >= 0) {
		struct winsize ws;

		if (ioctl(tty_fd, TIOCGWINSZ, &ws) >= 0) {
			if (ws.ws_col)
				x_cols = ws.ws_col;
			if (ws.ws_row)
				x_lins = ws.ws_row;
		}
	}
#endif

	/* bounds check for sane values, use defaults otherwise */
	if (x_cols < MIN_COLS)
		x_cols = 80;
	if (x_lins < MIN_LINS)
		x_lins = 24;

#ifdef SIGWINCH
	got_winch = 0;
#endif
}

uint32_t
evilhash(const char *s)
{
	register uint32_t h = 0x100;

	h = oaathash_update(h, (void *)&kshstate_f, sizeof(kshstate_f));
	kshstate_f.h = oaathash_full((const uint8_t *)s);
	return (oaathash_finalise(oaathash_update(h,
	    (void *)&kshstate_f.h, sizeof(kshstate_f.h))));
}
