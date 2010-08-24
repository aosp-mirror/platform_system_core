/*	$OpenBSD: history.c,v 1.39 2010/05/19 17:36:08 jasper Exp $	*/
/*	$OpenBSD: trap.c,v 1.23 2010/05/19 17:36:08 jasper Exp $	*/

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
#if HAVE_PERSISTENT_HISTORY
#include <sys/file.h>
#endif

__RCSID("$MirOS: src/bin/mksh/histrap.c,v 1.98 2010/07/24 17:08:29 tg Exp $");

/*-
 * MirOS: This is the default mapping type, and need not be specified.
 * IRIX doesn't have this constant.
 */
#ifndef MAP_FILE
#define MAP_FILE	0
#endif

Trap sigtraps[NSIG + 1];
static struct sigaction Sigact_ign;

#if HAVE_PERSISTENT_HISTORY
static int hist_count_lines(unsigned char *, int);
static int hist_shrink(unsigned char *, int);
static unsigned char *hist_skip_back(unsigned char *,int *,int);
static void histload(Source *, unsigned char *, int);
static void histinsert(Source *, int, const char *);
static void writehistfile(int, char *);
static int sprinkle(int);
#endif

static int hist_execute(char *);
static int hist_replace(char **, const char *, const char *, bool);
static char **hist_get(const char *, bool, bool);
static char **hist_get_oldest(void);
static void histbackup(void);

static char **current;		/* current position in history[] */
static int hstarted;		/* set after hist_init() called */
static Source *hist_source;

#if HAVE_PERSISTENT_HISTORY
static char *hname;		/* current name of history file */
static int histfd;
static int hsize;
#endif

int
c_fc(const char **wp)
{
	struct shf *shf;
	struct temp *tf;
	const char *p;
	char *editor = NULL;
	bool gflag = false, lflag = false, nflag = false, rflag = false,
	    sflag = false;
	int optc;
	const char *first = NULL, *last = NULL;
	char **hfirst, **hlast, **hp;

	if (!Flag(FTALKING_I)) {
		bi_errorf("history functions not available");
		return (1);
	}

	while ((optc = ksh_getopt(wp, &builtin_opt,
	    "e:glnrs0,1,2,3,4,5,6,7,8,9,")) != -1)
		switch (optc) {
		case 'e':
			p = builtin_opt.optarg;
			if (ksh_isdash(p))
				sflag = true;
			else {
				size_t len = strlen(p);
				editor = alloc(len + 4, ATEMP);
				memcpy(editor, p, len);
				memcpy(editor + len, " $_", 4);
			}
			break;
		case 'g': /* non-AT&T ksh */
			gflag = true;
			break;
		case 'l':
			lflag = true;
			break;
		case 'n':
			nflag = true;
			break;
		case 'r':
			rflag = true;
			break;
		case 's':	/* POSIX version of -e - */
			sflag = true;
			break;
		/* kludge city - accept -num as -- -num (kind of) */
		case '0': case '1': case '2': case '3': case '4':
		case '5': case '6': case '7': case '8': case '9':
			p = shf_smprintf("-%c%s",
					optc, builtin_opt.optarg);
			if (!first)
				first = p;
			else if (!last)
				last = p;
			else {
				bi_errorf("too many arguments");
				return (1);
			}
			break;
		case '?':
			return (1);
		}
	wp += builtin_opt.optind;

	/* Substitute and execute command */
	if (sflag) {
		char *pat = NULL, *rep = NULL;

		if (editor || lflag || nflag || rflag) {
			bi_errorf("can't use -e, -l, -n, -r with -s (-e -)");
			return (1);
		}

		/* Check for pattern replacement argument */
		if (*wp && **wp && (p = cstrchr(*wp + 1, '='))) {
			strdupx(pat, *wp, ATEMP);
			rep = pat + (p - *wp);
			*rep++ = '\0';
			wp++;
		}
		/* Check for search prefix */
		if (!first && (first = *wp))
			wp++;
		if (last || *wp) {
			bi_errorf("too many arguments");
			return (1);
		}

		hp = first ? hist_get(first, false, false) :
		    hist_get_newest(false);
		if (!hp)
			return (1);
		return (hist_replace(hp, pat, rep, gflag));
	}

	if (editor && (lflag || nflag)) {
		bi_errorf("can't use -l, -n with -e");
		return (1);
	}

	if (!first && (first = *wp))
		wp++;
	if (!last && (last = *wp))
		wp++;
	if (*wp) {
		bi_errorf("too many arguments");
		return (1);
	}
	if (!first) {
		hfirst = lflag ? hist_get("-16", true, true) :
		    hist_get_newest(false);
		if (!hfirst)
			return (1);
		/* can't fail if hfirst didn't fail */
		hlast = hist_get_newest(false);
	} else {
		/* POSIX says not an error if first/last out of bounds
		 * when range is specified; AT&T ksh and pdksh allow out of
		 * bounds for -l as well.
		 */
		hfirst = hist_get(first, (lflag || last) ? true : false, lflag);
		if (!hfirst)
			return (1);
		hlast = last ? hist_get(last, true, lflag) :
		    (lflag ? hist_get_newest(false) : hfirst);
		if (!hlast)
			return (1);
	}
	if (hfirst > hlast) {
		char **temp;

		temp = hfirst; hfirst = hlast; hlast = temp;
		rflag = !rflag; /* POSIX */
	}

	/* List history */
	if (lflag) {
		char *s, *t;

		for (hp = rflag ? hlast : hfirst;
		    hp >= hfirst && hp <= hlast; hp += rflag ? -1 : 1) {
			if (!nflag)
				shf_fprintf(shl_stdout, "%d",
				    hist_source->line - (int)(histptr - hp));
			shf_putc('\t', shl_stdout);
			/* print multi-line commands correctly */
			s = *hp;
			while ((t = strchr(s, '\n'))) {
				*t = '\0';
				shf_fprintf(shl_stdout, "%s\n\t", s);
				*t++ = '\n';
				s = t;
			}
			shf_fprintf(shl_stdout, "%s\n", s);
		}
		shf_flush(shl_stdout);
		return (0);
	}

	/* Run editor on selected lines, then run resulting commands */

	tf = maketemp(ATEMP, TT_HIST_EDIT, &e->temps);
	if (!(shf = tf->shf)) {
		bi_errorf("cannot create temp file %s - %s",
		    tf->name, strerror(errno));
		return (1);
	}
	for (hp = rflag ? hlast : hfirst;
	    hp >= hfirst && hp <= hlast; hp += rflag ? -1 : 1)
		shf_fprintf(shf, "%s\n", *hp);
	if (shf_close(shf) == EOF) {
		bi_errorf("error writing temporary file - %s", strerror(errno));
		return (1);
	}

	/* Ignore setstr errors here (arbitrary) */
	setstr(local("_", false), tf->name, KSH_RETURN_ERROR);

	/* XXX: source should not get trashed by this.. */
	{
		Source *sold = source;
		int ret;

		ret = command(editor ? editor : "${FCEDIT:-/bin/ed} $_", 0);
		source = sold;
		if (ret)
			return (ret);
	}

	{
		struct stat statb;
		XString xs;
		char *xp;
		int n;

		if (!(shf = shf_open(tf->name, O_RDONLY, 0, 0))) {
			bi_errorf("cannot open temp file %s", tf->name);
			return (1);
		}

		n = stat(tf->name, &statb) < 0 ? 128 : statb.st_size + 1;
		Xinit(xs, xp, n, hist_source->areap);
		while ((n = shf_read(xp, Xnleft(xs, xp), shf)) > 0) {
			xp += n;
			if (Xnleft(xs, xp) <= 0)
				XcheckN(xs, xp, Xlength(xs, xp));
		}
		if (n < 0) {
			bi_errorf("error reading temp file %s - %s",
			    tf->name, strerror(shf_errno(shf)));
			shf_close(shf);
			return (1);
		}
		shf_close(shf);
		*xp = '\0';
		strip_nuls(Xstring(xs, xp), Xlength(xs, xp));
		return (hist_execute(Xstring(xs, xp)));
	}
}

/* Save cmd in history, execute cmd (cmd gets trashed) */
static int
hist_execute(char *cmd)
{
	Source *sold;
	int ret;
	char *p, *q;

	histbackup();

	for (p = cmd; p; p = q) {
		if ((q = strchr(p, '\n'))) {
			*q++ = '\0'; /* kill the newline */
			if (!*q) /* ignore trailing newline */
				q = NULL;
		}
		histsave(&hist_source->line, p, true, true);

		shellf("%s\n", p); /* POSIX doesn't say this is done... */
		if (q)		/* restore \n (trailing \n not restored) */
			q[-1] = '\n';
	}

	/*
	 * Commands are executed here instead of pushing them onto the
	 * input 'cause POSIX says the redirection and variable assignments
	 * in
	 *	X=y fc -e - 42 2> /dev/null
	 * are to effect the repeated commands environment.
	 */
	/* XXX: source should not get trashed by this.. */
	sold = source;
	ret = command(cmd, 0);
	source = sold;
	return (ret);
}

static int
hist_replace(char **hp, const char *pat, const char *rep, bool globr)
{
	char *line;

	if (!pat)
		strdupx(line, *hp, ATEMP);
	else {
		char *s, *s1;
		int pat_len = strlen(pat);
		int rep_len = strlen(rep);
		int len;
		XString xs;
		char *xp;
		bool any_subst = false;

		Xinit(xs, xp, 128, ATEMP);
		for (s = *hp; (s1 = strstr(s, pat)) && (!any_subst || globr);
		    s = s1 + pat_len) {
			any_subst = true;
			len = s1 - s;
			XcheckN(xs, xp, len + rep_len);
			memcpy(xp, s, len);		/* first part */
			xp += len;
			memcpy(xp, rep, rep_len);	/* replacement */
			xp += rep_len;
		}
		if (!any_subst) {
			bi_errorf("substitution failed");
			return (1);
		}
		len = strlen(s) + 1;
		XcheckN(xs, xp, len);
		memcpy(xp, s, len);
		xp += len;
		line = Xclose(xs, xp);
	}
	return (hist_execute(line));
}

/*
 * get pointer to history given pattern
 * pattern is a number or string
 */
static char **
hist_get(const char *str, bool approx, bool allow_cur)
{
	char **hp = NULL;
	int n;

	if (getn(str, &n)) {
		hp = histptr + (n < 0 ? n : (n - hist_source->line));
		if ((ptrdiff_t)hp < (ptrdiff_t)history) {
			if (approx)
				hp = hist_get_oldest();
			else {
				bi_errorf("%s: not in history", str);
				hp = NULL;
			}
		} else if ((ptrdiff_t)hp > (ptrdiff_t)histptr) {
			if (approx)
				hp = hist_get_newest(allow_cur);
			else {
				bi_errorf("%s: not in history", str);
				hp = NULL;
			}
		} else if (!allow_cur && hp == histptr) {
			bi_errorf("%s: invalid range", str);
			hp = NULL;
		}
	} else {
		int anchored = *str == '?' ? (++str, 0) : 1;

		/* the -1 is to avoid the current fc command */
		if ((n = findhist(histptr - history - 1, 0, str, anchored)) < 0)
			bi_errorf("%s: not in history", str);
		else
			hp = &history[n];
	}
	return (hp);
}

/* Return a pointer to the newest command in the history */
char **
hist_get_newest(bool allow_cur)
{
	if (histptr < history || (!allow_cur && histptr == history)) {
		bi_errorf("no history (yet)");
		return (NULL);
	}
	return (allow_cur ? histptr : histptr - 1);
}

/* Return a pointer to the oldest command in the history */
static char **
hist_get_oldest(void)
{
	if (histptr <= history) {
		bi_errorf("no history (yet)");
		return (NULL);
	}
	return (history);
}

/******************************/
/* Back up over last histsave */
/******************************/
static void
histbackup(void)
{
	static int last_line = -1;

	if (histptr >= history && last_line != hist_source->line) {
		hist_source->line--;
		afree(*histptr, APERM);
		histptr--;
		last_line = hist_source->line;
	}
}

/*
 * Return the current position.
 */
char **
histpos(void)
{
	return (current);
}

int
histnum(int n)
{
	int last = histptr - history;

	if (n < 0 || n >= last) {
		current = histptr;
		return (last);
	} else {
		current = &history[n];
		return (n);
	}
}

/*
 * This will become unnecessary if hist_get is modified to allow
 * searching from positions other than the end, and in either
 * direction.
 */
int
findhist(int start, int fwd, const char *str, int anchored)
{
	char	**hp;
	int	maxhist = histptr - history;
	int	incr = fwd ? 1 : -1;
	int	len = strlen(str);

	if (start < 0 || start >= maxhist)
		start = maxhist;

	hp = &history[start];
	for (; hp >= history && hp <= histptr; hp += incr)
		if ((anchored && strncmp(*hp, str, len) == 0) ||
		    (!anchored && strstr(*hp, str)))
			return (hp - history);

	return (-1);
}

int
findhistrel(const char *str)
{
	int	maxhist = histptr - history;
	int	start = maxhist - 1;
	int	rec;

	getn(str, &rec);
	if (rec == 0)
		return (-1);
	if (rec > 0) {
		if (rec > maxhist)
			return (-1);
		return (rec - 1);
	}
	if (rec > maxhist)
		return (-1);
	return (start + rec + 1);
}

/*
 *	set history
 *	this means reallocating the dataspace
 */
void
sethistsize(int n)
{
	if (n > 0 && n != histsize) {
		int cursize = histptr - history;

		/* save most recent history */
		if (n < cursize) {
			memmove(history, histptr - n, n * sizeof(char *));
			cursize = n;
		}

		history = aresize(history, n * sizeof(char *), APERM);

		histsize = n;
		histptr = history + cursize;
	}
}

#if HAVE_PERSISTENT_HISTORY
/*
 *	set history file
 *	This can mean reloading/resetting/starting history file
 *	maintenance
 */
void
sethistfile(const char *name)
{
	/* if not started then nothing to do */
	if (hstarted == 0)
		return;

	/* if the name is the same as the name we have */
	if (hname && strcmp(hname, name) == 0)
		return;

	/*
	 * its a new name - possibly
	 */
	if (histfd) {
		/* yes the file is open */
		(void)close(histfd);
		histfd = 0;
		hsize = 0;
		afree(hname, APERM);
		hname = NULL;
		/* let's reset the history */
		histptr = history - 1;
		hist_source->line = 0;
	}

	hist_init(hist_source);
}
#endif

/*
 *	initialise the history vector
 */
void
init_histvec(void)
{
	if (history == (char **)NULL) {
		histsize = HISTORYSIZE;
		history = alloc(histsize * sizeof(char *), APERM);
		histptr = history - 1;
	}
}


/*
 *	Routines added by Peter Collinson BSDI(Europe)/Hillside Systems to
 *	a) permit HISTSIZE to control number of lines of history stored
 *	b) maintain a physical history file
 *
 *	It turns out that there is a lot of ghastly hackery here
 */

#if !defined(MKSH_SMALL) && HAVE_PERSISTENT_HISTORY
/* do not save command in history but possibly sync */
bool
histsync(void)
{
	bool changed = false;

	if (histfd) {
		int lno = hist_source->line;

		hist_source->line++;
		writehistfile(0, NULL);
		hist_source->line--;

		if (lno != hist_source->line)
			changed = true;
	}

	return (changed);
}
#endif

/*
 * save command in history
 */
void
histsave(int *lnp, const char *cmd, bool dowrite MKSH_A_UNUSED, bool ignoredups)
{
	char **hp;
	char *c, *cp;

	strdupx(c, cmd, APERM);
	if ((cp = strchr(c, '\n')) != NULL)
		*cp = '\0';

	if (ignoredups && !strcmp(c, *histptr)
#if !defined(MKSH_SMALL) && HAVE_PERSISTENT_HISTORY
	    && !histsync()
#endif
	    ) {
		afree(c, APERM);
		return;
	}
	++*lnp;

#if HAVE_PERSISTENT_HISTORY
	if (histfd && dowrite)
		writehistfile(*lnp, c);
#endif

	hp = histptr;

	if (++hp >= history + histsize) { /* remove oldest command */
		afree(*history, APERM);
		for (hp = history; hp < history + histsize - 1; hp++)
			hp[0] = hp[1];
	}
	*hp = c;
	histptr = hp;
}

/*
 *	Write history data to a file nominated by HISTFILE
 *	if HISTFILE is unset then history still happens, but
 *	the data is not written to a file
 *	All copies of ksh looking at the file will maintain the
 *	same history. This is ksh behaviour.
 *
 *	This stuff uses mmap()
 *	if your system ain't got it - then you'll have to undef HISTORYFILE
 */

/*
 *	Open a history file
 *	Format is:
 *	Bytes 1, 2:
 *		HMAGIC - just to check that we are dealing with
 *		the correct object
 *	Then follows a number of stored commands
 *	Each command is
 *	<command byte><command number(4 bytes)><bytes><null>
 */
#define HMAGIC1		0xab
#define HMAGIC2		0xcd
#define COMMAND		0xff

void
hist_init(Source *s)
{
#if HAVE_PERSISTENT_HISTORY
	unsigned char *base;
	int lines, fd, rv = 0;
#endif

	if (Flag(FTALKING) == 0)
		return;

	hstarted = 1;

	hist_source = s;

#if HAVE_PERSISTENT_HISTORY
	if ((hname = str_val(global("HISTFILE"))) == NULL)
		return;
	strdupx(hname, hname, APERM);

 retry:
	/* we have a file and are interactive */
	if ((fd = open(hname, O_RDWR|O_CREAT|O_APPEND, 0600)) < 0)
		return;

	histfd = savefd(fd);
	if (histfd != fd)
		close(fd);

	(void)flock(histfd, LOCK_EX);

	hsize = lseek(histfd, (off_t)0, SEEK_END);

	if (hsize == 0) {
		/* add magic */
		if (sprinkle(histfd)) {
			hist_finish();
			return;
		}
	} else if (hsize > 0) {
		/*
		 * we have some data
		 */
		base = (void *)mmap(NULL, hsize, PROT_READ,
		    MAP_FILE | MAP_PRIVATE, histfd, (off_t)0);
		/*
		 * check on its validity
		 */
		if (base == (unsigned char *)MAP_FAILED ||
		    *base != HMAGIC1 || base[1] != HMAGIC2) {
			if (base != (unsigned char *)MAP_FAILED)
				munmap((caddr_t)base, hsize);
			hist_finish();
			if (unlink(hname) /* fails */)
				goto hiniterr;
			goto retry;
		}
		if (hsize > 2) {
			lines = hist_count_lines(base+2, hsize-2);
			if (lines > histsize) {
				/* we need to make the file smaller */
				if (hist_shrink(base, hsize))
					rv = unlink(hname);
				munmap((caddr_t)base, hsize);
				hist_finish();
				if (rv) {
 hiniterr:
					bi_errorf("cannot unlink HISTFILE %s"
					    " - %s", hname, strerror(errno));
					hsize = 0;
					return;
				}
				goto retry;
			}
		}
		histload(hist_source, base+2, hsize-2);
		munmap((caddr_t)base, hsize);
	}
	(void)flock(histfd, LOCK_UN);
	hsize = lseek(histfd, (off_t)0, SEEK_END);
#endif
}

#if HAVE_PERSISTENT_HISTORY
typedef enum state {
	shdr,		/* expecting a header */
	sline,		/* looking for a null byte to end the line */
	sn1,		/* bytes 1 to 4 of a line no */
	sn2, sn3, sn4
} State;

static int
hist_count_lines(unsigned char *base, int bytes)
{
	State state = shdr;
	int lines = 0;

	while (bytes--) {
		switch (state) {
		case shdr:
			if (*base == COMMAND)
				state = sn1;
			break;
		case sn1:
			state = sn2; break;
		case sn2:
			state = sn3; break;
		case sn3:
			state = sn4; break;
		case sn4:
			state = sline; break;
		case sline:
			if (*base == '\0') {
				lines++;
				state = shdr;
			}
		}
		base++;
	}
	return (lines);
}

/*
 *	Shrink the history file to histsize lines
 */
static int
hist_shrink(unsigned char *oldbase, int oldbytes)
{
	int fd, rv = 0;
	char *nfile = NULL;
	struct	stat statb;
	unsigned char *nbase = oldbase;
	int nbytes = oldbytes;

	nbase = hist_skip_back(nbase, &nbytes, histsize);
	if (nbase == NULL)
		return (1);
	if (nbase == oldbase)
		return (0);

	/*
	 *	create temp file
	 */
	nfile = shf_smprintf("%s.%d", hname, (int)procpid);
	if ((fd = open(nfile, O_CREAT | O_TRUNC | O_WRONLY, 0600)) < 0)
		goto errout;
	if (fstat(histfd, &statb) >= 0 &&
	    chown(nfile, statb.st_uid, statb.st_gid))
		goto errout;

	if (sprinkle(fd) || write(fd, nbase, nbytes) != nbytes)
		goto errout;
	close(fd);
	fd = -1;

	/*
	 *	rename
	 */
	if (rename(nfile, hname) < 0) {
 errout:
		if (fd >= 0) {
			close(fd);
			if (nfile)
				unlink(nfile);
		}
		rv = 1;
	}
	afree(nfile, ATEMP);
	return (rv);
}

/*
 *	find a pointer to the data 'no' back from the end of the file
 *	return the pointer and the number of bytes left
 */
static unsigned char *
hist_skip_back(unsigned char *base, int *bytes, int no)
{
	int lines = 0;
	unsigned char *ep;

	for (ep = base + *bytes; --ep > base; ) {
		/*
		 * this doesn't really work: the 4 byte line number that
		 * is encoded after the COMMAND byte can itself contain
		 * the COMMAND byte....
		 */
		for (; ep > base && *ep != COMMAND; ep--)
			;
		if (ep == base)
			break;
		if (++lines == no) {
			*bytes = *bytes - ((char *)ep - (char *)base);
			return (ep);
		}
	}
	return (NULL);
}

/*
 *	load the history structure from the stored data
 */
static void
histload(Source *s, unsigned char *base, int bytes)
{
	State state;
	int lno = 0;
	unsigned char *line = NULL;

	for (state = shdr; bytes-- > 0; base++) {
		switch (state) {
		case shdr:
			if (*base == COMMAND)
				state = sn1;
			break;
		case sn1:
			lno = (((*base)&0xff)<<24);
			state = sn2;
			break;
		case sn2:
			lno |= (((*base)&0xff)<<16);
			state = sn3;
			break;
		case sn3:
			lno |= (((*base)&0xff)<<8);
			state = sn4;
			break;
		case sn4:
			lno |= (*base)&0xff;
			line = base+1;
			state = sline;
			break;
		case sline:
			if (*base == '\0') {
				/* worry about line numbers */
				if (histptr >= history && lno-1 != s->line) {
					/* a replacement ? */
					histinsert(s, lno, (char *)line);
				} else {
					s->line = lno--;
					histsave(&lno, (char *)line, false,
					    false);
				}
				state = shdr;
			}
		}
	}
}

/*
 *	Insert a line into the history at a specified number
 */
static void
histinsert(Source *s, int lno, const char *line)
{
	char **hp;

	if (lno >= s->line - (histptr - history) && lno <= s->line) {
		hp = &histptr[lno - s->line];
		if (*hp)
			afree(*hp, APERM);
		strdupx(*hp, line, APERM);
	}
}

/*
 *	write a command to the end of the history file
 *	This *MAY* seem easy but it's also necessary to check
 *	that the history file has not changed in size.
 *	If it has - then some other shell has written to it
 *	and we should read those commands to update our history
 */
static void
writehistfile(int lno, char *cmd)
{
	int	sizenow;
	unsigned char	*base;
	unsigned char	*news;
	int	bytes;
	unsigned char	hdr[5];

	(void)flock(histfd, LOCK_EX);
	sizenow = lseek(histfd, (off_t)0, SEEK_END);
	if (sizenow != hsize) {
		/*
		 *	Things have changed
		 */
		if (sizenow > hsize) {
			/* someone has added some lines */
			bytes = sizenow - hsize;
			base = (void *)mmap(NULL, sizenow, PROT_READ,
			    MAP_FILE | MAP_PRIVATE, histfd, (off_t)0);
			if (base == (unsigned char *)MAP_FAILED)
				goto bad;
			news = base + hsize;
			if (*news != COMMAND) {
				munmap((caddr_t)base, sizenow);
				goto bad;
			}
			hist_source->line--;
			histload(hist_source, news, bytes);
			hist_source->line++;
			lno = hist_source->line;
			munmap((caddr_t)base, sizenow);
			hsize = sizenow;
		} else {
			/* it has shrunk */
			/* but to what? */
			/* we'll give up for now */
			goto bad;
		}
	}
	if (cmd) {
		/*
		 *	we can write our bit now
		 */
		hdr[0] = COMMAND;
		hdr[1] = (lno>>24)&0xff;
		hdr[2] = (lno>>16)&0xff;
		hdr[3] = (lno>>8)&0xff;
		hdr[4] = lno&0xff;
		bytes = strlen(cmd) + 1;
		if ((write(histfd, hdr, 5) != 5) ||
		    (write(histfd, cmd, bytes) != bytes))
			goto bad;
		hsize = lseek(histfd, (off_t)0, SEEK_END);
	}
	(void)flock(histfd, LOCK_UN);
	return;
 bad:
	hist_finish();
}

void
hist_finish(void)
{
	(void)flock(histfd, LOCK_UN);
	(void)close(histfd);
	histfd = 0;
}

/*
 *	add magic to the history file
 */
static int
sprinkle(int fd)
{
	static const unsigned char mag[] = { HMAGIC1, HMAGIC2 };

	return (write(fd, mag, 2) != 2);
}
#endif

#if !HAVE_SYS_SIGNAME
static const struct mksh_sigpair {
	const char *const name;
	int nr;
} mksh_sigpairs[] = {
#include "signames.inc"
	{ NULL, 0 }
};
#endif

void
inittraps(void)
{
	int i;
	const char *cs;

	/* Populate sigtraps based on sys_signame and sys_siglist. */
	for (i = 0; i <= NSIG; i++) {
		sigtraps[i].signal = i;
		if (i == SIGERR_) {
			sigtraps[i].name = "ERR";
			sigtraps[i].mess = "Error handler";
		} else {
#if HAVE_SYS_SIGNAME
			cs = sys_signame[i];
#else
			const struct mksh_sigpair *pair = mksh_sigpairs;
			while ((pair->nr != i) && (pair->name != NULL))
				++pair;
			cs = pair->name;
#endif
			if ((cs == NULL) ||
			    (cs[0] == '\0'))
				sigtraps[i].name = shf_smprintf("%d", i);
			else {
				char *s;

				if (!strncasecmp(cs, "SIG", 3))
					cs += 3;
				strdupx(s, cs, APERM);
				sigtraps[i].name = s;
				while ((*s = ksh_toupper(*s)))
					++s;
			}
#if HAVE_SYS_SIGLIST
			sigtraps[i].mess = sys_siglist[i];
#elif HAVE_STRSIGNAL
			sigtraps[i].mess = strsignal(i);
#else
			sigtraps[i].mess = NULL;
#endif
			if ((sigtraps[i].mess == NULL) ||
			    (sigtraps[i].mess[0] == '\0'))
				sigtraps[i].mess = shf_smprintf("Signal %d", i);
		}
	}
	sigtraps[SIGEXIT_].name = "EXIT";	/* our name for signal 0 */

	(void)sigemptyset(&Sigact_ign.sa_mask);
	Sigact_ign.sa_flags = 0; /* interruptible */
	Sigact_ign.sa_handler = SIG_IGN;

	sigtraps[SIGINT].flags |= TF_DFL_INTR | TF_TTY_INTR;
	sigtraps[SIGQUIT].flags |= TF_DFL_INTR | TF_TTY_INTR;
	sigtraps[SIGTERM].flags |= TF_DFL_INTR;/* not fatal for interactive */
	sigtraps[SIGHUP].flags |= TF_FATAL;
	sigtraps[SIGCHLD].flags |= TF_SHELL_USES;

	/* these are always caught so we can clean up any temporary files. */
	setsig(&sigtraps[SIGINT], trapsig, SS_RESTORE_ORIG);
	setsig(&sigtraps[SIGQUIT], trapsig, SS_RESTORE_ORIG);
	setsig(&sigtraps[SIGTERM], trapsig, SS_RESTORE_ORIG);
	setsig(&sigtraps[SIGHUP], trapsig, SS_RESTORE_ORIG);
}

static void alarm_catcher(int sig);

void
alarm_init(void)
{
	sigtraps[SIGALRM].flags |= TF_SHELL_USES;
	setsig(&sigtraps[SIGALRM], alarm_catcher,
		SS_RESTORE_ORIG|SS_FORCE|SS_SHTRAP);
}

/* ARGSUSED */
static void
alarm_catcher(int sig MKSH_A_UNUSED)
{
	/* this runs inside interrupt context, with errno saved */

	if (ksh_tmout_state == TMOUT_READING) {
		int left = alarm(0);

		if (left == 0) {
			ksh_tmout_state = TMOUT_LEAVING;
			intrsig = 1;
		} else
			alarm(left);
	}
}

Trap *
gettrap(const char *name, int igncase)
{
	int n = NSIG + 1;
	Trap *p;
	const char *n2;
	int (*cmpfunc)(const char *, const char *) = strcmp;

	if (ksh_isdigit(*name)) {
		if (getn(name, &n) && 0 <= n && n < NSIG)
			return (&sigtraps[n]);
		else
			return (NULL);
	}

	n2 = strncasecmp(name, "SIG", 3) ? NULL : name + 3;
	if (igncase)
		cmpfunc = strcasecmp;
	for (p = sigtraps; --n >= 0; p++)
		if (!cmpfunc(p->name, name) || (n2 && !cmpfunc(p->name, n2)))
			return (p);
	return (NULL);
}

/*
 * trap signal handler
 */
void
trapsig(int i)
{
	Trap *p = &sigtraps[i];
	int errno_ = errno;

	trap = p->set = 1;
	if (p->flags & TF_DFL_INTR)
		intrsig = 1;
	if ((p->flags & TF_FATAL) && !p->trap) {
		fatal_trap = 1;
		intrsig = 1;
	}
	if (p->shtrap)
		(*p->shtrap)(i);
	errno = errno_;
}

/*
 * called when we want to allow the user to ^C out of something - won't
 * work if user has trapped SIGINT.
 */
void
intrcheck(void)
{
	if (intrsig)
		runtraps(TF_DFL_INTR|TF_FATAL);
}

/*
 * called after EINTR to check if a signal with normally causes process
 * termination has been received.
 */
int
fatal_trap_check(void)
{
	int i;
	Trap *p;

	/* todo: should check if signal is fatal, not the TF_DFL_INTR flag */
	for (p = sigtraps, i = NSIG+1; --i >= 0; p++)
		if (p->set && (p->flags & (TF_DFL_INTR|TF_FATAL)))
			/* return value is used as an exit code */
			return (128 + p->signal);
	return (0);
}

/*
 * Returns the signal number of any pending traps: ie, a signal which has
 * occurred for which a trap has been set or for which the TF_DFL_INTR flag
 * is set.
 */
int
trap_pending(void)
{
	int i;
	Trap *p;

	for (p = sigtraps, i = NSIG+1; --i >= 0; p++)
		if (p->set && ((p->trap && p->trap[0]) ||
		    ((p->flags & (TF_DFL_INTR|TF_FATAL)) && !p->trap)))
			return (p->signal);
	return (0);
}

/*
 * run any pending traps. If intr is set, only run traps that
 * can interrupt commands.
 */
void
runtraps(int flag)
{
	int i;
	Trap *p;

	if (ksh_tmout_state == TMOUT_LEAVING) {
		ksh_tmout_state = TMOUT_EXECUTING;
		warningf(false, "timed out waiting for input");
		unwind(LEXIT);
	} else
		/*
		 * XXX: this means the alarm will have no effect if a trap
		 * is caught after the alarm() was started...not good.
		 */
		ksh_tmout_state = TMOUT_EXECUTING;
	if (!flag)
		trap = 0;
	if (flag & TF_DFL_INTR)
		intrsig = 0;
	if (flag & TF_FATAL)
		fatal_trap = 0;
	for (p = sigtraps, i = NSIG+1; --i >= 0; p++)
		if (p->set && (!flag ||
		    ((p->flags & flag) && p->trap == NULL)))
			runtrap(p);
}

void
runtrap(Trap *p)
{
	int	i = p->signal;
	char	*trapstr = p->trap;
	int	oexstat;
	int	old_changed = 0;

	p->set = 0;
	if (trapstr == NULL) { /* SIG_DFL */
		if (p->flags & TF_FATAL) {
			/* eg, SIGHUP */
			exstat = 128 + i;
			unwind(LLEAVE);
		}
		if (p->flags & TF_DFL_INTR) {
			/* eg, SIGINT, SIGQUIT, SIGTERM, etc. */
			exstat = 128 + i;
			unwind(LINTR);
		}
		return;
	}
	if (trapstr[0] == '\0') /* SIG_IGN */
		return;
	if (i == SIGEXIT_ || i == SIGERR_) {	/* avoid recursion on these */
		old_changed = p->flags & TF_CHANGED;
		p->flags &= ~TF_CHANGED;
		p->trap = NULL;
	}
	oexstat = exstat;
	/*
	 * Note: trapstr is fully parsed before anything is executed, thus
	 * no problem with afree(p->trap) in settrap() while still in use.
	 */
	command(trapstr, current_lineno);
	exstat = oexstat;
	if (i == SIGEXIT_ || i == SIGERR_) {
		if (p->flags & TF_CHANGED)
			/* don't clear TF_CHANGED */
			afree(trapstr, APERM);
		else
			p->trap = trapstr;
		p->flags |= old_changed;
	}
}

/* clear pending traps and reset user's trap handlers; used after fork(2) */
void
cleartraps(void)
{
	int i;
	Trap *p;

	trap = 0;
	intrsig = 0;
	fatal_trap = 0;
	for (i = NSIG+1, p = sigtraps; --i >= 0; p++) {
		p->set = 0;
		if ((p->flags & TF_USER_SET) && (p->trap && p->trap[0]))
			settrap(p, NULL);
	}
}

/* restore signals just before an exec(2) */
void
restoresigs(void)
{
	int i;
	Trap *p;

	for (i = NSIG+1, p = sigtraps; --i >= 0; p++)
		if (p->flags & (TF_EXEC_IGN|TF_EXEC_DFL))
			setsig(p, (p->flags & TF_EXEC_IGN) ? SIG_IGN : SIG_DFL,
			    SS_RESTORE_CURR|SS_FORCE);
}

void
settrap(Trap *p, const char *s)
{
	sig_t f;

	if (p->trap)
		afree(p->trap, APERM);
	strdupx(p->trap, s, APERM); /* handles s == 0 */
	p->flags |= TF_CHANGED;
	f = !s ? SIG_DFL : s[0] ? trapsig : SIG_IGN;

	p->flags |= TF_USER_SET;
	if ((p->flags & (TF_DFL_INTR|TF_FATAL)) && f == SIG_DFL)
		f = trapsig;
	else if (p->flags & TF_SHELL_USES) {
		if (!(p->flags & TF_ORIG_IGN) || Flag(FTALKING)) {
			/* do what user wants at exec time */
			p->flags &= ~(TF_EXEC_IGN|TF_EXEC_DFL);
			if (f == SIG_IGN)
				p->flags |= TF_EXEC_IGN;
			else
				p->flags |= TF_EXEC_DFL;
		}

		/*
		 * assumes handler already set to what shell wants it
		 * (normally trapsig, but could be j_sigchld() or SIG_IGN)
		 */
		return;
	}

	/* todo: should we let user know signal is ignored? how? */
	setsig(p, f, SS_RESTORE_CURR|SS_USER);
}

/*
 * Called by c_print() when writing to a co-process to ensure SIGPIPE won't
 * kill shell (unless user catches it and exits)
 */
int
block_pipe(void)
{
	int restore_dfl = 0;
	Trap *p = &sigtraps[SIGPIPE];

	if (!(p->flags & (TF_ORIG_IGN|TF_ORIG_DFL))) {
		setsig(p, SIG_IGN, SS_RESTORE_CURR);
		if (p->flags & TF_ORIG_DFL)
			restore_dfl = 1;
	} else if (p->cursig == SIG_DFL) {
		setsig(p, SIG_IGN, SS_RESTORE_CURR);
		restore_dfl = 1; /* restore to SIG_DFL */
	}
	return (restore_dfl);
}

/* Called by c_print() to undo whatever block_pipe() did */
void
restore_pipe(int restore_dfl)
{
	if (restore_dfl)
		setsig(&sigtraps[SIGPIPE], SIG_DFL, SS_RESTORE_CURR);
}

/*
 * Set action for a signal. Action may not be set if original
 * action was SIG_IGN, depending on the value of flags and FTALKING.
 */
int
setsig(Trap *p, sig_t f, int flags)
{
	struct sigaction sigact;

	if (p->signal == SIGEXIT_ || p->signal == SIGERR_)
		return (1);

	/*
	 * First time setting this signal? If so, get and note the current
	 * setting.
	 */
	if (!(p->flags & (TF_ORIG_IGN|TF_ORIG_DFL))) {
		sigaction(p->signal, &Sigact_ign, &sigact);
		p->flags |= sigact.sa_handler == SIG_IGN ?
		    TF_ORIG_IGN : TF_ORIG_DFL;
		p->cursig = SIG_IGN;
	}

	/*-
	 * Generally, an ignored signal stays ignored, except if
	 *	- the user of an interactive shell wants to change it
	 *	- the shell wants for force a change
	 */
	if ((p->flags & TF_ORIG_IGN) && !(flags & SS_FORCE) &&
	    (!(flags & SS_USER) || !Flag(FTALKING)))
		return (0);

	setexecsig(p, flags & SS_RESTORE_MASK);

	/*
	 * This is here 'cause there should be a way of clearing
	 * shtraps, but don't know if this is a sane way of doing
	 * it. At the moment, all users of shtrap are lifetime
	 * users (SIGALRM, SIGCHLD, SIGWINCH).
	 */
	if (!(flags & SS_USER))
		p->shtrap = (sig_t)NULL;
	if (flags & SS_SHTRAP) {
		p->shtrap = f;
		f = trapsig;
	}

	if (p->cursig != f) {
		p->cursig = f;
		(void)sigemptyset(&sigact.sa_mask);
		sigact.sa_flags = 0 /* interruptible */;
		sigact.sa_handler = f;
		sigaction(p->signal, &sigact, NULL);
	}

	return (1);
}

/* control what signal is set to before an exec() */
void
setexecsig(Trap *p, int restore)
{
	/* XXX debugging */
	if (!(p->flags & (TF_ORIG_IGN|TF_ORIG_DFL)))
		internal_errorf("setexecsig: unset signal %d(%s)",
		    p->signal, p->name);

	/* restore original value for exec'd kids */
	p->flags &= ~(TF_EXEC_IGN|TF_EXEC_DFL);
	switch (restore & SS_RESTORE_MASK) {
	case SS_RESTORE_CURR: /* leave things as they currently are */
		break;
	case SS_RESTORE_ORIG:
		p->flags |= p->flags & TF_ORIG_IGN ? TF_EXEC_IGN : TF_EXEC_DFL;
		break;
	case SS_RESTORE_DFL:
		p->flags |= TF_EXEC_DFL;
		break;
	case SS_RESTORE_IGN:
		p->flags |= TF_EXEC_IGN;
		break;
	}
}
