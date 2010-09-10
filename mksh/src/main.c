/*	$OpenBSD: main.c,v 1.46 2010/05/19 17:36:08 jasper Exp $	*/
/*	$OpenBSD: tty.c,v 1.9 2006/03/14 22:08:01 deraadt Exp $	*/
/*	$OpenBSD: io.c,v 1.22 2006/03/17 16:30:13 millert Exp $	*/
/*	$OpenBSD: table.c,v 1.13 2009/01/17 22:06:44 millert Exp $	*/

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

#define	EXTERN
#include "sh.h"

#if HAVE_LANGINFO_CODESET
#include <langinfo.h>
#endif
#if HAVE_SETLOCALE_CTYPE
#include <locale.h>
#endif

__RCSID("$MirOS: src/bin/mksh/main.c,v 1.167 2010/07/04 17:45:15 tg Exp $");

extern char **environ;

#if !HAVE_SETRESUGID
extern uid_t kshuid;
extern gid_t kshgid, kshegid;
#endif

#ifndef MKSHRC_PATH
#define MKSHRC_PATH	"~/.mkshrc"
#endif

#ifndef MKSH_DEFAULT_TMPDIR
#define MKSH_DEFAULT_TMPDIR	"/tmp"
#endif

static void reclaim(void);
static void remove_temps(struct temp *);
void chvt_reinit(void);
Source *mksh_init(int, const char *[]);
#ifdef SIGWINCH
static void x_sigwinch(int);
#endif

static const char initifs[] = "IFS= \t\n";

static const char initsubs[] =
    "${PS2=> } ${PS3=#? } ${PS4=+ } ${SECONDS=0} ${TMOUT=0}";

static const char *initcoms[] = {
	T_typeset, "-r", initvsn, NULL,
	T_typeset, "-x", "HOME", "PATH", "RANDOM", "SHELL", NULL,
	T_typeset, "-i10", "COLUMNS", "LINES", "OPTIND", "PGRP", "PPID",
	    "RANDOM", "SECONDS", "TMOUT", "USER_ID", NULL,
	"alias",
	"integer=typeset -i",
	T_local_typeset,
	"hash=alias -t",	/* not "alias -t --": hash -r needs to work */
	"type=whence -v",
#ifndef MKSH_UNEMPLOYED
	"suspend=kill -STOP $$",
#endif
	"autoload=typeset -fu",
	"functions=typeset -f",
	"history=fc -l",
	"nameref=typeset -n",
	"nohup=nohup ",
	r_fc_e_,
	"source=PATH=$PATH:. command .",
	"login=exec login",
	NULL,
	 /* this is what AT&T ksh seems to track, with the addition of emacs */
	"alias", "-tU",
	"cat", "cc", "chmod", "cp", "date", "ed", "emacs", "grep", "ls",
	"make", "mv", "pr", "rm", "sed", "sh", "vi", "who", NULL,
	NULL
};

static int initio_done;

struct env *e = &kshstate_v.env_;

void
chvt_reinit(void)
{
	kshpid = procpid = getpid();
	ksheuid = geteuid();
	kshpgrp = getpgrp();
	kshppid = getppid();
}

Source *
mksh_init(int argc, const char *argv[])
{
	int argi, i;
	Source *s;
	struct block *l;
	unsigned char restricted, errexit, utf_flag;
	const char **wp;
	struct tbl *vp;
	struct stat s_stdin;
#if !defined(_PATH_DEFPATH) && defined(_CS_PATH)
	size_t k;
	char *cp;
#endif

	/* do things like getpgrp() et al. */
	chvt_reinit();

	/* make sure argv[] is sane */
	if (!*argv) {
		static const char *empty_argv[] = {
			"mksh", NULL
		};

		argv = empty_argv;
		argc = 1;
	}
	kshname = *argv;

	ainit(&aperm);		/* initialise permanent Area */

	/* set up base environment */
	kshstate_v.env_.type = E_NONE;
	ainit(&kshstate_v.env_.area);
	newblock();		/* set up global l->vars and l->funs */

	/* Do this first so output routines (eg, errorf, shellf) can work */
	initio();

	argi = parse_args(argv, OF_FIRSTTIME, NULL);
	if (argi < 0)
		return (NULL);

	initvar();

	initctypes();

	inittraps();

	coproc_init();

	/* set up variable and command dictionaries */
	ktinit(&taliases, APERM, 0);
	ktinit(&aliases, APERM, 0);
#ifndef MKSH_NOPWNAM
	ktinit(&homedirs, APERM, 0);
#endif

	/* define shell keywords */
	initkeywords();

	/* define built-in commands */
	ktinit(&builtins, APERM,
	    /* must be 80% of 2^n (currently 44 builtins) */ 64);
	for (i = 0; mkshbuiltins[i].name != NULL; i++)
		builtin(mkshbuiltins[i].name, mkshbuiltins[i].func);

	init_histvec();

#ifdef _PATH_DEFPATH
	def_path = _PATH_DEFPATH;
#else
#ifdef _CS_PATH
	if ((k = confstr(_CS_PATH, NULL, 0)) != (size_t)-1 && k > 0 &&
	    confstr(_CS_PATH, cp = alloc(k + 1, APERM), k + 1) == k + 1)
		def_path = cp;
	else
#endif
		/*
		 * this is uniform across all OSes unless it
		 * breaks somewhere; don't try to optimise,
		 * e.g. add stuff for Interix or remove /usr
		 * for HURD, because e.g. Debian GNU/HURD is
		 * "keeping a regular /usr"; this is supposed
		 * to be a sane 'basic' default PATH
		 */
		def_path = "/bin:/usr/bin:/sbin:/usr/sbin";
#endif

	/* Set PATH to def_path (will set the path global variable).
	 * (import of environment below will probably change this setting).
	 */
	vp = global("PATH");
	/* setstr can't fail here */
	setstr(vp, def_path, KSH_RETURN_ERROR);

	/* Turn on nohup by default for now - will change to off
	 * by default once people are aware of its existence
	 * (AT&T ksh does not have a nohup option - it always sends
	 * the hup).
	 */
	Flag(FNOHUP) = 1;

	/* Turn on brace expansion by default. AT&T kshs that have
	 * alternation always have it on.
	 */
	Flag(FBRACEEXPAND) = 1;

	/* Set edit mode to emacs by default, may be overridden
	 * by the environment or the user. Also, we want tab completion
	 * on in vi by default. */
	change_flag(FEMACS, OF_SPECIAL, 1);
#if !MKSH_S_NOVI
	Flag(FVITABCOMPLETE) = 1;
#endif

#ifdef MKSH_BINSHREDUCED
	/* set FSH if we're called as -sh or /bin/sh or so */
	{
		const char *cc;

		cc = kshname;
		i = 0; argi = 0;
		while (cc[i] != '\0')
			/* the following line matches '-' and '/' ;-) */
			if ((cc[i++] | 2) == '/')
				argi = i;
		if (((cc[argi] | 0x20) == 's') && ((cc[argi + 1] | 0x20) == 'h'))
			change_flag(FSH, OF_FIRSTTIME, 1);
	}
#endif

	/* import environment */
	if (environ != NULL)
		for (wp = (const char **)environ; *wp != NULL; wp++)
			typeset(*wp, IMPORT | EXPORT, 0, 0, 0);

	typeset(initifs, 0, 0, 0, 0);	/* for security */

	/* assign default shell variable values */
	substitute(initsubs, 0);

	/* Figure out the current working directory and set $PWD */
	{
		struct stat s_pwd, s_dot;
		struct tbl *pwd_v = global("PWD");
		char *pwd = str_val(pwd_v);
		char *pwdx = pwd;

		/* Try to use existing $PWD if it is valid */
		if (pwd[0] != '/' ||
		    stat(pwd, &s_pwd) < 0 || stat(".", &s_dot) < 0 ||
		    s_pwd.st_dev != s_dot.st_dev ||
		    s_pwd.st_ino != s_dot.st_ino)
			pwdx = NULL;
		set_current_wd(pwdx);
		if (current_wd[0])
			simplify_path(current_wd);
		/* Only set pwd if we know where we are or if it had a
		 * bogus value
		 */
		if (current_wd[0] || pwd != null)
			/* setstr can't fail here */
			setstr(pwd_v, current_wd, KSH_RETURN_ERROR);
	}

	for (wp = initcoms; *wp != NULL; wp++) {
		shcomexec(wp);
		while (*wp != NULL)
			wp++;
	}
	setint(global("COLUMNS"), 0);
	setint(global("LINES"), 0);
	setint(global("OPTIND"), 1);

	safe_prompt = ksheuid ? "$ " : "# ";
	vp = global("PS1");
	/* Set PS1 if unset or we are root and prompt doesn't contain a # */
	if (!(vp->flag & ISSET) ||
	    (!ksheuid && !strchr(str_val(vp), '#')))
		/* setstr can't fail here */
		setstr(vp, safe_prompt, KSH_RETURN_ERROR);
	setint((vp = global("PGRP")), (mksh_uari_t)kshpgrp);
	vp->flag |= INT_U;
	setint((vp = global("PPID")), (mksh_uari_t)kshppid);
	vp->flag |= INT_U;
	setint((vp = global("RANDOM")), (mksh_uari_t)evilhash(kshname));
	vp->flag |= INT_U;
	setint((vp = global("USER_ID")), (mksh_uari_t)ksheuid);
	vp->flag |= INT_U;

	/* Set this before parsing arguments */
#if HAVE_SETRESUGID
	Flag(FPRIVILEGED) = getuid() != ksheuid || getgid() != getegid();
#else
	Flag(FPRIVILEGED) = (kshuid = getuid()) != ksheuid ||
	    (kshgid = getgid()) != (kshegid = getegid());
#endif

	/* this to note if monitor is set on command line (see below) */
#ifndef MKSH_UNEMPLOYED
	Flag(FMONITOR) = 127;
#endif
	/* this to note if utf-8 mode is set on command line (see below) */
	UTFMODE = 2;

	argi = parse_args(argv, OF_CMDLINE, NULL);
	if (argi < 0)
		return (NULL);

	/* process this later only, default to off (hysterical raisins) */
	utf_flag = UTFMODE;
	UTFMODE = 0;

	if (Flag(FCOMMAND)) {
		s = pushs(SSTRING, ATEMP);
		if (!(s->start = s->str = argv[argi++]))
			errorf("-c requires an argument");
#ifdef MKSH_MIDNIGHTBSD01ASH_COMPAT
		/* compatibility to MidnightBSD 0.1 /bin/sh (kludge) */
		if (Flag(FSH) && argv[argi] && !strcmp(argv[argi], "--"))
			++argi;
#endif
		if (argv[argi])
			kshname = argv[argi++];
	} else if (argi < argc && !Flag(FSTDIN)) {
		s = pushs(SFILE, ATEMP);
		s->file = argv[argi++];
		s->u.shf = shf_open(s->file, O_RDONLY, 0,
		    SHF_MAPHI | SHF_CLEXEC);
		if (s->u.shf == NULL) {
			shl_stdout_ok = 0;
			warningf(true, "%s: %s", s->file, strerror(errno));
			/* mandated by SUSv4 */
			exstat = 127;
			unwind(LERROR);
		}
		kshname = s->file;
	} else {
		Flag(FSTDIN) = 1;
		s = pushs(SSTDIN, ATEMP);
		s->file = "<stdin>";
		s->u.shf = shf_fdopen(0, SHF_RD | can_seek(0),
		    NULL);
		if (isatty(0) && isatty(2)) {
			Flag(FTALKING) = Flag(FTALKING_I) = 1;
			/* The following only if isatty(0) */
			s->flags |= SF_TTY;
			s->u.shf->flags |= SHF_INTERRUPT;
			s->file = NULL;
		}
	}

	/* this bizarreness is mandated by POSIX */
	if (fstat(0, &s_stdin) >= 0 && S_ISCHR(s_stdin.st_mode) &&
	    Flag(FTALKING))
		reset_nonblock(0);

	/* initialise job control */
	j_init();
	/* set: 0/1; unset: 2->0 */
	UTFMODE = utf_flag & 1;
	/* Do this after j_init(), as tty_fd is not initialised until then */
	if (Flag(FTALKING)) {
		if (utf_flag == 2) {
#ifndef MKSH_ASSUME_UTF8
#define isuc(x)	(((x) != NULL) && \
		    (stristr((x), "UTF-8") || stristr((x), "utf8")))
		/* Check if we're in a UTF-8 locale */
			const char *ccp;

#if HAVE_SETLOCALE_CTYPE
			ccp = setlocale(LC_CTYPE, "");
#if HAVE_LANGINFO_CODESET
			if (!isuc(ccp))
				ccp = nl_langinfo(CODESET);
#endif
#else
			/* these were imported from environ earlier */
			ccp = str_val(global("LC_ALL"));
			if (ccp == null)
				ccp = str_val(global("LC_CTYPE"));
			if (ccp == null)
				ccp = str_val(global("LANG"));
#endif
			UTFMODE = isuc(ccp);
#undef isuc
#elif MKSH_ASSUME_UTF8
			UTFMODE = 1;
#else
			UTFMODE = 0;
#endif
		}
		x_init();
	}

#ifdef SIGWINCH
	sigtraps[SIGWINCH].flags |= TF_SHELL_USES;
	setsig(&sigtraps[SIGWINCH], x_sigwinch,
	    SS_RESTORE_ORIG|SS_FORCE|SS_SHTRAP);
#endif

	l = e->loc;
	l->argv = &argv[argi - 1];
	l->argc = argc - argi;
	l->argv[0] = kshname;
	getopts_reset(1);

	/* Disable during .profile/ENV reading */
	restricted = Flag(FRESTRICTED);
	Flag(FRESTRICTED) = 0;
	errexit = Flag(FERREXIT);
	Flag(FERREXIT) = 0;

	/* Do this before profile/$ENV so that if it causes problems in them,
	 * user will know why things broke.
	 */
	if (!current_wd[0] && Flag(FTALKING))
		warningf(false, "Cannot determine current working directory");

	if (Flag(FLOGIN)) {
		include(KSH_SYSTEM_PROFILE, 0, NULL, 1);
		if (!Flag(FPRIVILEGED))
			include(substitute("$HOME/.profile", 0), 0,
			    NULL, 1);
	}
	if (Flag(FPRIVILEGED))
		include("/etc/suid_profile", 0, NULL, 1);
	else if (Flag(FTALKING)) {
		char *env_file;

		/* include $ENV */
		env_file = substitute(substitute("${ENV:-" MKSHRC_PATH "}", 0),
		    DOTILDE);
		if (*env_file != '\0')
			include(env_file, 0, NULL, 1);
	}

	if (restricted) {
		static const char *restr_com[] = {
			T_typeset, "-r", "PATH",
			"ENV", "SHELL",
			NULL
		};
		shcomexec(restr_com);
		/* After typeset command... */
		Flag(FRESTRICTED) = 1;
	}
	Flag(FERREXIT) = errexit;

	if (Flag(FTALKING)) {
		hist_init(s);
		alarm_init();
	} else
		Flag(FTRACKALL) = 1;	/* set after ENV */

	return (s);
}

int
main(int argc, const char *argv[])
{
	Source *s;

	kshstate_v.lcg_state_ = 5381;

	if ((s = mksh_init(argc, argv))) {
		/* put more entropy into the LCG */
		change_random(s, sizeof(*s));
		/* doesn’t return */
		shell(s, true);
	}
	return (1);
}

int
include(const char *name, int argc, const char **argv, int intr_ok)
{
	Source *volatile s = NULL;
	struct shf *shf;
	const char **volatile old_argv;
	volatile int old_argc;
	int i;

	shf = shf_open(name, O_RDONLY, 0, SHF_MAPHI | SHF_CLEXEC);
	if (shf == NULL)
		return (-1);

	if (argv) {
		old_argv = e->loc->argv;
		old_argc = e->loc->argc;
	} else {
		old_argv = NULL;
		old_argc = 0;
	}
	newenv(E_INCL);
	i = sigsetjmp(e->jbuf, 0);
	if (i) {
		quitenv(s ? s->u.shf : NULL);
		if (old_argv) {
			e->loc->argv = old_argv;
			e->loc->argc = old_argc;
		}
		switch (i) {
		case LRETURN:
		case LERROR:
			return (exstat & 0xff); /* see below */
		case LINTR:
			/* intr_ok is set if we are including .profile or $ENV.
			 * If user ^Cs out, we don't want to kill the shell...
			 */
			if (intr_ok && (exstat - 128) != SIGTERM)
				return (1);
			/* FALLTHROUGH */
		case LEXIT:
		case LLEAVE:
		case LSHELL:
			unwind(i);
			/* NOTREACHED */
		default:
			internal_errorf("include: %d", i);
			/* NOTREACHED */
		}
	}
	if (argv) {
		e->loc->argv = argv;
		e->loc->argc = argc;
	}
	s = pushs(SFILE, ATEMP);
	s->u.shf = shf;
	strdupx(s->file, name, ATEMP);
	i = shell(s, false);
	quitenv(s->u.shf);
	if (old_argv) {
		e->loc->argv = old_argv;
		e->loc->argc = old_argc;
	}
	return (i & 0xff);	/* & 0xff to ensure value not -1 */
}

/* spawn a command into a shell optionally keeping track of the line number */
int
command(const char *comm, int line)
{
	Source *s;

	s = pushs(SSTRING, ATEMP);
	s->start = s->str = comm;
	s->line = line;
	return (shell(s, false));
}

/*
 * run the commands from the input source, returning status.
 */
int
shell(Source * volatile s, volatile int toplevel)
{
	struct op *t;
	volatile int wastty = s->flags & SF_TTY;
	volatile int attempts = 13;
	volatile int interactive = Flag(FTALKING) && toplevel;
	Source *volatile old_source = source;
	int i;

	s->flags |= SF_FIRST;	/* enable UTF-8 BOM check */

	newenv(E_PARSE);
	if (interactive)
		really_exit = 0;
	i = sigsetjmp(e->jbuf, 0);
	if (i) {
		switch (i) {
		case LINTR: /* we get here if SIGINT not caught or ignored */
		case LERROR:
		case LSHELL:
			if (interactive) {
				if (i == LINTR)
					shellf("\n");
				/* Reset any eof that was read as part of a
				 * multiline command.
				 */
				if (Flag(FIGNOREEOF) && s->type == SEOF &&
				    wastty)
					s->type = SSTDIN;
				/* Used by exit command to get back to
				 * top level shell. Kind of strange since
				 * interactive is set if we are reading from
				 * a tty, but to have stopped jobs, one only
				 * needs FMONITOR set (not FTALKING/SF_TTY)...
				 */
				/* toss any input we have so far */
				s->start = s->str = null;
				break;
			}
			/* FALLTHROUGH */
		case LEXIT:
		case LLEAVE:
		case LRETURN:
			source = old_source;
			quitenv(NULL);
			unwind(i);	/* keep on going */
			/* NOTREACHED */
		default:
			source = old_source;
			quitenv(NULL);
			internal_errorf("shell: %d", i);
			/* NOTREACHED */
		}
	}
	while (1) {
		if (trap)
			runtraps(0);

		if (s->next == NULL) {
			if (Flag(FVERBOSE))
				s->flags |= SF_ECHO;
			else
				s->flags &= ~SF_ECHO;
		}
		if (interactive) {
			j_notify();
			set_prompt(PS1, s);
		}
		t = compile(s);
		if (t != NULL && t->type == TEOF) {
			if (wastty && Flag(FIGNOREEOF) && --attempts > 0) {
				shellf("Use 'exit' to leave ksh\n");
				s->type = SSTDIN;
			} else if (wastty && !really_exit &&
			    j_stopped_running()) {
				really_exit = 1;
				s->type = SSTDIN;
			} else {
				/* this for POSIX which says EXIT traps
				 * shall be taken in the environment
				 * immediately after the last command
				 * executed.
				 */
				if (toplevel)
					unwind(LEXIT);
				break;
			}
		}
		if (t && (!Flag(FNOEXEC) || (s->flags & SF_TTY)))
			exstat = execute(t, 0, NULL);

		if (t != NULL && t->type != TEOF && interactive && really_exit)
			really_exit = 0;

		reclaim();
	}
	quitenv(NULL);
	source = old_source;
	return (exstat);
}

/* return to closest error handler or shell(), exit if none found */
void
unwind(int i)
{
	/* ordering for EXIT vs ERR is a bit odd (this is what AT&T ksh does) */
	if (i == LEXIT || (Flag(FERREXIT) && (i == LERROR || i == LINTR) &&
	    sigtraps[SIGEXIT_].trap)) {
		runtrap(&sigtraps[SIGEXIT_]);
		i = LLEAVE;
	} else if (Flag(FERREXIT) && (i == LERROR || i == LINTR)) {
		runtrap(&sigtraps[SIGERR_]);
		i = LLEAVE;
	}
	while (1) {
		switch (e->type) {
		case E_PARSE:
		case E_FUNC:
		case E_INCL:
		case E_LOOP:
		case E_ERRH:
			siglongjmp(e->jbuf, i);
			/* NOTREACHED */
		case E_NONE:
			if (i == LINTR)
				e->flags |= EF_FAKE_SIGDIE;
			/* FALLTHROUGH */
		default:
			quitenv(NULL);
		}
	}
}

void
newenv(int type)
{
	struct env *ep;
	char *cp;

	/*
	 * struct env includes ALLOC_ITEM for alignment constraints
	 * so first get the actually used memory, then assign it
	 */
	cp = alloc(sizeof(struct env) - ALLOC_SIZE, ATEMP);
	ep = (void *)(cp - ALLOC_SIZE);	/* undo what alloc() did */
	/* initialise public members of struct env (not the ALLOC_ITEM) */
	ainit(&ep->area);
	ep->oenv = e;
	ep->loc = e->loc;
	ep->savefd = NULL;
	ep->temps = NULL;
	ep->type = type;
	ep->flags = 0;
	/* jump buffer is invalid because flags == 0 */
	e = ep;
}

void
quitenv(struct shf *shf)
{
	struct env *ep = e;
	char *cp;
	int fd;

	if (ep->oenv && ep->oenv->loc != ep->loc)
		popblock();
	if (ep->savefd != NULL) {
		for (fd = 0; fd < NUFILE; fd++)
			/* if ep->savefd[fd] < 0, means fd was closed */
			if (ep->savefd[fd])
				restfd(fd, ep->savefd[fd]);
		if (ep->savefd[2])	/* Clear any write errors */
			shf_reopen(2, SHF_WR, shl_out);
	}
	/* Bottom of the stack.
	 * Either main shell is exiting or cleanup_parents_env() was called.
	 */
	if (ep->oenv == NULL) {
		if (ep->type == E_NONE) {	/* Main shell exiting? */
#if HAVE_PERSISTENT_HISTORY
			if (Flag(FTALKING))
				hist_finish();
#endif
			j_exit();
			if (ep->flags & EF_FAKE_SIGDIE) {
				int sig = exstat - 128;

				/* ham up our death a bit (AT&T ksh
				 * only seems to do this for SIGTERM)
				 * Don't do it for SIGQUIT, since we'd
				 * dump a core..
				 */
				if ((sig == SIGINT || sig == SIGTERM) &&
				    (kshpgrp == kshpid)) {
					setsig(&sigtraps[sig], SIG_DFL,
					    SS_RESTORE_CURR | SS_FORCE);
					kill(0, sig);
				}
			}
		}
		if (shf)
			shf_close(shf);
		reclaim();
		exit(exstat);
	}
	if (shf)
		shf_close(shf);
	reclaim();

	e = e->oenv;

	/* free the struct env - tricky due to the ALLOC_ITEM inside */
	cp = (void *)ep;
	afree(cp + ALLOC_SIZE, ATEMP);
}

/* Called after a fork to cleanup stuff left over from parents environment */
void
cleanup_parents_env(void)
{
	struct env *ep;
	int fd;

	mkssert(e != NULL);

	/*
	 * Don't clean up temporary files - parent will probably need them.
	 * Also, can't easily reclaim memory since variables, etc. could be
	 * anywhere.
	 */

	/* close all file descriptors hiding in savefd */
	for (ep = e; ep; ep = ep->oenv) {
		if (ep->savefd) {
			for (fd = 0; fd < NUFILE; fd++)
				if (ep->savefd[fd] > 0)
					close(ep->savefd[fd]);
			afree(ep->savefd, &ep->area);
			ep->savefd = NULL;
		}
	}
	e->oenv = NULL;
}

/* Called just before an execve cleanup stuff temporary files */
void
cleanup_proc_env(void)
{
	struct env *ep;

	for (ep = e; ep; ep = ep->oenv)
		remove_temps(ep->temps);
}

/* remove temp files and free ATEMP Area */
static void
reclaim(void)
{
	remove_temps(e->temps);
	e->temps = NULL;
	afreeall(&e->area);
}

static void
remove_temps(struct temp *tp)
{
	for (; tp != NULL; tp = tp->next)
		if (tp->pid == procpid)
			unlink(tp->name);
}

/* Initialise tty_fd. Used for saving/reseting tty modes upon
 * foreground job completion and for setting up tty process group.
 */
void
tty_init(bool init_ttystate, bool need_tty)
{
	bool do_close = true;
	int tfd;

	if (tty_fd >= 0) {
		close(tty_fd);
		tty_fd = -1;
	}
	tty_devtty = 1;

#ifdef _UWIN
	/* XXX imake style */
	if (isatty(3))
		tfd = 3;
	else
#endif
	if ((tfd = open("/dev/tty", O_RDWR, 0)) < 0) {
		tty_devtty = 0;
		if (need_tty)
			warningf(false,
			    "No controlling tty (open /dev/tty: %s)",
			    strerror(errno));
	}
	if (tfd < 0) {
		do_close = false;
		if (isatty(0))
			tfd = 0;
		else if (isatty(2))
			tfd = 2;
		else {
			if (need_tty)
				warningf(false,
				    "Can't find tty file descriptor");
			return;
		}
	}
	if ((tty_fd = fcntl(tfd, F_DUPFD, FDBASE)) < 0) {
		if (need_tty)
			warningf(false, "j_ttyinit: dup of tty fd failed: %s",
			    strerror(errno));
	} else if (fcntl(tty_fd, F_SETFD, FD_CLOEXEC) < 0) {
		if (need_tty)
			warningf(false,
			    "j_ttyinit: can't set close-on-exec flag: %s",
			    strerror(errno));
		close(tty_fd);
		tty_fd = -1;
	} else if (init_ttystate)
		tcgetattr(tty_fd, &tty_state);
	if (do_close)
		close(tfd);
}

void
tty_close(void)
{
	if (tty_fd >= 0) {
		close(tty_fd);
		tty_fd = -1;
	}
}

/* A shell error occurred (eg, syntax error, etc.) */
void
errorf(const char *fmt, ...)
{
	va_list va;

	shl_stdout_ok = 0;	/* debugging: note that stdout not valid */
	exstat = 1;
	if (*fmt != 1) {
		error_prefix(true);
		va_start(va, fmt);
		shf_vfprintf(shl_out, fmt, va);
		va_end(va);
		shf_putchar('\n', shl_out);
	}
	shf_flush(shl_out);
	unwind(LERROR);
}

/* like errorf(), but no unwind is done */
void
warningf(bool fileline, const char *fmt, ...)
{
	va_list va;

	error_prefix(fileline);
	va_start(va, fmt);
	shf_vfprintf(shl_out, fmt, va);
	va_end(va);
	shf_putchar('\n', shl_out);
	shf_flush(shl_out);
}

/* Used by built-in utilities to prefix shell and utility name to message
 * (also unwinds environments for special builtins).
 */
void
bi_errorf(const char *fmt, ...)
{
	va_list va;

	shl_stdout_ok = 0;	/* debugging: note that stdout not valid */
	exstat = 1;
	if (*fmt != 1) {
		error_prefix(true);
		/* not set when main() calls parse_args() */
		if (builtin_argv0)
			shf_fprintf(shl_out, "%s: ", builtin_argv0);
		va_start(va, fmt);
		shf_vfprintf(shl_out, fmt, va);
		va_end(va);
		shf_putchar('\n', shl_out);
	}
	shf_flush(shl_out);
	/* POSIX special builtins and ksh special builtins cause
	 * non-interactive shells to exit.
	 * XXX odd use of KEEPASN; also may not want LERROR here
	 */
	if (builtin_flag & SPEC_BI) {
		builtin_argv0 = NULL;
		unwind(LERROR);
	}
}

/* Called when something that shouldn't happen does */
void
internal_verrorf(const char *fmt, va_list ap)
{
	shf_fprintf(shl_out, "internal error: ");
	shf_vfprintf(shl_out, fmt, ap);
	shf_putchar('\n', shl_out);
	shf_flush(shl_out);
}

void
internal_errorf(const char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);
	internal_verrorf(fmt, va);
	va_end(va);
	unwind(LERROR);
}

void
internal_warningf(const char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);
	internal_verrorf(fmt, va);
	va_end(va);
}

/* used by error reporting functions to print "ksh: .kshrc[25]: " */
void
error_prefix(bool fileline)
{
	/* Avoid foo: foo[2]: ... */
	if (!fileline || !source || !source->file ||
	    strcmp(source->file, kshname) != 0)
		shf_fprintf(shl_out, "%s: ", kshname + (*kshname == '-'));
	if (fileline && source && source->file != NULL) {
		shf_fprintf(shl_out, "%s[%d]: ", source->file,
		    source->errline > 0 ? source->errline : source->line);
		source->errline = 0;
	}
}

/* printf to shl_out (stderr) with flush */
void
shellf(const char *fmt, ...)
{
	va_list va;

	if (!initio_done) /* shl_out may not be set up yet... */
		return;
	va_start(va, fmt);
	shf_vfprintf(shl_out, fmt, va);
	va_end(va);
	shf_flush(shl_out);
}

/* printf to shl_stdout (stdout) */
void
shprintf(const char *fmt, ...)
{
	va_list va;

	if (!shl_stdout_ok)
		internal_errorf("shl_stdout not valid");
	va_start(va, fmt);
	shf_vfprintf(shl_stdout, fmt, va);
	va_end(va);
}

/* test if we can seek backwards fd (returns 0 or SHF_UNBUF) */
int
can_seek(int fd)
{
	struct stat statb;

	return (fstat(fd, &statb) == 0 && !S_ISREG(statb.st_mode) ?
	    SHF_UNBUF : 0);
}

struct shf shf_iob[3];

void
initio(void)
{
	shf_fdopen(1, SHF_WR, shl_stdout);	/* force buffer allocation */
	shf_fdopen(2, SHF_WR, shl_out);
	shf_fdopen(2, SHF_WR, shl_spare);	/* force buffer allocation */
	initio_done = 1;
}

/* A dup2() with error checking */
int
ksh_dup2(int ofd, int nfd, bool errok)
{
	int rv;

	if (((rv = dup2(ofd, nfd)) < 0) && !errok && (errno != EBADF))
		errorf("too many files open in shell");

#ifdef __ultrix
	/* XXX imake style */
	if (rv >= 0)
		fcntl(nfd, F_SETFD, 0);
#endif

	return (rv);
}

/*
 * move fd from user space (0<=fd<10) to shell space (fd>=10),
 * set close-on-exec flag.
 */
short
savefd(int fd)
{
	int nfd = fd;

	if (fd < FDBASE && (nfd = fcntl(fd, F_DUPFD, FDBASE)) < 0 &&
	    errno == EBADF)
		return (-1);
	if (nfd < 0 || nfd > SHRT_MAX)
		errorf("too many files open in shell");
	fcntl(nfd, F_SETFD, FD_CLOEXEC);
	return ((short)nfd);
}

void
restfd(int fd, int ofd)
{
	if (fd == 2)
		shf_flush(&shf_iob[fd]);
	if (ofd < 0)		/* original fd closed */
		close(fd);
	else if (fd != ofd) {
		ksh_dup2(ofd, fd, true); /* XXX: what to do if this fails? */
		close(ofd);
	}
}

void
openpipe(int *pv)
{
	int lpv[2];

	if (pipe(lpv) < 0)
		errorf("can't create pipe - try again");
	pv[0] = savefd(lpv[0]);
	if (pv[0] != lpv[0])
		close(lpv[0]);
	pv[1] = savefd(lpv[1]);
	if (pv[1] != lpv[1])
		close(lpv[1]);
}

void
closepipe(int *pv)
{
	close(pv[0]);
	close(pv[1]);
}

/* Called by iosetup() (deals with 2>&4, etc.), c_read, c_print to turn
 * a string (the X in 2>&X, read -uX, print -uX) into a file descriptor.
 */
int
check_fd(const char *name, int mode, const char **emsgp)
{
	int fd, fl;

	if (name[0] == 'p' && !name[1])
		return (coproc_getfd(mode, emsgp));
	for (fd = 0; ksh_isdigit(*name); ++name)
		fd = (fd * 10) + *name - '0';
	if (*name || fd >= FDBASE) {
		if (emsgp)
			*emsgp = "illegal file descriptor name";
		return (-1);
	}
	if ((fl = fcntl(fd, F_GETFL, 0)) < 0) {
		if (emsgp)
			*emsgp = "bad file descriptor";
		return (-1);
	}
	fl &= O_ACCMODE;
	/* X_OK is a kludge to disable this check for dups (x<&1):
	 * historical shells never did this check (XXX don't know what
	 * POSIX has to say).
	 */
	if (!(mode & X_OK) && fl != O_RDWR && (
	    ((mode & R_OK) && fl != O_RDONLY) ||
	    ((mode & W_OK) && fl != O_WRONLY))) {
		if (emsgp)
			*emsgp = (fl == O_WRONLY) ?
			    "fd not open for reading" :
			    "fd not open for writing";
		return (-1);
	}
	return (fd);
}

/* Called once from main */
void
coproc_init(void)
{
	coproc.read = coproc.readw = coproc.write = -1;
	coproc.njobs = 0;
	coproc.id = 0;
}

/* Called by c_read() when eof is read - close fd if it is the co-process fd */
void
coproc_read_close(int fd)
{
	if (coproc.read >= 0 && fd == coproc.read) {
		coproc_readw_close(fd);
		close(coproc.read);
		coproc.read = -1;
	}
}

/* Called by c_read() and by iosetup() to close the other side of the
 * read pipe, so reads will actually terminate.
 */
void
coproc_readw_close(int fd)
{
	if (coproc.readw >= 0 && coproc.read >= 0 && fd == coproc.read) {
		close(coproc.readw);
		coproc.readw = -1;
	}
}

/* Called by c_print when a write to a fd fails with EPIPE and by iosetup
 * when co-process input is dup'd
 */
void
coproc_write_close(int fd)
{
	if (coproc.write >= 0 && fd == coproc.write) {
		close(coproc.write);
		coproc.write = -1;
	}
}

/* Called to check for existence of/value of the co-process file descriptor.
 * (Used by check_fd() and by c_read/c_print to deal with -p option).
 */
int
coproc_getfd(int mode, const char **emsgp)
{
	int fd = (mode & R_OK) ? coproc.read : coproc.write;

	if (fd >= 0)
		return (fd);
	if (emsgp)
		*emsgp = "no coprocess";
	return (-1);
}

/* called to close file descriptors related to the coprocess (if any)
 * Should be called with SIGCHLD blocked.
 */
void
coproc_cleanup(int reuse)
{
	/* This to allow co-processes to share output pipe */
	if (!reuse || coproc.readw < 0 || coproc.read < 0) {
		if (coproc.read >= 0) {
			close(coproc.read);
			coproc.read = -1;
		}
		if (coproc.readw >= 0) {
			close(coproc.readw);
			coproc.readw = -1;
		}
	}
	if (coproc.write >= 0) {
		close(coproc.write);
		coproc.write = -1;
	}
}

struct temp *
maketemp(Area *ap, Temp_type type, struct temp **tlist)
{
	struct temp *tp;
	int len;
	int fd;
	char *pathname;
	const char *dir;

	dir = tmpdir ? tmpdir : MKSH_DEFAULT_TMPDIR;
#if HAVE_MKSTEMP
	len = strlen(dir) + 6 + 10 + 1;
#else
	pathname = tempnam(dir, "mksh.");
	len = ((pathname == NULL) ? 0 : strlen(pathname)) + 1;
#endif
	tp = alloc(sizeof(struct temp) + len, ap);
	tp->name = (char *)&tp[1];
#if !HAVE_MKSTEMP
	if (pathname == NULL)
		tp->name[0] = '\0';
	else {
		memcpy(tp->name, pathname, len);
		free(pathname);
	}
#endif
	pathname = tp->name;
	tp->shf = NULL;
	tp->type = type;
#if HAVE_MKSTEMP
	shf_snprintf(pathname, len, "%s/mksh.XXXXXXXXXX", dir);
	if ((fd = mkstemp(pathname)) >= 0)
#else
	if (tp->name[0] && (fd = open(tp->name, O_CREAT | O_RDWR, 0600)) >= 0)
#endif
		tp->shf = shf_fdopen(fd, SHF_WR, NULL);
	tp->pid = procpid;

	tp->next = *tlist;
	*tlist = tp;
	return (tp);
}

/*
 * We use a similar collision resolution algorithm as Python 2.5.4
 * but with a slightly tweaked implementation written from scratch.
 */

#define	INIT_TBLS	8	/* initial table size (power of 2) */
#define PERTURB_SHIFT	5	/* see Python 2.5.4 Objects/dictobject.c */

static void texpand(struct table *, size_t);
static int tnamecmp(const void *, const void *);
static struct tbl *ktscan(struct table *, const char *, uint32_t,
    struct tbl ***);

static void
texpand(struct table *tp, size_t nsize)
{
	size_t i, j, osize = tp->size, perturb;
	struct tbl *tblp, **pp;
	struct tbl **ntblp, **otblp = tp->tbls;

	ntblp = alloc(nsize * sizeof(struct tbl *), tp->areap);
	for (i = 0; i < nsize; i++)
		ntblp[i] = NULL;
	tp->size = nsize;
	tp->nfree = (nsize * 4) / 5;	/* table can get 80% full */
	tp->tbls = ntblp;
	if (otblp == NULL)
		return;
	nsize--;			/* from here on nsize := mask */
	for (i = 0; i < osize; i++)
		if ((tblp = otblp[i]) != NULL) {
			if ((tblp->flag & DEFINED)) {
				/* search for free hash table slot */
				j = (perturb = tblp->ua.hval) & nsize;
				goto find_first_empty_slot;
 find_next_empty_slot:
				j = (j << 2) + j + perturb + 1;
				perturb >>= PERTURB_SHIFT;
 find_first_empty_slot:
				pp = &ntblp[j & nsize];
				if (*pp != NULL)
					goto find_next_empty_slot;
				/* found an empty hash table slot */
				*pp = tblp;
				tp->nfree--;
			} else if (!(tblp->flag & FINUSE)) {
				afree(tblp, tp->areap);
			}
		}
	afree(otblp, tp->areap);
}

void
ktinit(struct table *tp, Area *ap, size_t tsize)
{
	tp->areap = ap;
	tp->tbls = NULL;
	tp->size = tp->nfree = 0;
	if (tsize)
		texpand(tp, tsize);
}

/* table, name (key) to search for, hash(name), rv pointer to tbl ptr */
static struct tbl *
ktscan(struct table *tp, const char *name, uint32_t h, struct tbl ***ppp)
{
	size_t j, perturb, mask;
	struct tbl **pp, *p;

	mask = tp->size - 1;
	/* search for hash table slot matching name */
	j = (perturb = h) & mask;
	goto find_first_slot;
 find_next_slot:
	j = (j << 2) + j + perturb + 1;
	perturb >>= PERTURB_SHIFT;
 find_first_slot:
	pp = &tp->tbls[j & mask];
	if ((p = *pp) != NULL && (p->ua.hval != h || !(p->flag & DEFINED) ||
	    strcmp(p->name, name)))
		goto find_next_slot;
	/* p == NULL if not found, correct found entry otherwise */
	if (ppp)
		*ppp = pp;
	return (p);
}

/* table, name (key) to search for, hash(n) */
struct tbl *
ktsearch(struct table *tp, const char *n, uint32_t h)
{
	return (tp->size ? ktscan(tp, n, h, NULL) : NULL);
}

/* table, name (key) to enter, hash(n) */
struct tbl *
ktenter(struct table *tp, const char *n, uint32_t h)
{
	struct tbl **pp, *p;
	int len;

	if (tp->size == 0)
		texpand(tp, INIT_TBLS);
 Search:
	if ((p = ktscan(tp, n, h, &pp)))
		return (p);

	if (tp->nfree <= 0) {
		/* too full */
		texpand(tp, 2 * tp->size);
		goto Search;
	}

	/* create new tbl entry */
	len = strlen(n) + 1;
	p = alloc(offsetof(struct tbl, name[0]) + len, tp->areap);
	p->flag = 0;
	p->type = 0;
	p->areap = tp->areap;
	p->ua.hval = h;
	p->u2.field = 0;
	p->u.array = NULL;
	memcpy(p->name, n, len);

	/* enter in tp->tbls */
	tp->nfree--;
	*pp = p;
	return (p);
}

void
ktwalk(struct tstate *ts, struct table *tp)
{
	ts->left = tp->size;
	ts->next = tp->tbls;
}

struct tbl *
ktnext(struct tstate *ts)
{
	while (--ts->left >= 0) {
		struct tbl *p = *ts->next++;
		if (p != NULL && (p->flag & DEFINED))
			return (p);
	}
	return (NULL);
}

static int
tnamecmp(const void *p1, const void *p2)
{
	const struct tbl *a = *((const struct tbl * const *)p1);
	const struct tbl *b = *((const struct tbl * const *)p2);

	return (strcmp(a->name, b->name));
}

struct tbl **
ktsort(struct table *tp)
{
	size_t i;
	struct tbl **p, **sp, **dp;

	p = alloc((tp->size + 1) * sizeof(struct tbl *), ATEMP);
	sp = tp->tbls;		/* source */
	dp = p;			/* dest */
	i = (size_t)tp->size;
	while (i--)
		if ((*dp = *sp++) != NULL && (((*dp)->flag & DEFINED) ||
		    ((*dp)->flag & ARRAY)))
			dp++;
	qsort(p, (i = dp - p), sizeof(void *), tnamecmp);
	p[i] = NULL;
	return (p);
}

#ifdef SIGWINCH
static void
x_sigwinch(int sig MKSH_A_UNUSED)
{
	/* this runs inside interrupt context, with errno saved */

	got_winch = 1;
}
#endif
