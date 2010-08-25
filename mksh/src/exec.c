/*	$OpenBSD: exec.c,v 1.49 2009/01/29 23:27:26 jaredy Exp $	*/

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

__RCSID("$MirOS: src/bin/mksh/exec.c,v 1.75 2010/07/17 22:09:34 tg Exp $");

#ifndef MKSH_DEFAULT_EXECSHELL
#define MKSH_DEFAULT_EXECSHELL	"/bin/sh"
#endif

static int comexec(struct op *, struct tbl *volatile, const char **,
    int volatile, volatile int *);
static void scriptexec(struct op *, const char **) MKSH_A_NORETURN;
static int call_builtin(struct tbl *, const char **);
static int iosetup(struct ioword *, struct tbl *);
static int herein(const char *, int);
static const char *do_selectargs(const char **, bool);
static Test_op dbteste_isa(Test_env *, Test_meta);
static const char *dbteste_getopnd(Test_env *, Test_op, bool);
static void dbteste_error(Test_env *, int, const char *);

/*
 * execute command tree
 */
int
execute(struct op *volatile t,
    volatile int flags,		/* if XEXEC don't fork */
    volatile int * volatile xerrok)
{
	int i;
	volatile int rv = 0, dummy = 0;
	int pv[2];
	const char ** volatile ap;
	char ** volatile up;
	const char *s, *cp;
	struct ioword **iowp;
	struct tbl *tp = NULL;

	if (t == NULL)
		return (0);

	/* Caller doesn't care if XERROK should propagate. */
	if (xerrok == NULL)
		xerrok = &dummy;

	if ((flags&XFORK) && !(flags&XEXEC) && t->type != TPIPE)
		/* run in sub-process */
		return (exchild(t, flags & ~XTIME, xerrok, -1));

	newenv(E_EXEC);
	if (trap)
		runtraps(0);

	if (t->type == TCOM) {
		/* Clear subst_exstat before argument expansion. Used by
		 * null commands (see comexec() and c_eval()) and by c_set().
		 */
		subst_exstat = 0;

		current_lineno = t->lineno;	/* for $LINENO */

		/* POSIX says expand command words first, then redirections,
		 * and assignments last..
		 */
		up = eval(t->args, t->u.evalflags | DOBLANK | DOGLOB | DOTILDE);
		if (flags & XTIME)
			/* Allow option parsing (bizarre, but POSIX) */
			timex_hook(t, &up);
		ap = (const char **)up;
		if (Flag(FXTRACE) && ap[0]) {
			shf_fprintf(shl_out, "%s",
				substitute(str_val(global("PS4")), 0));
			for (i = 0; ap[i]; i++)
				shf_fprintf(shl_out, "%s%c", ap[i],
				    ap[i + 1] ? ' ' : '\n');
			shf_flush(shl_out);
		}
		if (ap[0])
			tp = findcom(ap[0], FC_BI|FC_FUNC);
	}
	flags &= ~XTIME;

	if (t->ioact != NULL || t->type == TPIPE || t->type == TCOPROC) {
		e->savefd = alloc(NUFILE * sizeof(short), ATEMP);
		/* initialise to not redirected */
		memset(e->savefd, 0, NUFILE * sizeof(short));
	}

	/* do redirection, to be restored in quitenv() */
	if (t->ioact != NULL)
		for (iowp = t->ioact; *iowp != NULL; iowp++) {
			if (iosetup(*iowp, tp) < 0) {
				exstat = rv = 1;
				/* Redirection failures for special commands
				 * cause (non-interactive) shell to exit.
				 */
				if (tp && tp->type == CSHELL &&
				    (tp->flag & SPEC_BI))
					errorfz();
				/* Deal with FERREXIT, quitenv(), etc. */
				goto Break;
			}
		}

	switch (t->type) {
	case TCOM:
		rv = comexec(t, tp, (const char **)ap, flags, xerrok);
		break;

	case TPAREN:
		rv = execute(t->left, flags | XFORK, xerrok);
		break;

	case TPIPE:
		flags |= XFORK;
		flags &= ~XEXEC;
		e->savefd[0] = savefd(0);
		e->savefd[1] = savefd(1);
		while (t->type == TPIPE) {
			openpipe(pv);
			ksh_dup2(pv[1], 1, false); /* stdout of curr */
			/**
			 * Let exchild() close pv[0] in child
			 * (if this isn't done, commands like
			 *	(: ; cat /etc/termcap) | sleep 1
			 * will hang forever).
			 */
			exchild(t->left, flags | XPIPEO | XCCLOSE,
			    NULL, pv[0]);
			ksh_dup2(pv[0], 0, false); /* stdin of next */
			closepipe(pv);
			flags |= XPIPEI;
			t = t->right;
		}
		restfd(1, e->savefd[1]); /* stdout of last */
		e->savefd[1] = 0; /* no need to re-restore this */
		/* Let exchild() close 0 in parent, after fork, before wait */
		i = exchild(t, flags | XPCLOSE, xerrok, 0);
		if (!(flags&XBGND) && !(flags&XXCOM))
			rv = i;
		break;

	case TLIST:
		while (t->type == TLIST) {
			execute(t->left, flags & XERROK, NULL);
			t = t->right;
		}
		rv = execute(t, flags & XERROK, xerrok);
		break;

	case TCOPROC: {
		sigset_t omask;

		/* Block sigchild as we are using things changed in the
		 * signal handler
		 */
		sigprocmask(SIG_BLOCK, &sm_sigchld, &omask);
		e->type = E_ERRH;
		i = sigsetjmp(e->jbuf, 0);
		if (i) {
			sigprocmask(SIG_SETMASK, &omask, NULL);
			quitenv(NULL);
			unwind(i);
			/* NOTREACHED */
		}
		/* Already have a (live) co-process? */
		if (coproc.job && coproc.write >= 0)
			errorf("coprocess already exists");

		/* Can we re-use the existing co-process pipe? */
		coproc_cleanup(true);

		/* do this before opening pipes, in case these fail */
		e->savefd[0] = savefd(0);
		e->savefd[1] = savefd(1);

		openpipe(pv);
		if (pv[0] != 0) {
			ksh_dup2(pv[0], 0, false);
			close(pv[0]);
		}
		coproc.write = pv[1];
		coproc.job = NULL;

		if (coproc.readw >= 0)
			ksh_dup2(coproc.readw, 1, false);
		else {
			openpipe(pv);
			coproc.read = pv[0];
			ksh_dup2(pv[1], 1, false);
			coproc.readw = pv[1];	 /* closed before first read */
			coproc.njobs = 0;
			/* create new coprocess id */
			++coproc.id;
		}
		sigprocmask(SIG_SETMASK, &omask, NULL);
		e->type = E_EXEC; /* no more need for error handler */

		/* exchild() closes coproc.* in child after fork,
		 * will also increment coproc.njobs when the
		 * job is actually created.
		 */
		flags &= ~XEXEC;
		exchild(t->left, flags | XBGND | XFORK | XCOPROC | XCCLOSE,
		    NULL, coproc.readw);
		break;
	}

	case TASYNC:
		/* XXX non-optimal, I think - "(foo &)", forks for (),
		 * forks again for async... parent should optimise
		 * this to "foo &"...
		 */
		rv = execute(t->left, (flags&~XEXEC)|XBGND|XFORK, xerrok);
		break;

	case TOR:
	case TAND:
		rv = execute(t->left, XERROK, xerrok);
		if ((rv == 0) == (t->type == TAND))
			rv = execute(t->right, XERROK, xerrok);
		flags |= XERROK;
		if (xerrok)
			*xerrok = 1;
		break;

	case TBANG:
		rv = !execute(t->right, XERROK, xerrok);
		flags |= XERROK;
		if (xerrok)
			*xerrok = 1;
		break;

	case TDBRACKET: {
		Test_env te;

		te.flags = TEF_DBRACKET;
		te.pos.wp = t->args;
		te.isa = dbteste_isa;
		te.getopnd = dbteste_getopnd;
		te.eval = test_eval;
		te.error = dbteste_error;

		rv = test_parse(&te);
		break;
	}

	case TFOR:
	case TSELECT: {
		volatile bool is_first = true;
		ap = (t->vars == NULL) ? e->loc->argv + 1 :
		    (const char **)eval((const char **)t->vars,
		    DOBLANK | DOGLOB | DOTILDE);
		e->type = E_LOOP;
		while (1) {
			i = sigsetjmp(e->jbuf, 0);
			if (!i)
				break;
			if ((e->flags&EF_BRKCONT_PASS) ||
			    (i != LBREAK && i != LCONTIN)) {
				quitenv(NULL);
				unwind(i);
			} else if (i == LBREAK) {
				rv = 0;
				goto Break;
			}
		}
		rv = 0; /* in case of a continue */
		if (t->type == TFOR) {
			while (*ap != NULL) {
				setstr(global(t->str), *ap++, KSH_UNWIND_ERROR);
				rv = execute(t->left, flags & XERROK, xerrok);
			}
		} else { /* TSELECT */
			for (;;) {
				if (!(cp = do_selectargs(ap, is_first))) {
					rv = 1;
					break;
				}
				is_first = false;
				setstr(global(t->str), cp, KSH_UNWIND_ERROR);
				execute(t->left, flags & XERROK, xerrok);
			}
		}
		break;
	}

	case TWHILE:
	case TUNTIL:
		e->type = E_LOOP;
		while (1) {
			i = sigsetjmp(e->jbuf, 0);
			if (!i)
				break;
			if ((e->flags&EF_BRKCONT_PASS) ||
			    (i != LBREAK && i != LCONTIN)) {
				quitenv(NULL);
				unwind(i);
			} else if (i == LBREAK) {
				rv = 0;
				goto Break;
			}
		}
		rv = 0; /* in case of a continue */
		while ((execute(t->left, XERROK, NULL) == 0) ==
		    (t->type == TWHILE))
			rv = execute(t->right, flags & XERROK, xerrok);
		break;

	case TIF:
	case TELIF:
		if (t->right == NULL)
			break;	/* should be error */
		rv = execute(t->left, XERROK, NULL) == 0 ?
		    execute(t->right->left, flags & XERROK, xerrok) :
		    execute(t->right->right, flags & XERROK, xerrok);
		break;

	case TCASE:
		cp = evalstr(t->str, DOTILDE);
		for (t = t->left; t != NULL && t->type == TPAT; t = t->right)
		    for (ap = (const char **)t->vars; *ap; ap++)
			if ((s = evalstr(*ap, DOTILDE|DOPAT)) &&
			    gmatchx(cp, s, false))
				goto Found;
		break;
 Found:
		rv = execute(t->left, flags & XERROK, xerrok);
		break;

	case TBRACE:
		rv = execute(t->left, flags & XERROK, xerrok);
		break;

	case TFUNCT:
		rv = define(t->str, t);
		break;

	case TTIME:
		/* Clear XEXEC so nested execute() call doesn't exit
		 * (allows "ls -l | time grep foo").
		 */
		rv = timex(t, flags & ~XEXEC, xerrok);
		break;

	case TEXEC:		/* an eval'd TCOM */
		s = t->args[0];
		up = makenv();
		restoresigs();
		cleanup_proc_env();
		{
			union mksh_ccphack cargs;

			cargs.ro = t->args;
			execve(t->str, cargs.rw, up);
			rv = errno;
		}
		if (rv == ENOEXEC)
			scriptexec(t, (const char **)up);
		else
			errorf("%s: %s", s, strerror(rv));
	}
 Break:
	exstat = rv;

	quitenv(NULL);		/* restores IO */
	if ((flags&XEXEC))
		unwind(LEXIT);	/* exit child */
	if (rv != 0 && !(flags & XERROK) &&
	    (xerrok == NULL || !*xerrok)) {
		trapsig(SIGERR_);
		if (Flag(FERREXIT))
			unwind(LERROR);
	}
	return (rv);
}

/*
 * execute simple command
 */

static int
comexec(struct op *t, struct tbl *volatile tp, const char **ap,
    volatile int flags, volatile int *xerrok)
{
	int i;
	volatile int rv = 0;
	const char *cp;
	const char **lastp;
	static struct op texec; /* Must be static (XXX but why?) */
	int type_flags;
	int keepasn_ok;
	int fcflags = FC_BI|FC_FUNC|FC_PATH;
	bool bourne_function_call = false;
	struct block *l_expand, *l_assign;

	/* snag the last argument for $_ XXX not the same as AT&T ksh,
	 * which only seems to set $_ after a newline (but not in
	 * functions/dot scripts, but in interactive and script) -
	 * perhaps save last arg here and set it in shell()?.
	 */
	if (Flag(FTALKING) && *(lastp = ap)) {
		while (*++lastp)
			;
		/* setstr() can't fail here */
		setstr(typeset("_", LOCAL, 0, INTEGER, 0), *--lastp,
		    KSH_RETURN_ERROR);
	}

	/* Deal with the shell builtins builtin, exec and command since
	 * they can be followed by other commands. This must be done before
	 * we know if we should create a local block which must be done
	 * before we can do a path search (in case the assignments change
	 * PATH).
	 * Odd cases:
	 *	FOO=bar exec >/dev/null		FOO is kept but not exported
	 *	FOO=bar exec foobar		FOO is exported
	 *	FOO=bar command exec >/dev/null	FOO is neither kept nor exported
	 *	FOO=bar command			FOO is neither kept nor exported
	 *	PATH=... foobar			use new PATH in foobar search
	 */
	keepasn_ok = 1;
	while (tp && tp->type == CSHELL) {
		fcflags = FC_BI|FC_FUNC|FC_PATH;/* undo effects of command */
		if (tp->val.f == c_builtin) {
			if ((cp = *++ap) == NULL) {
				tp = NULL;
				break;
			}
			tp = findcom(cp, FC_BI);
			if (tp == NULL)
				errorf("builtin: %s: not a builtin", cp);
			continue;
		} else if (tp->val.f == c_exec) {
			if (ap[1] == NULL)
				break;
			ap++;
			flags |= XEXEC;
		} else if (tp->val.f == c_command) {
			int optc, saw_p = 0;

			/* Ugly dealing with options in two places (here and
			 * in c_command(), but such is life)
			 */
			ksh_getopt_reset(&builtin_opt, 0);
			while ((optc = ksh_getopt(ap, &builtin_opt, ":p")) == 'p')
				saw_p = 1;
			if (optc != EOF)
				break;	/* command -vV or something */
			/* don't look for functions */
			fcflags = FC_BI|FC_PATH;
			if (saw_p) {
				if (Flag(FRESTRICTED)) {
					warningf(true,
					    "command -p: restricted");
					rv = 1;
					goto Leave;
				}
				fcflags |= FC_DEFPATH;
			}
			ap += builtin_opt.optind;
			/* POSIX says special builtins lose their status
			 * if accessed using command.
			 */
			keepasn_ok = 0;
			if (!ap[0]) {
				/* ensure command with no args exits with 0 */
				subst_exstat = 0;
				break;
			}
		} else
			break;
		tp = findcom(ap[0], fcflags & (FC_BI|FC_FUNC));
	}
	l_expand = e->loc;
	if (keepasn_ok && (!ap[0] || (tp && (tp->flag & KEEPASN))))
		type_flags = 0;
	else {
		/* create new variable/function block */
		newblock();
		/* ksh functions don't keep assignments, POSIX functions do. */
		if (keepasn_ok && tp && tp->type == CFUNC &&
		    !(tp->flag & FKSH)) {
			bourne_function_call = true;
			type_flags = EXPORT;
		} else
			type_flags = LOCAL|LOCAL_COPY|EXPORT;
	}
	l_assign = e->loc;
	if (Flag(FEXPORT))
		type_flags |= EXPORT;
	for (i = 0; t->vars[i]; i++) {
		/* do NOT lookup in the new var/fn block just created */
		e->loc = l_expand;
		cp = evalstr(t->vars[i], DOASNTILDE);
		e->loc = l_assign;
		/* but assign in there as usual */

		if (Flag(FXTRACE)) {
			if (i == 0)
				shf_fprintf(shl_out, "%s",
					substitute(str_val(global("PS4")), 0));
			shf_fprintf(shl_out, "%s%c", cp,
			    t->vars[i + 1] ? ' ' : '\n');
			if (!t->vars[i + 1])
				shf_flush(shl_out);
		}
		typeset(cp, type_flags, 0, 0, 0);
		if (bourne_function_call && !(type_flags & EXPORT))
			typeset(cp, LOCAL|LOCAL_COPY|EXPORT, 0, 0, 0);
	}

	if ((cp = *ap) == NULL) {
		rv = subst_exstat;
		goto Leave;
	} else if (!tp) {
		if (Flag(FRESTRICTED) && vstrchr(cp, '/')) {
			warningf(true, "%s: restricted", cp);
			rv = 1;
			goto Leave;
		}
		tp = findcom(cp, fcflags);
	}

	switch (tp->type) {
	case CSHELL:			/* shell built-in */
		rv = call_builtin(tp, (const char **)ap);
		break;

	case CFUNC: {			/* function call */
		volatile unsigned char old_xflag;
		volatile Tflag old_inuse;
		const char *volatile old_kshname;

		if (!(tp->flag & ISSET)) {
			struct tbl *ftp;

			if (!tp->u.fpath) {
				if (tp->u2.errno_) {
					warningf(true,
					    "%s: can't find function "
					    "definition file - %s",
					    cp, strerror(tp->u2.errno_));
					rv = 126;
				} else {
					warningf(true,
					    "%s: can't find function "
					    "definition file", cp);
					rv = 127;
				}
				break;
			}
			if (include(tp->u.fpath, 0, NULL, 0) < 0) {
				rv = errno;
				warningf(true,
				    "%s: can't open function definition file %s - %s",
				    cp, tp->u.fpath, strerror(rv));
				rv = 127;
				break;
			}
			if (!(ftp = findfunc(cp, hash(cp), false)) ||
			    !(ftp->flag & ISSET)) {
				warningf(true,
				    "%s: function not defined by %s",
				    cp, tp->u.fpath);
				rv = 127;
				break;
			}
			tp = ftp;
		}

		/* ksh functions set $0 to function name, POSIX functions leave
		 * $0 unchanged.
		 */
		old_kshname = kshname;
		if (tp->flag & FKSH)
			kshname = ap[0];
		else
			ap[0] = kshname;
		e->loc->argv = ap;
		for (i = 0; *ap++ != NULL; i++)
			;
		e->loc->argc = i - 1;
		/* ksh-style functions handle getopts sanely,
		 * Bourne/POSIX functions are insane...
		 */
		if (tp->flag & FKSH) {
			e->loc->flags |= BF_DOGETOPTS;
			e->loc->getopts_state = user_opt;
			getopts_reset(1);
		}

		old_xflag = Flag(FXTRACE);
		Flag(FXTRACE) = tp->flag & TRACE ? 1 : 0;

		old_inuse = tp->flag & FINUSE;
		tp->flag |= FINUSE;

		e->type = E_FUNC;
		i = sigsetjmp(e->jbuf, 0);
		if (i == 0) {
			/* seems odd to pass XERROK here, but AT&T ksh does */
			exstat = execute(tp->val.t, flags & XERROK, xerrok);
			i = LRETURN;
		}
		kshname = old_kshname;
		Flag(FXTRACE) = old_xflag;
		tp->flag = (tp->flag & ~FINUSE) | old_inuse;
		/* Were we deleted while executing? If so, free the execution
		 * tree. todo: Unfortunately, the table entry is never re-used
		 * until the lookup table is expanded.
		 */
		if ((tp->flag & (FDELETE|FINUSE)) == FDELETE) {
			if (tp->flag & ALLOC) {
				tp->flag &= ~ALLOC;
				tfree(tp->val.t, tp->areap);
			}
			tp->flag = 0;
		}
		switch (i) {
		case LRETURN:
		case LERROR:
			rv = exstat;
			break;
		case LINTR:
		case LEXIT:
		case LLEAVE:
		case LSHELL:
			quitenv(NULL);
			unwind(i);
			/* NOTREACHED */
		default:
			quitenv(NULL);
			internal_errorf("CFUNC %d", i);
		}
		break;
	}

	case CEXEC:		/* executable command */
	case CTALIAS:		/* tracked alias */
		if (!(tp->flag&ISSET)) {
			/* errno_ will be set if the named command was found
			 * but could not be executed (permissions, no execute
			 * bit, directory, etc). Print out a (hopefully)
			 * useful error message and set the exit status to 126.
			 */
			if (tp->u2.errno_) {
				warningf(true, "%s: cannot execute - %s", cp,
				    strerror(tp->u2.errno_));
				rv = 126;	/* POSIX */
			} else {
				warningf(true, "%s: not found", cp);
				rv = 127;
			}
			break;
		}

		/* set $_ to programme's full path */
		/* setstr() can't fail here */
		setstr(typeset("_", LOCAL|EXPORT, 0, INTEGER, 0),
		    tp->val.s, KSH_RETURN_ERROR);

		if (flags&XEXEC) {
			j_exit();
			if (!(flags&XBGND)
#ifndef MKSH_UNEMPLOYED
			    || Flag(FMONITOR)
#endif
			    ) {
				setexecsig(&sigtraps[SIGINT], SS_RESTORE_ORIG);
				setexecsig(&sigtraps[SIGQUIT], SS_RESTORE_ORIG);
			}
		}

		/* to fork we set up a TEXEC node and call execute */
		texec.type = TEXEC;
		texec.left = t;	/* for tprint */
		texec.str = tp->val.s;
		texec.args = ap;
		rv = exchild(&texec, flags, xerrok, -1);
		break;
	}
 Leave:
	if (flags & XEXEC) {
		exstat = rv;
		unwind(LLEAVE);
	}
	return (rv);
}

static void
scriptexec(struct op *tp, const char **ap)
{
	const char *sh;
#ifndef MKSH_SMALL
	unsigned char *cp;
	char buf[64];		/* 64 == MAXINTERP in MirBSD <sys/param.h> */
	int fd;
#endif
	union mksh_ccphack args, cap;

	sh = str_val(global("EXECSHELL"));
	if (sh && *sh)
		sh = search(sh, path, X_OK, NULL);
	if (!sh || !*sh)
		sh = MKSH_DEFAULT_EXECSHELL;

	*tp->args-- = tp->str;

#ifndef MKSH_SMALL
	if ((fd = open(tp->str, O_RDONLY)) >= 0) {
		/* read first MAXINTERP octets from file */
		if (read(fd, buf, sizeof(buf)) <= 0)
			/* read error -> no good */
			buf[0] = '\0';
		close(fd);
		/* scan for newline (or CR) or NUL _before_ end of buffer */
		cp = (unsigned char *)buf;
		while ((char *)cp < (buf + sizeof(buf)))
			if (*cp == '\0' || *cp == '\n' || *cp == '\r') {
				*cp = '\0';
				break;
			} else
				++cp;
		/* if the shebang line is longer than MAXINTERP, bail out */
		if ((char *)cp >= (buf + sizeof(buf)))
			goto noshebang;
		/* skip UTF-8 Byte Order Mark, if present */
		cp = (unsigned char *)buf;
		if ((cp[0] == 0xEF) && (cp[1] == 0xBB) && (cp[2] == 0xBF))
			cp += 3;
		/* bail out if read error (above) or no shebang */
		if ((cp[0] != '#') || (cp[1] != '!'))
			goto noshebang;
		cp += 2;
		/* skip whitespace before shell name */
		while (*cp == ' ' || *cp == '\t')
			++cp;
		/* just whitespace on the line? */
		if (*cp == '\0')
			goto noshebang;
		/* no, we actually found an interpreter name */
		sh = (char *)cp;
		/* look for end of shell/interpreter name */
		while (*cp != ' ' && *cp != '\t' && *cp != '\0')
			++cp;
		/* any arguments? */
		if (*cp) {
			*cp++ = '\0';
			/* skip spaces before arguments */
			while (*cp == ' ' || *cp == '\t')
				++cp;
			/* pass it all in ONE argument (historic reasons) */
			if (*cp)
				*tp->args-- = (char *)cp;
		}
 noshebang:
		fd = buf[0] << 8 | buf[1];
		if ((fd == /* OMAGIC */ 0407) ||
		    (fd == /* NMAGIC */ 0410) ||
		    (fd == /* ZMAGIC */ 0413) ||
		    (fd == /* QMAGIC */ 0314) ||
		    (fd == /* ECOFF_I386 */ 0x4C01) ||
		    (fd == /* ECOFF_M68K */ 0x0150 || fd == 0x5001) ||
		    (fd == /* ECOFF_SH */   0x0500 || fd == 0x0005) ||
		    (fd == 0x7F45 && buf[2] == 'L' && buf[3] == 'F') ||
		    (fd == /* "MZ" */ 0x4D5A) ||
		    (fd == /* gzip */ 0x1F8B))
			errorf("%s: not executable: magic %04X", tp->str, fd);
	}
#endif
	args.ro = tp->args;
	*args.ro = sh;

	cap.ro = ap;
	execve(args.rw[0], args.rw, cap.rw);

	/* report both the programme that was run and the bogus interpreter */
	errorf("%s: %s: %s", tp->str, sh, strerror(errno));
}

int
shcomexec(const char **wp)
{
	struct tbl *tp;

	tp = ktsearch(&builtins, *wp, hash(*wp));
	if (tp == NULL)
		internal_errorf("shcomexec: %s", *wp);
	return (call_builtin(tp, wp));
}

/*
 * Search function tables for a function. If create set, a table entry
 * is created if none is found.
 */
struct tbl *
findfunc(const char *name, uint32_t h, bool create)
{
	struct block *l;
	struct tbl *tp = NULL;

	for (l = e->loc; l; l = l->next) {
		tp = ktsearch(&l->funs, name, h);
		if (tp)
			break;
		if (!l->next && create) {
			tp = ktenter(&l->funs, name, h);
			tp->flag = DEFINED;
			tp->type = CFUNC;
			tp->val.t = NULL;
			break;
		}
	}
	return (tp);
}

/*
 * define function. Returns 1 if function is being undefined (t == 0) and
 * function did not exist, returns 0 otherwise.
 */
int
define(const char *name, struct op *t)
{
	struct tbl *tp;
	bool was_set = false;

	while (1) {
		tp = findfunc(name, hash(name), true);

		if (tp->flag & ISSET)
			was_set = true;
		/* If this function is currently being executed, we zap this
		 * table entry so findfunc() won't see it
		 */
		if (tp->flag & FINUSE) {
			tp->name[0] = '\0';
			tp->flag &= ~DEFINED; /* ensure it won't be found */
			tp->flag |= FDELETE;
		} else
			break;
	}

	if (tp->flag & ALLOC) {
		tp->flag &= ~(ISSET|ALLOC);
		tfree(tp->val.t, tp->areap);
	}

	if (t == NULL) {		/* undefine */
		ktdelete(tp);
		return (was_set ? 0 : 1);
	}

	tp->val.t = tcopy(t->left, tp->areap);
	tp->flag |= (ISSET|ALLOC);
	if (t->u.ksh_func)
		tp->flag |= FKSH;

	return (0);
}

/*
 * add builtin
 */
void
builtin(const char *name, int (*func) (const char **))
{
	struct tbl *tp;
	Tflag flag;

	/* see if any flags should be set for this builtin */
	for (flag = 0; ; name++) {
		if (*name == '=')	/* command does variable assignment */
			flag |= KEEPASN;
		else if (*name == '*')	/* POSIX special builtin */
			flag |= SPEC_BI;
		else if (*name == '+')	/* POSIX regular builtin */
			flag |= REG_BI;
		else
			break;
	}

	tp = ktenter(&builtins, name, hash(name));
	tp->flag = DEFINED | flag;
	tp->type = CSHELL;
	tp->val.f = func;
}

/*
 * find command
 * either function, hashed command, or built-in (in that order)
 */
struct tbl *
findcom(const char *name, int flags)
{
	static struct tbl temp;
	uint32_t h = hash(name);
	struct tbl *tp = NULL, *tbi;
	unsigned char insert = Flag(FTRACKALL);	/* insert if not found */
	char *fpath;			/* for function autoloading */
	union mksh_cchack npath;

	if (vstrchr(name, '/')) {
		insert = 0;
		/* prevent FPATH search below */
		flags &= ~FC_FUNC;
		goto Search;
	}
	tbi = (flags & FC_BI) ? ktsearch(&builtins, name, h) : NULL;
	/* POSIX says special builtins first, then functions, then
	 * POSIX regular builtins, then search path...
	 */
	if ((flags & FC_SPECBI) && tbi && (tbi->flag & SPEC_BI))
		tp = tbi;
	if (!tp && (flags & FC_FUNC)) {
		tp = findfunc(name, h, false);
		if (tp && !(tp->flag & ISSET)) {
			if ((fpath = str_val(global("FPATH"))) == null) {
				tp->u.fpath = NULL;
				tp->u2.errno_ = 0;
			} else
				tp->u.fpath = search(name, fpath, R_OK,
				    &tp->u2.errno_);
		}
	}
	if (!tp && (flags & FC_REGBI) && tbi && (tbi->flag & REG_BI))
		tp = tbi;
	if (!tp && (flags & FC_UNREGBI) && tbi)
		tp = tbi;
	if (!tp && (flags & FC_PATH) && !(flags & FC_DEFPATH)) {
		tp = ktsearch(&taliases, name, h);
		if (tp && (tp->flag & ISSET) && access(tp->val.s, X_OK) != 0) {
			if (tp->flag & ALLOC) {
				tp->flag &= ~ALLOC;
				afree(tp->val.s, APERM);
			}
			tp->flag &= ~ISSET;
		}
	}

 Search:
	if ((!tp || (tp->type == CTALIAS && !(tp->flag&ISSET))) &&
	    (flags & FC_PATH)) {
		if (!tp) {
			if (insert && !(flags & FC_DEFPATH)) {
				tp = ktenter(&taliases, name, h);
				tp->type = CTALIAS;
			} else {
				tp = &temp;
				tp->type = CEXEC;
			}
			tp->flag = DEFINED;	/* make ~ISSET */
		}
		npath.ro = search(name, flags & FC_DEFPATH ? def_path : path,
		    X_OK, &tp->u2.errno_);
		if (npath.ro) {
			strdupx(tp->val.s, npath.ro, APERM);
			if (npath.ro != name)
				afree(npath.rw, ATEMP);
			tp->flag |= ISSET|ALLOC;
		} else if ((flags & FC_FUNC) &&
		    (fpath = str_val(global("FPATH"))) != null &&
		    (npath.ro = search(name, fpath, R_OK,
		    &tp->u2.errno_)) != NULL) {
			/* An undocumented feature of AT&T ksh is that it
			 * searches FPATH if a command is not found, even
			 * if the command hasn't been set up as an autoloaded
			 * function (ie, no typeset -uf).
			 */
			tp = &temp;
			tp->type = CFUNC;
			tp->flag = DEFINED; /* make ~ISSET */
			tp->u.fpath = npath.ro;
		}
	}
	return (tp);
}

/*
 * flush executable commands with relative paths
 */
void
flushcom(int all)	/* just relative or all */
{
	struct tbl *tp;
	struct tstate ts;

	for (ktwalk(&ts, &taliases); (tp = ktnext(&ts)) != NULL; )
		if ((tp->flag&ISSET) && (all || tp->val.s[0] != '/')) {
			if (tp->flag&ALLOC) {
				tp->flag &= ~(ALLOC|ISSET);
				afree(tp->val.s, APERM);
			}
			tp->flag &= ~ISSET;
		}
}

/* Check if path is something we want to find. Returns -1 for failure. */
int
search_access(const char *lpath, int mode,
    int *errnop)	/* set if candidate found, but not suitable */
{
	int ret, err = 0;
	struct stat statb;

	if (stat(lpath, &statb) < 0)
		return (-1);
	ret = access(lpath, mode);
	if (ret < 0)
		err = errno; /* File exists, but we can't access it */
	else if (mode == X_OK && (!S_ISREG(statb.st_mode) ||
	    !(statb.st_mode & (S_IXUSR|S_IXGRP|S_IXOTH)))) {
		/* This 'cause access() says root can execute everything */
		ret = -1;
		err = S_ISDIR(statb.st_mode) ? EISDIR : EACCES;
	}
	if (err && errnop && !*errnop)
		*errnop = err;
	return (ret);
}

/*
 * search for command with PATH
 */
const char *
search(const char *name, const char *lpath,
    int mode,		/* R_OK or X_OK */
    int *errnop)	/* set if candidate found, but not suitable */
{
	const char *sp, *p;
	char *xp;
	XString xs;
	int namelen;

	if (errnop)
		*errnop = 0;
	if (vstrchr(name, '/')) {
		if (search_access(name, mode, errnop) == 0)
			return (name);
		return (NULL);
	}

	namelen = strlen(name) + 1;
	Xinit(xs, xp, 128, ATEMP);

	sp = lpath;
	while (sp != NULL) {
		xp = Xstring(xs, xp);
		if (!(p = cstrchr(sp, ':')))
			p = sp + strlen(sp);
		if (p != sp) {
			XcheckN(xs, xp, p - sp);
			memcpy(xp, sp, p - sp);
			xp += p - sp;
			*xp++ = '/';
		}
		sp = p;
		XcheckN(xs, xp, namelen);
		memcpy(xp, name, namelen);
		if (search_access(Xstring(xs, xp), mode, errnop) == 0)
			return (Xclose(xs, xp + namelen));
		if (*sp++ == '\0')
			sp = NULL;
	}
	Xfree(xs, xp);
	return (NULL);
}

static int
call_builtin(struct tbl *tp, const char **wp)
{
	int rv;

	builtin_argv0 = wp[0];
	builtin_flag = tp->flag;
	shf_reopen(1, SHF_WR, shl_stdout);
	shl_stdout_ok = 1;
	ksh_getopt_reset(&builtin_opt, GF_ERROR);
	rv = (*tp->val.f)(wp);
	shf_flush(shl_stdout);
	shl_stdout_ok = 0;
	builtin_flag = 0;
	builtin_argv0 = NULL;
	return (rv);
}

/*
 * set up redirection, saving old fds in e->savefd
 */
static int
iosetup(struct ioword *iop, struct tbl *tp)
{
	int u = -1;
	char *cp = iop->name;
	int iotype = iop->flag & IOTYPE;
	int do_open = 1, do_close = 0, flags = 0;
	struct ioword iotmp;
	struct stat statb;

	if (iotype != IOHERE)
		cp = evalonestr(cp, DOTILDE|(Flag(FTALKING_I) ? DOGLOB : 0));

	/* Used for tracing and error messages to print expanded cp */
	iotmp = *iop;
	iotmp.name = (iotype == IOHERE) ? NULL : cp;
	iotmp.flag |= IONAMEXP;

	if (Flag(FXTRACE))
		shellf("%s%s\n",
		    substitute(str_val(global("PS4")), 0),
		    snptreef(NULL, 32, "%R", &iotmp));

	switch (iotype) {
	case IOREAD:
		flags = O_RDONLY;
		break;

	case IOCAT:
		flags = O_WRONLY | O_APPEND | O_CREAT;
		break;

	case IOWRITE:
		flags = O_WRONLY | O_CREAT | O_TRUNC;
		/* The stat() is here to allow redirections to
		 * things like /dev/null without error.
		 */
		if (Flag(FNOCLOBBER) && !(iop->flag & IOCLOB) &&
		    (stat(cp, &statb) < 0 || S_ISREG(statb.st_mode)))
			flags |= O_EXCL;
		break;

	case IORDWR:
		flags = O_RDWR | O_CREAT;
		break;

	case IOHERE:
		do_open = 0;
		/* herein() returns -2 if error has been printed */
		u = herein(iop->heredoc, iop->flag & IOEVAL);
		/* cp may have wrong name */
		break;

	case IODUP: {
		const char *emsg;

		do_open = 0;
		if (*cp == '-' && !cp[1]) {
			u = 1009;	 /* prevent error return below */
			do_close = 1;
		} else if ((u = check_fd(cp,
		    X_OK | ((iop->flag & IORDUP) ? R_OK : W_OK),
		    &emsg)) < 0) {
			warningf(true, "%s: %s",
			    snptreef(NULL, 32, "%R", &iotmp), emsg);
			return (-1);
		}
		if (u == iop->unit)
			return (0);		/* "dup from" == "dup to" */
		break;
	}
	}

	if (do_open) {
		if (Flag(FRESTRICTED) && (flags & O_CREAT)) {
			warningf(true, "%s: restricted", cp);
			return (-1);
		}
		u = open(cp, flags, 0666);
	}
	if (u < 0) {
		/* herein() may already have printed message */
		if (u == -1) {
			u = errno;
			warningf(true, "cannot %s %s: %s",
			    iotype == IODUP ? "dup" :
			    (iotype == IOREAD || iotype == IOHERE) ?
			    "open" : "create", cp, strerror(u));
		}
		return (-1);
	}
	/* Do not save if it has already been redirected (i.e. "cat >x >y"). */
	if (e->savefd[iop->unit] == 0) {
		/* If these are the same, it means unit was previously closed */
		if (u == iop->unit)
			e->savefd[iop->unit] = -1;
		else
			/* c_exec() assumes e->savefd[fd] set for any
			 * redirections. Ask savefd() not to close iop->unit;
			 * this allows error messages to be seen if iop->unit
			 * is 2; also means we can't lose the fd (eg, both
			 * dup2 below and dup2 in restfd() failing).
			 */
			e->savefd[iop->unit] = savefd(iop->unit);
	}

	if (do_close)
		close(iop->unit);
	else if (u != iop->unit) {
		if (ksh_dup2(u, iop->unit, true) < 0) {
			int ev;

			ev = errno;
			warningf(true,
			    "could not finish (dup) redirection %s: %s",
			    snptreef(NULL, 32, "%R", &iotmp),
			    strerror(ev));
			if (iotype != IODUP)
				close(u);
			return (-1);
		}
		if (iotype != IODUP)
			close(u);
		/* Touching any co-process fd in an empty exec
		 * causes the shell to close its copies
		 */
		else if (tp && tp->type == CSHELL && tp->val.f == c_exec) {
			if (iop->flag & IORDUP)	/* possible exec <&p */
				coproc_read_close(u);
			else			/* possible exec >&p */
				coproc_write_close(u);
		}
	}
	if (u == 2) /* Clear any write errors */
		shf_reopen(2, SHF_WR, shl_out);
	return (0);
}

/*
 * open here document temp file.
 * if unquoted here, expand here temp file into second temp file.
 */
static int
herein(const char *content, int sub)
{
	volatile int fd = -1;
	struct source *s, *volatile osource;
	struct shf *volatile shf;
	struct temp *h;
	int i;

	/* ksh -c 'cat << EOF' can cause this... */
	if (content == NULL) {
		warningf(true, "here document missing");
		return (-2); /* special to iosetup(): don't print error */
	}

	/* Create temp file to hold content (done before newenv so temp
	 * doesn't get removed too soon).
	 */
	h = maketemp(ATEMP, TT_HEREDOC_EXP, &e->temps);
	if (!(shf = h->shf) || (fd = open(h->name, O_RDONLY, 0)) < 0) {
		fd = errno;
		warningf(true, "can't %s temporary file %s: %s",
		    !shf ? "create" : "open",
		    h->name, strerror(fd));
		if (shf)
			shf_close(shf);
		return (-2 /* special to iosetup(): don't print error */);
	}

	osource = source;
	newenv(E_ERRH);
	i = sigsetjmp(e->jbuf, 0);
	if (i) {
		source = osource;
		quitenv(shf);
		close(fd);
		return (-2); /* special to iosetup(): don't print error */
	}
	if (sub) {
		/* Do substitutions on the content of heredoc */
		s = pushs(SSTRING, ATEMP);
		s->start = s->str = content;
		source = s;
		if (yylex(ONEWORD|HEREDOC) != LWORD)
			internal_errorf("herein: yylex");
		source = osource;
		shf_puts(evalstr(yylval.cp, 0), shf);
	} else
		shf_puts(content, shf);

	quitenv(NULL);

	if (shf_close(shf) == EOF) {
		i = errno;
		close(fd);
		fd = errno;
		warningf(true, "error writing %s: %s, %s", h->name,
		    strerror(i), strerror(fd));
		return (-2);	/* special to iosetup(): don't print error */
	}

	return (fd);
}

/*
 *	ksh special - the select command processing section
 *	print the args in column form - assuming that we can
 */
static const char *
do_selectargs(const char **ap, bool print_menu)
{
	static const char *read_args[] = {
		"read", "-r", "REPLY", NULL
	};
	char *s;
	int i, argct;

	for (argct = 0; ap[argct]; argct++)
		;
	while (1) {
		/* Menu is printed if
		 *	- this is the first time around the select loop
		 *	- the user enters a blank line
		 *	- the REPLY parameter is empty
		 */
		if (print_menu || !*str_val(global("REPLY")))
			pr_menu(ap);
		shellf("%s", str_val(global("PS3")));
		if (call_builtin(findcom("read", FC_BI), read_args))
			return (NULL);
		s = str_val(global("REPLY"));
		if (*s) {
			getn(s, &i);
			return ((i >= 1 && i <= argct) ? ap[i - 1] : null);
		}
		print_menu = 1;
	}
}

struct select_menu_info {
	const char * const *args;
	int num_width;
};

static char *select_fmt_entry(char *, int, int, const void *);

/* format a single select menu item */
static char *
select_fmt_entry(char *buf, int buflen, int i, const void *arg)
{
	const struct select_menu_info *smi =
	    (const struct select_menu_info *)arg;

	shf_snprintf(buf, buflen, "%*d) %s",
	    smi->num_width, i + 1, smi->args[i]);
	return (buf);
}

/*
 *	print a select style menu
 */
int
pr_menu(const char * const *ap)
{
	struct select_menu_info smi;
	const char * const *pp;
	int acols = 0, aocts = 0, i, n;

	/*
	 * width/column calculations were done once and saved, but this
	 * means select can't be used recursively so we re-calculate
	 * each time (could save in a structure that is returned, but
	 * it's probably not worth the bother)
	 */

	/*
	 * get dimensions of the list
	 */
	for (n = 0, pp = ap; *pp; n++, pp++) {
		i = strlen(*pp);
		if (i > aocts)
			aocts = i;
		i = utf_mbswidth(*pp);
		if (i > acols)
			acols = i;
	}

	/*
	 * we will print an index of the form "%d) " in front of
	 * each entry, so get the maximum width of this
	 */
	for (i = n, smi.num_width = 1; i >= 10; i /= 10)
		smi.num_width++;

	smi.args = ap;
	print_columns(shl_out, n, select_fmt_entry, (void *)&smi,
	    smi.num_width + 2 + aocts, smi.num_width + 2 + acols,
	    true);

	return (n);
}

/* XXX: horrible kludge to fit within the framework */
static char *plain_fmt_entry(char *, int, int, const void *);

static char *
plain_fmt_entry(char *buf, int buflen, int i, const void *arg)
{
	shf_snprintf(buf, buflen, "%s", ((const char * const *)arg)[i]);
	return (buf);
}

int
pr_list(char * const *ap)
{
	int acols = 0, aocts = 0, i, n;
	char * const *pp;

	for (n = 0, pp = ap; *pp; n++, pp++) {
		i = strlen(*pp);
		if (i > aocts)
			aocts = i;
		i = utf_mbswidth(*pp);
		if (i > acols)
			acols = i;
	}

	print_columns(shl_out, n, plain_fmt_entry, (const void *)ap,
	    aocts, acols, false);

	return (n);
}

/*
 *	[[ ... ]] evaluation routines
 */

/*
 * Test if the current token is a whatever. Accepts the current token if
 * it is. Returns 0 if it is not, non-zero if it is (in the case of
 * TM_UNOP and TM_BINOP, the returned value is a Test_op).
 */
static Test_op
dbteste_isa(Test_env *te, Test_meta meta)
{
	Test_op ret = TO_NONOP;
	int uqword;
	const char *p;

	if (!*te->pos.wp)
		return (meta == TM_END ? TO_NONNULL : TO_NONOP);

	/* unquoted word? */
	for (p = *te->pos.wp; *p == CHAR; p += 2)
		;
	uqword = *p == EOS;

	if (meta == TM_UNOP || meta == TM_BINOP) {
		if (uqword) {
			char buf[8];	/* longer than the longest operator */
			char *q = buf;
			for (p = *te->pos.wp;
			    *p == CHAR && q < &buf[sizeof(buf) - 1]; p += 2)
				*q++ = p[1];
			*q = '\0';
			ret = test_isop(meta, buf);
		}
	} else if (meta == TM_END)
		ret = TO_NONOP;
	else
		ret = (uqword && !strcmp(*te->pos.wp,
		    dbtest_tokens[(int)meta])) ? TO_NONNULL : TO_NONOP;

	/* Accept the token? */
	if (ret != TO_NONOP)
		te->pos.wp++;

	return (ret);
}

static const char *
dbteste_getopnd(Test_env *te, Test_op op, bool do_eval)
{
	const char *s = *te->pos.wp;

	if (!s)
		return (NULL);

	te->pos.wp++;

	if (!do_eval)
		return (null);

	if (op == TO_STEQL || op == TO_STNEQ)
		s = evalstr(s, DOTILDE | DOPAT);
	else
		s = evalstr(s, DOTILDE);

	return (s);
}

static void
dbteste_error(Test_env *te, int offset, const char *msg)
{
	te->flags |= TEF_ERROR;
	internal_warningf("dbteste_error: %s (offset %d)", msg, offset);
}
