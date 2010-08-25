#if defined(SHFLAGS_DEFNS)
__RCSID("$MirOS: src/bin/mksh/sh_flags.h,v 1.7 2010/07/13 13:07:58 tg Exp $");
#define FN(sname,cname,ochar,flags)	/* nothing */
#elif defined(SHFLAGS_ENUMS)
#define FN(sname,cname,ochar,flags)	cname,
#define F0(sname,cname,ochar,flags)	cname = 0,
#elif defined(SHFLAGS_ITEMS)
#define FN(sname,cname,ochar,flags)	{ sname, ochar, flags },
#endif

#ifndef F0
#define F0 FN
#endif

/*
 * special cases (see parse_args()): -A, -o, -s
 *
 * options are sorted by their longnames
 */

/* -a	all new parameters are created with the export attribute */
F0("allexport", FEXPORT, 'a', OF_ANY)

/* ./.	backwards compat: dummy, emits a warning */
FN("arc4random", FARC4RANDOM, 0, OF_ANY)

#if HAVE_NICE
/* ./.	bgnice */
FN("bgnice", FBGNICE, 0, OF_ANY)
#endif

/* ./.	enable {} globbing (non-standard) */
FN("braceexpand", FBRACEEXPAND, 0, OF_ANY)

/* ./.	Emacs command line editing mode */
FN("emacs", FEMACS, 0, OF_ANY)

/* -e	quit on error */
FN("errexit", FERREXIT, 'e', OF_ANY)

/* ./.	Emacs command line editing mode, gmacs variant */
FN("gmacs", FGMACS, 0, OF_ANY)

/* ./.	reading EOF does not exit */
FN("ignoreeof", FIGNOREEOF, 0, OF_ANY)

/* -i	interactive shell */
FN("interactive", FTALKING, 'i', OF_CMDLINE)

/* -k	name=value are recognised anywhere */
FN("keyword", FKEYWORD, 'k', OF_ANY)

/* -l	login shell */
FN("login", FLOGIN, 'l', OF_CMDLINE)

/* -X	mark dirs with / in file name completion */
FN("markdirs", FMARKDIRS, 'X', OF_ANY)

#ifndef MKSH_UNEMPLOYED
/* -m	job control monitoring */
FN("monitor", FMONITOR, 'm', OF_ANY)
#endif

/* -C	don't overwrite existing files */
FN("noclobber", FNOCLOBBER, 'C', OF_ANY)

/* -n	don't execute any commands */
FN("noexec", FNOEXEC, 'n', OF_ANY)

/* -f	don't do file globbing */
FN("noglob", FNOGLOB, 'f', OF_ANY)

/* ./.	don't kill running jobs when login shell exits */
FN("nohup", FNOHUP, 0, OF_ANY)

/* ./.	don't save functions in history (no effect) */
FN("nolog", FNOLOG, 0, OF_ANY)

#ifndef MKSH_UNEMPLOYED
/* -b	asynchronous job completion notification */
FN("notify", FNOTIFY, 'b', OF_ANY)
#endif

/* -u	using an unset variable is an error */
FN("nounset", FNOUNSET, 'u', OF_ANY)

/* ./.	don't do logical cds/pwds (non-standard) */
FN("physical", FPHYSICAL, 0, OF_ANY)

/* ./.	pdksh compat: somewhat more POSIXish mode (non-standard) */
FN("posix", FPOSIX, 0, OF_ANY)

/* -p	use suid_profile; privileged shell */
FN("privileged", FPRIVILEGED, 'p', OF_ANY)

/* -r	restricted shell */
FN("restricted", FRESTRICTED, 'r', OF_CMDLINE)

/* ./.	pdksh compat: called as sh not mksh; kludge mode (non-standard) */
FN("sh", FSH, 0, OF_ANY)

/* -s	(invocation) parse stdin (pseudo non-standard) */
FN("stdin", FSTDIN, 's', OF_CMDLINE)

/* -h	create tracked aliases for all commands */
FN("trackall", FTRACKALL, 'h', OF_ANY)

/* -U	enable UTF-8 processing (non-standard) */
FN("utf8-mode", FUNICODE, 'U', OF_ANY)

/* -v	echo input */
FN("verbose", FVERBOSE, 'v', OF_ANY)

#if !MKSH_S_NOVI
/* ./.	Vi command line editing mode */
FN("vi", FVI, 0, OF_ANY)

/* ./.	enable ESC as file name completion character (non-standard) */
FN("vi-esccomplete", FVIESCCOMPLETE, 0, OF_ANY)

/* ./.	enable Tab as file name completion character (non-standard) */
FN("vi-tabcomplete", FVITABCOMPLETE, 0, OF_ANY)

/* ./.	always read in raw mode (no effect) */
FN("viraw", FVIRAW, 0, OF_ANY)
#endif

/* -x	execution trace (display commands as they are run) */
FN("xtrace", FXTRACE, 'x', OF_ANY)

/* -c	(invocation) execute specified command */
FN(NULL, FCOMMAND, 'c', OF_CMDLINE)

/*
 * anonymous flags: used internally by shell only (not visible to user)
 */

/* ./.	(internal) initial shell was interactive */
FN(NULL, FTALKING_I, 0, OF_INTERNAL)

#undef FN
#undef F0
#undef SHFLAGS_DEFNS
#undef SHFLAGS_ENUMS
#undef SHFLAGS_ITEMS
