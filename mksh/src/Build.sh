#!/bin/sh
srcversion='$MirOS: src/bin/mksh/Build.sh,v 1.459 2010/08/24 15:46:06 tg Exp $'
#-
# Copyright (c) 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010
#	Thorsten Glaser <tg@mirbsd.org>
#
# Provided that these terms and disclaimer and all copyright notices
# are retained or reproduced in an accompanying document, permission
# is granted to deal in this work without restriction, including un-
# limited rights to use, publicly perform, distribute, sell, modify,
# merge, give away, or sublicence.
#
# This work is provided "AS IS" and WITHOUT WARRANTY of any kind, to
# the utmost extent permitted by applicable law, neither express nor
# implied; without malicious intent or gross negligence. In no event
# may a licensor, author or contributor be held liable for indirect,
# direct, other damage, loss, or other issues arising in any way out
# of dealing in the work, even if advised of the possibility of such
# damage or existence of a defect, except proven that it results out
# of said person's immediate fault when using the work as intended.
#-
# People analysing the output must whitelist conftest.c for any kind
# of compiler warning checks (mirtoconf is by design not quiet).
#
# Environment used:	CC CFLAGS CPPFLAGS LDFLAGS LIBS NOWARN NROFF
#			TARGET_OS TARGET_OSREV
# Feature selectors:	USE_PRINTF_BUILTIN
# CPPFLAGS recognised:	MKSH_ASSUME_UTF8 MKSH_BINSHREDUCED MKSH_CLS_STRING
#			MKSH_CONSERVATIVE_FDS MKSH_MIDNIGHTBSD01ASH_COMPAT
#			MKSH_NOPWNAM MKSH_NO_LIMITS MKSH_SMALL MKSH_S_NOVI
#			MKSH_UNEMPLOYED MKSH_DEFAULT_EXECSHELL MKSHRC_PATH
#			MKSH_DEFAULT_TMPDIR MKSH_CLRTOEOL_STRING MKSH_A4PB

LC_ALL=C
export LC_ALL

v() {
	$e "$*"
	eval "$@"
}

vv() {
	_c=$1
	shift
	$e "\$ $*" 2>&1
	eval "$@" >vv.out 2>&1
	sed "s^${_c} " <vv.out
}

vq() {
	eval "$@"
}

rmf() {
	for _f in "$@"; do
		case ${_f} in
		mksh.1) ;;
		*) rm -f "${_f}" ;;
		esac
	done
}

if test -d /usr/xpg4/bin/. >/dev/null 2>&1; then
	# Solaris: some of the tools have weird behaviour, use portable ones
	PATH=/usr/xpg4/bin:$PATH
	export PATH
fi

if test -n "${ZSH_VERSION+x}" && (emulate sh) >/dev/null 2>&1; then
	emulate sh
	NULLCMD=:
fi

allu=QWERTYUIOPASDFGHJKLZXCVBNM
alll=qwertyuiopasdfghjklzxcvbnm
alln=0123456789
alls=______________________________________________________________
nl='
'
tcfn=no
bi=
ui=
ao=
fx=
me=`basename "$0"`
orig_CFLAGS=$CFLAGS
phase=x
oldish_ed=stdout-ed,no-stderr-ed

if test -t 1; then
	bi='[1m'
	ui='[4m'
	ao='[0m'
fi

upper() {
	echo :"$@" | sed 's/^://' | tr $alll $allu
}

# clean up after ac_testrun()
ac_testdone() {
	eval HAVE_$fu=$fv
	fr=no
	test 0 = $fv || fr=yes
	$e "$bi==> $fd...$ao $ui$fr$ao$fx"
	fx=
}

# ac_cache label: sets f, fu, fv?=0
ac_cache() {
	f=$1
	fu=`upper $f`
	eval fv=\$HAVE_$fu
	case $fv in
	0|1)
		fx=' (cached)'
		return 0
		;;
	esac
	fv=0
	return 1
}

# ac_testinit label [!] checkif[!]0 [setlabelifcheckis[!]0] useroutput
# returns 1 if value was cached/implied, 0 otherwise: call ac_testdone
ac_testinit() {
	if ac_cache $1; then
		test x"$2" = x"!" && shift
		test x"$2" = x"" || shift
		fd=${3-$f}
		ac_testdone
		return 1
	fi
	fc=0
	if test x"$2" = x""; then
		ft=1
	else
		if test x"$2" = x"!"; then
			fc=1
			shift
		fi
		eval ft=\$HAVE_`upper $2`
		shift
	fi
	fd=${3-$f}
	if test $fc = "$ft"; then
		fv=$2
		fx=' (implied)'
		ac_testdone
		return 1
	fi
	$e ... $fd
	return 0
}

# pipe .c | ac_test[n] [!] label [!] checkif[!]0 [setlabelifcheckis[!]0] useroutput
ac_testn() {
	if test x"$1" = x"!"; then
		fr=1
		shift
	else
		fr=0
	fi
	ac_testinit "$@" || return
	cat >conftest.c
	vv ']' "$CC $CFLAGS $CPPFLAGS $LDFLAGS $NOWARN conftest.c $LIBS $ccpr"
	test $tcfn = no && test -f a.out && tcfn=a.out
	test $tcfn = no && test -f a.exe && tcfn=a.exe
	test $tcfn = no && test -f conftest && tcfn=conftest
	if test -f $tcfn; then
		test 1 = $fr || fv=1
	else
		test 0 = $fr || fv=1
	fi
	vscan=
	if test $phase = u; then
		test $ct = gcc && vscan='unrecogni[sz]ed'
		test $ct = hpcc && vscan='unsupported'
		test $ct = pcc && vscan='unsupported'
		test $ct = sunpro && vscan='-e ignored -e turned.off'
	fi
	test -n "$vscan" && grep $vscan vv.out >/dev/null 2>&1 && fv=$fr
	rmf conftest.c conftest.o ${tcfn}* vv.out
	ac_testdone
}

# ac_ifcpp cppexpr [!] label [!] checkif[!]0 [setlabelifcheckis[!]0] useroutput
ac_ifcpp() {
	expr=$1; shift
	ac_testn "$@" <<-EOF
		int main(void) { return (
		#$expr
		    0
		#else
		/* force a failure: expr is false */
		    thiswillneverbedefinedIhope()
		#endif
		    ); }
EOF
	test x"$1" = x"!" && shift
	f=$1
	fu=`upper $f`
	eval fv=\$HAVE_$fu
	test x"$fv" = x"1"
}

ac_cppflags() {
	test x"$1" = x"" || fu=$1
	fv=$2
	test x"$2" = x"" && eval fv=\$HAVE_$fu
	CPPFLAGS="$CPPFLAGS -DHAVE_$fu=$fv"
}

ac_test() {
	ac_testn "$@"
	ac_cppflags
}

# ac_flags [-] add varname flags [text]
ac_flags() {
	if test x"$1" = x"-"; then
		shift
		hf=1
	else
		hf=0
	fi
	fa=$1
	vn=$2
	f=$3
	ft=$4
	test x"$ft" = x"" && ft="if $f can be used"
	save_CFLAGS=$CFLAGS
	CFLAGS="$CFLAGS $f"
	if test 1 = $hf; then
		ac_testn can_$vn '' "$ft"
	else
		ac_testn can_$vn '' "$ft" <<-'EOF'
			/* evil apo'stroph in comment test */
			int main(void) { return (0); }
		EOF
	fi
	eval fv=\$HAVE_CAN_`upper $vn`
	test 11 = $fa$fv || CFLAGS=$save_CFLAGS
}

# ac_header [!] header [prereq ...]
ac_header() {
	if test x"$1" = x"!"; then
		na=1
		shift
	else
		na=0
	fi
	hf=$1; shift
	hv=`echo "$hf" | tr -d '\012\015' | tr -c $alll$allu$alln $alls`
	for i
	do
		echo "#include <$i>" >>x
	done
	echo "#include <$hf>" >>x
	echo 'int main(void) { return (0); }' >>x
	ac_testn "$hv" "" "<$hf>" <x
	rmf x
	test 1 = $na || ac_cppflags
}

addsrcs() {
	if test x"$1" = x"!"; then
		fr=0
		shift
	else
		fr=1
	fi
	eval i=\$$1
	test $fr = "$i" && case " $SRCS " in
	*\ $2\ *)	;;
	*)		SRCS="$SRCS $2" ;;
	esac
}


if test -d mksh || test -d mksh.exe; then
	echo "$me: Error: ./mksh is a directory!" >&2
	exit 1
fi
rmf a.exe* a.out* conftest.c *core lft mksh* no *.bc *.ll *.o \
    Rebuild.sh signames.inc test.sh x vv.out

curdir=`pwd` srcdir=`dirname "$0"` check_categories=
test -n "$dirname" || dirname=.
dstversion=`sed -n '/define MKSH_VERSION/s/^.*"\(.*\)".*$/\1/p' $srcdir/sh.h`

e=echo
r=0
eq=0
pm=0
cm=normal
optflags=-std-compile-opts
last=

for i
do
	case $last:$i in
	c:combine|c:dragonegg|c:llvm)
		cm=$i
		last=
		;;
	c:*)
		echo "$me: Unknown option -c '$i'!" >&2
		exit 1
		;;
	o:*)
		optflags=$i
		last=
		;;
	:-c)
		last=c
		;;
	:-combine)
		cm=combine
		echo "$me: Warning: '$i' is deprecated, use '-c combine' instead!" >&2
		;;
	:-g)
		# checker, debug, valgrind build
		CPPFLAGS="$CPPFLAGS -DDEBUG"
		CFLAGS="$CFLAGS -g3 -fno-builtin"
		;;
	:-j)
		pm=1
		;;
	:-llvm)
		cm=llvm
		optflags=-std-compile-opts
		echo "$me: Warning: '$i' is deprecated, use '-c llvm -O' instead!" >&2
		;;
	:-llvm=*)
		cm=llvm
		optflags=`echo "x$i" | sed 's/^x-llvm=//'`
		echo "$me: Warning: '$i' is deprecated, use '-c llvm -o $llvm' instead!" >&2
		;;
	:-M)
		cm=makefile
		;;
	:-O)
		optflags=-std-compile-opts
		;;
	:-o)
		last=o
		;;
	:-Q)
		eq=1
		;;
	:-r)
		r=1
		;;
	:-v)
		echo "Build.sh $srcversion"
		echo "for mksh $dstversion"
		exit 0
		;;
	:*)
		echo "$me: Unknown option '$i'!" >&2
		exit 1
		;;
	*)
		echo "$me: Unknown option -'$last' '$i'!" >&2
		exit 1
		;;
	esac
done
if test -n "$last"; then
	echo "$me: Option -'$last' not followed by argument!" >&2
	exit 1
fi

SRCS="lalloc.c edit.c eval.c exec.c expr.c funcs.c histrap.c"
SRCS="$SRCS jobs.c lex.c main.c misc.c shf.c syn.c tree.c var.c"

if test x"$srcdir" = x"."; then
	CPPFLAGS="-I. $CPPFLAGS"
else
	CPPFLAGS="-I. -I'$srcdir' $CPPFLAGS"
fi

test x"$TARGET_OS" = x"" && TARGET_OS=`uname -s 2>/dev/null || uname`
oswarn=
ccpc=-Wc,
ccpl=-Wl,
tsts=
ccpr='|| for _f in ${tcfn}*; do test x"${_f}" = x"mksh.1" || rm -f "${_f}"; done'

# Configuration depending on OS revision, on OSes that need them
case $TARGET_OS in
QNX)
	test x"$TARGET_OSREV" = x"" && TARGET_OSREV=`uname -r`
	;;
esac

# Configuration depending on OS name
case $TARGET_OS in
AIX)
	CPPFLAGS="$CPPFLAGS -D_ALL_SOURCE"
	: ${HAVE_SETLOCALE_CTYPE=0}
	;;
BeOS)
	oswarn=' and will currently not work'
	;;
BSD/OS)
	: ${HAVE_SETLOCALE_CTYPE=0}
	;;
CYGWIN*)
	: ${HAVE_SETLOCALE_CTYPE=0}
	;;
Darwin)
	;;
DragonFly)
	;;
FreeBSD)
	;;
GNU)
	# define NO_PATH_MAX to use Hurd-only functions
	CPPFLAGS="$CPPFLAGS -D_GNU_SOURCE -DNO_PATH_MAX"
	;;
GNU/kFreeBSD)
	CPPFLAGS="$CPPFLAGS -D_GNU_SOURCE"
	;;
Haiku)
	CPPFLAGS="$CPPFLAGS -DMKSH_ASSUME_UTF8"
	;;
HP-UX)
	;;
Interix)
	ccpc='-X '
	ccpl='-Y '
	CPPFLAGS="$CPPFLAGS -D_ALL_SOURCE"
	: ${LIBS='-lcrypt'}
	: ${HAVE_SETLOCALE_CTYPE=0}
	;;
IRIX*)
	: ${HAVE_SETLOCALE_CTYPE=0}
	;;
Linux)
	CPPFLAGS="$CPPFLAGS -D_GNU_SOURCE"
	: ${HAVE_REVOKE=0}
	;;
MidnightBSD)
	;;
Minix)
	CPPFLAGS="$CPPFLAGS -DMKSH_UNEMPLOYED -DMKSH_CONSERVATIVE_FDS"
	CPPFLAGS="$CPPFLAGS -D_POSIX_SOURCE -D_POSIX_1_SOURCE=2 -D_MINIX"
	oldish_ed=no-stderr-ed		# /usr/bin/ed(!) is broken
	: ${HAVE_SETLOCALE_CTYPE=0}
	;;
MirBSD)
	;;
NetBSD)
	;;
OpenBSD)
	: ${HAVE_SETLOCALE_CTYPE=0}
	;;
OSF1)
	HAVE_SIG_T=0	# incompatible
	CPPFLAGS="$CPPFLAGS -D_OSF_SOURCE -D_POSIX_C_SOURCE=200112L"
	CPPFLAGS="$CPPFLAGS -D_XOPEN_SOURCE=600 -D_XOPEN_SOURCE_EXTENDED"
	: ${HAVE_SETLOCALE_CTYPE=0}
	;;
Plan9)
	CPPFLAGS="$CPPFLAGS -D_POSIX_SOURCE -D_LIMITS_EXTENSION"
	CPPFLAGS="$CPPFLAGS -D_BSD_EXTENSION -D_SUSV2_SOURCE"
	oswarn=' and will currently not work'
	CPPFLAGS="$CPPFLAGS -DMKSH_ASSUME_UTF8 -DMKSH_UNEMPLOYED"
	;;
PW32*)
	HAVE_SIG_T=0	# incompatible
	oswarn=' and will currently not work'
	: ${HAVE_SETLOCALE_CTYPE=0}
	;;
QNX)
	CPPFLAGS="$CPPFLAGS -D__NO_EXT_QNX"
	case $TARGET_OSREV in
	[012345].*|6.[0123].*|6.4.[01])
		oldish_ed=no-stderr-ed		# oldish /bin/ed is broken
		;;
	esac
	: ${HAVE_SETLOCALE_CTYPE=0}
	;;
SunOS)
	CPPFLAGS="$CPPFLAGS -D_BSD_SOURCE -D__EXTENSIONS__"
	;;
syllable)
	CPPFLAGS="$CPPFLAGS -D_GNU_SOURCE"
	oswarn=' and will currently not work'
	;;
ULTRIX)
	: ${CC=cc -YPOSIX}
	CPPFLAGS="$CPPFLAGS -Dssize_t=int"
	: ${HAVE_SETLOCALE_CTYPE=0}
	;;
UWIN*)
	ccpc='-Yc,'
	ccpl='-Yl,'
	tsts=" 3<>/dev/tty"
	oswarn="; it will compile, but the target"
	oswarn="$oswarn${nl}platform itself is very flakey/unreliable"
	: ${HAVE_SETLOCALE_CTYPE=0}
	;;
*)
	oswarn='; it may or may not work'
	;;
esac

: ${CC=cc} ${NROFF=nroff}
test 0 = $r && echo | $NROFF -v 2>&1 | grep GNU >/dev/null 2>&1 && \
    NROFF="$NROFF -c"

# this aids me in tracing FTBFSen without access to the buildd
$e "Hi from$ao $bi$srcversion$ao on:"
case $TARGET_OS in
Darwin)
	vv '|' "hwprefs machine_type os_type os_class >&2"
	vv '|' "uname -a >&2"
	;;
IRIX*)
	vv '|' "uname -a >&2"
	vv '|' "hinv -v >&2"
	;;
OSF1)
	vv '|' "uname -a >&2"
	vv '|' "/usr/sbin/sizer -v >&2"
	;;
*)
	vv '|' "uname -a >&2"
	;;
esac
test -z "$oswarn" || echo >&2 "
Warning: mksh has not yet been ported to or tested on your
operating system '$TARGET_OS'$oswarn. If you can provide
a shell account to the developer, this may improve; please
drop us a success or failure notice or even send in diffs.
"
$e "$bi$me: Building the MirBSD Korn Shell$ao $ui$dstversion$ao"

#
# Begin of mirtoconf checks
#
$e $bi$me: Scanning for functions... please ignore any errors.$ao

#
# Compiler: which one?
#
# notes:
# - ICC defines __GNUC__ too
# - GCC defines __hpux too
# - LLVM+clang defines __GNUC__ too
# - nwcc defines __GNUC__ too
CPP="$CC -E"
$e ... which compiler seems to be used
cat >conftest.c <<'EOF'
#if defined(__ICC) || defined(__INTEL_COMPILER)
ct=icc
#elif defined(__xlC__) || defined(__IBMC__)
ct=xlc
#elif defined(__SUNPRO_C)
ct=sunpro
#elif defined(__ACK__)
ct=ack
#elif defined(__BORLANDC__)
ct=bcc
#elif defined(__WATCOMC__)
ct=watcom
#elif defined(__MWERKS__)
ct=metrowerks
#elif defined(__HP_cc)
ct=hpcc
#elif defined(__DECC) || (defined(__osf__) && !defined(__GNUC__))
ct=dec
#elif defined(__PGI)
ct=pgi
#elif defined(__DMC__)
ct=dmc
#elif defined(_MSC_VER)
ct=msc
#elif defined(__ADSPBLACKFIN__) || defined(__ADSPTS__) || defined(__ADSP21000__)
ct=adsp
#elif defined(__IAR_SYSTEMS_ICC__)
ct=iar
#elif defined(SDCC)
ct=sdcc
#elif defined(__PCC__)
ct=pcc
#elif defined(__TenDRA__)
ct=tendra
#elif defined(__TINYC__)
ct=tcc
#elif defined(__llvm__) && defined(__clang__)
ct=clang
#elif defined(__NWCC__)
ct=nwcc
#elif defined(__GNUC__)
ct=gcc
#elif defined(_COMPILER_VERSION)
ct=mipspro
#elif defined(__sgi)
ct=mipspro
#elif defined(__hpux) || defined(__hpua)
ct=hpcc
#elif defined(__ultrix)
ct=ucode
#else
ct=unknown
#endif
EOF
ct=unknown
vv ']' "$CPP $CFLAGS $CPPFLAGS $NOWARN conftest.c | grep ct= | tr -d \\\\015 >x"
sed 's/^/[ /' x
eval `cat x`
rmf x vv.out
echo 'int main(void) { return (0); }' >conftest.c
case $ct in
ack)
	# work around "the famous ACK const bug"
	CPPFLAGS="-Dconst= $CPPFLAGS"
	;;
adsp)
	echo >&2 'Warning: Analog Devices C++ compiler for Blackfin, TigerSHARC
    and SHARC (21000) DSPs detected. This compiler has not yet
    been tested for compatibility with mksh. Continue at your
    own risk, please report success/failure to the developers.'
	;;
bcc)
	echo >&2 "Warning: Borland C++ Builder detected. This compiler might
    produce broken executables. Continue at your own risk,
    please report success/failure to the developers."
	;;
clang)
	# does not work with current "ccc" compiler driver
	vv '|' "$CC $CFLAGS $CPPFLAGS $LDFLAGS $NOWARN $LIBS -version"
	# this works, for now
	vv '|' "${CLANG-clang} -version"
	# ensure compiler and linker are in sync unless overridden
	case $CCC_CC:$CCC_LD in
	:*)	;;
	*:)	CCC_LD=$CCC_CC; export CCC_LD ;;
	esac
	;;
dec)
	vv '|' "$CC $CFLAGS $CPPFLAGS $LDFLAGS $NOWARN $LIBS -V"
	vv '|' "$CC $CFLAGS $CPPFLAGS $LDFLAGS $NOWARN -Wl,-V conftest.c $LIBS"
	;;
dmc)
	echo >&2 "Warning: Digital Mars Compiler detected. When running under"
	echo >&2 "    UWIN, mksh tends to be unstable due to the limitations"
	echo >&2 "    of this platform. Continue at your own risk,"
	echo >&2 "    please report success/failure to the developers."
	;;
gcc)
	vv '|' "$CC $CFLAGS $CPPFLAGS $LDFLAGS $NOWARN -v conftest.c $LIBS"
	vv '|' 'echo `$CC $CFLAGS $CPPFLAGS $LDFLAGS $NOWARN $LIBS \
	    -dumpmachine` gcc`$CC $CFLAGS $CPPFLAGS $LDFLAGS $NOWARN \
	    $LIBS -dumpversion`'
	;;
hpcc)
	vv '|' "$CC $CFLAGS $CPPFLAGS $LDFLAGS $NOWARN -V conftest.c $LIBS"
	;;
iar)
	echo >&2 'Warning: IAR Systems (http://www.iar.com) compiler for embedded
    systems detected. This unsupported compiler has not yet
    been tested for compatibility with mksh. Continue at your
    own risk, please report success/failure to the developers.'
	;;
icc)
	vv '|' "$CC $CFLAGS $CPPFLAGS $LDFLAGS $NOWARN $LIBS -V"
	;;
metrowerks)
	echo >&2 'Warning: Metrowerks C compiler detected. This has not yet
    been tested for compatibility with mksh. Continue at your
    own risk, please report success/failure to the developers.'
	;;
mipspro)
	vv '|' "$CC $CFLAGS $CPPFLAGS $LDFLAGS $NOWARN $LIBS -version"
	;;
msc)
	ccpr=		# errorlevels are not reliable
	case $TARGET_OS in
	Interix)
		if [[ -n $C89_COMPILER ]]; then
			C89_COMPILER=`ntpath2posix -c "$C89_COMPILER"`
		else
			C89_COMPILER=CL.EXE
		fi
		if [[ -n $C89_LINKER ]]; then
			C89_LINKER=`ntpath2posix -c "$C89_LINKER"`
		else
			C89_LINKER=LINK.EXE
		fi
		vv '|' "$C89_COMPILER /HELP >&2"
		vv '|' "$C89_LINKER /LINK >&2"
		;;
	esac
	;;
nwcc)
	vv '|' "$CC $CFLAGS $CPPFLAGS $LDFLAGS $NOWARN $LIBS -version"
	;;
pcc)
	vv '|' "$CC $CFLAGS $CPPFLAGS $LDFLAGS $NOWARN $LIBS -v"
	;;
pgi)
	echo >&2 'Warning: PGI detected. This unknown compiler has not yet
    been tested for compatibility with mksh. Continue at your
    own risk, please report success/failure to the developers.'
	;;
sdcc)
	echo >&2 'Warning: sdcc (http://sdcc.sourceforge.net), the small devices
    C compiler for embedded systems detected. This has not yet
    been tested for compatibility with mksh. Continue at your
    own risk, please report success/failure to the developers.'
	;;
sunpro)
	vv '|' "$CC $CFLAGS $CPPFLAGS $LDFLAGS $NOWARN -V conftest.c $LIBS"
	;;
tcc)
	vv '|' "$CC $CFLAGS $CPPFLAGS $LDFLAGS $NOWARN $LIBS -v"
	;;
tendra)
	vv '|' "$CC $CFLAGS $CPPFLAGS $LDFLAGS $NOWARN $LIBS -V 2>&1 | \
	    fgrep -i -e version -e release"
	;;
ucode)
	vv '|' "$CC $CFLAGS $CPPFLAGS $LDFLAGS $NOWARN $LIBS -V"
	vv '|' "$CC $CFLAGS $CPPFLAGS $LDFLAGS $NOWARN -Wl,-V conftest.c $LIBS"
	;;
watcom)
	echo >&2 'Warning: Watcom C Compiler detected. This compiler has not yet
    been tested for compatibility with mksh. Continue at your
    own risk, please report success/failure to the developers.'
	;;
xlc)
	vv '|' "$CC $CFLAGS $CPPFLAGS $LDFLAGS $NOWARN $LIBS -qversion=verbose"
	vv '|' "ld -V"
	;;
*)
	ct=unknown
	;;
esac
case $cm in
dragonegg|llvm)
	vv '|' "llc -version"
	;;
esac
$e "$bi==> which compiler seems to be used...$ao $ui$ct$ao"
rmf conftest.c conftest.o conftest a.out* a.exe* vv.out

#
# Compiler: works as-is, with -Wno-error and -Werror
#
save_NOWARN=$NOWARN
NOWARN=
DOWARN=
ac_flags 0 compiler_works '' 'if the compiler works'
test 1 = $HAVE_CAN_COMPILER_WORKS || exit 1
HAVE_COMPILER_KNOWN=0
test $ct = unknown || HAVE_COMPILER_KNOWN=1
if ac_ifcpp 'if 0' compiler_fails '' \
    'if the compiler does not fail correctly'; then
	save_CFLAGS=$CFLAGS
	: ${HAVE_CAN_DELEXE=x}
	if test $ct = dmc; then
		CFLAGS="$CFLAGS ${ccpl}/DELEXECUTABLE"
		ac_testn can_delexe compiler_fails 0 'for the /DELEXECUTABLE linker option' <<-EOF
			int main(void) { return (0); }
		EOF
	elif test $ct = dec; then
		CFLAGS="$CFLAGS ${ccpl}-non_shared"
		ac_testn can_delexe compiler_fails 0 'for the -non_shared linker option' <<-EOF
			int main(void) { return (0); }
		EOF
	else
		exit 1
	fi
	test 1 = $HAVE_CAN_DELEXE || CFLAGS=$save_CFLAGS
	ac_testn compiler_still_fails '' 'if the compiler still does not fail correctly' <<-EOF
	EOF
	test 1 = $HAVE_COMPILER_STILL_FAILS && exit 1
fi
if ac_ifcpp 'ifdef __TINYC__' couldbe_tcc '!' compiler_known 0 \
    'if this could be tcc'; then
	ct=tcc
	CPP='cpp -D__TINYC__'
fi

if test $ct = sunpro; then
	test x"$save_NOWARN" = x"" && save_NOWARN='-errwarn=%none'
	ac_flags 0 errwarnnone "$save_NOWARN"
	test 1 = $HAVE_CAN_ERRWARNNONE || save_NOWARN=
	ac_flags 0 errwarnall "-errwarn=%all"
	test 1 = $HAVE_CAN_ERRWARNALL && DOWARN="-errwarn=%all"
elif test $ct = hpcc; then
	save_NOWARN=
	DOWARN=+We
elif test $ct = mipspro; then
	save_NOWARN=
	DOWARN="-diag_error 1-10000"
elif test $ct = msc; then
	save_NOWARN="${ccpc}/w"
	DOWARN="${ccpc}/WX"
elif test $ct = dmc; then
	save_NOWARN="${ccpc}-w"
	DOWARN="${ccpc}-wx"
elif test $ct = bcc; then
	save_NOWARN="${ccpc}-w"
	DOWARN="${ccpc}-w!"
elif test $ct = dec; then
	: -msg_* flags not used yet, or is -w2 correct?
elif test $ct = xlc; then
	save_NOWARN=-qflag=i:e
	DOWARN=-qflag=i:i
elif test $ct = tendra; then
	save_NOWARN=-w
elif test $ct = ucode; then
	save_NOWARN=
	DOWARN=-w2
else
	test x"$save_NOWARN" = x"" && save_NOWARN=-Wno-error
	ac_flags 0 wnoerror "$save_NOWARN"
	test 1 = $HAVE_CAN_WNOERROR || save_NOWARN=
	ac_flags 0 werror -Werror
	test 1 = $HAVE_CAN_WERROR && DOWARN=-Werror
fi

test $ct = icc && DOWARN="$DOWARN -wd1419"
NOWARN=$save_NOWARN

#
# Compiler: extra flags (-O2 -f* -W* etc.)
#
i=`echo :"$orig_CFLAGS" | sed 's/^://' | tr -c -d $alll$allu$alln`
# optimisation: only if orig_CFLAGS is empty
test x"$i" = x"" && if test $ct = sunpro; then
	cat >x <<-'EOF'
		int main(void) { return (0); }
		#define __IDSTRING_CONCAT(l,p)	__LINTED__ ## l ## _ ## p
		#define __IDSTRING_EXPAND(l,p)	__IDSTRING_CONCAT(l,p)
		#define pad			void __IDSTRING_EXPAND(__LINE__,x)(void) { }
	EOF
	yes pad | head -n 256 >>x
	ac_flags - 1 otwo -xO2 <x
	rmf x
elif test $ct = hpcc; then
	phase=u
	ac_flags 1 otwo +O2
	phase=x
elif test $ct = xlc; then
	ac_flags 1 othree "-O3 -qstrict"
	test 1 = $HAVE_CAN_OTHREE || ac_flags 1 otwo -O2
elif test $ct = tcc || test $ct = tendra; then
	: no special optimisation
else
	ac_flags 1 otwo -O2
	test 1 = $HAVE_CAN_OTWO || ac_flags 1 optimise -O
fi
# other flags: just add them if they are supported
i=0
if test $ct = gcc; then
	# The following tests run with -Werror (gcc only) if possible
	NOWARN=$DOWARN; phase=u
	ac_flags 1 fnostrictaliasing -fno-strict-aliasing
	ac_flags 1 fstackprotectorall -fstack-protector-all
	ac_flags 1 fwrapv -fwrapv
	test $cm = combine && ac_flags 0 combine \
	    '-fwhole-program --combine' \
	    'if gcc supports -fwhole-program --combine'
	i=1
elif test $ct = icc; then
	ac_flags 1 fnobuiltinsetmode -fno-builtin-setmode
	ac_flags 1 fnostrictaliasing -fno-strict-aliasing
	ac_flags 1 fstacksecuritycheck -fstack-security-check
	i=1
elif test $ct = sunpro; then
	phase=u
	ac_flags 1 v -v
	ac_flags 1 xc99 -xc99 'for support of ISO C99'
	ac_flags 1 ipo -xipo 'for cross-module optimisation'
	phase=x
elif test $ct = hpcc; then
	phase=u
	ac_flags 1 agcc -Agcc 'for support of GCC extensions'
	ac_flags 1 ac99 -AC99 'for support of ISO C99'
	phase=x
elif test $ct = dec; then
	ac_flags 0 verb -verbose
	ac_flags 1 rodata -readonly_strings
elif test $ct = dmc; then
	ac_flags 1 decl "${ccpc}-r" 'for strict prototype checks'
	ac_flags 1 schk "${ccpc}-s" 'for stack overflow checking'
elif test $ct = bcc; then
	ac_flags 1 strpool "${ccpc}-d" 'if string pooling can be enabled'
elif test $ct = mipspro; then
	ac_flags 1 xc99 -c99 'for support of ISO C99'
	ac_flags 1 fullwarn -fullwarn 'for remark output support'
elif test $ct = msc; then
	ac_flags 1 strpool "${ccpc}/GF" 'if string pooling can be enabled'
	echo 'int main(void) { char test[64] = ""; return (*test); }' >x
	ac_flags - 1 stackon "${ccpc}/GZ" 'if stack checks can be enabled' <x
	ac_flags - 1 stckall "${ccpc}/Ge" 'stack checks for all functions' <x
	ac_flags - 1 secuchk "${ccpc}/GS" 'for compiler security checks' <x
	rmf x
	ac_flags 1 wall "${ccpc}/Wall" 'to enable all warnings'
	ac_flags 1 wp64 "${ccpc}/Wp64" 'to enable 64-bit warnings'
elif test $ct = xlc; then
	ac_flags 1 x99 -qlanglvl=extc99
	test 1 = $HAVE_CAN_X99 || ac_flags 1 c99 -qlanglvl=stdc99
	ac_flags 1 rodata "-qro -qroconst -qroptr"
	ac_flags 1 rtcheck -qcheck=all
	ac_flags 1 rtchkc -qextchk
	ac_flags 1 wformat "-qformat=all -qformat=nozln"
	#ac_flags 1 wp64 -qwarn64	# too verbose for now
elif test $ct = tendra; then
	ac_flags 0 ysystem -Ysystem
	test 1 = $HAVE_CAN_YSYSTEM && CPPFLAGS="-Ysystem $CPPFLAGS"
	ac_flags 1 extansi -Xa
elif test $ct = tcc; then
	ac_flags 1 boundschk -b
elif test $ct = clang; then
	i=1
elif test $ct = nwcc; then
	i=1
	#broken# ac_flags 1 ssp -stackprotect
fi
# flags common to a subset of compilers (run with -Werror on gcc)
if test 1 = $i; then
	ac_flags 1 stdg99 -std=gnu99 'for support of ISO C99 + GCC extensions'
	test 1 = $HAVE_CAN_STDG99 || \
	    ac_flags 1 stdc99 -std=c99 'for support of ISO C99'
	ac_flags 1 wall -Wall
fi
phase=x

# The following tests run with -Werror or similar (all compilers) if possible
NOWARN=$DOWARN
test $ct = pcc && phase=u

#
# Compiler: check for stuff that only generates warnings
#
ac_test attribute_bounded '' 'for __attribute__((bounded))' <<-'EOF'
	#if defined(__GNUC__) && (__GNUC__ < 2)
	/* force a failure: gcc 1.42 has a false positive here */
	int main(void) { return (thiswillneverbedefinedIhope()); }
	#else
	#include <string.h>
	#undef __attribute__
	int xcopy(const void *, void *, size_t)
	    __attribute__((bounded (buffer, 1, 3)))
	    __attribute__((bounded (buffer, 2, 3)));
	int main(int ac, char *av[]) { return (xcopy(av[0], av[--ac], 1)); }
	int xcopy(const void *s, void *d, size_t n) {
		memmove(d, s, n); return ((int)n);
	}
	#endif
EOF
ac_test attribute_format '' 'for __attribute__((format))' <<-'EOF'
	#if defined(__GNUC__) && (__GNUC__ < 2)
	/* force a failure: gcc 1.42 has a false positive here */
	int main(void) { return (thiswillneverbedefinedIhope()); }
	#else
	#include <stdio.h>
	#undef __attribute__
	#undef printf
	extern int printf(const char *format, ...)
	    __attribute__((format (printf, 1, 2)));
	int main(int ac, char **av) { return (printf("%s%d", *av, ac)); }
	#endif
EOF
ac_test attribute_nonnull '' 'for __attribute__((nonnull))' <<-'EOF'
	#if defined(__GNUC__) && (__GNUC__ < 2)
	/* force a failure: gcc 1.42 has a false positive here */
	int main(void) { return (thiswillneverbedefinedIhope()); }
	#else
	int foo(char *s1, char *s2) __attribute__((nonnull));
	int bar(char *s1, char *s2) __attribute__((nonnull (1, 2)));
	int baz(char *s) __attribute__((nonnull (1)));
	int foo(char *s1, char *s2) { return (bar(s2, s1)); }
	int bar(char *s1, char *s2) { return (baz(s1) - baz(s2)); }
	int baz(char *s) { return (*s); }
	int main(int ac, char **av) { return (ac == foo(av[0], av[ac-1])); }
	#endif
EOF
ac_test attribute_noreturn '' 'for __attribute__((noreturn))' <<-'EOF'
	#if defined(__GNUC__) && (__GNUC__ < 2)
	/* force a failure: gcc 1.42 has a false positive here */
	int main(void) { return (thiswillneverbedefinedIhope()); }
	#else
	#include <stdlib.h>
	#undef __attribute__
	void fnord(void) __attribute__((noreturn));
	int main(void) { fnord(); }
	void fnord(void) { exit(0); }
	#endif
EOF
ac_test attribute_unused '' 'for __attribute__((unused))' <<-'EOF'
	#if defined(__GNUC__) && (__GNUC__ < 2)
	/* force a failure: gcc 1.42 has a false positive here */
	int main(void) { return (thiswillneverbedefinedIhope()); }
	#else
	int main(int ac __attribute__((unused)), char **av
	    __attribute__((unused))) { return (0); }
	#endif
EOF
ac_test attribute_used '' 'for __attribute__((used))' <<-'EOF'
	#if defined(__GNUC__) && (__GNUC__ < 2)
	/* force a failure: gcc 1.42 has a false positive here */
	int main(void) { return (thiswillneverbedefinedIhope()); }
	#else
	static const char fnord[] __attribute__((used)) = "42";
	int main(void) { return (0); }
	#endif
EOF

# End of tests run with -Werror
NOWARN=$save_NOWARN
phase=x

#
# mksh: flavours (full/small mksh, omit certain stuff)
#
if ac_ifcpp 'ifdef MKSH_SMALL' isset_MKSH_SMALL '' \
    "if a reduced-feature mksh is requested"; then
	#XXX this sucks; fix it for *all* compilers
	case $ct in
	clang|icc|nwcc)
		ac_flags 1 fnoinline -fno-inline
		;;
	gcc)
		NOWARN=$DOWARN; phase=u
		ac_flags 1 fnoinline -fno-inline
		NOWARN=$save_NOWARN; phase=x
		;;
	sunpro)
		ac_flags 1 fnoinline -xinline=
		;;
	xlc)
		ac_flags 1 fnoinline -qnoinline
		;;
	esac

	: ${HAVE_MKNOD=0}
	: ${HAVE_NICE=0}
	: ${HAVE_REVOKE=0}
	: ${HAVE_PERSISTENT_HISTORY=0}
	check_categories=$check_categories,smksh
	HAVE_ISSET_MKSH_CONSERVATIVE_FDS=1	# from sh.h
fi
ac_ifcpp 'ifdef MKSH_BINSHREDUCED' isset_MKSH_BINSHREDUCED '' \
    "if a reduced-feature sh is requested" && \
    check_categories=$check_categories,binsh
ac_ifcpp 'ifdef MKSH_UNEMPLOYED' isset_MKSH_UNEMPLOYED '' \
    "if mksh will be built without job control" && \
    check_categories=$check_categories,arge
ac_ifcpp 'ifdef MKSH_ASSUME_UTF8' isset_MKSH_ASSUME_UTF8 '' \
    'if the default UTF-8 mode is specified' && : ${HAVE_SETLOCALE_CTYPE=0}
ac_ifcpp 'ifdef MKSH_CONSERVATIVE_FDS' isset_MKSH_CONSERVATIVE_FDS '' \
    'if traditional/conservative fd use is requested' && \
    check_categories=$check_categories,convfds

#
# Environment: headers
#
ac_header sys/param.h
ac_header sys/mkdev.h sys/types.h
ac_header sys/mman.h sys/types.h
ac_header sys/sysmacros.h
ac_header grp.h sys/types.h
ac_header libgen.h
ac_header libutil.h sys/types.h
ac_header paths.h
ac_header stdbool.h
ac_header stdint.h stdarg.h
ac_header strings.h sys/types.h
ac_header ulimit.h sys/types.h
ac_header values.h

#
# Environment: definitions
#
echo '#include <sys/types.h>
/* check that off_t can represent 2^63-1 correctly, thx FSF */
#define LARGE_OFF_T (((off_t)1 << 62) - 1 + ((off_t)1 << 62))
int off_t_is_large[(LARGE_OFF_T % 2147483629 == 721 &&
    LARGE_OFF_T % 2147483647 == 1) ? 1 : -1];
int main(void) { return (0); }' >lft.c
ac_testn can_lfs '' "for large file support" <lft.c
save_CPPFLAGS=$CPPFLAGS
CPPFLAGS="$CPPFLAGS -D_FILE_OFFSET_BITS=64"
ac_testn can_lfs_sus '!' can_lfs 0 "... with -D_FILE_OFFSET_BITS=64" <lft.c
if test 0 = $HAVE_CAN_LFS_SUS; then
	CPPFLAGS="$save_CPPFLAGS -D_LARGE_FILES=1"
	ac_testn can_lfs_aix '!' can_lfs 0 "... with -D_LARGE_FILES=1" <lft.c
	test 1 = $HAVE_CAN_LFS_AIX || CPPFLAGS=$save_CPPFLAGS
fi
rmf lft*	# end of large file support test

#
# Environment: types
#
ac_test can_inttypes '!' stdint_h 1 "for standard 32-bit integer types" <<-'EOF'
	#include <sys/types.h>
	#include <stddef.h>
	int main(int ac, char **av) { return ((uint32_t)(ptrdiff_t)*av + (int32_t)ac); }
EOF
ac_test can_ucbints '!' can_inttypes 1 "for UCB 32-bit integer types" <<-'EOF'
	#include <sys/types.h>
	#include <stddef.h>
	int main(int ac, char **av) { return ((u_int32_t)(ptrdiff_t)*av + (int32_t)ac); }
EOF
ac_test can_int8type '!' stdint_h 1 "for standard 8-bit integer type" <<-'EOF'
	#include <sys/types.h>
	#include <stddef.h>
	int main(int ac, char **av) { return ((uint8_t)(ptrdiff_t)av[ac]); }
EOF
ac_test can_ucbint8 '!' can_int8type 1 "for UCB 8-bit integer type" <<-'EOF'
	#include <sys/types.h>
	#include <stddef.h>
	int main(int ac, char **av) { return ((u_int8_t)(ptrdiff_t)av[ac]); }
EOF

ac_test rlim_t <<-'EOF'
	#include <sys/types.h>
	#include <sys/time.h>
	#include <sys/resource.h>
	#include <unistd.h>
	int main(void) { return ((int)(rlim_t)0); }
EOF

# only testn: added later below
ac_testn sig_t <<-'EOF'
	#include <sys/types.h>
	#include <signal.h>
	#include <stddef.h>
	int main(void) { return ((int)(ptrdiff_t)(sig_t)kill(0,0)); }
EOF

ac_testn sighandler_t '!' sig_t 0 <<-'EOF'
	#include <sys/types.h>
	#include <signal.h>
	#include <stddef.h>
	int main(void) { return ((int)(ptrdiff_t)(sighandler_t)kill(0,0)); }
EOF
if test 1 = $HAVE_SIGHANDLER_T; then
	CPPFLAGS="$CPPFLAGS -Dsig_t=sighandler_t"
	HAVE_SIG_T=1
fi

ac_testn __sighandler_t '!' sig_t 0 <<-'EOF'
	#include <sys/types.h>
	#include <signal.h>
	#include <stddef.h>
	int main(void) { return ((int)(ptrdiff_t)(__sighandler_t)kill(0,0)); }
EOF
if test 1 = $HAVE___SIGHANDLER_T; then
	CPPFLAGS="$CPPFLAGS -Dsig_t=__sighandler_t"
	HAVE_SIG_T=1
fi

test 1 = $HAVE_SIG_T || CPPFLAGS="$CPPFLAGS -Dsig_t=nosig_t"
ac_cppflags SIG_T

#
# Environment: signals
#
test x"NetBSD" = x"$TARGET_OS" && $e Ignore the compatibility warning.

for what in name list; do
	uwhat=`upper $what`
	ac_testn sys_sig$what '' "the sys_sig${what}[] array" <<-EOF
		extern const char *const sys_sig${what}[];
		int main(void) { return (sys_sig${what}[0][0]); }
	EOF
	ac_testn _sys_sig$what '!' sys_sig$what 0 "the _sys_sig${what}[] array" <<-EOF
		extern const char *const _sys_sig${what}[];
		int main(void) { return (_sys_sig${what}[0][0]); }
	EOF
	if eval "test 1 = \$HAVE__SYS_SIG$uwhat"; then
		CPPFLAGS="$CPPFLAGS -Dsys_sig$what=_sys_sig$what"
		eval "HAVE_SYS_SIG$uwhat=1"
	fi
	ac_cppflags SYS_SIG$uwhat
done

ac_test strsignal '!' sys_siglist 0 <<-'EOF'
	#include <string.h>
	#include <signal.h>
	int main(void) { return (strsignal(1)[0]); }
EOF

#
# Environment: library functions
#
ac_testn flock_ex '' 'flock and mmap' <<-'EOF'
	#include <sys/types.h>
	#include <sys/file.h>
	#include <sys/mman.h>
	#include <fcntl.h>
	#include <stdlib.h>
	int main(void) { return ((void *)mmap(NULL, (size_t)flock(0, LOCK_EX),
	    PROT_READ, MAP_PRIVATE, 0, (off_t)0) == (void *)NULL ? 1 :
	    munmap(NULL, 0)); }
EOF

ac_test getrusage <<-'EOF'
	#define MKSH_INCLUDES_ONLY
	#include "sh.h"
	int main(void) {
		struct rusage ru;
		return (getrusage(RUSAGE_SELF, &ru) +
		    getrusage(RUSAGE_CHILDREN, &ru));
	}
EOF

ac_test killpg <<-'EOF'
	#include <signal.h>
	int main(int ac, char *av[]) { return (av[0][killpg(123, ac)]); }
EOF

ac_test mknod '' 'if to use mknod(), makedev() and friends' <<-'EOF'
	#define MKSH_INCLUDES_ONLY
	#include "sh.h"
	int main(int ac, char *av[]) {
		dev_t dv;
		dv = makedev((unsigned int)ac, (unsigned int)av[0][0]);
		return (mknod(av[0], (mode_t)0, dv) ? (int)major(dv) :
		    (int)minor(dv));
	}
EOF

ac_test mkstemp <<-'EOF'
	#include <stdlib.h>
	#include <unistd.h>
	int main(void) { char tmpl[] = "X"; return (mkstemp(tmpl)); }
EOF

ac_test nice <<-'EOF'
	#include <unistd.h>
	int main(void) { return (nice(4)); }
EOF

ac_test revoke <<-'EOF'
	#include <sys/types.h>
	#if HAVE_LIBUTIL_H
	#include <libutil.h>
	#endif
	#include <unistd.h>
	int main(int ac, char *av[]) { return (ac + revoke(av[0])); }
EOF

ac_test setlocale_ctype '' 'setlocale(LC_CTYPE, "")' <<-'EOF'
	#include <locale.h>
	#include <stddef.h>
	int main(void) { return ((int)(ptrdiff_t)(void *)setlocale(LC_CTYPE, "")); }
EOF

ac_test langinfo_codeset setlocale_ctype 0 'nl_langinfo(CODESET)' <<-'EOF'
	#include <langinfo.h>
	#include <stddef.h>
	int main(void) { return ((int)(ptrdiff_t)(void *)nl_langinfo(CODESET)); }
EOF

ac_test setmode mknod 1 <<-'EOF'
	/* XXX imake style */
	/* XXX conditions correct? */
	#if defined(__MSVCRT__) || defined(__CYGWIN__)
	/* force a failure: Win32 setmode() is not what we want... */
	int main(void) { return (thiswillneverbedefinedIhope()); }
	#else
	#include <sys/types.h>
	#include <unistd.h>
	int main(int ac, char *av[]) { return (getmode(setmode(av[0]),
	    (mode_t)ac)); }
	#endif
EOF

ac_test setresugid <<-'EOF'
	#include <sys/types.h>
	#include <unistd.h>
	int main(void) { setresuid(0,0,0); return (setresgid(0,0,0)); }
EOF

ac_test setgroups setresugid 0 <<-'EOF'
	#include <sys/types.h>
	#if HAVE_GRP_H
	#include <grp.h>
	#endif
	#include <unistd.h>
	int main(void) { gid_t gid = 0; return (setgroups(0, &gid)); }
EOF

ac_test strcasestr <<-'EOF'
	#include <sys/types.h>
	#include <stddef.h>
	#include <string.h>
	#if HAVE_STRINGS_H
	#include <strings.h>
	#endif
	int main(int ac, char *av[]) {
		return ((int)(ptrdiff_t)(void *)strcasestr(*av, av[ac]));
	}
EOF

ac_test strlcpy <<-'EOF'
	#include <string.h>
	int main(int ac, char *av[]) { return (strlcpy(*av, av[1],
	    (size_t)ac)); }
EOF

#
# check headers for declarations
#
save_CC=$CC; save_LDFLAGS=$LDFLAGS; save_LIBS=$LIBS
CC="$CC -c -o $tcfn"; LDFLAGS=; LIBS=
ac_test '!' flock_decl flock_ex 1 'if flock() does not need to be declared' <<-'EOF'
	#define MKSH_INCLUDES_ONLY
	#include "sh.h"
	long flock(void);		/* this clashes if defined before */
	int main(void) { return ((int)flock()); }
EOF
ac_test '!' revoke_decl revoke 1 'if revoke() does not need to be declared' <<-'EOF'
	#define MKSH_INCLUDES_ONLY
	#include "sh.h"
	long revoke(void);		/* this clashes if defined before */
	int main(void) { return ((int)revoke()); }
EOF
ac_test sys_siglist_decl sys_siglist 1 'if sys_siglist[] does not need to be declared' <<-'EOF'
	#define MKSH_INCLUDES_ONLY
	#include "sh.h"
	int main(void) { return (sys_siglist[0][0]); }
EOF
CC=$save_CC; LDFLAGS=$save_LDFLAGS; LIBS=$save_LIBS

#
# other checks
#
fd='if to use persistent history'
ac_cache PERSISTENT_HISTORY || test 0 = $HAVE_FLOCK_EX || fv=1
test 1 = $fv || check_categories=$check_categories,no-histfile
ac_testdone
ac_cppflags

#
# Compiler: Praeprocessor (only if needed)
#
test 0 = $HAVE_SYS_SIGNAME && if ac_testinit cpp_dd '' \
    'checking if the C Preprocessor supports -dD'; then
	echo '#define foo bar' >conftest.c
	vv ']' "$CPP $CFLAGS $CPPFLAGS $NOWARN -dD conftest.c >x"
	grep '#define foo bar' x >/dev/null 2>&1 && fv=1
	rmf conftest.c x vv.out
	ac_testdone
fi

#
# End of mirtoconf checks
#
$e ... done.

# Some operating systems have ancient versions of ed(1) writing
# the character count to standard output; cope for that
echo wq >x
ed x <x 2>/dev/null | grep 3 >/dev/null 2>&1 && \
    check_categories=$check_categories,$oldish_ed
rmf x vv.out

if test 0 = $HAVE_SYS_SIGNAME; then
	if test 1 = $HAVE_CPP_DD; then
		$e Generating list of signal names...
	else
		$e No list of signal names available via cpp. Falling back...
	fi
	sigseen=:
	echo '#include <signal.h>
#ifndef NSIG
#if defined(_NSIG)
#define NSIG _NSIG
#elif defined(SIGMAX)
#define NSIG (SIGMAX+1)
#endif
#endif
mksh_cfg: NSIG' >conftest.c
	NSIG=`vq "$CPP $CFLAGS $CPPFLAGS $NOWARN conftest.c" | \
	    grep mksh_cfg: | sed 's/^mksh_cfg:[	 ]*\([0-9x ()+-]*\).*$/\1/'`
	case $NSIG in
	*[\ \(\)+-]*) NSIG=`awk "BEGIN { print $NSIG }"` ;;
	esac
	printf=printf
	(printf hallo) >/dev/null 2>&1 || printf=echo
	test $printf = echo || NSIG=`printf %d "$NSIG" 2>/dev/null`
	$printf "NSIG=$NSIG ... "
	sigs="ABRT ALRM BUS CHLD CLD CONT DIL EMT FPE HUP ILL INFO INT IO IOT"
	sigs="$sigs KILL LOST PIPE PROF PWR QUIT RESV SAK SEGV STOP SYS TERM"
	sigs="$sigs TRAP TSTP TTIN TTOU URG USR1 USR2 VTALRM WINCH XCPU XFSZ"
	test 1 = $HAVE_CPP_DD && test $NSIG -gt 1 && sigs="$sigs "`vq \
	    "$CPP $CFLAGS $CPPFLAGS $NOWARN -dD conftest.c" | \
	    grep '[	 ]SIG[A-Z0-9]*[	 ]' | \
	    sed 's/^\(.*[	 ]SIG\)\([A-Z0-9]*\)\([	 ].*\)$/\2/' | sort`
	test $NSIG -gt 1 || sigs=
	for name in $sigs; do
		echo '#include <signal.h>' >conftest.c
		echo mksh_cfg: SIG$name >>conftest.c
		vq "$CPP $CFLAGS $CPPFLAGS $NOWARN conftest.c" | \
		    grep mksh_cfg: | \
		    sed 's/^mksh_cfg:[	 ]*\([0-9x]*\).*$/\1:'$name/
	done | grep -v '^:' | while IFS=: read nr name; do
		test $printf = echo || nr=`printf %d "$nr" 2>/dev/null`
		test $nr -gt 0 && test $nr -le $NSIG || continue
		case $sigseen in
		*:$nr:*) ;;
		*)	echo "		{ \"$name\", $nr },"
			sigseen=$sigseen$nr:
			$printf "$name=$nr " >&2
			;;
		esac
	done 2>&1 >signames.inc
	rmf conftest.c
	$e done.
fi

addsrcs '!' HAVE_SETMODE setmode.c
addsrcs '!' HAVE_STRLCPY strlcpy.c
addsrcs USE_PRINTF_BUILTIN printf.c
test 1 = "$USE_PRINTF_BUILTIN" && CPPFLAGS="$CPPFLAGS -DMKSH_PRINTF_BUILTIN"
test 0 = "$HAVE_SETMODE" && CPPFLAGS="$CPPFLAGS -DHAVE_CONFIG_H -DCONFIG_H_FILENAME=\\\"sh.h\\\""
test 1 = "$HAVE_CAN_VERB" && CFLAGS="$CFLAGS -verbose"

$e $bi$me: Finished configuration testing, now producing output.$ao

files=
objs=
sp=
case $curdir in
*\ *)	echo "#!./mksh" >test.sh ;;
*)	echo "#!$curdir/mksh" >test.sh ;;
esac
cat >>test.sh <<-EOF
	LC_ALL=C PATH='$PATH'; export LC_ALL PATH
	test -n "\$KSH_VERSION" || exit 1
	check_categories=$check_categories
	print Testing mksh for conformance:
	fgrep MirOS: '$srcdir/check.t'
	fgrep MIRBSD '$srcdir/check.t'
	print "This shell is actually:\\n\\t\$KSH_VERSION"
	print 'test.sh built for mksh $dstversion'
	cstr='\$os = defined \$^O ? \$^O : "unknown";'
	cstr="\$cstr"'print \$os . ", Perl version " . \$];'
	for perli in \$PERL perl5 perl no; do
		[[ \$perli = no ]] && exit 1
		perlos=\$(\$perli -e "\$cstr") 2>&- || continue
		print "Perl interpreter '\$perli' running on '\$perlos'"
		[[ -n \$perlos ]] && break
	done
	exec \$perli '$srcdir/check.pl' -s '$srcdir/check.t' -p '$curdir/mksh' \${check_categories:+-C} \${check_categories#,} \$*$tsts
EOF
chmod 755 test.sh
test $HAVE_CAN_COMBINE$cm = 0combine && cm=normal
if test $cm = llvm; then
	emitbc="-emit-llvm -c"
elif test $cm = dragonegg; then
	emitbc="-S -flto"
else
	emitbc=-c
fi
echo set -x >Rebuild.sh
for file in $SRCS; do
	op=`echo x"$file" | sed 's/^x\(.*\)\.c$/\1./'`
	test -f $file || file=$srcdir/$file
	files="$files$sp$file"
	sp=' '
	echo "$CC $CFLAGS $CPPFLAGS $emitbc $file || exit 1" >>Rebuild.sh
	if test $cm = dragonegg; then
		echo "mv ${op}s ${op}ll" >>Rebuild.sh
		echo "llvm-as ${op}ll || exit 1" >>Rebuild.sh
		objs="$objs$sp${op}bc"
	else
		objs="$objs$sp${op}o"
	fi
done
case $cm in
dragonegg|llvm)
	echo "rm -f mksh.s" >>Rebuild.sh
	echo "llvm-link -o - $objs | opt $optflags | llc -o mksh.s" >>Rebuild.sh
	lobjs=mksh.s
	;;
*)
	lobjs=$objs
	;;
esac
case $tcfn in
a.exe)	mkshexe=mksh.exe ;;
*)	mkshexe=mksh ;;
esac
echo tcfn=$mkshexe >>Rebuild.sh
echo "$CC $CFLAGS $LDFLAGS -o \$tcfn $lobjs $LIBS $ccpr" >>Rebuild.sh
echo 'test -f $tcfn || exit 1; size $tcfn' >>Rebuild.sh
if test $cm = makefile; then
	extras='emacsfn.h sh.h sh_flags.h var_spec.h'
	test 0 = $HAVE_SYS_SIGNAME && extras="$extras signames.inc"
	cat >Makefrag.inc <<EOF
# Makefile fragment for building mksh $dstversion

PROG=		$mkshexe
MAN=		mksh.1
SRCS=		$SRCS
SRCS_FP=	$files
OBJS_BP=	$objs
INDSRCS=	$extras
NONSRCS_INST=	dot.mkshrc \$(MAN)
NONSRCS_NOINST=	Build.sh Makefile Rebuild.sh check.pl check.t test.sh
CC=		$CC
CFLAGS=		$CFLAGS
CPPFLAGS=	$CPPFLAGS
LDFLAGS=	$LDFLAGS
LIBS=		$LIBS

# not BSD make only:
#VPATH=		$srcdir
#all: \$(PROG)
#\$(PROG): \$(OBJS_BP)
#	\$(CC) \$(CFLAGS) \$(LDFLAGS) -o \$@ \$(OBJS_BP) \$(LIBS)
#\$(OBJS_BP): \$(SRCS_FP) \$(NONSRCS)
#.c.o:
#	\$(CC) \$(CFLAGS) \$(CPPFLAGS) -c \$<

# for all make variants:
#REGRESS_FLAGS=	-v
#regress:
#	./test.sh \$(REGRESS_FLAGS)

# for BSD make only:
#.PATH: $srcdir
#.include <bsd.prog.mk>
EOF
	$e
	$e Generated Makefrag.inc successfully.
	exit 0
fi
if test $cm = combine; then
	objs="-o $mkshexe"
	for file in $SRCS; do
		test -f $file || file=$srcdir/$file
		objs="$objs $file"
	done
	emitbc="-fwhole-program --combine"
	v "$CC $CFLAGS $CPPFLAGS $LDFLAGS $emitbc $objs $LIBS $ccpr"
elif test 1 = $pm; then
	for file in $SRCS; do
		test -f $file || file=$srcdir/$file
		v "$CC $CFLAGS $CPPFLAGS $emitbc $file" &
	done
	wait
else
	for file in $SRCS; do
		test $cm = dragonegg && \
		    op=`echo x"$file" | sed 's/^x\(.*\)\.c$/\1./'`
		test -f $file || file=$srcdir/$file
		v "$CC $CFLAGS $CPPFLAGS $emitbc $file" || exit 1
		if test $cm = dragonegg; then
			v "mv ${op}s ${op}ll"
			v "llvm-as ${op}ll" || exit 1
		fi
	done
fi
case $cm in
dragonegg|llvm)
	rmf mksh.s
	v "llvm-link -o - $objs | opt $optflags | llc -o mksh.s"
	;;
esac
tcfn=$mkshexe
test $cm = combine || v "$CC $CFLAGS $LDFLAGS -o $tcfn $lobjs $LIBS $ccpr"
test -f $tcfn || exit 1
test 1 = $r || v "$NROFF -mdoc <'$srcdir/mksh.1' >mksh.cat1" || \
    rmf mksh.cat1
test 0 = $eq && v size $tcfn
i=install
test -f /usr/ucb/$i && i=/usr/ucb/$i
test 1 = $eq && e=:
$e
$e Installing the shell:
$e "# $i -c -s -o root -g bin -m 555 mksh /bin/mksh"
$e "# grep -x /bin/mksh /etc/shells >/dev/null || echo /bin/mksh >>/etc/shells"
$e "# $i -c -o root -g bin -m 444 dot.mkshrc /usr/share/doc/mksh/examples/"
$e
$e Installing the manual:
if test -f mksh.cat1; then
	$e "# $i -c -o root -g bin -m 444 mksh.cat1" \
	    "/usr/share/man/cat1/mksh.0"
	$e or
fi
$e "# $i -c -o root -g bin -m 444 mksh.1 /usr/share/man/man1/mksh.1"
$e
$e Run the regression test suite: ./test.sh
$e Please also read the sample file dot.mkshrc and the fine manual.
exit 0
