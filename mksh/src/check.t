# $MirOS: src/bin/mksh/check.t,v 1.388 2010/08/24 15:47:44 tg Exp $
# $OpenBSD: bksl-nl.t,v 1.2 2001/01/28 23:04:56 niklas Exp $
# $OpenBSD: history.t,v 1.5 2001/01/28 23:04:56 niklas Exp $
# $OpenBSD: read.t,v 1.3 2003/03/10 03:48:16 david Exp $
#-
# Copyright © 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010
#	Thorsten Glaser <tg@mirbsd.org>
#
# Provided that these terms and disclaimer and all copyright notices
# are retained or reproduced in an accompanying document, permission
# is granted to deal in this work without restriction, including un‐
# limited rights to use, publicly perform, distribute, sell, modify,
# merge, give away, or sublicence.
#
# This work is provided “AS IS” and WITHOUT WARRANTY of any kind, to
# the utmost extent permitted by applicable law, neither express nor
# implied; without malicious intent or gross negligence. In no event
# may a licensor, author or contributor be held liable for indirect,
# direct, other damage, loss, or other issues arising in any way out
# of dealing in the work, even if advised of the possibility of such
# damage or existence of a defect, except proven that it results out
# of said person’s immediate fault when using the work as intended.
#-
# You may also want to test IFS with the script at
# http://www.research.att.com/~gsf/public/ifs.sh

expected-stdout:
	@(#)MIRBSD KSH R39 2010/08/24
description:
	Check version of shell.
stdin:
	echo $KSH_VERSION
name: KSH_VERSION
---
name: selftest-1
description:
	Regression test self-testing
stdin:
	echo ${foo:-baz}
expected-stdout:
	baz
---
name: selftest-2
description:
	Regression test self-testing
env-setup: !foo=bar!
stdin:
	echo ${foo:-baz}
expected-stdout:
	bar
---
name: selftest-3
description:
	Regression test self-testing
env-setup: !ENV=fnord!
stdin:
	echo "<$ENV>"
expected-stdout:
	<fnord>
---
name: selftest-env
description:
	Just output the environment variables set (always fails)
category: disabled
stdin:
	set
---
name: alias-1
description:
	Check that recursion is detected/avoided in aliases.
stdin:
	alias fooBar=fooBar
	fooBar
	exit 0
expected-stderr-pattern:
	/fooBar.*not found.*/
---
name: alias-2
description:
	Check that recursion is detected/avoided in aliases.
stdin:
	alias fooBar=barFoo
	alias barFoo=fooBar
	fooBar
	barFoo
	exit 0
expected-stderr-pattern:
	/fooBar.*not found.*\n.*barFoo.*not found/
---
name: alias-3
description:
	Check that recursion is detected/avoided in aliases.
stdin:
	alias Echo='echo '
	alias fooBar=barFoo
	alias barFoo=fooBar
	Echo fooBar
	unalias barFoo
	Echo fooBar
expected-stdout:
	fooBar
	barFoo
---
name: alias-4
description:
	Check that alias expansion isn't done on keywords (in keyword
	postitions).
stdin:
	alias Echo='echo '
	alias while=While
	while false; do echo hi ; done
	Echo while
expected-stdout:
	While
---
name: alias-5
description:
	Check that alias expansion done after alias with trailing space.
stdin:
	alias Echo='echo '
	alias foo='bar stuff '
	alias bar='Bar1 Bar2 '
	alias stuff='Stuff'
	alias blah='Blah'
	Echo foo blah
expected-stdout:
	Bar1 Bar2 Stuff Blah
---
name: alias-6
description:
	Check that alias expansion done after alias with trailing space.
stdin:
	alias Echo='echo '
	alias foo='bar bar'
	alias bar='Bar '
	alias blah=Blah
	Echo foo blah
expected-stdout:
	Bar Bar Blah
---
name: alias-7
description:
	Check that alias expansion done after alias with trailing space
	after a keyword.
stdin:
	alias X='case '
	alias Y=Z
	X Y in 'Y') echo is y ;; Z) echo is z ; esac
expected-stdout:
	is z
---
name: alias-8
description:
	Check that newlines in an alias don't cause the command to be lost.
stdin:
	alias foo='
	
	
	echo hi
	
	
	
	echo there
	
	
	'
	foo
expected-stdout:
	hi
	there
---
name: alias-9
description:
	Check that recursion is detected/avoided in aliases.
	This check fails for slow machines or Cygwin, raise
	the time-limit clause (e.g. to 7) if this occurs.
time-limit: 3
stdin:
	echo -n >tf
	alias ls=ls
	ls
	echo $(ls)
	exit 0
expected-stdout:
	tf
	tf
---
name: alias-10
description:
	Check that recursion is detected/avoided in aliases.
	Regression, introduced during an old bugfix.
stdin:
	alias foo='print hello '
	alias bar='foo world'
	echo $(bar)
expected-stdout:
	hello world
---
name: arith-lazy-1
description:
	Check that only one side of ternary operator is evaluated
stdin:
	x=i+=2
	y=j+=2
	typeset -i i=1 j=1
	echo $((1 ? 20 : (x+=2)))
	echo $i,$x
	echo $((0 ? (y+=2) : 30))
	echo $j,$y
expected-stdout:
	20
	1,i+=2
	30
	1,j+=2
---
name: arith-lazy-2
description:
	Check that assignments not done on non-evaluated side of ternary
	operator
stdin:
	x=i+=2
	y=j+=2
	typeset -i i=1 j=1
	echo $((1 ? 20 : (x+=2)))
	echo $i,$x
	echo $((0 ? (y+=2) : 30))
	echo $i,$y
expected-stdout:
	20
	1,i+=2
	30
	1,j+=2
---
name: arith-lazy-3
description:
	Check that assignments not done on non-evaluated side of ternary
	operator and this construct is parsed correctly (Debian #445651)
stdin:
	x=4
	y=$((0 ? x=1 : 2))
	echo = $x $y =
expected-stdout:
	= 4 2 =
---
name: arith-ternary-prec-1
description:
	Check precedence of ternary operator vs assignment
stdin:
	typeset -i x=2
	y=$((1 ? 20 : x+=2))
expected-exit: e != 0
expected-stderr-pattern:
	/.*:.*1 \? 20 : x\+=2.*lvalue.*\n$/
---
name: arith-ternary-prec-2
description:
	Check precedence of ternary operator vs assignment
stdin:
	typeset -i x=2
	echo $((0 ? x+=2 : 20))
expected-stdout:
	20
---
name: arith-div-assoc-1
description:
	Check associativity of division operator
stdin:
	echo $((20 / 2 / 2))
expected-stdout:
	5
---
name: arith-assop-assoc-1
description:
	Check associativity of assignment-operator operator
stdin:
	typeset -i i=1 j=2 k=3
	echo $((i += j += k))
	echo $i,$j,$k
expected-stdout:
	6
	6,5,3
---
name: arith-unsigned-1
description:
	Check if unsigned arithmetics work
stdin:
	# signed vs unsigned
	echo x1 $((-1)) $((#-1))
	# calculating
	typeset -i vs
	typeset -Ui vu
	vs=4123456789; vu=4123456789
	echo x2 $vs $vu
	(( vs %= 2147483647 ))
	(( vu %= 2147483647 ))
	echo x3 $vs $vu
	vs=4123456789; vu=4123456789
	(( # vs %= 2147483647 ))
	(( # vu %= 2147483647 ))
	echo x4 $vs $vu
	# make sure the calculation does not change unsigned flag
	vs=4123456789; vu=4123456789
	echo x5 $vs $vu
	# short form
	echo x6 $((# vs % 2147483647)) $((# vu % 2147483647))
	# array refs
	set -A va
	va[1975973142]=right
	va[4123456789]=wrong
	echo x7 ${va[#4123456789%2147483647]}
expected-stdout:
	x1 -1 4294967295
	x2 -171510507 4123456789
	x3 -171510507 4123456789
	x4 1975973142 1975973142
	x5 -171510507 4123456789
	x6 1975973142 1975973142
	x7 right
---
name: arith-limit32-1
description:
	Check if arithmetics are 32 bit
stdin:
	# signed vs unsigned
	echo x1 $((-1)) $((#-1))
	# calculating
	typeset -i vs
	typeset -Ui vu
	vs=2147483647; vu=2147483647
	echo x2 $vs $vu
	let vs++ vu++
	echo x3 $vs $vu
	vs=4294967295; vu=4294967295
	echo x4 $vs $vu
	let vs++ vu++
	echo x5 $vs $vu
	let vs++ vu++
	echo x6 $vs $vu
expected-stdout:
	x1 -1 4294967295
	x2 2147483647 2147483647
	x3 -2147483648 2147483648
	x4 -1 4294967295
	x5 0 0
	x6 1 1
---
name: bksl-nl-ign-1
description:
	Check that \newline is not collasped after #
stdin:
	echo hi #there \
	echo folks
expected-stdout:
	hi
	folks
---
name: bksl-nl-ign-2
description:
	Check that \newline is not collasped inside single quotes
stdin:
	echo 'hi \
	there'
	echo folks
expected-stdout:
	hi \
	there
	folks
---
name: bksl-nl-ign-3
description:
	Check that \newline is not collasped inside single quotes
stdin:
	cat << \EOF
	hi \
	there
	EOF
expected-stdout:
	hi \
	there
---
name: bksl-nl-ign-4
description:
	Check interaction of aliases, single quotes and here-documents
	with backslash-newline
	(don't know what POSIX has to say about this)
stdin:
	a=2
	alias x='echo hi
	cat << "EOF"
	foo\
	bar
	some'
	x
	more\
	stuff$a
	EOF
expected-stdout:
	hi
	foo\
	bar
	some
	more\
	stuff$a
---
name: bksl-nl-ign-5
description:
	Check what happens with backslash at end of input
	(the old Bourne shell trashes them; so do we)
stdin: !
	echo `echo foo\\`bar
	echo hi\
expected-stdout:
	foobar
	hi
---
#
# Places \newline should be collapsed
#
name: bksl-nl-1
description:
	Check that \newline is collasped before, in the middle of, and
	after words
stdin:
	 	 	\
			 echo hi\
	There, \
	folks
expected-stdout:
	hiThere, folks
---
name: bksl-nl-2
description:
	Check that \newline is collasped in $ sequences
	(ksh93 fails this)
stdin:
	a=12
	ab=19
	echo $\
	a
	echo $a\
	b
	echo $\
	{a}
	echo ${a\
	b}
	echo ${ab\
	}
expected-stdout:
	12
	19
	12
	19
	19
---
name: bksl-nl-3
description:
	Check that \newline is collasped in $(..) and `...` sequences
	(ksh93 fails this)
stdin:
	echo $\
	(echo foobar1)
	echo $(\
	echo foobar2)
	echo $(echo foo\
	bar3)
	echo $(echo foobar4\
	)
	echo `
	echo stuff1`
	echo `echo st\
	uff2`
expected-stdout:
	foobar1
	foobar2
	foobar3
	foobar4
	stuff1
	stuff2
---
name: bksl-nl-4
description:
	Check that \newline is collasped in $((..)) sequences
	(ksh93 fails this)
stdin:
	echo $\
	((1+2))
	echo $(\
	(1+2+3))
	echo $((\
	1+2+3+4))
	echo $((1+\
	2+3+4+5))
	echo $((1+2+3+4+5+6)\
	)
expected-stdout:
	3
	6
	10
	15
	21
---
name: bksl-nl-5
description:
	Check that \newline is collasped in double quoted strings
stdin:
	echo "\
	hi"
	echo "foo\
	bar"
	echo "folks\
	"
expected-stdout:
	hi
	foobar
	folks
---
name: bksl-nl-6
description:
	Check that \newline is collasped in here document delimiters
	(ksh93 fails second part of this)
stdin:
	a=12
	cat << EO\
	F
	a=$a
	foo\
	bar
	EOF
	cat << E_O_F
	foo
	E_O_\
	F
	echo done
expected-stdout:
	a=12
	foobar
	foo
	done
---
name: bksl-nl-7
description:
	Check that \newline is collasped in double-quoted here-document
	delimiter.
stdin:
	a=12
	cat << "EO\
	F"
	a=$a
	foo\
	bar
	EOF
	echo done
expected-stdout:
	a=$a
	foo\
	bar
	done
---
name: bksl-nl-8
description:
	Check that \newline is collasped in various 2+ character tokens
	delimiter.
	(ksh93 fails this)
stdin:
	echo hi &\
	& echo there
	echo foo |\
	| echo bar
	cat <\
	< EOF
	stuff
	EOF
	cat <\
	<\
	- EOF
		more stuff
	EOF
	cat <<\
	EOF
	abcdef
	EOF
	echo hi >\
	> /dev/null
	echo $?
	i=1
	case $i in
	(\
	x|\
	1\
	) echo hi;\
	;
	(*) echo oops
	esac
expected-stdout:
	hi
	there
	foo
	stuff
	more stuff
	abcdef
	0
	hi
---
name: bksl-nl-9
description:
	Check that \ at the end of an alias is collapsed when followed
	by a newline
	(don't know what POSIX has to say about this)
stdin:
	alias x='echo hi\'
	x
	echo there
expected-stdout:
	hiecho there
---
name: bksl-nl-10
description:
	Check that \newline in a keyword is collapsed
stdin:
	i\
	f true; then\
	 echo pass; el\
	se echo fail; fi
expected-stdout:
	pass
---
#
# Places \newline should be collapsed (ksh extensions)
#
name: bksl-nl-ksh-1
description:
	Check that \newline is collapsed in extended globbing
	(ksh93 fails this)
stdin:
	xxx=foo
	case $xxx in
	(f*\
	(\
	o\
	)\
	) echo ok ;;
	*) echo bad
	esac
expected-stdout:
	ok
---
name: bksl-nl-ksh-2
description:
	Check that \newline is collapsed in ((...)) expressions
	(ksh93 fails this)
stdin:
	i=1
	(\
	(\
	i=i+2\
	)\
	)
	echo $i
expected-stdout:
	3
---
name: break-1
description:
	See if break breaks out of loops
stdin:
	for i in a b c; do echo $i; break; echo bad-$i; done
	echo end-1
	for i in a b c; do echo $i; break 1; echo bad-$i; done
	echo end-2
	for i in a b c; do
	    for j in x y z; do
		echo $i:$j
		break
		echo bad-$i
	    done
	    echo end-$i
	done
	echo end-3
expected-stdout:
	a
	end-1
	a
	end-2
	a:x
	end-a
	b:x
	end-b
	c:x
	end-c
	end-3
---
name: break-2
description:
	See if break breaks out of nested loops
stdin:
	for i in a b c; do
	    for j in x y z; do
		echo $i:$j
		break 2
		echo bad-$i
	    done
	    echo end-$i
	done
	echo end
expected-stdout:
	a:x
	end
---
name: break-3
description:
	What if break used outside of any loops
	(ksh88,ksh93 don't print error messages here)
stdin:
	break
expected-stderr-pattern:
	/.*break.*/
---
name: break-4
description:
	What if break N used when only N-1 loops
	(ksh88,ksh93 don't print error messages here)
stdin:
	for i in a b c; do echo $i; break 2; echo bad-$i; done
	echo end
expected-stdout:
	a
	end
expected-stderr-pattern:
	/.*break.*/
---
name: break-5
description:
	Error if break argument isn't a number
stdin:
	for i in a b c; do echo $i; break abc; echo more-$i; done
	echo end
expected-stdout:
	a
expected-exit: e != 0
expected-stderr-pattern:
	/.*break.*/
---
name: continue-1
description:
	See if continue continues loops
stdin:
	for i in a b c; do echo $i; continue; echo bad-$i ; done
	echo end-1
	for i in a b c; do echo $i; continue 1; echo bad-$i; done
	echo end-2
	for i in a b c; do
	    for j in x y z; do
		echo $i:$j
		continue
		echo bad-$i-$j
	    done
	    echo end-$i
	done
	echo end-3
expected-stdout:
	a
	b
	c
	end-1
	a
	b
	c
	end-2
	a:x
	a:y
	a:z
	end-a
	b:x
	b:y
	b:z
	end-b
	c:x
	c:y
	c:z
	end-c
	end-3
---
name: continue-2
description:
	See if continue breaks out of nested loops
stdin:
	for i in a b c; do
	    for j in x y z; do
		echo $i:$j
		continue 2
		echo bad-$i-$j
	    done
	    echo end-$i
	done
	echo end
expected-stdout:
	a:x
	b:x
	c:x
	end
---
name: continue-3
description:
	What if continue used outside of any loops
	(ksh88,ksh93 don't print error messages here)
stdin:
	continue
expected-stderr-pattern:
	/.*continue.*/
---
name: continue-4
description:
	What if continue N used when only N-1 loops
	(ksh88,ksh93 don't print error messages here)
stdin:
	for i in a b c; do echo $i; continue 2; echo bad-$i; done
	echo end
expected-stdout:
	a
	b
	c
	end
expected-stderr-pattern:
	/.*continue.*/
---
name: continue-5
description:
	Error if continue argument isn't a number
stdin:
	for i in a b c; do echo $i; continue abc; echo more-$i; done
	echo end
expected-stdout:
	a
expected-exit: e != 0
expected-stderr-pattern:
	/.*continue.*/
---
name: cd-history
description:
	Test someone's CD history package (uses arrays)
stdin:
	# go to known place before doing anything
	cd /
	
	alias cd=_cd
	function _cd
	{
		typeset -i cdlen i
		typeset t
	
		if [ $# -eq 0 ]
		then
			set -- $HOME
		fi
	
		if [ "$CDHISTFILE" -a -r "$CDHISTFILE" ] # if directory history exists
		then
			typeset CDHIST
			i=-1
			while read -r t			# read directory history file
			do
				CDHIST[i=i+1]=$t
			done <$CDHISTFILE
		fi
	
		if [ "${CDHIST[0]}" != "$PWD" -a "$PWD" != "" ]
		then
			_cdins				# insert $PWD into cd history
		fi
	
		cdlen=${#CDHIST[*]}			# number of elements in history
	
		case "$@" in
		-)					# cd to new dir
			if [ "$OLDPWD" = "" ] && ((cdlen>1))
			then
				'print' ${CDHIST[1]}
				'cd' ${CDHIST[1]}
				_pwd
			else
				'cd' $@
				_pwd
			fi
			;;
		-l)					# print directory list
			typeset -R3 num
			((i=cdlen))
			while (((i=i-1)>=0))
			do
				num=$i
				'print' "$num ${CDHIST[i]}"
			done
			return
			;;
		-[0-9]|-[0-9][0-9])			# cd to dir in list
			if (((i=${1#-})<cdlen))
			then
				'print' ${CDHIST[i]}
				'cd' ${CDHIST[i]}
				_pwd
			else
				'cd' $@
				_pwd
			fi
			;;
		-*)					# cd to matched dir in list
			t=${1#-}
			i=1
			while ((i<cdlen))
			do
				case ${CDHIST[i]} in
				*$t*)
					'print' ${CDHIST[i]}
					'cd' ${CDHIST[i]}
					_pwd
					break
					;;
				esac
				((i=i+1))
			done
			if ((i>=cdlen))
			then
				'cd' $@
				_pwd
			fi
			;;
		*)					# cd to new dir
			'cd' $@
			_pwd
			;;
		esac
	
		_cdins					# insert $PWD into cd history
	
		if [ "$CDHISTFILE" ]
		then
			cdlen=${#CDHIST[*]}		# number of elements in history
	
			i=0
			while ((i<cdlen))
			do
				'print' -r ${CDHIST[i]}	# update directory history
				((i=i+1))
			done >$CDHISTFILE
		fi
	}
	
	function _cdins					# insert $PWD into cd history
	{						# meant to be called only by _cd
		typeset -i i
	
		((i=0))
		while ((i<${#CDHIST[*]}))		# see if dir is already in list
		do
			if [ "${CDHIST[$i]}" = "$PWD" ]
			then
				break
			fi
			((i=i+1))
		done
	
		if ((i>22))				# limit max size of list
		then
			i=22
		fi
	
		while (((i=i-1)>=0))			# bump old dirs in list
		do
			CDHIST[i+1]=${CDHIST[i]}
		done
	
		CDHIST[0]=$PWD				# insert new directory in list
	}
	
	
	function _pwd
	{
		if [ -n "$ECD" ]
		then
			pwd 1>&6
		fi
	}
	# Start of test
	cd /tmp
	cd /bin
	cd /etc
	cd -
	cd -2
	cd -l
expected-stdout:
	/bin
	/tmp
	  3 /
	  2 /etc
	  1 /bin
	  0 /tmp
---
name: env-prompt
description:
	Check that prompt not printed when processing ENV
env-setup: !ENV=./foo!
file-setup: file 644 "foo"
	XXX=_
	PS1=X
	false && echo hmmm
arguments: !-i!
stdin:
	echo hi${XXX}there
expected-stdout:
	hi_there
expected-stderr: !
	XX
---
name: expand-ugly
description:
	Check that weird ${foo+bar} constructs are parsed correctly
stdin:
	(echo 1 ${IFS+'}'z}) 2>&- || echo failed in 1
	(echo 2 "${IFS+'}'z}") 2>&- || echo failed in 2
	(echo 3 "foo ${IFS+'bar} baz") 2>&- || echo failed in 3
	(echo -n '4 '; printf '%s\n' "foo ${IFS+"b   c"} baz") 2>&- || echo failed in 4
	(echo -n '5 '; printf '%s\n' "foo ${IFS+b   c} baz") 2>&- || echo failed in 5
	(echo 6 ${IFS+"}"z}) 2>&- || echo failed in 6
	(echo 7 "${IFS+"}"z}") 2>&- || echo failed in 7
	(echo 8 "${IFS+\"}\"z}") 2>&- || echo failed in 8
	(echo 9 "${IFS+\"\}\"z}") 2>&- || echo failed in 9
	(echo 10 foo ${IFS+'bar} baz'}) 2>&- || echo failed in 10
	(echo 11 "$(echo "${IFS+'}'z}")") 2>&- || echo failed in 11
	(echo 12 "$(echo ${IFS+'}'z})") 2>&- || echo failed in 12
	(echo 13 ${IFS+\}z}) 2>&- || echo failed in 13
	(echo 14 "${IFS+\}z}") 2>&- || echo failed in 14
	u=x; (echo -n '15 '; printf '<%s> ' "foo ${IFS+a"b$u{ {"{{\}b} c ${IFS+d{}} bar" ${IFS-e{}} baz; echo .) 2>&- || echo failed in 15
	l=t; (echo 16 ${IFS+h`echo -n i ${IFS+$l}h`ere}) 2>&- || echo failed in 16
	l=t; (echo 17 ${IFS+h$(echo -n i ${IFS+$l}h)ere}) 2>&- || echo failed in 17
	l=t; (echo 18 "${IFS+h`echo -n i ${IFS+$l}h`ere}") 2>&- || echo failed in 18
	l=t; (echo 19 "${IFS+h$(echo -n i ${IFS+$l}h)ere}") 2>&- || echo failed in 19
	l=t; (echo 20 ${IFS+h`echo -n i "${IFS+$l}"h`ere}) 2>&- || echo failed in 20
	l=t; (echo 21 ${IFS+h$(echo -n i "${IFS+$l}"h)ere}) 2>&- || echo failed in 21
	l=t; (echo 22 "${IFS+h`echo -n i "${IFS+$l}"h`ere}") 2>&- || echo failed in 22
	l=t; (echo 23 "${IFS+h$(echo -n i "${IFS+$l}"h)ere}") 2>&- || echo failed in 23
	key=value; (echo -n '24 '; printf '%s\n' "${IFS+'$key'}") 2>&- || echo failed in 24
	key=value; (echo -n '25 '; printf '%s\n' "${IFS+"'$key'"}") 2>&- || echo failed in 25	# ksh93: “'$key'”
	key=value; (echo -n '26 '; printf '%s\n' ${IFS+'$key'}) 2>&- || echo failed in 26
	key=value; (echo -n '27 '; printf '%s\n' ${IFS+"'$key'"}) 2>&- || echo failed in 27
	(echo -n '28 '; printf '%s\n' "${IFS+"'"x ~ x'}'x"'}"x}" #') 2>&- || echo failed in 28
	u=x; (echo -n '29 '; printf '<%s> ' foo ${IFS+a"b$u{ {"{ {\}b} c ${IFS+d{}} bar ${IFS-e{}} baz; echo .) 2>&- || echo failed in 29
	(echo -n '30 '; printf '<%s> ' ${IFS+foo 'b\
	ar' baz}; echo .) 2>&- || (echo failed in 30; echo failed in 31)
	(echo -n '32 '; printf '<%s> ' ${IFS+foo "b\
	ar" baz}; echo .) 2>&- || echo failed in 32
	(echo -n '33 '; printf '<%s> ' "${IFS+foo 'b\
	ar' baz}"; echo .) 2>&- || echo failed in 33
	(echo -n '34 '; printf '<%s> ' "${IFS+foo "b\
	ar" baz}"; echo .) 2>&- || echo failed in 34
	(echo -n '35 '; printf '<%s> ' ${v=a\ b} x ${v=c\ d}; echo .) 2>&- || echo failed in 35
	(echo -n '36 '; printf '<%s> ' "${v=a\ b}" x "${v=c\ d}"; echo .) 2>&- || echo failed in 36
	(echo -n '37 '; printf '<%s> ' ${v-a\ b} x ${v-c\ d}; echo .) 2>&- || echo failed in 37
	(echo 38 ${IFS+x'a'y} / "${IFS+x'a'y}" .) 2>&- || echo failed in 38
	foo="x'a'y"; (echo 39 ${foo%*'a'*} / "${foo%*'a'*}" .) 2>&- || echo failed in 39
	foo="a b c"; (echo -n '40 '; printf '<%s> ' "${foo#a}"; echo .) 2>&- || echo failed in 40
expected-stdout:
	1 }z
	2 ''z}
	3 foo 'bar baz
	4 foo b   c baz
	5 foo b   c baz
	6 }z
	7 }z
	8 ""z}
	9 "}"z
	10 foo bar} baz
	11 ''z}
	12 }z
	13 }z
	14 }z
	15 <foo abx{ {{{}b c d{} bar> <}> <baz> .
	16 hi there
	17 hi there
	18 hi there
	19 hi there
	20 hi there
	21 hi there
	22 hi there
	23 hi there
	24 'value'
	25 'value'
	26 $key
	27 'value'
	28 'x ~ x''x}"x}" #
	29 <foo> <abx{ {{> <{}b> <c> <d{}> <bar> <}> <baz> .
	30 <foo> <b\
	ar> <baz> .
	32 <foo> <bar> <baz> .
	33 <foo 'bar' baz> .
	34 <foo bar baz> .
	35 <a> <b> <x> <a> <b> .
	36 <a\ b> <x> <a\ b> .
	37 <a b> <x> <c d> .
	38 xay / x'a'y .
	39 x' / x' .
	40 < b c> .
---
name: expand-unglob-dblq
description:
	Check that regular "${foo+bar}" constructs are parsed correctly
stdin:
	u=x
	tl_norm() {
		v=$2
		test x"$v" = x"-" && unset v
		(echo "$1 plus norm foo ${v+'bar'} baz")
		(echo "$1 dash norm foo ${v-'bar'} baz")
		(echo "$1 eqal norm foo ${v='bar'} baz")
		(echo "$1 qstn norm foo ${v?'bar'} baz") 2>&- || \
		    echo "$1 qstn norm -> error"
		(echo "$1 PLUS norm foo ${v:+'bar'} baz")
		(echo "$1 DASH norm foo ${v:-'bar'} baz")
		(echo "$1 EQAL norm foo ${v:='bar'} baz")
		(echo "$1 QSTN norm foo ${v:?'bar'} baz") 2>&- || \
		    echo "$1 QSTN norm -> error"
	}
	tl_paren() {
		v=$2
		test x"$v" = x"-" && unset v
		(echo "$1 plus parn foo ${v+(bar)} baz")
		(echo "$1 dash parn foo ${v-(bar)} baz")
		(echo "$1 eqal parn foo ${v=(bar)} baz")
		(echo "$1 qstn parn foo ${v?(bar)} baz") 2>&- || \
		    echo "$1 qstn parn -> error"
		(echo "$1 PLUS parn foo ${v:+(bar)} baz")
		(echo "$1 DASH parn foo ${v:-(bar)} baz")
		(echo "$1 EQAL parn foo ${v:=(bar)} baz")
		(echo "$1 QSTN parn foo ${v:?(bar)} baz") 2>&- || \
		    echo "$1 QSTN parn -> error"
	}
	tl_brace() {
		v=$2
		test x"$v" = x"-" && unset v
		(echo "$1 plus brac foo ${v+a$u{{{\}b} c ${v+d{}} baz")
		(echo "$1 dash brac foo ${v-a$u{{{\}b} c ${v-d{}} baz")
		(echo "$1 eqal brac foo ${v=a$u{{{\}b} c ${v=d{}} baz")
		(echo "$1 qstn brac foo ${v?a$u{{{\}b} c ${v?d{}} baz") 2>&- || \
		    echo "$1 qstn brac -> error"
		(echo "$1 PLUS brac foo ${v:+a$u{{{\}b} c ${v:+d{}} baz")
		(echo "$1 DASH brac foo ${v:-a$u{{{\}b} c ${v:-d{}} baz")
		(echo "$1 EQAL brac foo ${v:=a$u{{{\}b} c ${v:=d{}} baz")
		(echo "$1 QSTN brac foo ${v:?a$u{{{\}b} c ${v:?d{}} baz") 2>&- || \
		    echo "$1 QSTN brac -> error"
	}
	tl_norm 1 -
	tl_norm 2 ''
	tl_norm 3 x
	tl_paren 4 -
	tl_paren 5 ''
	tl_paren 6 x
	tl_brace 7 -
	tl_brace 8 ''
	tl_brace 9 x
expected-stdout:
	1 plus norm foo  baz
	1 dash norm foo 'bar' baz
	1 eqal norm foo 'bar' baz
	1 qstn norm -> error
	1 PLUS norm foo  baz
	1 DASH norm foo 'bar' baz
	1 EQAL norm foo 'bar' baz
	1 QSTN norm -> error
	2 plus norm foo 'bar' baz
	2 dash norm foo  baz
	2 eqal norm foo  baz
	2 qstn norm foo  baz
	2 PLUS norm foo  baz
	2 DASH norm foo 'bar' baz
	2 EQAL norm foo 'bar' baz
	2 QSTN norm -> error
	3 plus norm foo 'bar' baz
	3 dash norm foo x baz
	3 eqal norm foo x baz
	3 qstn norm foo x baz
	3 PLUS norm foo 'bar' baz
	3 DASH norm foo x baz
	3 EQAL norm foo x baz
	3 QSTN norm foo x baz
	4 plus parn foo  baz
	4 dash parn foo (bar) baz
	4 eqal parn foo (bar) baz
	4 qstn parn -> error
	4 PLUS parn foo  baz
	4 DASH parn foo (bar) baz
	4 EQAL parn foo (bar) baz
	4 QSTN parn -> error
	5 plus parn foo (bar) baz
	5 dash parn foo  baz
	5 eqal parn foo  baz
	5 qstn parn foo  baz
	5 PLUS parn foo  baz
	5 DASH parn foo (bar) baz
	5 EQAL parn foo (bar) baz
	5 QSTN parn -> error
	6 plus parn foo (bar) baz
	6 dash parn foo x baz
	6 eqal parn foo x baz
	6 qstn parn foo x baz
	6 PLUS parn foo (bar) baz
	6 DASH parn foo x baz
	6 EQAL parn foo x baz
	6 QSTN parn foo x baz
	7 plus brac foo  c } baz
	7 dash brac foo ax{{{}b c d{} baz
	7 eqal brac foo ax{{{}b c ax{{{}b} baz
	7 qstn brac -> error
	7 PLUS brac foo  c } baz
	7 DASH brac foo ax{{{}b c d{} baz
	7 EQAL brac foo ax{{{}b c ax{{{}b} baz
	7 QSTN brac -> error
	8 plus brac foo ax{{{}b c d{} baz
	8 dash brac foo  c } baz
	8 eqal brac foo  c } baz
	8 qstn brac foo  c } baz
	8 PLUS brac foo  c } baz
	8 DASH brac foo ax{{{}b c d{} baz
	8 EQAL brac foo ax{{{}b c ax{{{}b} baz
	8 QSTN brac -> error
	9 plus brac foo ax{{{}b c d{} baz
	9 dash brac foo x c x} baz
	9 eqal brac foo x c x} baz
	9 qstn brac foo x c x} baz
	9 PLUS brac foo ax{{{}b c d{} baz
	9 DASH brac foo x c x} baz
	9 EQAL brac foo x c x} baz
	9 QSTN brac foo x c x} baz
---
name: expand-unglob-unq
description:
	Check that regular ${foo+bar} constructs are parsed correctly
stdin:
	u=x
	tl_norm() {
		v=$2
		test x"$v" = x"-" && unset v
		(echo $1 plus norm foo ${v+'bar'} baz)
		(echo $1 dash norm foo ${v-'bar'} baz)
		(echo $1 eqal norm foo ${v='bar'} baz)
		(echo $1 qstn norm foo ${v?'bar'} baz) 2>&- || \
		    echo "$1 qstn norm -> error"
		(echo $1 PLUS norm foo ${v:+'bar'} baz)
		(echo $1 DASH norm foo ${v:-'bar'} baz)
		(echo $1 EQAL norm foo ${v:='bar'} baz)
		(echo $1 QSTN norm foo ${v:?'bar'} baz) 2>&- || \
		    echo "$1 QSTN norm -> error"
	}
	tl_paren() {
		v=$2
		test x"$v" = x"-" && unset v
		(echo $1 plus parn foo ${v+\(bar')'} baz)
		(echo $1 dash parn foo ${v-\(bar')'} baz)
		(echo $1 eqal parn foo ${v=\(bar')'} baz)
		(echo $1 qstn parn foo ${v?\(bar')'} baz) 2>&- || \
		    echo "$1 qstn parn -> error"
		(echo $1 PLUS parn foo ${v:+\(bar')'} baz)
		(echo $1 DASH parn foo ${v:-\(bar')'} baz)
		(echo $1 EQAL parn foo ${v:=\(bar')'} baz)
		(echo $1 QSTN parn foo ${v:?\(bar')'} baz) 2>&- || \
		    echo "$1 QSTN parn -> error"
	}
	tl_brace() {
		v=$2
		test x"$v" = x"-" && unset v
		(echo $1 plus brac foo ${v+a$u{{{\}b} c ${v+d{}} baz)
		(echo $1 dash brac foo ${v-a$u{{{\}b} c ${v-d{}} baz)
		(echo $1 eqal brac foo ${v=a$u{{{\}b} c ${v=d{}} baz)
		(echo $1 qstn brac foo ${v?a$u{{{\}b} c ${v?d{}} baz) 2>&- || \
		    echo "$1 qstn brac -> error"
		(echo $1 PLUS brac foo ${v:+a$u{{{\}b} c ${v:+d{}} baz)
		(echo $1 DASH brac foo ${v:-a$u{{{\}b} c ${v:-d{}} baz)
		(echo $1 EQAL brac foo ${v:=a$u{{{\}b} c ${v:=d{}} baz)
		(echo $1 QSTN brac foo ${v:?a$u{{{\}b} c ${v:?d{}} baz) 2>&- || \
		    echo "$1 QSTN brac -> error"
	}
	tl_norm 1 -
	tl_norm 2 ''
	tl_norm 3 x
	tl_paren 4 -
	tl_paren 5 ''
	tl_paren 6 x
	tl_brace 7 -
	tl_brace 8 ''
	tl_brace 9 x
expected-stdout:
	1 plus norm foo baz
	1 dash norm foo bar baz
	1 eqal norm foo bar baz
	1 qstn norm -> error
	1 PLUS norm foo baz
	1 DASH norm foo bar baz
	1 EQAL norm foo bar baz
	1 QSTN norm -> error
	2 plus norm foo bar baz
	2 dash norm foo baz
	2 eqal norm foo baz
	2 qstn norm foo baz
	2 PLUS norm foo baz
	2 DASH norm foo bar baz
	2 EQAL norm foo bar baz
	2 QSTN norm -> error
	3 plus norm foo bar baz
	3 dash norm foo x baz
	3 eqal norm foo x baz
	3 qstn norm foo x baz
	3 PLUS norm foo bar baz
	3 DASH norm foo x baz
	3 EQAL norm foo x baz
	3 QSTN norm foo x baz
	4 plus parn foo baz
	4 dash parn foo (bar) baz
	4 eqal parn foo (bar) baz
	4 qstn parn -> error
	4 PLUS parn foo baz
	4 DASH parn foo (bar) baz
	4 EQAL parn foo (bar) baz
	4 QSTN parn -> error
	5 plus parn foo (bar) baz
	5 dash parn foo baz
	5 eqal parn foo baz
	5 qstn parn foo baz
	5 PLUS parn foo baz
	5 DASH parn foo (bar) baz
	5 EQAL parn foo (bar) baz
	5 QSTN parn -> error
	6 plus parn foo (bar) baz
	6 dash parn foo x baz
	6 eqal parn foo x baz
	6 qstn parn foo x baz
	6 PLUS parn foo (bar) baz
	6 DASH parn foo x baz
	6 EQAL parn foo x baz
	6 QSTN parn foo x baz
	7 plus brac foo c } baz
	7 dash brac foo ax{{{}b c d{} baz
	7 eqal brac foo ax{{{}b c ax{{{}b} baz
	7 qstn brac -> error
	7 PLUS brac foo c } baz
	7 DASH brac foo ax{{{}b c d{} baz
	7 EQAL brac foo ax{{{}b c ax{{{}b} baz
	7 QSTN brac -> error
	8 plus brac foo ax{{{}b c d{} baz
	8 dash brac foo c } baz
	8 eqal brac foo c } baz
	8 qstn brac foo c } baz
	8 PLUS brac foo c } baz
	8 DASH brac foo ax{{{}b c d{} baz
	8 EQAL brac foo ax{{{}b c ax{{{}b} baz
	8 QSTN brac -> error
	9 plus brac foo ax{{{}b c d{} baz
	9 dash brac foo x c x} baz
	9 eqal brac foo x c x} baz
	9 qstn brac foo x c x} baz
	9 PLUS brac foo ax{{{}b c d{} baz
	9 DASH brac foo x c x} baz
	9 EQAL brac foo x c x} baz
	9 QSTN brac foo x c x} baz
---
name: eglob-bad-1
description:
	Check that globbing isn't done when glob has syntax error
file-setup: file 644 "abcx"
file-setup: file 644 "abcz"
file-setup: file 644 "bbc"
stdin:
	echo !([*)*
	echo +(a|b[)*
expected-stdout:
	!([*)*
	+(a|b[)*
---
name: eglob-bad-2
description:
	Check that globbing isn't done when glob has syntax error
	(AT&T ksh fails this test)
file-setup: file 644 "abcx"
file-setup: file 644 "abcz"
file-setup: file 644 "bbc"
stdin:
	echo [a*(]*)z
expected-stdout:
	[a*(]*)z
---
name: eglob-infinite-plus
description:
	Check that shell doesn't go into infinite loop expanding +(...)
	expressions.
file-setup: file 644 "abc"
time-limit: 3
stdin:
	echo +()c
	echo +()x
	echo +(*)c
	echo +(*)x
expected-stdout:
	+()c
	+()x
	abc
	+(*)x
---
name: eglob-subst-1
description:
	Check that eglobbing isn't done on substitution results
file-setup: file 644 "abc"
stdin:
	x='@(*)'
	echo $x
expected-stdout:
	@(*)
---
name: eglob-nomatch-1
description:
	Check that the pattern doesn't match
stdin:
	echo 1: no-file+(a|b)stuff
	echo 2: no-file+(a*(c)|b)stuff
	echo 3: no-file+((((c)))|b)stuff
expected-stdout:
	1: no-file+(a|b)stuff
	2: no-file+(a*(c)|b)stuff
	3: no-file+((((c)))|b)stuff
---
name: eglob-match-1
description:
	Check that the pattern matches correctly
file-setup: file 644 "abd"
file-setup: file 644 "acd"
file-setup: file 644 "abac"
stdin:
	echo 1: a+(b|c)d
	echo 2: a!(@(b|B))d
	echo 3: *(a(b|c))		# (...|...) can be used within X(..)
	echo 4: a[b*(foo|bar)]d		# patterns not special inside [...]
expected-stdout:
	1: abd acd
	2: acd
	3: abac
	4: abd
---
name: eglob-case-1
description:
	Simple negation tests
stdin:
	case foo in !(foo|bar)) echo yes;; *) echo no;; esac
	case bar in !(foo|bar)) echo yes;; *) echo no;; esac
expected-stdout:
	no
	no
---
name: eglob-case-2
description:
	Simple kleene tests
stdin:
	case foo in *(a|b[)) echo yes;; *) echo no;; esac
	case foo in *(a|b[)|f*) echo yes;; *) echo no;; esac
	case '*(a|b[)' in *(a|b[)) echo yes;; *) echo no;; esac
expected-stdout:
	no
	yes
	yes
---
name: eglob-trim-1
description:
	Eglobbing in trim expressions...
	(AT&T ksh fails this - docs say # matches shortest string, ## matches
	longest...)
stdin:
	x=abcdef
	echo 1: ${x#a|abc}
	echo 2: ${x##a|abc}
	echo 3: ${x%def|f}
	echo 4: ${x%%f|def}
expected-stdout:
	1: bcdef
	2: def
	3: abcde
	4: abc
---
name: eglob-trim-2
description:
	Check eglobbing works in trims...
stdin:
	x=abcdef
	echo 1: ${x#*(a|b)cd}
	echo 2: "${x#*(a|b)cd}"
	echo 3: ${x#"*(a|b)cd"}
	echo 4: ${x#a(b|c)}
expected-stdout:
	1: ef
	2: ef
	3: abcdef
	4: cdef
---
name: eglob-substrpl-1
description:
	Check eglobbing works in substs... and they work at all
stdin:
	[[ -n $BASH_VERSION ]] && shopt -s extglob
	x=1222321_ab/cde_b/c_1221
	y=xyz
	echo 1: ${x/2}
	echo 2: ${x//2}
	echo 3: ${x/+(2)}
	echo 4: ${x//+(2)}
	echo 5: ${x/2/4}
	echo 6: ${x//2/4}
	echo 7: ${x/+(2)/4}
	echo 8: ${x//+(2)/4}
	echo 9: ${x/b/c/e/f}
	echo 10: ${x/b\/c/e/f}
	echo 11: ${x/b\/c/e\/f}
	echo 12: ${x/b\/c/e\\/f}
	echo 13: ${x/b\\/c/e\\/f}
	echo 14: ${x//b/c/e/f}
	echo 15: ${x//b\/c/e/f}
	echo 16: ${x//b\/c/e\/f}
	echo 17: ${x//b\/c/e\\/f}
	echo 18: ${x//b\\/c/e\\/f}
	echo 19: ${x/b\/*\/c/x}
	echo 20: ${x/\//.}
	echo 21: ${x//\//.}
	echo 22: ${x///.}
	echo 23: ${x//#1/9}
	echo 24: ${x//%1/9}
	echo 25: ${x//\%1/9}
	echo 26: ${x//\\%1/9}
	echo 27: ${x//\a/9}
	echo 28: ${x//\\a/9}
	echo 29: ${x/2/$y}
expected-stdout:
	1: 122321_ab/cde_b/c_1221
	2: 131_ab/cde_b/c_11
	3: 1321_ab/cde_b/c_1221
	4: 131_ab/cde_b/c_11
	5: 1422321_ab/cde_b/c_1221
	6: 1444341_ab/cde_b/c_1441
	7: 14321_ab/cde_b/c_1221
	8: 14341_ab/cde_b/c_141
	9: 1222321_ac/e/f/cde_b/c_1221
	10: 1222321_ae/fde_b/c_1221
	11: 1222321_ae/fde_b/c_1221
	12: 1222321_ae\/fde_b/c_1221
	13: 1222321_ab/cde_b/c_1221
	14: 1222321_ac/e/f/cde_c/e/f/c_1221
	15: 1222321_ae/fde_e/f_1221
	16: 1222321_ae/fde_e/f_1221
	17: 1222321_ae\/fde_e\/f_1221
	18: 1222321_ab/cde_b/c_1221
	19: 1222321_ax_1221
	20: 1222321_ab.cde_b/c_1221
	21: 1222321_ab.cde_b.c_1221
	22: 1222321_ab/cde_b/c_1221
	23: 9222321_ab/cde_b/c_1221
	24: 1222321_ab/cde_b/c_1229
	25: 1222321_ab/cde_b/c_1229
	26: 1222321_ab/cde_b/c_1221
	27: 1222321_9b/cde_b/c_1221
	28: 1222321_9b/cde_b/c_1221
	29: 1xyz22321_ab/cde_b/c_1221
---
name: eglob-substrpl-2
description:
	Check anchored substring replacement works, corner cases
stdin:
	foo=123
	echo 1: ${foo/#/x}
	echo 2: ${foo/%/x}
	echo 3: ${foo/#/}
	echo 4: ${foo/#}
	echo 5: ${foo/%/}
	echo 6: ${foo/%}
expected-stdout:
	1: x123
	2: 123x
	3: 123
	4: 123
	5: 123
	6: 123
---
name: eglob-substrpl-3a
description:
	Check substring replacement works with variables and slashes, too
stdin:
	pfx=/home/user
	wd=/home/user/tmp
	echo "${wd/#$pfx/~}"
	echo "${wd/#\$pfx/~}"
	echo "${wd/#"$pfx"/~}"
	echo "${wd/#'$pfx'/~}"
	echo "${wd/#"\$pfx"/~}"
	echo "${wd/#'\$pfx'/~}"
expected-stdout:
	~/tmp
	/home/user/tmp
	~/tmp
	/home/user/tmp
	/home/user/tmp
	/home/user/tmp
---
name: eglob-substrpl-3b
description:
	More of this, bash fails it (bash4 passes)
stdin:
	pfx=/home/user
	wd=/home/user/tmp
	echo "${wd/#$(echo /home/user)/~}"
	echo "${wd/#"$(echo /home/user)"/~}"
	echo "${wd/#'$(echo /home/user)'/~}"
expected-stdout:
	~/tmp
	~/tmp
	/home/user/tmp
---
name: eglob-substrpl-3c
description:
	Even more weird cases
stdin:
	pfx=/home/user
	wd='$pfx/tmp'
	echo 1: ${wd/#$pfx/~}
	echo 2: ${wd/#\$pfx/~}
	echo 3: ${wd/#"$pfx"/~}
	echo 4: ${wd/#'$pfx'/~}
	echo 5: ${wd/#"\$pfx"/~}
	echo 6: ${wd/#'\$pfx'/~}
	ts='a/ba/b$tp$tp_a/b$tp_*(a/b)_*($tp)'
	tp=a/b
	tr=c/d
	[[ -n $BASH_VERSION ]] && shopt -s extglob
	echo 7: ${ts/a\/b/$tr}
	echo 8: ${ts/a\/b/\$tr}
	echo 9: ${ts/$tp/$tr}
	echo 10: ${ts/\$tp/$tr}
	echo 11: ${ts/\\$tp/$tr}
	echo 12: ${ts/$tp/c/d}
	echo 13: ${ts/$tp/c\/d}
	echo 14: ${ts/$tp/c\\/d}
	echo 15: ${ts/+(a\/b)/$tr}
	echo 16: ${ts/+(a\/b)/\$tr}
	echo 17: ${ts/+($tp)/$tr}
	echo 18: ${ts/+($tp)/c/d}
	echo 19: ${ts/+($tp)/c\/d}
	echo 25: ${ts//a\/b/$tr}
	echo 26: ${ts//a\/b/\$tr}
	echo 27: ${ts//$tp/$tr}
	echo 28: ${ts//$tp/c/d}
	echo 29: ${ts//$tp/c\/d}
	echo 30: ${ts//+(a\/b)/$tr}
	echo 31: ${ts//+(a\/b)/\$tr}
	echo 32: ${ts//+($tp)/$tr}
	echo 33: ${ts//+($tp)/c/d}
	echo 34: ${ts//+($tp)/c\/d}
	tp="+($tp)"
	echo 40: ${ts/$tp/$tr}
	echo 41: ${ts//$tp/$tr}
expected-stdout:
	1: $pfx/tmp
	2: ~/tmp
	3: $pfx/tmp
	4: ~/tmp
	5: ~/tmp
	6: ~/tmp
	7: c/da/b$tp$tp_a/b$tp_*(a/b)_*($tp)
	8: $tra/b$tp$tp_a/b$tp_*(a/b)_*($tp)
	9: c/da/b$tp$tp_a/b$tp_*(a/b)_*($tp)
	10: a/ba/bc/d$tp_a/b$tp_*(a/b)_*($tp)
	11: c/da/b$tp$tp_a/b$tp_*(a/b)_*($tp)
	12: c/da/b$tp$tp_a/b$tp_*(a/b)_*($tp)
	13: c/da/b$tp$tp_a/b$tp_*(a/b)_*($tp)
	14: c\/da/b$tp$tp_a/b$tp_*(a/b)_*($tp)
	15: c/d$tp$tp_a/b$tp_*(a/b)_*($tp)
	16: $tr$tp$tp_a/b$tp_*(a/b)_*($tp)
	17: c/d$tp$tp_a/b$tp_*(a/b)_*($tp)
	18: c/d$tp$tp_a/b$tp_*(a/b)_*($tp)
	19: c/d$tp$tp_a/b$tp_*(a/b)_*($tp)
	25: c/dc/d$tp$tp_c/d$tp_*(c/d)_*($tp)
	26: $tr$tr$tp$tp_$tr$tp_*($tr)_*($tp)
	27: c/dc/d$tp$tp_c/d$tp_*(c/d)_*($tp)
	28: c/dc/d$tp$tp_c/d$tp_*(c/d)_*($tp)
	29: c/dc/d$tp$tp_c/d$tp_*(c/d)_*($tp)
	30: c/d$tp$tp_c/d$tp_*(c/d)_*($tp)
	31: $tr$tp$tp_$tr$tp_*($tr)_*($tp)
	32: c/d$tp$tp_c/d$tp_*(c/d)_*($tp)
	33: c/d$tp$tp_c/d$tp_*(c/d)_*($tp)
	34: c/d$tp$tp_c/d$tp_*(c/d)_*($tp)
	40: a/ba/b$tp$tp_a/b$tp_*(a/b)_*($tp)
	41: a/ba/b$tp$tp_a/b$tp_*(a/b)_*($tp)
#	This is what GNU bash does:
#	40: c/d$tp$tp_a/b$tp_*(a/b)_*($tp)
#	41: c/d$tp$tp_c/d$tp_*(c/d)_*($tp)
---
name: eglob-utf8-1
description:
	UTF-8 mode differences for eglobbing
stdin:
	s=blöd
	set +U
	print 1: ${s%???} .
	print 2: ${s/b???d/x} .
	set -U
	print 3: ${s%???} .
	print 4: ${s/b??d/x} .
	x=nö
	print 5: ${x%?} ${x%%?} .
	x=äh
	print 6: ${x#?} ${x##?} .
	x=��
	print 7: ${x%?} ${x%%?} .
	x=mä�
	print 8: ${x%?} ${x%%?} .
	x=何
	print 9: ${x%?} ${x%%?} .
expected-stdout:
	1: bl .
	2: x .
	3: b .
	4: x .
	5: n n .
	6: h h .
	7: � � .
	8: mä mä .
	9: .
---
name: glob-bad-1
description:
	Check that globbing isn't done when glob has syntax error
file-setup: dir 755 "[x"
file-setup: file 644 "[x/foo"
stdin:
	echo [*
	echo *[x
	echo [x/*
expected-stdout:
	[*
	*[x
	[x/foo
---
name: glob-bad-2
description:
	Check that symbolic links aren't stat()'d
file-setup: dir 755 "dir"
file-setup: symlink 644 "dir/abc"
	non-existent-file
stdin:
	echo d*/*
	echo d*/abc
expected-stdout:
	dir/abc
	dir/abc
---
name: glob-range-1
description:
	Test range matching
file-setup: file 644 ".bc"
file-setup: file 644 "abc"
file-setup: file 644 "bbc"
file-setup: file 644 "cbc"
file-setup: file 644 "-bc"
stdin:
	echo [ab-]*
	echo [-ab]*
	echo [!-ab]*
	echo [!ab]*
	echo []ab]*
expected-stdout:
	-bc abc bbc
	-bc abc bbc
	cbc
	-bc cbc
	abc bbc
---
name: glob-range-2
description:
	Test range matching
	(AT&T ksh fails this; POSIX says invalid)
file-setup: file 644 "abc"
stdin:
	echo [a--]*
expected-stdout:
	[a--]*
---
name: glob-range-3
description:
	Check that globbing matches the right things...
# breaks on Mac OSX (HFS+ non-standard Unicode canonical decomposition)
category: !os:darwin
file-setup: file 644 "a�c"
stdin:
	echo a[�-�]*
expected-stdout:
	a�c
---
name: glob-range-4
description:
	Results unspecified according to POSIX
file-setup: file 644 ".bc"
stdin:
	echo [a.]*
expected-stdout:
	[a.]*
---
name: glob-range-5
description:
	Results unspecified according to POSIX
	(AT&T ksh treats this like [a-cc-e]*)
file-setup: file 644 "abc"
file-setup: file 644 "bbc"
file-setup: file 644 "cbc"
file-setup: file 644 "dbc"
file-setup: file 644 "ebc"
file-setup: file 644 "-bc"
stdin:
	echo [a-c-e]*
expected-stdout:
	-bc abc bbc cbc ebc
---
name: heredoc-1
description:
	Check ordering/content of redundent here documents.
stdin:
	cat << EOF1 << EOF2
	hi
	EOF1
	there
	EOF2
expected-stdout:
	there
---
name: heredoc-2
description:
	Check quoted here-doc is protected.
stdin:
	a=foo
	cat << 'EOF'
	hi\
	there$a
	stuff
	EO\
	F
	EOF
expected-stdout:
	hi\
	there$a
	stuff
	EO\
	F
---
name: heredoc-3
description:
	Check that newline isn't needed after heredoc-delimiter marker.
stdin: !
	cat << EOF
	hi
	there
	EOF
expected-stdout:
	hi
	there
---
name: heredoc-4
description:
	Check that an error occurs if the heredoc-delimiter is missing.
stdin: !
	cat << EOF
	hi
	there
expected-exit: e > 0
expected-stderr-pattern: /.*/
---
name: heredoc-5
description:
	Check that backslash quotes a $, ` and \ and kills a \newline
stdin:
	a=BAD
	b=ok
	cat << EOF
	h\${a}i
	h\\${b}i
	th\`echo not-run\`ere
	th\\`echo is-run`ere
	fol\\ks
	more\\
	last \
	line
	EOF
expected-stdout:
	h${a}i
	h\oki
	th`echo not-run`ere
	th\is-runere
	fol\ks
	more\
	last line
---
name: heredoc-6
description:
	Check that \newline in initial here-delim word doesn't imply
	a quoted here-doc.
stdin:
	a=i
	cat << EO\
	F
	h$a
	there
	EOF
expected-stdout:
	hi
	there
---
name: heredoc-7
description:
	Check that double quoted $ expressions in here delimiters are
	not expanded and match the delimiter.
	POSIX says only quote removal is applied to the delimiter.
stdin:
	a=b
	cat << "E$a"
	hi
	h$a
	hb
	E$a
	echo done
expected-stdout:
	hi
	h$a
	hb
	done
---
name: heredoc-8
description:
	Check that double quoted escaped $ expressions in here
	delimiters are not expanded and match the delimiter.
	POSIX says only quote removal is applied to the delimiter
	(\ counts as a quote).
stdin:
	a=b
	cat << "E\$a"
	hi
	h$a
	h\$a
	hb
	h\b
	E$a
	echo done
expected-stdout:
	hi
	h$a
	h\$a
	hb
	h\b
	done
---
name: heredoc-9a
description:
	Check that here strings work.
stdin:
	bar="bar
		baz"
	tr abcdefghijklmnopqrstuvwxyz nopqrstuvwxyzabcdefghijklm <<<foo
	"$__progname" -c "tr abcdefghijklmnopqrstuvwxyz nopqrstuvwxyzabcdefghijklm <<<foo"
	tr abcdefghijklmnopqrstuvwxyz nopqrstuvwxyzabcdefghijklm <<<"$bar"
	tr abcdefghijklmnopqrstuvwxyz nopqrstuvwxyzabcdefghijklm <<<'$bar'
	tr abcdefghijklmnopqrstuvwxyz nopqrstuvwxyzabcdefghijklm <<<\$bar
	tr abcdefghijklmnopqrstuvwxyz nopqrstuvwxyzabcdefghijklm <<<-foo
expected-stdout:
	sbb
	sbb
	one
		onm
	$one
	$one
	-sbb
---
name: heredoc-9b
description:
	Check that a corner case of here strings works like bash
stdin:
	fnord=42
	bar="bar
		 \$fnord baz"
	tr abcdefghijklmnopqrstuvwxyz nopqrstuvwxyzabcdefghijklm <<<$bar
expected-stdout:
	one $sabeq onm
category: bash
---
name: heredoc-9c
description:
	Check that a corner case of here strings works like ksh93, zsh
stdin:
	fnord=42
	bar="bar
		 \$fnord baz"
	tr abcdefghijklmnopqrstuvwxyz nopqrstuvwxyzabcdefghijklm <<<$bar
expected-stdout:
	one
		 $sabeq onm
---
name: heredoc-9d
description:
	Check another corner case of here strings
stdin:
	tr abcdefghijklmnopqrstuvwxyz nopqrstuvwxyzabcdefghijklm <<< bar
expected-stdout:
	one
---
name: heredoc-quoting-unsubst
description:
	Check for correct handling of quoted characters in
	here documents without substitution (marker is quoted).
stdin:
	foo=bar
	cat <<-'EOF'
		x " \" \ \\ $ \$ `echo baz` \`echo baz\` $foo \$foo x
	EOF
expected-stdout:
	x " \" \ \\ $ \$ `echo baz` \`echo baz\` $foo \$foo x
---
name: heredoc-quoting-subst
description:
	Check for correct handling of quoted characters in
	here documents with substitution (marker is not quoted).
stdin:
	foo=bar
	cat <<-EOF
		x " \" \ \\ $ \$ `echo baz` \`echo baz\` $foo \$foo x
	EOF
expected-stdout:
	x " \" \ \ $ $ baz `echo baz` bar $foo x
---
name: heredoc-tmpfile-1
description:
	Check that heredoc temp files aren't removed too soon or too late.
	Heredoc in simple command.
stdin:
	TMPDIR=$PWD
	eval '
		cat <<- EOF
		hi
		EOF
		for i in a b ; do
			cat <<- EOF
			more
			EOF
		done
	    ' &
	sleep 1
	echo Left overs: *
expected-stdout:
	hi
	more
	more
	Left overs: *
---
name: heredoc-tmpfile-2
description:
	Check that heredoc temp files aren't removed too soon or too late.
	Heredoc in function, multiple calls to function.
stdin:
	TMPDIR=$PWD
	eval '
		foo() {
			cat <<- EOF
			hi
			EOF
		}
		foo
		foo
	    ' &
	sleep 1
	echo Left overs: *
expected-stdout:
	hi
	hi
	Left overs: *
---
name: heredoc-tmpfile-3
description:
	Check that heredoc temp files aren't removed too soon or too late.
	Heredoc in function in loop, multiple calls to function.
stdin:
	TMPDIR=$PWD
	eval '
		foo() {
			cat <<- EOF
			hi
			EOF
		}
		for i in a b; do
			foo
			foo() {
				cat <<- EOF
				folks $i
				EOF
			}
		done
		foo
	    ' &
	sleep 1
	echo Left overs: *
expected-stdout:
	hi
	folks b
	folks b
	Left overs: *
---
name: heredoc-tmpfile-4
description:
	Check that heredoc temp files aren't removed too soon or too late.
	Backgrounded simple command with here doc
stdin:
	TMPDIR=$PWD
	eval '
		cat <<- EOF &
		hi
		EOF
	    ' &
	sleep 1
	echo Left overs: *
expected-stdout:
	hi
	Left overs: *
---
name: heredoc-tmpfile-5
description:
	Check that heredoc temp files aren't removed too soon or too late.
	Backgrounded subshell command with here doc
stdin:
	TMPDIR=$PWD
	eval '
	      (
		sleep 1	# so parent exits
		echo A
		cat <<- EOF
		hi
		EOF
		echo B
	      ) &
	    ' &
	sleep 2
	echo Left overs: *
expected-stdout:
	A
	hi
	B
	Left overs: *
---
name: heredoc-tmpfile-6
description:
	Check that heredoc temp files aren't removed too soon or too late.
	Heredoc in pipeline.
stdin:
	TMPDIR=$PWD
	eval '
		cat <<- EOF | sed "s/hi/HI/"
		hi
		EOF
	    ' &
	sleep 1
	echo Left overs: *
expected-stdout:
	HI
	Left overs: *
---
name: heredoc-tmpfile-7
description:
	Check that heredoc temp files aren't removed too soon or too late.
	Heredoc in backgrounded pipeline.
stdin:
	TMPDIR=$PWD
	eval '
		cat <<- EOF | sed 's/hi/HI/' &
		hi
		EOF
	    ' &
	sleep 1
	echo Left overs: *
expected-stdout:
	HI
	Left overs: *
---
name: heredoc-tmpfile-8
description:
	Check that heredoc temp files aren't removed too soon or too
	late. Heredoc in function, backgrounded call to function.
	This check can fail on slow machines (<100 MHz), or Cygwin,
	that's normal.
stdin:
	TMPDIR=$PWD
	# Background eval so main shell doesn't do parsing
	eval '
		foo() {
			cat <<- EOF
			hi
			EOF
		}
		foo
		# sleep so eval can die
		(sleep 1; foo) &
		(sleep 1; foo) &
		foo
	    ' &
	sleep 2
	echo Left overs: *
expected-stdout:
	hi
	hi
	hi
	hi
	Left overs: *
---
name: history-basic
description:
	See if we can test history at all
arguments: !-i!
env-setup: !ENV=./Env!HISTFILE=hist.file!
file-setup: file 644 "Env"
	PS1=X
stdin:
	echo hi
	fc -l
expected-stdout:
	hi
	1	echo hi
expected-stderr-pattern:
	/^X*$/
---
name: history-dups
description:
	Verify duplicates and spaces are not entered
arguments: !-i!
env-setup: !ENV=./Env!HISTFILE=hist.file!
file-setup: file 644 "Env"
	PS1=X
stdin:
	echo hi
	 echo yo
	echo hi
	fc -l
expected-stdout:
	hi
	yo
	hi
	1	echo hi
expected-stderr-pattern:
	/^X*$/
---
name: history-unlink
description:
	Check if broken HISTFILEs do not cause trouble
arguments: !-i!
env-setup: !ENV=./Env!HISTFILE=foo/hist.file!
file-setup: file 644 "Env"
	PS1=X
file-setup: dir 755 "foo"
file-setup: file 644 "foo/hist.file"
	sometext
time-limit: 5
perl-setup: chmod(0555, "foo");
stdin:
	echo hi
	fc -l
	chmod 0755 foo
expected-stdout:
	hi
	1	echo hi
expected-stderr-pattern:
	/(.*cannot unlink HISTFILE.*\n)?X*$/
---
name: history-e-minus-1
description:
	Check if more recent command is executed
arguments: !-i!
env-setup: !ENV=./Env!HISTFILE=hist.file!
file-setup: file 644 "Env"
	PS1=X
stdin:
	echo hi
	echo there
	fc -e -
expected-stdout:
	hi
	there
	there
expected-stderr-pattern:
	/^X*echo there\nX*$/
---
name: history-e-minus-2
description:
	Check that repeated command is printed before command
	is re-executed.
arguments: !-i!
env-setup: !ENV=./Env!HISTFILE=hist.file!
file-setup: file 644 "Env"
	PS1=X
stdin:
	exec 2>&1
	echo hi
	echo there
	fc -e -
expected-stdout-pattern:
	/X*hi\nX*there\nX*echo there\nthere\nX*/
expected-stderr-pattern:
	/^X*$/
---
name: history-e-minus-3
description:
	fc -e - fails when there is no history
	(ksh93 has a bug that causes this to fail)
	(ksh88 loops on this)
arguments: !-i!
env-setup: !ENV=./Env!HISTFILE=hist.file!
file-setup: file 644 "Env"
	PS1=X
stdin:
	fc -e -
	echo ok
expected-stdout:
	ok
expected-stderr-pattern:
	/^X*.*:.*history.*\nX*$/
---
name: history-e-minus-4
description:
	Check if "fc -e -" command output goes to stdout.
arguments: !-i!
env-setup: !ENV=./Env!HISTFILE=hist.file!
file-setup: file 644 "Env"
	PS1=X
stdin:
	echo abc
	fc -e - | (read x; echo "A $x")
	echo ok
expected-stdout:
	abc
	A abc
	ok
expected-stderr-pattern:
	/^X*echo abc\nX*/
---
name: history-e-minus-5
description:
	fc is replaced in history by new command.
arguments: !-i!
env-setup: !ENV=./Env!HISTFILE=hist.file!
file-setup: file 644 "Env"
	PS1=X
stdin:
	echo abc def
	echo ghi jkl
	:
	fc -e - echo
	fc -l 2 5
expected-stdout:
	abc def
	ghi jkl
	ghi jkl
	2	echo ghi jkl
	3	:
	4	echo ghi jkl
	5	fc -l 2 5
expected-stderr-pattern:
	/^X*echo ghi jkl\nX*$/
---
name: history-list-1
description:
	List lists correct range
	(ksh88 fails 'cause it lists the fc command)
arguments: !-i!
env-setup: !ENV=./Env!HISTFILE=hist.file!
file-setup: file 644 "Env"
	PS1=X
stdin:
	echo line 1
	echo line 2
	echo line 3
	fc -l -- -2
expected-stdout:
	line 1
	line 2
	line 3
	2	echo line 2
	3	echo line 3
expected-stderr-pattern:
	/^X*$/
---
name: history-list-2
description:
	Lists oldest history if given pre-historic number
	(ksh93 has a bug that causes this to fail)
	(ksh88 fails 'cause it lists the fc command)
arguments: !-i!
env-setup: !ENV=./Env!HISTFILE=hist.file!
file-setup: file 644 "Env"
	PS1=X
stdin:
	echo line 1
	echo line 2
	echo line 3
	fc -l -- -40
expected-stdout:
	line 1
	line 2
	line 3
	1	echo line 1
	2	echo line 2
	3	echo line 3
expected-stderr-pattern:
	/^X*$/
---
name: history-list-3
description:
	Can give number 'options' to fc
arguments: !-i!
env-setup: !ENV=./Env!HISTFILE=hist.file!
file-setup: file 644 "Env"
	PS1=X
stdin:
	echo line 1
	echo line 2
	echo line 3
	echo line 4
	fc -l -3 -2
expected-stdout:
	line 1
	line 2
	line 3
	line 4
	2	echo line 2
	3	echo line 3
expected-stderr-pattern:
	/^X*$/
---
name: history-list-4
description:
	-1 refers to previous command
arguments: !-i!
env-setup: !ENV=./Env!HISTFILE=hist.file!
file-setup: file 644 "Env"
	PS1=X
stdin:
	echo line 1
	echo line 2
	echo line 3
	echo line 4
	fc -l -1 -1
expected-stdout:
	line 1
	line 2
	line 3
	line 4
	4	echo line 4
expected-stderr-pattern:
	/^X*$/
---
name: history-list-5
description:
	List command stays in history
arguments: !-i!
env-setup: !ENV=./Env!HISTFILE=hist.file!
file-setup: file 644 "Env"
	PS1=X
stdin:
	echo line 1
	echo line 2
	echo line 3
	echo line 4
	fc -l -1 -1
	fc -l -2 -1
expected-stdout:
	line 1
	line 2
	line 3
	line 4
	4	echo line 4
	4	echo line 4
	5	fc -l -1 -1
expected-stderr-pattern:
	/^X*$/
---
name: history-list-6
description:
	HISTSIZE limits about of history kept.
	(ksh88 fails 'cause it lists the fc command)
arguments: !-i!
env-setup: !ENV=./Env!HISTFILE=hist.file!HISTSIZE=3!
file-setup: file 644 "Env"
	PS1=X
stdin:
	echo line 1
	echo line 2
	echo line 3
	echo line 4
	echo line 5
	fc -l
expected-stdout:
	line 1
	line 2
	line 3
	line 4
	line 5
	4	echo line 4
	5	echo line 5
expected-stderr-pattern:
	/^X*$/
---
name: history-list-7
description:
	fc allows too old/new errors in range specification
arguments: !-i!
env-setup: !ENV=./Env!HISTFILE=hist.file!HISTSIZE=3!
file-setup: file 644 "Env"
	PS1=X
stdin:
	echo line 1
	echo line 2
	echo line 3
	echo line 4
	echo line 5
	fc -l 1 30
expected-stdout:
	line 1
	line 2
	line 3
	line 4
	line 5
	4	echo line 4
	5	echo line 5
	6	fc -l 1 30
expected-stderr-pattern:
	/^X*$/
---
name: history-list-r-1
description:
	test -r flag in history
arguments: !-i!
env-setup: !ENV=./Env!HISTFILE=hist.file!
file-setup: file 644 "Env"
	PS1=X
stdin:
	echo line 1
	echo line 2
	echo line 3
	echo line 4
	echo line 5
	fc -l -r 2 4
expected-stdout:
	line 1
	line 2
	line 3
	line 4
	line 5
	4	echo line 4
	3	echo line 3
	2	echo line 2
expected-stderr-pattern:
	/^X*$/
---
name: history-list-r-2
description:
	If first is newer than last, -r is implied.
arguments: !-i!
env-setup: !ENV=./Env!HISTFILE=hist.file!
file-setup: file 644 "Env"
	PS1=X
stdin:
	echo line 1
	echo line 2
	echo line 3
	echo line 4
	echo line 5
	fc -l 4 2
expected-stdout:
	line 1
	line 2
	line 3
	line 4
	line 5
	4	echo line 4
	3	echo line 3
	2	echo line 2
expected-stderr-pattern:
	/^X*$/
---
name: history-list-r-3
description:
	If first is newer than last, -r is cancelled.
arguments: !-i!
env-setup: !ENV=./Env!HISTFILE=hist.file!
file-setup: file 644 "Env"
	PS1=X
stdin:
	echo line 1
	echo line 2
	echo line 3
	echo line 4
	echo line 5
	fc -l -r 4 2
expected-stdout:
	line 1
	line 2
	line 3
	line 4
	line 5
	2	echo line 2
	3	echo line 3
	4	echo line 4
expected-stderr-pattern:
	/^X*$/
---
name: history-subst-1
description:
	Basic substitution
arguments: !-i!
env-setup: !ENV=./Env!HISTFILE=hist.file!
file-setup: file 644 "Env"
	PS1=X
stdin:
	echo abc def
	echo ghi jkl
	fc -e - abc=AB 'echo a'
expected-stdout:
	abc def
	ghi jkl
	AB def
expected-stderr-pattern:
	/^X*echo AB def\nX*$/
---
name: history-subst-2
description:
	Does subst find previous command?
arguments: !-i!
env-setup: !ENV=./Env!HISTFILE=hist.file!
file-setup: file 644 "Env"
	PS1=X
stdin:
	echo abc def
	echo ghi jkl
	fc -e - jkl=XYZQRT 'echo g'
expected-stdout:
	abc def
	ghi jkl
	ghi XYZQRT
expected-stderr-pattern:
	/^X*echo ghi XYZQRT\nX*$/
---
name: history-subst-3
description:
	Does subst find previous command when no arguments given
arguments: !-i!
env-setup: !ENV=./Env!HISTFILE=hist.file!
file-setup: file 644 "Env"
	PS1=X
stdin:
	echo abc def
	echo ghi jkl
	fc -e - jkl=XYZQRT
expected-stdout:
	abc def
	ghi jkl
	ghi XYZQRT
expected-stderr-pattern:
	/^X*echo ghi XYZQRT\nX*$/
---
name: history-subst-4
description:
	Global substitutions work
	(ksh88 and ksh93 do not have -g option)
arguments: !-i!
env-setup: !ENV=./Env!HISTFILE=hist.file!
file-setup: file 644 "Env"
	PS1=X
stdin:
	echo abc def asjj sadjhasdjh asdjhasd
	fc -e - -g a=FooBAR
expected-stdout:
	abc def asjj sadjhasdjh asdjhasd
	FooBARbc def FooBARsjj sFooBARdjhFooBARsdjh FooBARsdjhFooBARsd
expected-stderr-pattern:
	/^X*echo FooBARbc def FooBARsjj sFooBARdjhFooBARsdjh FooBARsdjhFooBARsd\nX*$/
---
name: history-subst-5
description:
	Make sure searches don't find current (fc) command
	(ksh88/ksh93 don't have the ? prefix thing so they fail this test)
arguments: !-i!
env-setup: !ENV=./Env!HISTFILE=hist.file!
file-setup: file 644 "Env"
	PS1=X
stdin:
	echo abc def
	echo ghi jkl
	fc -e - abc=AB \?abc
expected-stdout:
	abc def
	ghi jkl
	AB def
expected-stderr-pattern:
	/^X*echo AB def\nX*$/
---
name: history-ed-1-old
description:
	Basic (ed) editing works (assumes you have generic ed editor
	that prints no prompts). This is for oldish ed(1) which write
	the character count to stdout.
category: stdout-ed
arguments: !-i!
env-setup: !ENV=./Env!HISTFILE=hist.file!
file-setup: file 644 "Env"
	PS1=X
stdin:
	echo abc def
	fc echo
	s/abc/FOOBAR/
	w
	q
expected-stdout:
	abc def
	13
	16
	FOOBAR def
expected-stderr-pattern:
	/^X*echo FOOBAR def\nX*$/
---
name: history-ed-2-old
description:
	Correct command is edited when number given
category: stdout-ed
arguments: !-i!
env-setup: !ENV=./Env!HISTFILE=hist.file!
file-setup: file 644 "Env"
	PS1=X
stdin:
	echo line 1
	echo line 2 is here
	echo line 3
	echo line 4
	fc 2
	s/is here/is changed/
	w
	q
expected-stdout:
	line 1
	line 2 is here
	line 3
	line 4
	20
	23
	line 2 is changed
expected-stderr-pattern:
	/^X*echo line 2 is changed\nX*$/
---
name: history-ed-3-old
description:
	Newly created multi line commands show up as single command
	in history.
	(NOTE: adjusted for COMPLEX HISTORY compile time option)
	(ksh88 fails 'cause it lists the fc command)
category: stdout-ed
arguments: !-i!
env-setup: !ENV=./Env!HISTFILE=hist.file!
file-setup: file 644 "Env"
	PS1=X
stdin:
	echo abc def
	fc echo
	s/abc/FOOBAR/
	$a
	echo a new line
	.
	w
	q
	fc -l
expected-stdout:
	abc def
	13
	32
	FOOBAR def
	a new line
	1	echo abc def
	2	echo FOOBAR def
	3	echo a new line
expected-stderr-pattern:
	/^X*echo FOOBAR def\necho a new line\nX*$/
---
name: history-ed-1
description:
	Basic (ed) editing works (assumes you have generic ed editor
	that prints no prompts). This is for newish ed(1) and stderr.
category: !no-stderr-ed
arguments: !-i!
env-setup: !ENV=./Env!HISTFILE=hist.file!
file-setup: file 644 "Env"
	PS1=X
stdin:
	echo abc def
	fc echo
	s/abc/FOOBAR/
	w
	q
expected-stdout:
	abc def
	FOOBAR def
expected-stderr-pattern:
	/^X*13\n16\necho FOOBAR def\nX*$/
---
name: history-ed-2
description:
	Correct command is edited when number given
category: !no-stderr-ed
arguments: !-i!
env-setup: !ENV=./Env!HISTFILE=hist.file!
file-setup: file 644 "Env"
	PS1=X
stdin:
	echo line 1
	echo line 2 is here
	echo line 3
	echo line 4
	fc 2
	s/is here/is changed/
	w
	q
expected-stdout:
	line 1
	line 2 is here
	line 3
	line 4
	line 2 is changed
expected-stderr-pattern:
	/^X*20\n23\necho line 2 is changed\nX*$/
---
name: history-ed-3
description:
	Newly created multi line commands show up as single command
	in history.
category: !no-stderr-ed
arguments: !-i!
env-setup: !ENV=./Env!HISTFILE=hist.file!
file-setup: file 644 "Env"
	PS1=X
stdin:
	echo abc def
	fc echo
	s/abc/FOOBAR/
	$a
	echo a new line
	.
	w
	q
	fc -l
expected-stdout:
	abc def
	FOOBAR def
	a new line
	1	echo abc def
	2	echo FOOBAR def
	3	echo a new line
expected-stderr-pattern:
	/^X*13\n32\necho FOOBAR def\necho a new line\nX*$/
---
name: IFS-space-1
description:
	Simple test, default IFS
stdin:
	showargs() { for i; do echo -n " <$i>"; done; echo; }
	set -- A B C
	showargs 1 $*
	showargs 2 "$*"
	showargs 3 $@
	showargs 4 "$@"
expected-stdout:
	 <1> <A> <B> <C>
	 <2> <A B C>
	 <3> <A> <B> <C>
	 <4> <A> <B> <C>
---
name: IFS-colon-1
description:
	Simple test, IFS=:
stdin:
	showargs() { for i; do echo -n " <$i>"; done; echo; }
	IFS=:
	set -- A B C
	showargs 1 $*
	showargs 2 "$*"
	showargs 3 $@
	showargs 4 "$@"
expected-stdout:
	 <1> <A> <B> <C>
	 <2> <A:B:C>
	 <3> <A> <B> <C>
	 <4> <A> <B> <C>
---
name: IFS-null-1
description:
	Simple test, IFS=""
stdin:
	showargs() { for i; do echo -n " <$i>"; done; echo; }
	IFS=""
	set -- A B C
	showargs 1 $*
	showargs 2 "$*"
	showargs 3 $@
	showargs 4 "$@"
expected-stdout:
	 <1> <A B C>
	 <2> <ABC>
	 <3> <A B C>
	 <4> <A B C>
---
name: IFS-space-colon-1
description:
	Simple test, IFS=<white-space>:
stdin:
	showargs() { for i; do echo -n " <$i>"; done; echo; }
	IFS="$IFS:"
	set --
	showargs 1 $*
	showargs 2 "$*"
	showargs 3 $@
	showargs 4 "$@"
	showargs 5 : "$@"
expected-stdout:
	 <1>
	 <2> <>
	 <3>
	 <4>
	 <5> <:>
---
name: IFS-space-colon-2
description:
	Simple test, IFS=<white-space>:
	AT&T ksh fails this, POSIX says the test is correct.
stdin:
	showargs() { for i; do echo -n " <$i>"; done; echo; }
	IFS="$IFS:"
	set --
	showargs :"$@"
expected-stdout:
	 <:>
---
name: IFS-space-colon-3
description:
	Simple test, IFS=<white-space>:
	pdksh fails both of these tests
	not sure whether #2 is correct
stdin:
	showargs() { for i; do echo -n " <$i>"; done; echo; }
	IFS="$IFS:"
	x=
	set --
	showargs "$x$@" 1
	showargs "$@$x" 2
expected-fail: yes
expected-stdout:
	 <> <1>
	 <> <2>
---
name: IFS-space-colon-4
description:
	Simple test, IFS=<white-space>:
stdin:
	showargs() { for i; do echo -n " <$i>"; done; echo; }
	IFS="$IFS:"
	set --
	showargs "$@$@"
expected-stdout:
	
---
name: IFS-space-colon-5
description:
	Simple test, IFS=<white-space>:
	Don't know what POSIX thinks of this.  AT&T ksh does not do this.
stdin:
	showargs() { for i; do echo -n " <$i>"; done; echo; }
	IFS="$IFS:"
	set --
	showargs "${@:-}"
expected-stdout:
	 <>
---
name: IFS-subst-1
description:
	Simple test, IFS=<white-space>:
stdin:
	showargs() { for i; do echo -n " <$i>"; done; echo; }
	IFS="$IFS:"
	x=":b: :"
	echo -n '1:'; for i in $x ; do echo -n " [$i]" ; done ; echo
	echo -n '2:'; for i in :b:: ; do echo -n " [$i]" ; done ; echo
	showargs 3 $x
	showargs 4 :b::
	x="a:b:"
	echo -n '5:'; for i in $x ; do echo -n " [$i]" ; done ; echo
	showargs 6 $x
	x="a::c"
	echo -n '7:'; for i in $x ; do echo -n " [$i]" ; done ; echo
	showargs 8 $x
	echo -n '9:'; for i in ${FOO-`echo -n h:i`th:ere} ; do echo -n " [$i]" ; done ; echo
	showargs 10 ${FOO-`echo -n h:i`th:ere}
	showargs 11 "${FOO-`echo -n h:i`th:ere}"
	x=" A :  B::D"
	echo -n '12:'; for i in $x ; do echo -n " [$i]" ; done ; echo
	showargs 13 $x
expected-stdout:
	1: [] [b] []
	2: [:b::]
	 <3> <> <b> <>
	 <4> <:b::>
	5: [a] [b]
	 <6> <a> <b>
	7: [a] [] [c]
	 <8> <a> <> <c>
	9: [h] [ith] [ere]
	 <10> <h> <ith> <ere>
	 <11> <h:ith:ere>
	12: [A] [B] [] [D]
	 <13> <A> <B> <> <D>
---
name: integer-base-err-1
description:
	Can't have 0 base (causes shell to exit)
expected-exit: e != 0
stdin:
	typeset -i i
	i=3
	i=0#4
	echo $i
expected-stderr-pattern:
	/^.*:.*0#4.*\n$/
---
name: integer-base-err-2
description:
	Can't have multiple bases in a 'constant' (causes shell to exit)
	(ksh88 fails this test)
expected-exit: e != 0
stdin:
	typeset -i i
	i=3
	i=2#110#11
	echo $i
expected-stderr-pattern:
	/^.*:.*2#110#11.*\n$/
---
name: integer-base-err-3
description:
	Syntax errors in expressions and effects on bases
	(interactive so errors don't cause exits)
	(ksh88 fails this test - shell exits, even with -i)
arguments: !-i!
stdin:
	PS1= # minimise prompt hassles
	typeset -i4 a=10
	typeset -i a=2+
	echo $a
	typeset -i4 a=10
	typeset -i2 a=2+
	echo $a
expected-stderr-pattern:
	/^([#\$] )?.*:.*2+.*\n.*:.*2+.*\n$/
expected-stdout:
	4#22
	4#22
---
name: integer-base-err-4
description:
	Are invalid digits (according to base) errors?
	(ksh93 fails this test)
expected-exit: e != 0
stdin:
	typeset -i i;
	i=3#4
expected-stderr-pattern:
	/^([#\$] )?.*:.*3#4.*\n$/
---
name: integer-base-1
description:
	Missing number after base is treated as 0.
stdin:
	typeset -i i
	i=3
	i=2#
	echo $i
expected-stdout:
	0
---
name: integer-base-2
description:
	Check 'stickyness' of base in various situations
stdin:
	typeset -i i=8
	echo $i
	echo ---------- A
	typeset -i4 j=8
	echo $j
	echo ---------- B
	typeset -i k=8
	typeset -i4 k=8
	echo $k
	echo ---------- C
	typeset -i4 l
	l=3#10
	echo $l
	echo ---------- D
	typeset -i m
	m=3#10
	echo $m
	echo ---------- E
	n=2#11
	typeset -i n
	echo $n
	n=10
	echo $n
	echo ---------- F
	typeset -i8 o=12
	typeset -i4 o
	echo $o
	echo ---------- G
	typeset -i p
	let p=8#12
	echo $p
expected-stdout:
	8
	---------- A
	4#20
	---------- B
	4#20
	---------- C
	4#3
	---------- D
	3#10
	---------- E
	2#11
	2#1010
	---------- F
	4#30
	---------- G
	8#12
---
name: integer-base-3
description:
	More base parsing (hmm doesn't test much..)
stdin:
	typeset -i aa
	aa=1+12#10+2
	echo $aa
	typeset -i bb
	bb=1+$aa
	echo $bb
	typeset -i bb
	bb=$aa
	echo $bb
	typeset -i cc
	cc=$aa
	echo $cc
expected-stdout:
	15
	16
	15
	15
---
name: integer-base-4
description:
	Check that things not declared as integers are not made integers,
	also, check if base is not reset by -i with no arguments.
	(ksh93 fails - prints 10#20 - go figure)
stdin:
	xx=20
	let xx=10
	typeset -i | grep '^xx='
	typeset -i4 a=10
	typeset -i a=20
	echo $a
expected-stdout:
	4#110
---
name: integer-base-5
description:
	More base stuff
stdin:
	typeset -i4 a=3#10
	echo $a
	echo --
	typeset -i j=3
	j='~3'
	echo $j
	echo --
	typeset -i k=1
	x[k=k+1]=3
	echo $k
	echo --
	typeset -i l
	for l in 1 2+3 4; do echo $l; done
expected-stdout:
	4#3
	--
	-4
	--
	2
	--
	1
	5
	4
---
name: integer-base-6
description:
	Even more base stuff
	(ksh93 fails this test - prints 0)
stdin:
	typeset -i7 i
	i=
	echo $i
expected-stdout:
	7#0
---
name: integer-base-7
description:
	Check that non-integer parameters don't get bases assigned
stdin:
	echo $(( zz = 8#100 ))
	echo $zz
expected-stdout:
	64
	64
---
name: lineno-stdin
description:
	See if $LINENO is updated and can be modified.
stdin:
	echo A $LINENO
	echo B $LINENO
	LINENO=20
	echo C $LINENO
expected-stdout:
	A 1
	B 2
	C 20
---
name: lineno-inc
description:
	See if $LINENO is set for .'d files.
file-setup: file 644 "dotfile"
	echo dot A $LINENO
	echo dot B $LINENO
	LINENO=20
	echo dot C $LINENO
stdin:
	echo A $LINENO
	echo B $LINENO
	. ./dotfile
expected-stdout:
	A 1
	B 2
	dot A 1
	dot B 2
	dot C 20
---
name: lineno-func
description:
	See if $LINENO is set for commands in a function.
stdin:
	echo A $LINENO
	echo B $LINENO
	bar() {
	    echo func A $LINENO
	    echo func B $LINENO
	}
	bar
	echo C $LINENO
expected-stdout:
	A 1
	B 2
	func A 4
	func B 5
	C 8
---
name: lineno-unset
description:
	See if unsetting LINENO makes it non-magic.
file-setup: file 644 "dotfile"
	echo dot A $LINENO
	echo dot B $LINENO
stdin:
	unset LINENO
	echo A $LINENO
	echo B $LINENO
	bar() {
	    echo func A $LINENO
	    echo func B $LINENO
	}
	bar
	. ./dotfile
	echo C $LINENO
expected-stdout:
	A
	B
	func A
	func B
	dot A
	dot B
	C
---
name: lineno-unset-use
description:
	See if unsetting LINENO makes it non-magic even
	when it is re-used.
file-setup: file 644 "dotfile"
	echo dot A $LINENO
	echo dot B $LINENO
stdin:
	unset LINENO
	LINENO=3
	echo A $LINENO
	echo B $LINENO
	bar() {
	    echo func A $LINENO
	    echo func B $LINENO
	}
	bar
	. ./dotfile
	echo C $LINENO
expected-stdout:
	A 3
	B 3
	func A 3
	func B 3
	dot A 3
	dot B 3
	C 3
---
name: lineno-trap
description:
	Check if LINENO is tracked in traps
stdin:
	fail() {
		echo "line <$1>"
		exit 1
	}
	trap 'fail $LINENO' INT ERR
	false
expected-stdout:
	line <6>
expected-exit: 1
---
name: read-IFS-1
description:
	Simple test, default IFS
stdin:
	echo "A B " > IN
	unset x y z
	read x y z < IN
	echo 1: "x[$x] y[$y] z[$z]"
	echo 1a: ${z-z not set}
	read x < IN
	echo 2: "x[$x]"
expected-stdout:
	1: x[A] y[B] z[]
	1a:
	2: x[A B]
---
name: read-ksh-1
description:
	If no var specified, REPLY is used
stdin:
	echo "abc" > IN
	read < IN
	echo "[$REPLY]";
expected-stdout:
	[abc]
---
name: regression-1
description:
	Lex array code had problems with this.
stdin:
	echo foo[
	n=bar
	echo "hi[ $n ]=1"
expected-stdout:
	foo[
	hi[ bar ]=1
---
name: regression-2
description:
	When PATH is set before running a command, the new path is
	not used in doing the path search
		$ echo echo hi > /tmp/q ; chmod a+rx /tmp/q
		$ PATH=/tmp q
		q: not found
		$
	in comexec() the two lines
		while (*vp != NULL)
			(void) typeset(*vp++, xxx, 0);
	need to be moved out of the switch to before findcom() is
	called - I don't know what this will break.
stdin:
	: ${PWD:-`pwd 2> /dev/null`}
	: ${PWD:?"PWD not set - can't do test"}
	mkdir Y
	cat > Y/xxxscript << EOF
	#!/bin/sh
	# Need to restore path so echo can be found (some shells don't have
	# it as a built-in)
	PATH=\$OLDPATH
	echo hi
	exit 0
	EOF
	chmod a+rx Y/xxxscript
	export OLDPATH="$PATH"
	PATH=$PWD/Y xxxscript
	exit $?
expected-stdout:
	hi
---
name: regression-6
description:
	Parsing of $(..) expressions is non-optimal.  It is
	impossible to have any parentheses inside the expression.
	I.e.,
		$ ksh -c 'echo $(echo \( )'
		no closing quote
		$ ksh -c 'echo $(echo "(" )'
		no closing quote
		$
	The solution is to hack the parsing clode in lex.c, the
	question is how to hack it: should any parentheses be
	escaped by a backslash, or should recursive parsing be done
	(so quotes could also be used to hide hem).  The former is
	easier, the later better...
stdin:
	echo $(echo \()
expected-stdout:
	(
---
name: regression-9
description:
	Continue in a for loop does not work right:
		for i in a b c ; do
			if [ $i = b ] ; then
				continue
			fi
			echo $i
		done
	Prints a forever...
stdin:
	first=yes
	for i in a b c ; do
		if [ $i = b ] ; then
			if [ $first = no ] ; then
				echo 'continue in for loop broken'
				break	# hope break isn't broken too :-)
			fi
			first=no
			continue
		fi
	done
	echo bye
expected-stdout:
	bye
---
name: regression-10
description:
	The following:
		set -- `false`
		echo $?
	should print 0 according to POSIX (dash, bash, ksh93, posh)
	but not 0 according to the getopt(1) manual page, ksh88, and
	Bourne sh (such as /bin/sh on Solaris).
	In mksh R39b, we honour POSIX except when -o sh is set.
stdin:
	showf() {
		[[ -o posix ]]; FPOSIX=$((1-$?))
		[[ -o sh ]]; FSH=$((1-$?))
		echo -n "FPOSIX=$FPOSIX FSH=$FSH "
	}
	set +o posix +o sh
	showf
	set -- `false`
	echo rv=$?
	set -o sh
	showf
	set -- `false`
	echo rv=$?
	set -o posix
	showf
	set -- `false`
	echo rv=$?
expected-stdout:
	FPOSIX=0 FSH=0 rv=0
	FPOSIX=0 FSH=1 rv=1
	FPOSIX=1 FSH=0 rv=0
---
name: regression-11
description:
	The following:
		x=/foo/bar/blah
		echo ${x##*/}
	should echo blah but on some machines echos /foo/bar/blah.
stdin:
	x=/foo/bar/blah
	echo ${x##*/}
expected-stdout:
	blah
---
name: regression-12
description:
	Both of the following echos produce the same output under sh/ksh.att:
		#!/bin/sh
		x="foo	bar"
		echo "`echo \"$x\"`"
		echo "`echo "$x"`"
	pdksh produces different output for the former (foo instead of foo\tbar)
stdin:
	x="foo	bar"
	echo "`echo \"$x\"`"
	echo "`echo "$x"`"
expected-stdout:
	foo	bar
	foo	bar
---
name: regression-13
description:
	The following command hangs forever:
		$ (: ; cat /etc/termcap) | sleep 2
	This is because the shell forks a shell to run the (..) command
	and this shell has the pipe open.  When the sleep dies, the cat
	doesn't get a SIGPIPE 'cause a process (ie, the second shell)
	still has the pipe open.
	
	NOTE: this test provokes a bizarre bug in ksh93 (shell starts reading
	      commands from /etc/termcap..)
time-limit: 10
stdin:
	echo A line of text that will be duplicated quite a number of times.> t1
	cat t1 t1 t1 t1  t1 t1 t1 t1  t1 t1 t1 t1  t1 t1 t1 t1  > t2
	cat t2 t2 t2 t2  t2 t2 t2 t2  t2 t2 t2 t2  t2 t2 t2 t2  > t1
	cat t1 t1 t1 t1 > t2
	(: ; cat t2 2>&-) | sleep 1
---
name: regression-14
description:
	The command
		$ (foobar) 2> /dev/null
	generates no output under /bin/sh, but pdksh produces the error
		foobar: not found
	Also, the command
		$ foobar 2> /dev/null
	generates an error under /bin/sh and pdksh, but AT&T ksh88 produces
	no error (redirected to /dev/null).
stdin:
	(you/should/not/see/this/error/1) 2> /dev/null
	you/should/not/see/this/error/2 2> /dev/null
	true
---
name: regression-15
description:
	The command
		$ whence foobar
	generates a blank line under pdksh and sets the exit status to 0.
	AT&T ksh88 generates no output and sets the exit status to 1.  Also,
	the command
		$ whence foobar cat
	generates no output under AT&T ksh88 (pdksh generates a blank line
	and /bin/cat).
stdin:
	whence does/not/exist > /dev/null
	echo 1: $?
	echo 2: $(whence does/not/exist | wc -l)
	echo 3: $(whence does/not/exist cat | wc -l)
expected-stdout:
	1: 1
	2: 0
	3: 0
---
name: regression-16
description:
	${var%%expr} seems to be broken in many places.  On the mips
	the commands
		$ read line < /etc/passwd
		$ echo $line
		root:0:1:...
		$ echo ${line%%:*}
		root
		$ echo $line
		root
		$
	change the value of line.  On sun4s & pas, the echo ${line%%:*} doesn't
	work.  Haven't checked elsewhere...
script:
	read x
	y=$x
	echo ${x%%:*}
	echo $x
stdin:
	root:asdjhasdasjhs:0:1:Root:/:/bin/sh
expected-stdout:
	root
	root:asdjhasdasjhs:0:1:Root:/:/bin/sh
---
name: regression-17
description:
	The command
		. /foo/bar
	should set the exit status to non-zero (sh and AT&T ksh88 do).
	XXX doting a non existent file is a fatal error for a script
stdin:
	. does/not/exist
expected-exit: e != 0
expected-stderr-pattern: /.?/
---
name: regression-19
description:
	Both of the following echos should produce the same thing, but don't:
		$ x=foo/bar
		$ echo ${x%/*}
		foo
		$ echo "${x%/*}"
		foo/bar
stdin:
	x=foo/bar
	echo "${x%/*}"
expected-stdout:
	foo
---
name: regression-21
description:
	backslash does not work as expected in case labels:
	$ x='-x'
	$ case $x in
	-\?) echo hi
	esac
	hi
	$ x='-?'
	$ case $x in
	-\\?) echo hi
	esac
	hi
	$
stdin:
	case -x in
	-\?)	echo fail
	esac
---
name: regression-22
description:
	Quoting backquotes inside backquotes doesn't work:
	$ echo `echo hi \`echo there\` folks`
	asks for more info.  sh and AT&T ksh88 both echo
	hi there folks
stdin:
	echo `echo hi \`echo there\` folks`
expected-stdout:
	hi there folks
---
name: regression-23
description:
	)) is not treated `correctly':
	    $ (echo hi ; (echo there ; echo folks))
	    missing ((
	    $
	instead of (as sh and ksh.att)
	    $ (echo hi ; (echo there ; echo folks))
	    hi
	    there
	    folks
	    $
stdin:
	( : ; ( : ; echo hi))
expected-stdout:
	hi
---
name: regression-25
description:
	Check reading stdin in a while loop.  The read should only read
	a single line, not a whole stdio buffer; the cat should get
	the rest.
stdin:
	(echo a; echo b) | while read x ; do
	    echo $x
	    cat > /dev/null
	done
expected-stdout:
	a
---
name: regression-26
description:
	Check reading stdin in a while loop.  The read should read both
	lines, not just the first.
script:
	a=
	while [ "$a" != xxx ] ; do
	    last=$x
	    read x
	    cat /dev/null | sed 's/x/y/'
	    a=x$a
	done
	echo $last
stdin:
	a
	b
expected-stdout:
	b
---
name: regression-27
description:
	The command
		. /does/not/exist
	should cause a script to exit.
stdin:
	. does/not/exist
	echo hi
expected-exit: e != 0
expected-stderr-pattern: /does\/not\/exist/
---
name: regression-28
description:
	variable assignements not detected well
stdin:
	a.x=1 echo hi
expected-exit: e != 0
expected-stderr-pattern: /a\.x=1/
---
name: regression-29
description:
	alias expansion different from AT&T ksh88
stdin:
	alias a='for ' b='i in'
	a b hi ; do echo $i ; done
expected-stdout:
	hi
---
name: regression-30
description:
	strange characters allowed inside ${...}
stdin:
	echo ${a{b}}
expected-exit: e != 0
expected-stderr-pattern: /.?/
---
name: regression-31
description:
	Does read handle partial lines correctly
script:
	a= ret=
	while [ "$a" != xxx ] ; do
	    read x y z
	    ret=$?
	    a=x$a
	done
	echo "[$x]"
	echo $ret
stdin: !
	a A aA
	b B Bb
	c
expected-stdout:
	[c]
	1
---
name: regression-32
description:
	Does read set variables to null at eof?
script:
	a=
	while [ "$a" != xxx ] ; do
	    read x y z
	    a=x$a
	done
	echo 1: ${x-x not set} ${y-y not set} ${z-z not set}
	echo 2: ${x:+x not null} ${y:+y not null} ${z:+z not null}
stdin:
	a A Aa
	b B Bb
expected-stdout:
	1:
	2:
---
name: regression-33
description:
	Does umask print a leading 0 when umask is 3 digits?
stdin:
	umask 222
	umask
expected-stdout:
	0222
---
name: regression-35
description:
	Tempory files used for here-docs in functions get trashed after
	the function is parsed (before it is executed)
stdin:
	f1() {
		cat <<- EOF
			F1
		EOF
		f2() {
			cat <<- EOF
				F2
			EOF
		}
	}
	f1
	f2
	unset -f f1
	f2
expected-stdout:
	F1
	F2
	F2
---
name: regression-36
description:
	Command substitution breaks reading in while loop
	(test from <sjg@void.zen.oz.au>)
stdin:
	(echo abcdef; echo; echo 123) |
	    while read line
	    do
	      # the following line breaks it
	      c=`echo $line | wc -c`
	      echo $c
	    done
expected-stdout:
	7
	1
	4
---
name: regression-37
description:
	Machines with broken times() (reported by <sjg@void.zen.oz.au>)
	time does not report correct real time
stdin:
	time sleep 1
expected-stderr-pattern: !/^\s*0\.0[\s\d]+real|^\s*real[\s]+0+\.0/
---
name: regression-38
description:
	set -e doesn't ignore exit codes for if/while/until/&&/||/!.
arguments: !-e!
stdin:
	if false; then echo hi ; fi
	false || true
	false && true
	while false; do echo hi; done
	echo ok
expected-stdout:
	ok
---
name: regression-39
description:
	set -e: errors in command substitutions aren't ignored
	Not clear if they should be or not... bash passes here
	this may actually be required for make, so changed the
	test to make this an mksh feature, not a bug
arguments: !-e!
stdin:
	echo `false; echo hi`
#expected-fail: yes
#expected-stdout:
#	hi
expected-stdout:
	
---
name: regression-40
description:
	This used to cause a core dump
env-setup: !RANDOM=12!
stdin:
	echo hi
expected-stdout:
	hi
---
name: regression-41
description:
	foo should be set to bar (should not be empty)
stdin:
	foo=`
	echo bar`
	echo "($foo)"
expected-stdout:
	(bar)
---
name: regression-42
description:
	Can't use command line assignments to assign readonly parameters.
stdin:
	foo=bar
	readonly foo
	foo=stuff env | grep '^foo'
expected-exit: e != 0
expected-stderr-pattern:
	/.*read *only.*/
---
name: regression-43
description:
	Can subshells be prefixed by redirections (historical shells allow
	this)
stdin:
	< /dev/null (sed 's/^/X/')
---
name: regression-45
description:
	Parameter assignments with [] recognised correctly
stdin:
	FOO=*[12]
	BAR=abc[
	MORE=[abc]
	JUNK=a[bc
	echo "<$FOO>"
	echo "<$BAR>"
	echo "<$MORE>"
	echo "<$JUNK>"
expected-stdout:
	<*[12]>
	<abc[>
	<[abc]>
	<a[bc>
---
name: regression-46
description:
	Check that alias expansion works in command substitutions and
	at the end of file.
stdin:
	alias x='echo hi'
	FOO="`x` "
	echo "[$FOO]"
	x
expected-stdout:
	[hi ]
	hi
---
name: regression-47
description:
	Check that aliases are fully read.
stdin:
	alias x='echo hi;
	echo there'
	x
	echo done
expected-stdout:
	hi
	there
	done
---
name: regression-48
description:
	Check that (here doc) temp files are not left behind after an exec.
stdin:
	mkdir foo || exit 1
	TMPDIR=$PWD/foo "$__progname" <<- 'EOF'
		x() {
			sed 's/^/X /' << E_O_F
			hi
			there
			folks
			E_O_F
			echo "done ($?)"
		}
		echo=echo; [ -x /bin/echo ] && echo=/bin/echo
		exec $echo subtest-1 hi
	EOF
	echo subtest-1 foo/*
	TMPDIR=$PWD/foo "$__progname" <<- 'EOF'
		echo=echo; [ -x /bin/echo ] && echo=/bin/echo
		sed 's/^/X /' << E_O_F; exec $echo subtest-2 hi
		a
		few
		lines
		E_O_F
	EOF
	echo subtest-2 foo/*
expected-stdout:
	subtest-1 hi
	subtest-1 foo/*
	X a
	X few
	X lines
	subtest-2 hi
	subtest-2 foo/*
---
name: regression-49
description:
	Check that unset params with attributes are reported by set, those
	sans attributes are not.
stdin:
	unset FOO BAR
	echo X$FOO
	export BAR
	typeset -i BLAH
	set | grep FOO
	set | grep BAR
	set | grep BLAH
expected-stdout:
	X
	BAR
	BLAH
---
name: regression-50
description:
	Check that aliases do not use continuation prompt after trailing
	semi-colon.
file-setup: file 644 "env"
	PS1=Y
	PS2=X
env-setup: !ENV=./env!
arguments: !-i!
stdin:
	alias foo='echo hi ; '
	foo
	foo echo there
expected-stdout:
	hi
	hi
	there
expected-stderr: !
	YYYY
---
name: regression-51
description:
	Check that set allows both +o and -o options on same command line.
stdin:
	set a b c
	set -o noglob +o allexport
	echo A: $*, *
expected-stdout:
	A: a b c, *
---
name: regression-52
description:
	Check that globbing works in pipelined commands
file-setup: file 644 "env"
	PS1=P
file-setup: file 644 "abc"
	stuff
env-setup: !ENV=./env!
arguments: !-i!
stdin:
	sed 's/^/X /' < ab*
	echo mark 1
	sed 's/^/X /' < ab* | sed 's/^/Y /'
	echo mark 2
expected-stdout:
	X stuff
	mark 1
	Y X stuff
	mark 2
expected-stderr: !
	PPPPP
---
name: regression-53
description:
	Check that getopts works in functions
stdin:
	bfunc() {
	    echo bfunc: enter "(args: $*; OPTIND=$OPTIND)"
	    while getopts B oc; do
		case $oc in
		  (B)
		    echo bfunc: B option
		    ;;
		  (*)
		    echo bfunc: odd option "($oc)"
		    ;;
		esac
	    done
	    echo bfunc: leave
	}
	
	function kfunc {
	    echo kfunc: enter "(args: $*; OPTIND=$OPTIND)"
	    while getopts K oc; do
		case $oc in
		  (K)
		    echo kfunc: K option
		    ;;
		  (*)
		    echo bfunc: odd option "($oc)"
		    ;;
		esac
	    done
	    echo kfunc: leave
	}
	
	set -- -f -b -k -l
	echo "line 1: OPTIND=$OPTIND"
	getopts kbfl optc
	echo "line 2: ret=$?, optc=$optc, OPTIND=$OPTIND"
	bfunc -BBB blah
	echo "line 3: OPTIND=$OPTIND"
	getopts kbfl optc
	echo "line 4: ret=$?, optc=$optc, OPTIND=$OPTIND"
	kfunc -KKK blah
	echo "line 5: OPTIND=$OPTIND"
	getopts kbfl optc
	echo "line 6: ret=$?, optc=$optc, OPTIND=$OPTIND"
	echo
	
	OPTIND=1
	set -- -fbkl
	echo "line 10: OPTIND=$OPTIND"
	getopts kbfl optc
	echo "line 20: ret=$?, optc=$optc, OPTIND=$OPTIND"
	bfunc -BBB blah
	echo "line 30: OPTIND=$OPTIND"
	getopts kbfl optc
	echo "line 40: ret=$?, optc=$optc, OPTIND=$OPTIND"
	kfunc -KKK blah
	echo "line 50: OPTIND=$OPTIND"
	getopts kbfl optc
	echo "line 60: ret=$?, optc=$optc, OPTIND=$OPTIND"
expected-stdout:
	line 1: OPTIND=1
	line 2: ret=0, optc=f, OPTIND=2
	bfunc: enter (args: -BBB blah; OPTIND=2)
	bfunc: B option
	bfunc: B option
	bfunc: leave
	line 3: OPTIND=2
	line 4: ret=0, optc=b, OPTIND=3
	kfunc: enter (args: -KKK blah; OPTIND=1)
	kfunc: K option
	kfunc: K option
	kfunc: K option
	kfunc: leave
	line 5: OPTIND=3
	line 6: ret=0, optc=k, OPTIND=4
	
	line 10: OPTIND=1
	line 20: ret=0, optc=f, OPTIND=2
	bfunc: enter (args: -BBB blah; OPTIND=2)
	bfunc: B option
	bfunc: B option
	bfunc: leave
	line 30: OPTIND=2
	line 40: ret=1, optc=?, OPTIND=2
	kfunc: enter (args: -KKK blah; OPTIND=1)
	kfunc: K option
	kfunc: K option
	kfunc: K option
	kfunc: leave
	line 50: OPTIND=2
	line 60: ret=1, optc=?, OPTIND=2
---
name: regression-54
description:
	Check that ; is not required before the then in if (( ... )) then ...
stdin:
	if (( 1 )) then
	    echo ok dparen
	fi
	if [[ -n 1 ]] then
	    echo ok dbrackets
	fi
expected-stdout:
	ok dparen
	ok dbrackets
---
name: regression-55
description:
	Check ${foo:%bar} is allowed (ksh88 allows it...)
stdin:
	x=fooXbarXblah
	echo 1 ${x%X*}
	echo 2 ${x:%X*}
	echo 3 ${x%%X*}
	echo 4 ${x:%%X*}
	echo 5 ${x#*X}
	echo 6 ${x:#*X}
	echo 7 ${x##*X}
	echo 8 ${x:##*X}
expected-stdout:
	1 fooXbar
	2 fooXbar
	3 foo
	4 foo
	5 barXblah
	6 barXblah
	7 blah
	8 blah
---
name: regression-57
description:
	Check if typeset output is correct for
	uninitialised array elements.
stdin:
	typeset -i xxx[4]
	echo A
	typeset -i | grep xxx | sed 's/^/    /'
	echo B
	typeset | grep xxx | sed 's/^/    /'
	
	xxx[1]=2+5
	echo M
	typeset -i | grep xxx | sed 's/^/    /'
	echo N
	typeset | grep xxx | sed 's/^/    /'
expected-stdout:
	A
	    xxx
	B
	    typeset -i xxx
	M
	    xxx[1]=7
	N
	    typeset -i xxx
---
name: regression-58
description:
	Check if trap exit is ok (exit not mistaken for signal name)
stdin:
	trap 'echo hi' exit
	trap exit 1
expected-stdout:
	hi
---
name: regression-59
description:
	Check if ${#array[*]} is calculated correctly.
stdin:
	a[12]=hi
	a[8]=there
	echo ${#a[*]}
expected-stdout:
	2
---
name: regression-60
description:
	Check if default exit status is previous command
stdin:
	(true; exit)
	echo A $?
	(false; exit)
	echo B $?
	( (exit 103) ; exit)
	echo C $?
expected-stdout:
	A 0
	B 1
	C 103
---
name: regression-61
description:
	Check if EXIT trap is executed for sub shells.
stdin:
	trap 'echo parent exit' EXIT
	echo start
	(echo A; echo A last)
	echo B
	(echo C; trap 'echo sub exit' EXIT; echo C last)
	echo parent last
expected-stdout:
	start
	A
	A last
	B
	C
	C last
	sub exit
	parent last
	parent exit
---
name: regression-62
description:
	Check if test -nt/-ot succeeds if second(first) file is missing.
stdin:
	touch a
	test a -nt b && echo nt OK || echo nt BAD
	test b -ot a && echo ot OK || echo ot BAD
expected-stdout:
	nt OK
	ot OK
---
name: regression-63
description:
	Check if typeset, export, and readonly work
stdin:
	{
		echo FNORD-0
		FNORD_A=1
		FNORD_B=2
		FNORD_C=3
		FNORD_D=4
		FNORD_E=5
		FNORD_F=6
		FNORD_G=7
		FNORD_H=8
		integer FNORD_E FNORD_F FNORD_G FNORD_H
		export FNORD_C FNORD_D FNORD_G FNORD_H
		readonly FNORD_B FNORD_D FNORD_F FNORD_H
		echo FNORD-1
		export
		echo FNORD-2
		export -p
		echo FNORD-3
		readonly
		echo FNORD-4
		readonly -p
		echo FNORD-5
		typeset
		echo FNORD-6
		typeset -p
		echo FNORD-7
		typeset -
		echo FNORD-8
	} | fgrep FNORD
expected-stdout:
	FNORD-0
	FNORD-1
	FNORD_C
	FNORD_D
	FNORD_G
	FNORD_H
	FNORD-2
	export FNORD_C=3
	export FNORD_D=4
	export FNORD_G=7
	export FNORD_H=8
	FNORD-3
	FNORD_B
	FNORD_D
	FNORD_F
	FNORD_H
	FNORD-4
	readonly FNORD_B=2
	readonly FNORD_D=4
	readonly FNORD_F=6
	readonly FNORD_H=8
	FNORD-5
	typeset FNORD_A
	typeset -r FNORD_B
	typeset -x FNORD_C
	typeset -x -r FNORD_D
	typeset -i FNORD_E
	typeset -i -r FNORD_F
	typeset -i -x FNORD_G
	typeset -i -x -r FNORD_H
	FNORD-6
	typeset FNORD_A=1
	typeset -r FNORD_B=2
	typeset -x FNORD_C=3
	typeset -x -r FNORD_D=4
	typeset -i FNORD_E=5
	typeset -i -r FNORD_F=6
	typeset -i -x FNORD_G=7
	typeset -i -x -r FNORD_H=8
	FNORD-7
	FNORD_A=1
	FNORD_B=2
	FNORD_C=3
	FNORD_D=4
	FNORD_E=5
	FNORD_F=6
	FNORD_G=7
	FNORD_H=8
	FNORD-8
---
name: regression-64
description:
	Check that we can redefine functions calling time builtin
stdin:
	t() {
		time >/dev/null
	}
	t 2>/dev/null
	t() {
		time
	}
---
name: syntax-1
description:
	Check that lone ampersand is a syntax error
stdin:
	 &
expected-exit: e != 0
expected-stderr-pattern:
	/syntax error/
---
name: xxx-quoted-newline-1
description:
	Check that \<newline> works inside of ${}
stdin:
	abc=2
	echo ${ab\
	c}
expected-stdout:
	2
---
name: xxx-quoted-newline-2
description:
	Check that \<newline> works at the start of a here document
stdin:
	cat << EO\
	F
	hi
	EOF
expected-stdout:
	hi
---
name: xxx-quoted-newline-3
description:
	Check that \<newline> works at the end of a here document
stdin:
	cat << EOF
	hi
	EO\
	F
expected-stdout:
	hi
---
name: xxx-multi-assignment-cmd
description:
	Check that assignments in a command affect subsequent assignments
	in the same command
stdin:
	FOO=abc
	FOO=123 BAR=$FOO
	echo $BAR
expected-stdout:
	123
---
name: xxx-multi-assignment-posix-cmd
description:
	Check that the behaviour for multiple assignments with a
	command name matches POSIX. See:
	http://thread.gmane.org/gmane.comp.standards.posix.austin.general/1925
stdin:
	X=a Y=b; X=$Y Y=$X "$__progname" -c 'echo 1 $X $Y .'; echo 2 $X $Y .
	unset X Y Z
	X=a Y=${X=b} Z=$X "$__progname" -c 'echo 3 $Z .'
	unset X Y Z
	X=a Y=${X=b} Z=$X; echo 4 $Z .
expected-stdout:
	1 b a .
	2 a b .
	3 b .
	4 a .
---
name: xxx-multi-assignment-posix-nocmd
description:
	Check that the behaviour for multiple assignments with no
	command name matches POSIX (Debian #334182). See:
	http://thread.gmane.org/gmane.comp.standards.posix.austin.general/1925
stdin:
	X=a Y=b; X=$Y Y=$X; echo 1 $X $Y .
expected-stdout:
	1 b b .
---
name: xxx-multi-assignment-posix-subassign
description:
	Check that the behaviour for multiple assignments matches POSIX:
	- The assignment words shall be expanded in the current execution
	  environment.
	- The assignments happen in the temporary execution environment.
stdin:
	unset X Y Z
	Z=a Y=${X:=b} sh -c 'echo +$X+ +$Y+ +$Z+'
	echo /$X/
	# Now for the special case:
	unset X Y Z
	X= Y=${X:=b} sh -c 'echo +$X+ +$Y+'
	echo /$X/
expected-stdout:
	++ +b+ +a+
	/b/
	++ +b+
	/b/
---
name: xxx-exec-environment-1
description:
	Check to see if exec sets it's environment correctly
stdin:
	FOO=bar exec env
expected-stdout-pattern:
	/(^|.*\n)FOO=bar\n/
---
name: xxx-exec-environment-2
description:
	Check to make sure exec doesn't change environment if a program
	isn't exec-ed
stdin:
	sortprog=$(whence -p sort) || sortprog=cat
	env | $sortprog | grep -v '^RANDOM=' >bar1
	FOO=bar exec; env | $sortprog | grep -v '^RANDOM=' >bar2
	cmp -s bar1 bar2
---
name: exec-function-environment-1
description:
	Check assignments in function calls and whether they affect
	the current execution environment (ksh93, SUSv4)
stdin:
	f() { a=2; }; g() { b=3; echo y$c-; }; a=1 f; b=2; c=1 g
	echo x$a-$b- z$c-
expected-stdout:
	y1-
	x2-3- z1-
---
name: xxx-what-do-you-call-this-1
stdin:
	echo "${foo:-"a"}*"
expected-stdout:
	a*
---
name: xxx-prefix-strip-1
stdin:
	foo='a cdef'
	echo ${foo#a c}
expected-stdout:
	def
---
name: xxx-prefix-strip-2
stdin:
	set a c
	x='a cdef'
	echo ${x#$*}
expected-stdout:
	def
---
name: xxx-variable-syntax-1
stdin:
	echo ${:}
expected-stderr-pattern:
	/bad substitution/
expected-exit: 1
---
name: xxx-variable-syntax-2
stdin:
	set 0
	echo ${*:0}
expected-stderr-pattern:
	/bad substitution/
expected-exit: 1
---
name: xxx-variable-syntax-3
stdin:
	set -A foo 0
	echo ${foo[*]:0}
expected-stderr-pattern:
	/bad substitution/
expected-exit: 1
---
name: xxx-substitution-eval-order
description:
	Check order of evaluation of expressions
stdin:
	i=1 x= y=
	set -A A abc def GHI j G k
	echo ${A[x=(i+=1)]#${A[y=(i+=2)]}}
	echo $x $y
expected-stdout:
	HI
	2 4
---
name: xxx-set-option-1
description:
	Check option parsing in set
stdin:
	set -vsA foo -- A 1 3 2
	echo ${foo[*]}
expected-stderr:
	echo ${foo[*]}
expected-stdout:
	1 2 3 A
---
name: xxx-exec-1
description:
	Check that exec exits for built-ins
arguments: !-i!
stdin:
	exec echo hi
	echo still herre
expected-stdout:
	hi
expected-stderr-pattern: /.*/
---
name: xxx-while-1
description:
	Check the return value of while loops
	XXX need to do same for for/select/until loops
stdin:
	i=x
	while [ $i != xxx ] ; do
	    i=x$i
	    if [ $i = xxx ] ; then
		false
		continue
	    fi
	done
	echo loop1=$?
	
	i=x
	while [ $i != xxx ] ; do
	    i=x$i
	    if [ $i = xxx ] ; then
		false
		break
	    fi
	done
	echo loop2=$?
	
	i=x
	while [ $i != xxx ] ; do
	    i=x$i
	    false
	done
	echo loop3=$?
expected-stdout:
	loop1=0
	loop2=0
	loop3=1
---
name: xxx-status-1
description:
	Check that blank lines don't clear $?
arguments: !-i!
stdin:
	(exit 1)
	echo $?
	(exit 1)
	
	echo $?
	true
expected-stdout:
	1
	1
expected-stderr-pattern: /.*/
---
name: xxx-status-2
description:
	Check that $? is preserved in subshells, includes, traps.
stdin:
	(exit 1)
	
	echo blank: $?
	
	(exit 2)
	(echo subshell: $?)
	
	echo 'echo include: $?' > foo
	(exit 3)
	. ./foo
	
	trap 'echo trap: $?' ERR
	(exit 4)
	echo exit: $?
expected-stdout:
	blank: 1
	subshell: 2
	include: 3
	trap: 4
	exit: 4
---
name: xxx-clean-chars-1
description:
	Check MAGIC character is stuffed correctly
stdin:
	echo `echo [�`
expected-stdout:
	[�
---
name: xxx-param-subst-qmark-1
description:
	Check suppresion of error message with null string.  According to
	POSIX, it shouldn't print the error as 'word' isn't ommitted.
	ksh88/93, Solaris /bin/sh and /usr/xpg4/bin/sh all print the error,
	that's why the condition is reversed.
stdin:
	unset foo
	x=
	echo x${foo?$x}
expected-exit: 1
# POSIX
#expected-fail: yes
#expected-stderr-pattern: !/not set/
# common use
expected-stderr-pattern: /parameter null or not set/
---
name: xxx-param-_-1
# fails due to weirdness of execv stuff
category: !os:uwin-nt
description:
	Check c flag is set.
arguments: !-c!echo "[$-]"!
expected-stdout-pattern: /^\[.*c.*\]$/
---
name: tilde-expand-1
description:
	Check tilde expansion after equal signs
env-setup: !HOME=/sweet!
stdin:
	echo ${A=a=}~ b=~ c=d~ ~
	set +o braceexpand
	echo ${A=a=}~ b=~ c=d~ ~
expected-stdout:
	a=/sweet b=/sweet c=d~ /sweet
	a=~ b=~ c=d~ /sweet
---
name: exit-err-1
description:
	Check some "exit on error" conditions
stdin:
	set -ex
	/usr/bin/env false && echo something
	echo END
expected-stdout:
	END
expected-stderr:
	+ /usr/bin/env false
	+ echo END
---
name: exit-err-2
description:
	Check some "exit on error" edge conditions (POSIXly)
stdin:
	set -ex
	if /usr/bin/env true; then
		/usr/bin/env false && echo something
	fi
	echo END
expected-stdout:
	END
expected-stderr:
	+ /usr/bin/env true
	+ /usr/bin/env false
	+ echo END
---
name: exit-err-3
description:
	pdksh regression which AT&T ksh does right
	TFM says: [set] -e | errexit
		Exit (after executing the ERR trap) ...
stdin:
	trap 'echo EXIT' EXIT
	trap 'echo ERR' ERR
	set -e
	cd /XXXXX 2>/dev/null
	echo DONE
	exit 0
expected-stdout:
	ERR
	EXIT
expected-exit: e != 0
---
name: exit-err-4
description:
	"set -e" test suite (POSIX)
stdin:
	set -e
	echo pre
	if true ; then
		false && echo foo
	fi
	echo bar
expected-stdout:
	pre
	bar
---
name: exit-err-5
description:
	"set -e" test suite (POSIX)
stdin:
	set -e
	foo() {
		while [ "$1" ]; do
			for E in $x; do
				[ "$1" = "$E" ] && { shift ; continue 2 ; }
			done
			x="$x $1"
			shift
		done
		echo $x
	}
	echo pre
	foo a b b c
	echo post
expected-stdout:
	pre
	a b c
	post
---
name: exit-err-6
description:
	"set -e" test suite (BSD make)
category: os:mirbsd
stdin:
	mkdir zd zd/a zd/b
	print 'all:\n\t@echo eins\n\t@exit 42\n' >zd/a/Makefile
	print 'all:\n\t@echo zwei\n' >zd/b/Makefile
	wd=$(pwd)
	set -e
	for entry in a b; do (  set -e;  if [[ -d $wd/zd/$entry.i386 ]]; then  _newdir_="$entry.i386";  else  _newdir_="$entry";  fi;  if [[ -z $_THISDIR_ ]]; then  _nextdir_="$_newdir_";  else  _nextdir_="$_THISDIR_/$_newdir_";  fi;  _makefile_spec_=;  [[ ! -f $wd/zd/$_newdir_/Makefile.bsd-wrapper ]]  || _makefile_spec_="-f Makefile.bsd-wrapper";  subskipdir=;  for skipdir in ; do  subentry=${skipdir#$entry};  if [[ $subentry != $skipdir ]]; then  if [[ -z $subentry ]]; then  echo "($_nextdir_ skipped)";  break;  fi;  subskipdir="$subskipdir ${subentry#/}";  fi;  done;  if [[ -z $skipdir || -n $subentry ]]; then  echo "===> $_nextdir_";  cd $wd/zd/$_newdir_;  make SKIPDIR="$subskipdir" $_makefile_spec_  _THISDIR_="$_nextdir_"   all;  fi;  ) done 2>&1 | sed "s!$wd!WD!g"
expected-stdout:
	===> a
	eins
	*** Error code 42
	
	Stop in WD/zd/a (line 2 of Makefile).
---
name: exit-enoent-1
description:
	SUSv4 says that the shell should exit with 126/127 in some situations
stdin:
	i=0
	(echo; echo :) >x
	"$__progname" ./x >/dev/null 2>&1; r=$?; echo $((i++)) $r .
	"$__progname" -c ./x >/dev/null 2>&1; r=$?; echo $((i++)) $r .
	echo exit 42 >x
	"$__progname" ./x >/dev/null 2>&1; r=$?; echo $((i++)) $r .
	"$__progname" -c ./x >/dev/null 2>&1; r=$?; echo $((i++)) $r .
	rm -f x
	"$__progname" ./x >/dev/null 2>&1; r=$?; echo $((i++)) $r .
	"$__progname" -c ./x >/dev/null 2>&1; r=$?; echo $((i++)) $r .
expected-stdout:
	0 0 .
	1 126 .
	2 42 .
	3 126 .
	4 127 .
	5 127 .
---
name: exit-eval-1
description:
	Check eval vs substitution exit codes (ksh93 alike)
stdin:
	eval $(false)
	echo A $?
	eval ' $(false)'
	echo B $?
	eval " $(false)"
	echo C $?
	eval "eval $(false)"
	echo D $?
	eval 'eval '"$(false)"
	echo E $?
	IFS="$IFS:"
	eval $(echo :; false)
	echo F $?
expected-stdout:
	A 0
	B 1
	C 0
	D 0
	E 0
	F 0
---
name: test-stlt-1
description:
	Check that test also can handle string1 < string2 etc.
stdin:
	test 2005/10/08 '<' 2005/08/21 && echo ja || echo nein
	test 2005/08/21 \< 2005/10/08 && echo ja || echo nein
	test 2005/10/08 '>' 2005/08/21 && echo ja || echo nein
	test 2005/08/21 \> 2005/10/08 && echo ja || echo nein
expected-stdout:
	nein
	ja
	ja
	nein
expected-stderr-pattern: !/unexpected op/
---
name: test-precedence-1
description:
	Check a weird precedence case (and POSIX echo)
stdin:
	test \( -f = -f \)
	rv=$?
	test -n "$POSH_VERSION" || set -o sh
	echo -e $rv
expected-stdout:
	-e 0
---
name: test-option-1
description:
	Test the test -o operator
stdin:
	runtest() {
		test -o $1; echo $?
		[ -o $1 ]; echo $?
		[[ -o $1 ]]; echo $?
	}
	if_test() {
		test -o $1 -o -o !$1; echo $?
		[ -o $1 -o -o !$1 ]; echo $?
		[[ -o $1 || -o !$1 ]]; echo $?
		test -o ?$1; echo $?
	}
	echo 0y $(if_test utf8-mode) =
	echo 0n $(if_test utf8-hack) =
	echo 1= $(runtest utf8-hack) =
	echo 2= $(runtest !utf8-hack) =
	echo 3= $(runtest ?utf8-hack) =
	set +U
	echo 1+ $(runtest utf8-mode) =
	echo 2+ $(runtest !utf8-mode) =
	echo 3+ $(runtest ?utf8-mode) =
	set -U
	echo 1- $(runtest utf8-mode) =
	echo 2- $(runtest !utf8-mode) =
	echo 3- $(runtest ?utf8-mode) =
	echo = short flags =
	echo 0y $(if_test -U) =
	echo 0y $(if_test +U) =
	echo 0n $(if_test -_) =
	echo 0n $(if_test -U-) =
	echo 1= $(runtest -_) =
	echo 2= $(runtest !-_) =
	echo 3= $(runtest ?-_) =
	set +U
	echo 1+ $(runtest -U) =
	echo 2+ $(runtest !-U) =
	echo 3+ $(runtest ?-U) =
	echo 1+ $(runtest +U) =
	echo 2+ $(runtest !+U) =
	echo 3+ $(runtest ?+U) =
	set -U
	echo 1- $(runtest -U) =
	echo 2- $(runtest !-U) =
	echo 3- $(runtest ?-U) =
	echo 1- $(runtest +U) =
	echo 2- $(runtest !+U) =
	echo 3- $(runtest ?+U) =
expected-stdout:
	0y 0 0 0 0 =
	0n 1 1 1 1 =
	1= 1 1 1 =
	2= 1 1 1 =
	3= 1 1 1 =
	1+ 1 1 1 =
	2+ 0 0 0 =
	3+ 0 0 0 =
	1- 0 0 0 =
	2- 1 1 1 =
	3- 0 0 0 =
	= short flags =
	0y 0 0 0 0 =
	0y 0 0 0 0 =
	0n 1 1 1 1 =
	0n 1 1 1 1 =
	1= 1 1 1 =
	2= 1 1 1 =
	3= 1 1 1 =
	1+ 1 1 1 =
	2+ 0 0 0 =
	3+ 0 0 0 =
	1+ 1 1 1 =
	2+ 0 0 0 =
	3+ 0 0 0 =
	1- 0 0 0 =
	2- 1 1 1 =
	3- 0 0 0 =
	1- 0 0 0 =
	2- 1 1 1 =
	3- 0 0 0 =
---
name: mkshrc-1
description:
	Check that ~/.mkshrc works correctly.
	Part 1: verify user environment is not read (internal)
stdin:
	echo x $FNORD
expected-stdout:
	x
---
name: mkshrc-2a
description:
	Check that ~/.mkshrc works correctly.
	Part 2: verify mkshrc is not read (non-interactive shells)
file-setup: file 644 ".mkshrc"
	FNORD=42
env-setup: !HOME=.!ENV=!
stdin:
	echo x $FNORD
expected-stdout:
	x
---
name: mkshrc-2b
description:
	Check that ~/.mkshrc works correctly.
	Part 2: verify mkshrc can be read (interactive shells)
file-setup: file 644 ".mkshrc"
	FNORD=42
arguments: !-i!
env-setup: !HOME=.!ENV=!PS1=!
stdin:
	echo x $FNORD
expected-stdout:
	x 42
expected-stderr-pattern:
	/(# )*/
---
name: mkshrc-3
description:
	Check that ~/.mkshrc works correctly.
	Part 3: verify mkshrc can be turned off
file-setup: file 644 ".mkshrc"
	FNORD=42
env-setup: !HOME=.!ENV=nonexistant!
stdin:
	echo x $FNORD
expected-stdout:
	x
---
name: sh-mode-1
description:
	Check that sh mode turns braceexpand off
	and that that works correctly
stdin:
	set -o braceexpand
	set +o sh
	[[ $(set +o) == *@(-o sh)@(| *) ]] && echo sh || echo nosh
	[[ $(set +o) == *@(-o braceexpand)@(| *) ]] && echo brex || echo nobrex
	echo {a,b,c}
	set +o braceexpand
	echo {a,b,c}
	set -o braceexpand
	echo {a,b,c}
	set -o sh
	echo {a,b,c}
	[[ $(set +o) == *@(-o sh)@(| *) ]] && echo sh || echo nosh
	[[ $(set +o) == *@(-o braceexpand)@(| *) ]] && echo brex || echo nobrex
	set -o braceexpand
	echo {a,b,c}
	[[ $(set +o) == *@(-o sh)@(| *) ]] && echo sh || echo nosh
	[[ $(set +o) == *@(-o braceexpand)@(| *) ]] && echo brex || echo nobrex
expected-stdout:
	nosh
	brex
	a b c
	{a,b,c}
	a b c
	{a,b,c}
	sh
	nobrex
	a b c
	sh
	brex
---
name: sh-mode-2a
description:
	Check that sh mode is *not* automatically turned on
category: !binsh
stdin:
	ln -s "$__progname" ksh
	ln -s "$__progname" sh
	ln -s "$__progname" ./-ksh
	ln -s "$__progname" ./-sh
	for shell in {,-}{,k}sh; do
		print -- $shell $(./$shell +l -c \
		    '[[ $(set +o) == *@(-o sh)@(| *) ]] && echo sh || echo nosh')
	done
expected-stdout:
	sh nosh
	ksh nosh
	-sh nosh
	-ksh nosh
---
name: sh-mode-2b
description:
	Check that sh mode *is* automatically turned on
category: binsh
stdin:
	ln -s "$__progname" ksh
	ln -s "$__progname" sh
	ln -s "$__progname" ./-ksh
	ln -s "$__progname" ./-sh
	for shell in {,-}{,k}sh; do
		print -- $shell $(./$shell +l -c \
		    '[[ $(set +o) == *@(-o sh)@(| *) ]] && echo sh || echo nosh')
	done
expected-stdout:
	sh sh
	ksh nosh
	-sh sh
	-ksh nosh
---
name: pipeline-1
description:
	pdksh bug: last command of a pipeline is executed in a
	subshell - make sure it still is, scripts depend on it
file-setup: file 644 "abcx"
file-setup: file 644 "abcy"
stdin:
	echo *
	echo a | while read d; do
		echo $d
		echo $d*
		echo *
		set -o noglob
		echo $d*
		echo *
	done
	echo *
expected-stdout:
	abcx abcy
	a
	abcx abcy
	abcx abcy
	a*
	*
	abcx abcy
---
name: pipeline-2
description:
	check that co-processes work with TCOMs, TPIPEs and TPARENs
stdin:
	"$__progname" -c 'i=100; echo hi |& while read -p line; do echo "$((i++)) $line"; done'
	"$__progname" -c 'i=200; echo hi | cat |& while read -p line; do echo "$((i++)) $line"; done'
	"$__progname" -c 'i=300; (echo hi | cat) |& while read -p line; do echo "$((i++)) $line"; done'
expected-stdout:
	100 hi
	200 hi
	300 hi
---
name: persist-history-1
description:
	Check if persistent history saving works
category: !no-histfile
arguments: !-i!
env-setup: !ENV=./Env!HISTFILE=hist.file!
file-setup: file 644 "Env"
	PS1=X
stdin:
	cat hist.file
expected-stdout-pattern:
	/cat hist.file/
expected-stderr-pattern:
	/^X*$/
---
name: typeset-padding-1
description:
	Check if left/right justification works as per TFM
stdin:
	typeset -L10 ln=0hall0
	typeset -R10 rn=0hall0
	typeset -ZL10 lz=0hall0
	typeset -ZR10 rz=0hall0
	typeset -Z10 rx=" hallo "
	echo "<$ln> <$rn> <$lz> <$rz> <$rx>"
expected-stdout:
	<0hall0    > <    0hall0> <hall0     > <00000hall0> <0000 hallo>
---
name: typeset-padding-2
description:
	Check if base-!10 integers are padded right
stdin:
	typeset -Uui16 -L9 ln=16#1
	typeset -Uui16 -R9 rn=16#1
	typeset -Uui16 -Z9 zn=16#1
	typeset -L9 ls=16#1
	typeset -R9 rs=16#1
	typeset -Z9 zs=16#1
	echo "<$ln> <$rn> <$zn> <$ls> <$rs> <$zs>"
expected-stdout:
	<16#1     > <     16#1> <16#000001> <16#1     > <     16#1> <0000016#1>
---
name: utf8bom-1
description:
	Check that the UTF-8 Byte Order Mark is ignored as the first
	multibyte character of the shell input (with -c, from standard
	input, as file, or as eval argument), but nowhere else
# breaks on Mac OSX (HFS+ non-standard Unicode canonical decomposition)
category: !os:darwin
stdin:
	mkdir foo
	print '#!/bin/sh\necho ohne' >foo/fnord
	print '#!/bin/sh\necho mit' >foo/﻿fnord
	print '﻿fnord\nfnord\n﻿fnord\nfnord' >foo/bar
	print eval \''﻿fnord\nfnord\n﻿fnord\nfnord'\' >foo/zoo
	set -A anzahl -- foo/*
	echo got ${#anzahl[*]} files
	chmod +x foo/*
	export PATH=$(pwd)/foo:$PATH
	"$__progname" -c '﻿fnord'
	echo =
	"$__progname" -c '﻿fnord; fnord; ﻿fnord; fnord'
	echo =
	"$__progname" foo/bar
	echo =
	"$__progname" <foo/bar
	echo =
	"$__progname" foo/zoo
	echo =
	"$__progname" -c 'echo ﻿: $(﻿fnord)'
	rm -rf foo
expected-stdout:
	got 4 files
	ohne
	=
	ohne
	ohne
	mit
	ohne
	=
	ohne
	ohne
	mit
	ohne
	=
	ohne
	ohne
	mit
	ohne
	=
	ohne
	ohne
	mit
	ohne
	=
	﻿: mit
---
name: utf8bom-2
description:
	Check that we can execute BOM-shebangs (failures not fatal)
	XXX if the OS can already execute them, we lose
	note: cygwin execve(2) doesn't return to us with ENOEXEC, we lose
	note: Ultrix perl5 t4 returns 65280 (exit-code 255) and no text
category: !os:cygwin,!os:uwin-nt,!os:ultrix,!smksh
env-setup: !FOO=BAR!
stdin:
	print '#!'"$__progname"'\nprint "1 a=$ENV{FOO}";' >t1
	print '﻿#!'"$__progname"'\nprint "2 a=$ENV{FOO}";' >t2
	print '#!'"$__perlname"'\nprint "3 a=$ENV{FOO}\n";' >t3
	print '﻿#!'"$__perlname"'\nprint "4 a=$ENV{FOO}\n";' >t4
	chmod +x t?
	./t1
	./t2
	./t3
	./t4
expected-stdout:
	1 a=/nonexistant{FOO}
	2 a=/nonexistant{FOO}
	3 a=BAR
	4 a=BAR
expected-stderr-pattern:
	/(Unrecognized character .... ignored at \..t4 line 1)*/
---
name: utf8bom-3
description:
	Reading the UTF-8 BOM should enable the utf8-mode flag
stdin:
	"$__progname" -c ':; if [[ $- = *U* ]]; then echo 1 on; else echo 1 off; fi'
	"$__progname" -c '﻿:; if [[ $- = *U* ]]; then echo 2 on; else echo 2 off; fi'
expected-stdout:
	1 off
	2 on
---
name: utf8opt-1a
description:
	Check that the utf8-mode flag is not set at non-interactive startup
category: !os:hpux
env-setup: !PS1=!PS2=!LC_CTYPE=en_US.UTF-8!
stdin:
	if [[ $- = *U* ]]; then
		echo is set
	else
		echo is not set
	fi
expected-stdout:
	is not set
---
name: utf8opt-1b
description:
	Check that the utf8-mode flag is not set at non-interactive startup
category: os:hpux
env-setup: !PS1=!PS2=!LC_CTYPE=en_US.utf8!
stdin:
	if [[ $- = *U* ]]; then
		echo is set
	else
		echo is not set
	fi
expected-stdout:
	is not set
---
name: utf8opt-2a
description:
	Check that the utf8-mode flag is set at interactive startup.
	-DMKSH_ASSUME_UTF8=0 => expected failure, please ignore
	-DMKSH_ASSUME_UTF8=1 => not expected, please investigate
	-UMKSH_ASSUME_UTF8 => not expected, but if your OS is old,
	 try passing HAVE_SETLOCALE_CTYPE=0 to Build.sh
category: !os:hpux
arguments: !-i!
env-setup: !PS1=!PS2=!LC_CTYPE=en_US.UTF-8!
stdin:
	if [[ $- = *U* ]]; then
		echo is set
	else
		echo is not set
	fi
expected-stdout:
	is set
expected-stderr-pattern:
	/(# )*/
---
name: utf8opt-2b
description:
	Check that the utf8-mode flag is set at interactive startup
	Expected failure if -DMKSH_ASSUME_UTF8=0
category: os:hpux
arguments: !-i!
env-setup: !PS1=!PS2=!LC_CTYPE=en_US.utf8!
stdin:
	if [[ $- = *U* ]]; then
		echo is set
	else
		echo is not set
	fi
expected-stdout:
	is set
expected-stderr-pattern:
	/(# )*/
---
name: utf8opt-3
description:
	Ensure ±U on the command line is honoured
	(this test may pass falsely depending on CPPFLAGS)
stdin:
	export i=0
	code='if [[ $- = *U* ]]; then echo $i on; else echo $i off; fi'
	let i++; "$__progname" -U -c "$code"
	let i++; "$__progname" +U -c "$code"
	let i++; "$__progname" -U -ic "$code"
	let i++; "$__progname" +U -ic "$code"
	echo $((++i)) done
expected-stdout:
	1 on
	2 off
	3 on
	4 off
	5 done
---
name: aliases-1
description:
	Check if built-in shell aliases are okay
category: !arge
stdin:
	alias
	typeset -f
expected-stdout:
	autoload='typeset -fu'
	functions='typeset -f'
	hash='alias -t'
	history='fc -l'
	integer='typeset -i'
	local=typeset
	login='exec login'
	nameref='typeset -n'
	nohup='nohup '
	r='fc -e -'
	source='PATH=$PATH:. command .'
	stop='kill -STOP'
	suspend='kill -STOP $$'
	type='whence -v'
---
name: aliases-1-hartz4
description:
	Check if built-in shell aliases are okay
category: arge
stdin:
	alias
	typeset -f
expected-stdout:
	autoload='typeset -fu'
	functions='typeset -f'
	hash='alias -t'
	history='fc -l'
	integer='typeset -i'
	local=typeset
	login='exec login'
	nameref='typeset -n'
	nohup='nohup '
	r='fc -e -'
	source='PATH=$PATH:. command .'
	type='whence -v'
---
name: aliases-2a
description:
	Check if “set -o sh” disables built-in aliases (except a few)
category: disabled
arguments: !-o!sh!
stdin:
	alias
	typeset -f
expected-stdout:
	integer='typeset -i'
	local=typeset
---
name: aliases-3a
description:
	Check if running as sh disables built-in aliases (except a few)
category: disabled
arguments: !-o!sh!
stdin:
	cp "$__progname" sh
	./sh -c 'alias; typeset -f'
	rm -f sh
expected-stdout:
	integer='typeset -i'
	local=typeset
---
name: aliases-2b
description:
	Check if “set -o sh” does not influence built-in aliases
category: !arge
arguments: !-o!sh!
stdin:
	alias
	typeset -f
expected-stdout:
	autoload='typeset -fu'
	functions='typeset -f'
	hash='alias -t'
	history='fc -l'
	integer='typeset -i'
	local=typeset
	login='exec login'
	nameref='typeset -n'
	nohup='nohup '
	r='fc -e -'
	source='PATH=$PATH:. command .'
	stop='kill -STOP'
	suspend='kill -STOP $$'
	type='whence -v'
---
name: aliases-3b
description:
	Check if running as sh does not influence built-in aliases
category: !arge
arguments: !-o!sh!
stdin:
	cp "$__progname" sh
	./sh -c 'alias; typeset -f'
	rm -f sh
expected-stdout:
	autoload='typeset -fu'
	functions='typeset -f'
	hash='alias -t'
	history='fc -l'
	integer='typeset -i'
	local=typeset
	login='exec login'
	nameref='typeset -n'
	nohup='nohup '
	r='fc -e -'
	source='PATH=$PATH:. command .'
	stop='kill -STOP'
	suspend='kill -STOP $$'
	type='whence -v'
---
name: aliases-2b-hartz4
description:
	Check if “set -o sh” does not influence built-in aliases
category: arge
arguments: !-o!sh!
stdin:
	alias
	typeset -f
expected-stdout:
	autoload='typeset -fu'
	functions='typeset -f'
	hash='alias -t'
	history='fc -l'
	integer='typeset -i'
	local=typeset
	login='exec login'
	nameref='typeset -n'
	nohup='nohup '
	r='fc -e -'
	source='PATH=$PATH:. command .'
	type='whence -v'
---
name: aliases-3b-hartz4
description:
	Check if running as sh does not influence built-in aliases
category: arge
arguments: !-o!sh!
stdin:
	cp "$__progname" sh
	./sh -c 'alias; typeset -f'
	rm -f sh
expected-stdout:
	autoload='typeset -fu'
	functions='typeset -f'
	hash='alias -t'
	history='fc -l'
	integer='typeset -i'
	local=typeset
	login='exec login'
	nameref='typeset -n'
	nohup='nohup '
	r='fc -e -'
	source='PATH=$PATH:. command .'
	type='whence -v'
---
name: aliases-funcdef-1
description:
	Check if POSIX functions take precedences over aliases
stdin:
	alias foo='echo makro'
	foo() {
		echo funktion
	}
	foo
expected-stdout:
	funktion
---
name: aliases-funcdef-2
description:
	Check if POSIX functions take precedences over aliases
stdin:
	alias foo='echo makro'
	foo () {
		echo funktion
	}
	foo
expected-stdout:
	funktion
---
name: aliases-funcdef-3
description:
	Check if aliases take precedences over Korn functions
stdin:
	alias foo='echo makro'
	function foo {
		echo funktion
	}
	foo
expected-stdout:
	makro
---
name: arrays-1
description:
	Check if Korn Shell arrays work as expected
stdin:
	v="c d"
	set -A foo -- a \$v "$v" '$v' b
	echo "${#foo[*]}|${foo[0]}|${foo[1]}|${foo[2]}|${foo[3]}|${foo[4]}|"
expected-stdout:
	5|a|$v|c d|$v|b|
---
name: arrays-2
description:
	Check if bash-style arrays work as expected
category: !smksh
stdin:
	v="c d"
	foo=(a \$v "$v" '$v' b)
	echo "${#foo[*]}|${foo[0]}|${foo[1]}|${foo[2]}|${foo[3]}|${foo[4]}|"
expected-stdout:
	5|a|$v|c d|$v|b|
---
name: arrays-3
description:
	Check if array bounds are uint32_t
stdin:
	set -A foo a b c
	foo[4097]=d
	foo[2147483637]=e
	echo ${foo[*]}
	foo[-1]=f
	echo ${foo[4294967295]} g ${foo[*]}
expected-stdout:
	a b c d e
	f g a b c d e f
---
name: arrays-4
description:
	Check if Korn Shell arrays with specified indices work as expected
category: !smksh
stdin:
	v="c d"
	set -A foo -- [1]=\$v [2]="$v" [4]='$v' [0]=a [5]=b
	echo "${#foo[*]}|${foo[0]}|${foo[1]}|${foo[2]}|${foo[3]}|${foo[4]}|${foo[5]}|"
expected-stdout:
	5|a|$v|c d||$v|b|
---
name: arrays-5
description:
	Check if bash-style arrays with specified indices work as expected
category: !smksh
stdin:
	v="c d"
	foo=([1]=\$v [2]="$v" [4]='$v' [0]=a [5]=b)
	echo "${#foo[*]}|${foo[0]}|${foo[1]}|${foo[2]}|${foo[3]}|${foo[4]}|${foo[5]}|"
	x=([128]=foo bar baz)
	echo k= ${!x[*]} .
	echo v= ${x[*]} .
expected-stdout:
	5|a|$v|c d||$v|b|
	k= 128 129 130 .
	v= foo bar baz .
---
name: arrays-6
description:
	Check if we can get the array keys (indices) for indexed arrays,
	Korn shell style
stdin:
	of() {
		i=0
		for x in "$@"; do
			echo -n "$((i++))<$x>"
		done
		echo
	}
	foo[1]=eins
	set | grep '^foo'
	echo =
	foo[0]=zwei
	foo[4]=drei
	set | grep '^foo'
	echo =
	echo a $(of ${foo[*]}) = $(of ${bar[*]}) a
	echo b $(of "${foo[*]}") = $(of "${bar[*]}") b
	echo c $(of ${foo[@]}) = $(of ${bar[@]}) c
	echo d $(of "${foo[@]}") = $(of "${bar[@]}") d
	echo e $(of ${!foo[*]}) = $(of ${!bar[*]}) e
	echo f $(of "${!foo[*]}") = $(of "${!bar[*]}") f
	echo g $(of ${!foo[@]}) = $(of ${!bar[@]}) g
	echo h $(of "${!foo[@]}") = $(of "${!bar[@]}") h
expected-stdout:
	foo[1]=eins
	=
	foo[0]=zwei
	foo[1]=eins
	foo[4]=drei
	=
	a 0<zwei>1<eins>2<drei> = a
	b 0<zwei eins drei> = 0<> b
	c 0<zwei>1<eins>2<drei> = c
	d 0<zwei>1<eins>2<drei> = d
	e 0<0>1<1>2<4> = e
	f 0<0 1 4> = 0<> f
	g 0<0>1<1>2<4> = g
	h 0<0>1<1>2<4> = h
---
name: arrays-7
description:
	Check if we can get the array keys (indices) for indexed arrays,
	Korn shell style, in some corner cases
stdin:
	echo !arz: ${!arz}
	echo !arz[0]: ${!arz[0]}
	echo !arz[1]: ${!arz[1]}
	arz=foo
	echo !arz: ${!arz}
	echo !arz[0]: ${!arz[0]}
	echo !arz[1]: ${!arz[1]}
	unset arz
	echo !arz: ${!arz}
	echo !arz[0]: ${!arz[0]}
	echo !arz[1]: ${!arz[1]}
expected-stdout:
	!arz: 0
	!arz[0]:
	!arz[1]:
	!arz: arz
	!arz[0]: 0
	!arz[1]:
	!arz: 0
	!arz[0]:
	!arz[1]:
---
name: arrays-8
description:
	Check some behavioural rules for arrays.
stdin:
	fna() {
		set -A aa 9
	}
	fnb() {
		typeset ab
		set -A ab 9
	}
	fnc() {
		typeset ac
		set -A ac 91
		unset ac
		set -A ac 92
	}
	fnd() {
		set +A ad 9
	}
	fne() {
		unset ae
		set +A ae 9
	}
	fnf() {
		unset af[0]
		set +A af 9
	}
	fng() {
		unset ag[*]
		set +A ag 9
	}
	set -A aa 1 2
	set -A ab 1 2
	set -A ac 1 2
	set -A ad 1 2
	set -A ae 1 2
	set -A af 1 2
	set -A ag 1 2
	set -A ah 1 2
	typeset -Z3 aa ab ac ad ae af ag
	print 1a ${aa[*]} .
	print 1b ${ab[*]} .
	print 1c ${ac[*]} .
	print 1d ${ad[*]} .
	print 1e ${ae[*]} .
	print 1f ${af[*]} .
	print 1g ${ag[*]} .
	print 1h ${ah[*]} .
	fna
	fnb
	fnc
	fnd
	fne
	fnf
	fng
	typeset -Z5 ah[*]
	print 2a ${aa[*]} .
	print 2b ${ab[*]} .
	print 2c ${ac[*]} .
	print 2d ${ad[*]} .
	print 2e ${ae[*]} .
	print 2f ${af[*]} .
	print 2g ${ag[*]} .
	print 2h ${ah[*]} .
expected-stdout:
	1a 001 002 .
	1b 001 002 .
	1c 001 002 .
	1d 001 002 .
	1e 001 002 .
	1f 001 002 .
	1g 001 002 .
	1h 1 2 .
	2a 9 .
	2b 001 002 .
	2c 92 .
	2d 009 002 .
	2e 9 .
	2f 9 002 .
	2g 009 .
	2h 00001 00002 .
---
name: varexpand-substr-1
description:
	Check if bash-style substring expansion works
	when using positive numerics
stdin:
	x=abcdefghi
	typeset -i y=123456789
	typeset -i 16 z=123456789	# 16#75bcd15
	echo a t${x:2:2} ${y:2:3} ${z:2:3} a
	echo b ${x::3} ${y::3} ${z::3} b
	echo c ${x:2:} ${y:2:} ${z:2:} c
	echo d ${x:2} ${y:2} ${z:2} d
	echo e ${x:2:6} ${y:2:6} ${z:2:7} e
	echo f ${x:2:7} ${y:2:7} ${z:2:8} f
	echo g ${x:2:8} ${y:2:8} ${z:2:9} g
expected-stdout:
	a tcd 345 #75 a
	b abc 123 16# b
	c c
	d cdefghi 3456789 #75bcd15 d
	e cdefgh 345678 #75bcd1 e
	f cdefghi 3456789 #75bcd15 f
	g cdefghi 3456789 #75bcd15 g
---
name: varexpand-substr-2
description:
	Check if bash-style substring expansion works
	when using negative numerics or expressions
stdin:
	x=abcdefghi
	typeset -i y=123456789
	typeset -i 16 z=123456789	# 16#75bcd15
	n=2
	echo a ${x:$n:3} ${y:$n:3} ${z:$n:3} a
	echo b ${x:(n):3} ${y:(n):3} ${z:(n):3} b
	echo c ${x:(-2):1} ${y:(-2):1} ${z:(-2):1} c
	echo d t${x: n:2} ${y: n:3} ${z: n:3} d
expected-stdout:
	a cde 345 #75 a
	b cde 345 #75 b
	c h 8 1 c
	d tcd 345 #75 d
---
name: varexpand-substr-3
description:
	Check that some things that work in bash fail.
	This is by design. And that some things fail in both.
stdin:
	export x=abcdefghi n=2
	"$__progname" -c 'echo v${x:(n)}x'
	"$__progname" -c 'echo w${x: n}x'
	"$__progname" -c 'echo x${x:n}x'
	"$__progname" -c 'echo y${x:}x'
	"$__progname" -c 'echo z${x}x'
	"$__progname" -c 'x=abcdef;y=123;echo ${x:${y:2:1}:2}' >/dev/null 2>&1; echo $?
expected-stdout:
	vcdefghix
	wcdefghix
	zabcdefghix
	1
expected-stderr-pattern:
	/x:n.*bad substitution.*\n.*bad substitution/
---
name: varexpand-substr-4
description:
	Check corner cases for substring expansion
stdin:
	x=abcdefghi
	integer y=2
	echo a ${x:(y == 1 ? 2 : 3):4} a
expected-stdout:
	a defg a
---
name: varexpand-substr-5A
description:
	Check that substring expansions work on characters
stdin:
	set +U
	x=mäh
	echo a ${x::1} ${x: -1} a
	echo b ${x::3} ${x: -3} b
	echo c ${x:1:2} ${x: -3:2} c
	echo d ${#x} d
expected-stdout:
	a m h a
	b mä äh b
	c ä ä c
	d 4 d
---
name: varexpand-substr-5W
description:
	Check that substring expansions work on characters
stdin:
	set -U
	x=mäh
	echo a ${x::1} ${x: -1} a
	echo b ${x::2} ${x: -2} b
	echo c ${x:1:1} ${x: -2:1} c
	echo d ${#x} d
expected-stdout:
	a m h a
	b mä äh b
	c ä ä c
	d 3 d
---
name: varexpand-substr-6
description:
	Check that string substitution works correctly
stdin:
	foo=1
	bar=2
	baz=qwertyuiop
	echo a ${baz: foo: bar}
	echo b ${baz: foo: $bar}
	echo c ${baz: $foo: bar}
	echo d ${baz: $foo: $bar}
expected-stdout:
	a we
	b we
	c we
	d we
---
name: varexpand-null-1
description:
	Ensure empty strings expand emptily
stdin:
	print x ${a} ${b} y
	print z ${a#?} ${b%?} w
	print v ${a=} ${b/c/d} u
expected-stdout:
	x y
	z w
	v u
---
name: varexpand-null-2
description:
	Ensure empty strings, when quoted, are expanded as empty strings
stdin:
	printf '<%s> ' 1 "${a}" 2 "${a#?}" + "${b%?}" 3 "${a=}" + "${b/c/d}"
	echo .
expected-stdout:
	<1> <> <2> <> <+> <> <3> <> <+> <> .
---
name: print-funny-chars
description:
	Check print builtin's capability to output designated characters
stdin:
	print '<\0144\0344\xDB\u00DB\u20AC\uDB\x40>'
expected-stdout:
	<d��Û€Û@>
---
name: print-bksl-c
description:
	Check print builtin's \c escape
stdin:
	print '\ca'; print b
expected-stdout:
	ab
---
name: print-nul-chars
description:
	Check handling of NUL characters for print and read
	note: second line should output “4 3” but we cannot
	handle NUL characters in strings yet
stdin:
	print $(($(print '<\0>' | wc -c)))
	x=$(print '<\0>')
	print $(($(print "$x" | wc -c))) ${#x}
expected-stdout:
	4
	3 2
---
name: print-escapes
description:
	Check backslash expansion by the print builtin
stdin:
	print '\ \!\"\#\$\%\&'\\\''\(\)\*\+\,\-\.\/\0\1\2\3\4\5\6\7\8' \
	    '\9\:\;\<\=\>\?\@\A\B\C\D\E\F\G\H\I\J\K\L\M\N\O\P\Q\R\S\T' \
	    '\U\V\W\X\Y\Z\[\\\]\^\_\`\a\b  \d\e\f\g\h\i\j\k\l\m\n\o\p' \
	    '\q\r\s\t\u\v\w\x\y\z\{\|\}\~' '\u20acd' '\U20acd' '\x123' \
	    '\0x' '\0123' '\01234' | {
		typeset -Uui16 -Z11 pos=0
		typeset -Uui16 -Z5 hv
		typeset -i1 wc=0x0A
		dasc=
		nl=${wc#1#}
		while IFS= read -r line; do
			line=$line$nl
			while [[ -n $line ]]; do
				hv=1#${line::1}
				if (( (pos & 15) == 0 )); then
					(( pos )) && print "$dasc|"
					print -n "${pos#16#}  "
					dasc=' |'
				fi
				print -n "${hv#16#} "
				if (( (hv < 32) || (hv > 126) )); then
					dasc=$dasc.
				else
					dasc=$dasc${line::1}
				fi
				(( (pos++ & 15) == 7 )) && print -n -- '- '
				line=${line:1}
			done
		done
		if (( (pos & 15) != 1 )); then
			while (( pos & 15 )); do
				print -n '   '
				(( (pos++ & 15) == 7 )) && print -n -- '- '
			done
			print "$dasc|"
		fi
	}
expected-stdout:
	00000000  5C 20 5C 21 5C 22 5C 23 - 5C 24 5C 25 5C 26 5C 27  |\ \!\"\#\$\%\&\'|
	00000010  5C 28 5C 29 5C 2A 5C 2B - 5C 2C 5C 2D 5C 2E 5C 2F  |\(\)\*\+\,\-\.\/|
	00000020  5C 31 5C 32 5C 33 5C 34 - 5C 35 5C 36 5C 37 5C 38  |\1\2\3\4\5\6\7\8|
	00000030  20 5C 39 5C 3A 5C 3B 5C - 3C 5C 3D 5C 3E 5C 3F 5C  | \9\:\;\<\=\>\?\|
	00000040  40 5C 41 5C 42 5C 43 5C - 44 1B 5C 46 5C 47 5C 48  |@\A\B\C\D.\F\G\H|
	00000050  5C 49 5C 4A 5C 4B 5C 4C - 5C 4D 5C 4E 5C 4F 5C 50  |\I\J\K\L\M\N\O\P|
	00000060  5C 51 5C 52 5C 53 5C 54 - 20 5C 56 5C 57 5C 58 5C  |\Q\R\S\T \V\W\X\|
	00000070  59 5C 5A 5C 5B 5C 5C 5D - 5C 5E 5C 5F 5C 60 07 08  |Y\Z\[\]\^\_\`..|
	00000080  20 20 5C 64 1B 0C 5C 67 - 5C 68 5C 69 5C 6A 5C 6B  |  \d..\g\h\i\j\k|
	00000090  5C 6C 5C 6D 0A 5C 6F 5C - 70 20 5C 71 0D 5C 73 09  |\l\m.\o\p \q.\s.|
	000000A0  0B 5C 77 5C 79 5C 7A 5C - 7B 5C 7C 5C 7D 5C 7E 20  |.\w\y\z\{\|\}\~ |
	000000B0  E2 82 AC 64 20 EF BF BD - 20 12 33 20 78 20 53 20  |...d ... .3 x S |
	000000C0  53 34 0A                -                          |S4.|
---
name: dollar-quoted-strings
description:
	Check backslash expansion by $'…' strings
stdin:
	printf '%s\n' $'\ \!\"\#\$\%\&\'\(\)\*\+\,\-\.\/ \1\2\3\4\5\6' \
	    $'a\0b' $'a\01b' $'\7\8\9\:\;\<\=\>\?\@\A\B\C\D\E\F\G\H\I' \
	    $'\J\K\L\M\N\O\P\Q\R\S\T\U1\V\W\X\Y\Z\[\\\]\^\_\`\a\b\d\e' \
	    $'\f\g\h\i\j\k\l\m\n\o\p\q\r\s\t\u1\v\w\x1\y\z\{\|\}\~ $x' \
	    $'\u20acd' $'\U20acd' $'\x123' $'fn\x0rd' $'\0234' $'\234' \
	    $'\2345' $'\ca' $'\c!' $'\c?' $'\c€' $'a\
	b' | {
		typeset -Uui16 -Z11 pos=0
		typeset -Uui16 -Z5 hv
		typeset -i1 wc=0x0A
		dasc=
		nl=${wc#1#}
		while IFS= read -r line; do
			line=$line$nl
			while [[ -n $line ]]; do
				hv=1#${line::1}
				if (( (pos & 15) == 0 )); then
					(( pos )) && print "$dasc|"
					print -n "${pos#16#}  "
					dasc=' |'
				fi
				print -n "${hv#16#} "
				if (( (hv < 32) || (hv > 126) )); then
					dasc=$dasc.
				else
					dasc=$dasc${line::1}
				fi
				(( (pos++ & 15) == 7 )) && print -n -- '- '
				line=${line:1}
			done
		done
		if (( (pos & 15) != 1 )); then
			while (( pos & 15 )); do
				print -n '   '
				(( (pos++ & 15) == 7 )) && print -n -- '- '
			done
			print "$dasc|"
		fi
	}
expected-stdout:
	00000000  20 21 22 23 24 25 26 27 - 28 29 2A 2B 2C 2D 2E 2F  | !"#$%&'()*+,-./|
	00000010  20 01 02 03 04 05 06 0A - 61 0A 61 01 62 0A 07 38  | .......a.a.b..8|
	00000020  39 3A 3B 3C 3D 3E 3F 40 - 41 42 43 44 1B 46 47 48  |9:;<=>?@ABCD.FGH|
	00000030  49 0A 4A 4B 4C 4D 4E 4F - 50 51 52 53 54 01 56 57  |I.JKLMNOPQRST.VW|
	00000040  58 59 5A 5B 5C 5D 5E 5F - 60 07 08 64 1B 0A 0C 67  |XYZ[\]^_`..d...g|
	00000050  68 69 6A 6B 6C 6D 0A 6F - 70 71 0D 73 09 01 0B 77  |hijklm.opq.s...w|
	00000060  01 79 7A 7B 7C 7D 7E 20 - 24 78 0A E2 82 AC 64 0A  |.yz{|}~ $x....d.|
	00000070  EF BF BD 0A C4 A3 0A 66 - 6E 0A 13 34 0A 9C 0A 9C  |.......fn..4....|
	00000080  35 0A 01 0A 01 0A 7F 0A - 02 82 AC 0A 61 0A 62 0A  |5...........a.b.|
---
name: dollar-quotes-in-heredocs
description:
	They are, however, not parsed in here documents
stdin:
	cat <<EOF
		dollar = strchr(s, '$');	/* ' */
	EOF
	cat <<$'a\tb'
	a\tb
	a	b
expected-stdout:
		dollar = strchr(s, '$');	/* ' */
	a\tb
---
name: dollar-quotes-in-herestrings
description:
	They are, not parsed in here strings either
stdin:
	cat <<<"dollar = strchr(s, '$');	/* ' */"
	cat <<<'dollar = strchr(s, '\''$'\'');	/* '\'' */'
	x="dollar = strchr(s, '$');	/* ' */"
	cat <<<"$x"
	cat <<<$'a\E[0m\tb'
expected-stdout:
	dollar = strchr(s, '$');	/* ' */
	dollar = strchr(s, '$');	/* ' */
	dollar = strchr(s, '$');	/* ' */
	a[0m	b
---
name: dot-needs-argument
description:
	check Debian #415167 solution: '.' without arguments should fail
stdin:
	"$__progname" -c .
	"$__progname" -c source
expected-exit: e != 0
expected-stderr-pattern:
	/\.: missing argument.*\n.*\.: missing argument/
---
name: alias-function-no-conflict
description:
	make aliases not conflict with functions
	note: for ksh-like functions, the order of preference is
	different; bash outputs baz instead of bar in line 2 below
stdin:
	alias foo='echo bar'
	foo() {
		echo baz
	}
	alias korn='echo bar'
	function korn {
		echo baz
	}
	foo
	korn
	unset -f foo
	foo 2>&- || echo rab
expected-stdout:
	baz
	bar
	rab
---
name: bash-function-parens
description:
	ensure the keyword function is ignored when preceding
	POSIX style function declarations (bashism)
stdin:
	mk() {
		echo '#!'"$__progname"
		echo "$1 {"
		echo '	echo "bar='\''$0'\'\"
		echo '}'
		echo ${2:-foo}
	}
	mk 'function foo' >f-korn
	mk 'foo ()' >f-dash
	mk 'function foo ()' >f-bash
	mk 'function stop ()' stop >f-stop
	chmod +x f-*
	echo "korn: $(./f-korn)"
	echo "dash: $(./f-dash)"
	echo "bash: $(./f-bash)"
	echo "stop: $(./f-stop)"
expected-stdout:
	korn: bar='foo'
	dash: bar='./f-dash'
	bash: bar='./f-bash'
	stop: bar='./f-stop'
---
name: integer-base-one-1
description:
	check if the use of fake integer base 1 works
stdin:
	set -U
	typeset -Uui16 i0=1#� i1=1#€
	typeset -i1 o0a=64
	typeset -i1 o1a=0x263A
	typeset -Uui1 o0b=0x7E
	typeset -Uui1 o1b=0xFDD0
	integer px=0xCAFE 'p0=1# ' p1=1#… pl=1#f
	echo "in <$i0> <$i1>"
	echo "out <${o0a#1#}|${o0b#1#}> <${o1a#1#}|${o1b#1#}>"
	typeset -Uui1 i0 i1
	echo "pass <$px> <$p0> <$p1> <$pl> <${i0#1#}|${i1#1#}>"
	typeset -Uui16 tv1=1#~ tv2=1# tv3=1#� tv4=1#� tv5=1#� tv6=1#� tv7=1#  tv8=1#
	echo "specX <${tv1#16#}> <${tv2#16#}> <${tv3#16#}> <${tv4#16#}> <${tv5#16#}> <${tv6#16#}> <${tv7#16#}> <${tv8#16#}>"
	typeset -i1 tv1 tv2 tv3 tv4 tv5 tv6 tv7 tv8
	echo "specW <${tv1#1#}> <${tv2#1#}> <${tv3#1#}> <${tv4#1#}> <${tv5#1#}> <${tv6#1#}> <${tv7#1#}> <${tv8#1#}>"
	typeset -i1 xs1=0xEF7F xs2=0xEF80 xs3=0xFDD0
	echo "specU <${xs1#1#}> <${xs2#1#}> <${xs3#1#}>"
expected-stdout:
	in <16#EFEF> <16#20AC>
	out <@|~> <☺|﷐>
	pass <16#cafe> <1# > <1#…> <1#f> <�|€>
	specX <7E> <7F> <EF80> <EF81> <EFC0> <EFC1> <A0> <80>
	specW <~> <> <�> <�> <�> <�> < > <>
	specU <> <�> <﷐>
---
name: integer-base-one-2a
description:
	check if the use of fake integer base 1 stops at correct characters
stdin:
	set -U
	integer x=1#foo
	echo /$x/
expected-stderr-pattern:
	/1#foo: unexpected 'oo'/
expected-exit: e != 0
---
name: integer-base-one-2b
description:
	check if the use of fake integer base 1 stops at correct characters
stdin:
	set -U
	integer x=1#��
	echo /$x/
expected-stderr-pattern:
	/1#��: unexpected '�'/
expected-exit: e != 0
---
name: integer-base-one-2c1
description:
	check if the use of fake integer base 1 stops at correct characters
stdin:
	set -U
	integer x=1#…
	echo /$x/
expected-stdout:
	/1#…/
---
name: integer-base-one-2c2
description:
	check if the use of fake integer base 1 stops at correct characters
stdin:
	set +U
	integer x=1#…
	echo /$x/
expected-stderr-pattern:
	/1#…: unexpected '�'/
expected-exit: e != 0
---
name: integer-base-one-2d1
description:
	check if the use of fake integer base 1 handles octets okay
stdin:
	set -U
	typeset -i16 x=1#�
	echo /$x/	# invalid utf-8
expected-stdout:
	/16#efff/
---
name: integer-base-one-2d2
description:
	check if the use of fake integer base 1 handles octets
stdin:
	set -U
	typeset -i16 x=1#�
	echo /$x/	# invalid 2-byte
expected-stdout:
	/16#efc2/
---
name: integer-base-one-2d3
description:
	check if the use of fake integer base 1 handles octets
stdin:
	set -U
	typeset -i16 x=1#�
	echo /$x/	# invalid 2-byte
expected-stdout:
	/16#efef/
---
name: integer-base-one-2d4
description:
	check if the use of fake integer base 1 stops at invalid input
stdin:
	set -U
	typeset -i16 x=1#��
	echo /$x/	# invalid 3-byte
expected-stderr-pattern:
	/1#��: unexpected '�'/
expected-exit: e != 0
---
name: integer-base-one-2d5
description:
	check if the use of fake integer base 1 stops at invalid input
stdin:
	set -U
	typeset -i16 x=1#��
	echo /$x/	# non-minimalistic
expected-stderr-pattern:
	/1#��: unexpected '�'/
expected-exit: e != 0
---
name: integer-base-one-2d6
description:
	check if the use of fake integer base 1 stops at invalid input
stdin:
	set -U
	typeset -i16 x=1#���
	echo /$x/	# non-minimalistic
expected-stderr-pattern:
	/1#���: unexpected '�'/
expected-exit: e != 0
---
name: integer-base-one-3A
description:
	some sample code for hexdumping
stdin:
	{
		print 'Hello, World!\\\nこんにちは！'
		typeset -Uui16 i=0x100
		# change that to 0xFF once we can handle embedded
		# NUL characters in strings / here documents
		while (( i++ < 0x1FF )); do
			print -n "\x${i#16#1}"
		done
		print
	} | {
		typeset -Uui16 -Z11 pos=0
		typeset -Uui16 -Z5 hv
		typeset -i1 wc=0x0A
		dasc=
		nl=${wc#1#}
		while IFS= read -r line; do
			line=$line$nl
			while [[ -n $line ]]; do
				hv=1#${line::1}
				if (( (pos & 15) == 0 )); then
					(( pos )) && print "$dasc|"
					print -n "${pos#16#}  "
					dasc=' |'
				fi
				print -n "${hv#16#} "
				if (( (hv < 32) || (hv > 126) )); then
					dasc=$dasc.
				else
					dasc=$dasc${line::1}
				fi
				(( (pos++ & 15) == 7 )) && print -n -- '- '
				line=${line:1}
			done
		done
		if (( (pos & 15) != 1 )); then
			while (( pos & 15 )); do
				print -n '   '
				(( (pos++ & 15) == 7 )) && print -n -- '- '
			done
			print "$dasc|"
		fi
	}
expected-stdout:
	00000000  48 65 6C 6C 6F 2C 20 57 - 6F 72 6C 64 21 5C 0A E3  |Hello, World!\..|
	00000010  81 93 E3 82 93 E3 81 AB - E3 81 A1 E3 81 AF EF BC  |................|
	00000020  81 0A 01 02 03 04 05 06 - 07 08 09 0A 0B 0C 0D 0E  |................|
	00000030  0F 10 11 12 13 14 15 16 - 17 18 19 1A 1B 1C 1D 1E  |................|
	00000040  1F 20 21 22 23 24 25 26 - 27 28 29 2A 2B 2C 2D 2E  |. !"#$%&'()*+,-.|
	00000050  2F 30 31 32 33 34 35 36 - 37 38 39 3A 3B 3C 3D 3E  |/0123456789:;<=>|
	00000060  3F 40 41 42 43 44 45 46 - 47 48 49 4A 4B 4C 4D 4E  |?@ABCDEFGHIJKLMN|
	00000070  4F 50 51 52 53 54 55 56 - 57 58 59 5A 5B 5C 5D 5E  |OPQRSTUVWXYZ[\]^|
	00000080  5F 60 61 62 63 64 65 66 - 67 68 69 6A 6B 6C 6D 6E  |_`abcdefghijklmn|
	00000090  6F 70 71 72 73 74 75 76 - 77 78 79 7A 7B 7C 7D 7E  |opqrstuvwxyz{|}~|
	000000A0  7F 80 81 82 83 84 85 86 - 87 88 89 8A 8B 8C 8D 8E  |................|
	000000B0  8F 90 91 92 93 94 95 96 - 97 98 99 9A 9B 9C 9D 9E  |................|
	000000C0  9F A0 A1 A2 A3 A4 A5 A6 - A7 A8 A9 AA AB AC AD AE  |................|
	000000D0  AF B0 B1 B2 B3 B4 B5 B6 - B7 B8 B9 BA BB BC BD BE  |................|
	000000E0  BF C0 C1 C2 C3 C4 C5 C6 - C7 C8 C9 CA CB CC CD CE  |................|
	000000F0  CF D0 D1 D2 D3 D4 D5 D6 - D7 D8 D9 DA DB DC DD DE  |................|
	00000100  DF E0 E1 E2 E3 E4 E5 E6 - E7 E8 E9 EA EB EC ED EE  |................|
	00000110  EF F0 F1 F2 F3 F4 F5 F6 - F7 F8 F9 FA FB FC FD FE  |................|
	00000120  FF 0A                   -                          |..|
---
name: integer-base-one-3W
description:
	some sample code for hexdumping Unicode
stdin:
	set -U
	{
		print 'Hello, World!\\\nこんにちは！'
		typeset -Uui16 i=0x100
		# change that to 0xFF once we can handle embedded
		# NUL characters in strings / here documents
		while (( i++ < 0x1FF )); do
			print -n "\u${i#16#1}"
		done
		print
		print \\xff		# invalid utf-8
		print \\xc2		# invalid 2-byte
		print \\xef\\xbf\\xc0	# invalid 3-byte
		print \\xc0\\x80	# non-minimalistic
		print \\xe0\\x80\\x80	# non-minimalistic
		print '�￾￿'	# end of range
	} | {
		typeset -Uui16 -Z11 pos=0
		typeset -Uui16 -Z7 hv
		typeset -i1 wc=0x0A
		typeset -i lpos
		dasc=
		nl=${wc#1#}
		while IFS= read -r line; do
			line=$line$nl
			lpos=0
			while (( lpos < ${#line} )); do
				wc=1#${line:(lpos++):1}
				if (( (wc < 32) || \
				    ((wc > 126) && (wc < 160)) )); then
					dch=.
				elif (( (wc & 0xFF80) == 0xEF80 )); then
					dch=�
				else
					dch=${wc#1#}
				fi
				if (( (pos & 7) == 7 )); then
					dasc=$dasc$dch
					dch=
				elif (( (pos & 7) == 0 )); then
					(( pos )) && print "$dasc|"
					print -n "${pos#16#}  "
					dasc=' |'
				fi
				let hv=wc
				print -n "${hv#16#} "
				(( (pos++ & 7) == 3 )) && \
				    print -n -- '- '
				dasc=$dasc$dch
			done
		done
		if (( pos & 7 )); then
			while (( pos & 7 )); do
				print -n '     '
				(( (pos++ & 7) == 3 )) && print -n -- '- '
			done
			print "$dasc|"
		fi
	}
expected-stdout:
	00000000  0048 0065 006C 006C - 006F 002C 0020 0057  |Hello, W|
	00000008  006F 0072 006C 0064 - 0021 005C 000A 3053  |orld!\.こ|
	00000010  3093 306B 3061 306F - FF01 000A 0001 0002  |んにちは！...|
	00000018  0003 0004 0005 0006 - 0007 0008 0009 000A  |........|
	00000020  000B 000C 000D 000E - 000F 0010 0011 0012  |........|
	00000028  0013 0014 0015 0016 - 0017 0018 0019 001A  |........|
	00000030  001B 001C 001D 001E - 001F 0020 0021 0022  |..... !"|
	00000038  0023 0024 0025 0026 - 0027 0028 0029 002A  |#$%&'()*|
	00000040  002B 002C 002D 002E - 002F 0030 0031 0032  |+,-./012|
	00000048  0033 0034 0035 0036 - 0037 0038 0039 003A  |3456789:|
	00000050  003B 003C 003D 003E - 003F 0040 0041 0042  |;<=>?@AB|
	00000058  0043 0044 0045 0046 - 0047 0048 0049 004A  |CDEFGHIJ|
	00000060  004B 004C 004D 004E - 004F 0050 0051 0052  |KLMNOPQR|
	00000068  0053 0054 0055 0056 - 0057 0058 0059 005A  |STUVWXYZ|
	00000070  005B 005C 005D 005E - 005F 0060 0061 0062  |[\]^_`ab|
	00000078  0063 0064 0065 0066 - 0067 0068 0069 006A  |cdefghij|
	00000080  006B 006C 006D 006E - 006F 0070 0071 0072  |klmnopqr|
	00000088  0073 0074 0075 0076 - 0077 0078 0079 007A  |stuvwxyz|
	00000090  007B 007C 007D 007E - 007F 0080 0081 0082  |{|}~....|
	00000098  0083 0084 0085 0086 - 0087 0088 0089 008A  |........|
	000000A0  008B 008C 008D 008E - 008F 0090 0091 0092  |........|
	000000A8  0093 0094 0095 0096 - 0097 0098 0099 009A  |........|
	000000B0  009B 009C 009D 009E - 009F 00A0 00A1 00A2  |..... ¡¢|
	000000B8  00A3 00A4 00A5 00A6 - 00A7 00A8 00A9 00AA  |£¤¥¦§¨©ª|
	000000C0  00AB 00AC 00AD 00AE - 00AF 00B0 00B1 00B2  |«¬­®¯°±²|
	000000C8  00B3 00B4 00B5 00B6 - 00B7 00B8 00B9 00BA  |³´µ¶·¸¹º|
	000000D0  00BB 00BC 00BD 00BE - 00BF 00C0 00C1 00C2  |»¼½¾¿ÀÁÂ|
	000000D8  00C3 00C4 00C5 00C6 - 00C7 00C8 00C9 00CA  |ÃÄÅÆÇÈÉÊ|
	000000E0  00CB 00CC 00CD 00CE - 00CF 00D0 00D1 00D2  |ËÌÍÎÏÐÑÒ|
	000000E8  00D3 00D4 00D5 00D6 - 00D7 00D8 00D9 00DA  |ÓÔÕÖ×ØÙÚ|
	000000F0  00DB 00DC 00DD 00DE - 00DF 00E0 00E1 00E2  |ÛÜÝÞßàáâ|
	000000F8  00E3 00E4 00E5 00E6 - 00E7 00E8 00E9 00EA  |ãäåæçèéê|
	00000100  00EB 00EC 00ED 00EE - 00EF 00F0 00F1 00F2  |ëìíîïðñò|
	00000108  00F3 00F4 00F5 00F6 - 00F7 00F8 00F9 00FA  |óôõö÷øùú|
	00000110  00FB 00FC 00FD 00FE - 00FF 000A EFFF 000A  |ûüýþÿ.�.|
	00000118  EFC2 000A EFEF EFBF - EFC0 000A EFC0 EF80  |�.���.��|
	00000120  000A EFE0 EF80 EF80 - 000A FFFD EFEF EFBF  |.���.���|
	00000128  EFBE EFEF EFBF EFBF - 000A                 |����.|
---
name: integer-base-one-4
description:
	Check if ksh93-style base-one integers work
category: !smksh
stdin:
	set -U
	echo 1 $(('a'))
	(echo 2f $(('aa'))) 2>&1 | sed "s/^[^']*'/2p '/"
	echo 3 $(('…'))
	x="'a'"
	echo "4 <$x>"
	echo 5 $(($x))
	echo 6 $((x))
expected-stdout:
	1 97
	2p 'aa': multi-character character constant
	3 8230
	4 <'a'>
	5 97
	6 97
---
name: ulimit-1
description:
	Check if we can use a specific syntax idiom for ulimit
stdin:
	if ! x=$(ulimit -d) || [[ $x = unknown ]]; then
		#echo expected to fail on this OS
		echo okay
	else
		ulimit -dS $x && echo okay
	fi
expected-stdout:
	okay
---
name: bashiop-1
description:
	Check if GNU bash-like I/O redirection works
	Part 1: this is also supported by GNU bash
stdin:
	exec 3>&1
	function threeout {
		echo ras
		echo dwa >&2
		echo tri >&3
	}
	threeout &>foo
	echo ===
	cat foo
expected-stdout:
	tri
	===
	ras
	dwa
---
name: bashiop-2a
description:
	Check if GNU bash-like I/O redirection works
	Part 2: this is *not* supported by GNU bash
stdin:
	exec 3>&1
	function threeout {
		echo ras
		echo dwa >&2
		echo tri >&3
	}
	threeout 3&>foo
	echo ===
	cat foo
expected-stdout:
	ras
	===
	dwa
	tri
---
name: bashiop-2b
description:
	Check if GNU bash-like I/O redirection works
	Part 2: this is *not* supported by GNU bash
stdin:
	exec 3>&1
	function threeout {
		echo ras
		echo dwa >&2
		echo tri >&3
	}
	threeout 3>foo &>&3
	echo ===
	cat foo
expected-stdout:
	===
	ras
	dwa
	tri
---
name: bashiop-2c
description:
	Check if GNU bash-like I/O redirection works
	Part 2: this is supported by GNU bash 4 only
stdin:
	echo mir >foo
	set -o noclobber
	exec 3>&1
	function threeout {
		echo ras
		echo dwa >&2
		echo tri >&3
	}
	threeout &>>foo
	echo ===
	cat foo
expected-stdout:
	tri
	===
	mir
	ras
	dwa
---
name: bashiop-3a
description:
	Check if GNU bash-like I/O redirection fails correctly
	Part 1: this is also supported by GNU bash
stdin:
	echo mir >foo
	set -o noclobber
	exec 3>&1
	function threeout {
		echo ras
		echo dwa >&2
		echo tri >&3
	}
	threeout &>foo
	echo ===
	cat foo
expected-stdout:
	===
	mir
expected-stderr-pattern: /.*: cannot (create|overwrite) .*/
---
name: bashiop-3b
description:
	Check if GNU bash-like I/O redirection fails correctly
	Part 2: this is *not* supported by GNU bash
stdin:
	echo mir >foo
	set -o noclobber
	exec 3>&1
	function threeout {
		echo ras
		echo dwa >&2
		echo tri >&3
	}
	threeout &>|foo
	echo ===
	cat foo
expected-stdout:
	tri
	===
	ras
	dwa
---
name: bashiop-4
description:
	Check if GNU bash-like I/O redirection works
	Part 4: this is also supported by GNU bash,
	but failed in some mksh versions
stdin:
	exec 3>&1
	function threeout {
		echo ras
		echo dwa >&2
		echo tri >&3
	}
	function blubb {
		[[ -e bar ]] && threeout "$bf" &>foo
	}
	blubb
	echo -n >bar
	blubb
	echo ===
	cat foo
expected-stdout:
	tri
	===
	ras
	dwa
---
name: mkshiop-1
description:
	Check for support of more than 9 file descriptors
category: !convfds
stdin:
	read -u10 foo 10<<< bar
	echo x$foo
expected-stdout:
	xbar
---
name: mkshiop-2
description:
	Check for support of more than 9 file descriptors
category: !convfds
stdin:
	exec 12>foo
	print -u12 bar
	echo baz >&12
	cat foo
expected-stdout:
	bar
	baz
---
name: oksh-shcrash
description:
	src/regress/bin/ksh/shcrash.sh,v 1.1
stdin:
	deplibs="-lz -lpng /usr/local/lib/libjpeg.la -ltiff -lm -lX11 -lXext /usr/local/lib/libiconv.la -L/usr/local/lib -L/usr/ports/devel/gettext/w-gettext-0.10.40/gettext-0.10.40/intl/.libs /usr/local/lib/libintl.la /usr/local/lib/libglib.la /usr/local/lib/libgmodule.la -lintl -lm -lX11 -lXext -L/usr/X11R6/lib -lglib -lgmodule -L/usr/local/lib /usr/local/lib/libgdk.la -lintl -lm -lX11 -lXext -L/usr/X11R6/lib -lglib -lgmodule -L/usr/local/lib /usr/local/lib/libgtk.la -ltiff -ljpeg -lz -lpng -lm -lX11 -lXext -lintl -lglib -lgmodule -lgdk -lgtk -L/usr/X11R6/lib -lglib -lgmodule -L/usr/local/lib /usr/local/lib/libgdk_pixbuf.la -lz -lpng /usr/local/lib/libiconv.la -L/usr/local/lib -L/usr/ports/devel/gettext/w-gettext-0.10.40/gettext-0.10.40/intl/.libs /usr/local/lib/libintl.la /usr/local/lib/libglib.la -lm -lm /usr/local/lib/libaudiofile.la -lm -lm -laudiofile -L/usr/local/lib /usr/local/lib/libesd.la -lm -lz -L/usr/local/lib /usr/local/lib/libgnomesupport.la -lm -lz -lm -lglib -L/usr/local/lib /usr/local/lib/libgnome.la -lX11 -lXext /usr/local/lib/libiconv.la -L/usr/local/lib -L/usr/ports/devel/gettext/w-gettext-0.10.40/gettext-0.10.40/intl/.libs /usr/local/lib/libintl.la /usr/local/lib/libgmodule.la -lintl -lm -lX11 -lXext -L/usr/X11R6/lib -lglib -lgmodule -L/usr/local/lib /usr/local/lib/libgdk.la -lintl -lm -lX11 -lXext -L/usr/X11R6/lib -lglib -lgmodule -L/usr/local/lib /usr/local/lib/libgtk.la -lICE -lSM -lz -lpng /usr/local/lib/libungif.la /usr/local/lib/libjpeg.la -ltiff -lm -lz -lpng /usr/local/lib/libungif.la -lz /usr/local/lib/libjpeg.la -ltiff -L/usr/local/lib -L/usr/X11R6/lib /usr/local/lib/libgdk_imlib.la -lm -L/usr/local/lib /usr/local/lib/libart_lgpl.la -lm -lz -lm -lX11 -lXext -lintl -lglib -lgmodule -lgdk -lgtk -lICE -lSM -lm -lX11 -lXext -lintl -lglib -lgmodule -lgdk -lgtk -L/usr/X11R6/lib -lm -lz -lpng -lungif -lz -ljpeg -ltiff -ljpeg -lgdk_imlib -lglib -lm -laudiofile -lm -laudiofile -lesd -L/usr/local/lib /usr/local/lib/libgnomeui.la -lz -lz /usr/local/lib/libxml.la -lz -lz -lz /usr/local/lib/libxml.la -lm -lX11 -lXext /usr/local/lib/libiconv.la -L/usr/ports/devel/gettext/w-gettext-0.10.40/gettext-0.10.40/intl/.libs /usr/local/lib/libintl.la /usr/local/lib/libglib.la /usr/local/lib/libgmodule.la -lintl -lglib -lgmodule /usr/local/lib/libgdk.la /usr/local/lib/libgtk.la -L/usr/X11R6/lib -L/usr/local/lib /usr/local/lib/libglade.la -lz -lz -lz /usr/local/lib/libxml.la /usr/local/lib/libglib.la -lm -lm /usr/local/lib/libaudiofile.la -lm -lm -laudiofile /usr/local/lib/libesd.la -lm -lz /usr/local/lib/libgnomesupport.la -lm -lz -lm -lglib /usr/local/lib/libgnome.la -lX11 -lXext /usr/local/lib/libiconv.la -L/usr/ports/devel/gettext/w-gettext-0.10.40/gettext-0.10.40/intl/.libs /usr/local/lib/libintl.la /usr/local/lib/libgmodule.la -lintl -lm -lX11 -lXext -lglib -lgmodule /usr/local/lib/libgdk.la -lintl -lm -lX11 -lXext -lglib -lgmodule /usr/local/lib/libgtk.la -lICE -lSM -lz -lpng /usr/local/lib/libungif.la /usr/local/lib/libjpeg.la -ltiff -lm -lz -lz /usr/local/lib/libgdk_imlib.la /usr/local/lib/libart_lgpl.la -lm -lz -lm -lX11 -lXext -lintl -lglib -lgmodule -lgdk -lgtk -lm -lX11 -lXext -lintl -lglib -lgmodule -lgdk -lgtk -lm -lz -lungif -lz -ljpeg -ljpeg -lgdk_imlib -lglib -lm -laudiofile -lm -laudiofile -lesd /usr/local/lib/libgnomeui.la -L/usr/X11R6/lib -L/usr/local/lib /usr/local/lib/libglade-gnome.la /usr/local/lib/libglib.la -lm -lm /usr/local/lib/libaudiofile.la -lm -lm -laudiofile -L/usr/local/lib /usr/local/lib/libesd.la -lm -lz -L/usr/local/lib /usr/local/lib/libgnomesupport.la -lm -lz -lm -lglib -L/usr/local/lib /usr/local/lib/libgnome.la -lX11 -lXext /usr/local/lib/libiconv.la -L/usr/local/lib -L/usr/ports/devel/gettext/w-gettext-0.10.40/gettext-0.10.40/intl/.libs /usr/local/lib/libintl.la /usr/local/lib/libgmodule.la -lintl -lm -lX11 -lXext -L/usr/X11R6/lib -lglib -lgmodule -L/usr/local/lib /usr/local/lib/libgdk.la -lintl -lm -lX11 -lXext -L/usr/X11R6/lib -lglib -lgmodule -L/usr/local/lib /usr/local/lib/libgtk.la -lICE -lSM -lz -lpng /usr/local/lib/libungif.la /usr/local/lib/libjpeg.la -ltiff -lm -lz -lpng /usr/local/lib/libungif.la -lz /usr/local/lib/libjpeg.la -ltiff -L/usr/local/lib -L/usr/X11R6/lib /usr/local/lib/libgdk_imlib.la -lm -L/usr/local/lib /usr/local/lib/libart_lgpl.la -lm -lz -lm -lX11 -lXext -lintl -lglib -lgmodule -lgdk -lgtk -lICE -lSM -lm -lX11 -lXext -lintl -lglib -lgmodule -lgdk -lgtk -L/usr/X11R6/lib -lm -lz -lpng -lungif -lz -ljpeg -ltiff -ljpeg -lgdk_imlib -lglib -lm -laudiofile -lm -laudiofile -lesd -L/usr/local/lib /usr/local/lib/libgnomeui.la -L/usr/X11R6/lib -L/usr/local/lib"
	specialdeplibs="-lgnomeui -lart_lgpl -lgdk_imlib -ltiff -ljpeg -lungif -lpng -lz -lSM -lICE -lgtk -lgdk -lgmodule -lintl -lXext -lX11 -lgnome -lgnomesupport -lesd -laudiofile -lm -lglib"
	for deplib in $deplibs; do
		case $deplib in
		-L*)
			new_libs="$deplib $new_libs"
			;;
		*)
			case " $specialdeplibs " in
			*" $deplib "*)
				new_libs="$deplib $new_libs";;
			esac
			;;
		esac
	done
---
name: oksh-varfunction-mod1
description:
	$OpenBSD: varfunction.sh,v 1.1 2003/12/15 05:28:40 otto Exp $
	Calling
		FOO=bar f
	where f is a ksh style function, should not set FOO in the current
	env. If f is a Bourne style function, FOO should be set. Furthermore,
	the function should receive a correct value of FOO. However, differing
	from oksh, setting FOO in the function itself must change the value in
	setting FOO in the function itself should not change the value in
	global environment.
	Inspired by PR 2450.
stdin:
	function k {
		if [ x$FOO != xbar ]; then
			echo 1
			return 1
		fi
		x=$(env | grep FOO)
		if [ "x$x" != "xFOO=bar" ]; then
			echo 2
			return 1;
		fi
		FOO=foo
		return 0
	}
	b () {
		if [ x$FOO != xbar ]; then
			echo 3
			return 1
		fi
		x=$(env | grep FOO)
		if [ "x$x" != "xFOO=bar" ]; then
			echo 4
			return 1;
		fi
		FOO=foo
		return 0
	}
	FOO=bar k
	if [ $? != 0 ]; then
		exit 1
	fi
	if [ x$FOO != x ]; then
		exit 1
	fi
	FOO=bar b
	if [ $? != 0 ]; then
		exit 1
	fi
	if [ x$FOO != xfoo ]; then
		exit 1
	fi
	FOO=barbar
	FOO=bar k
	if [ $? != 0 ]; then
		exit 1
	fi
	if [ x$FOO != xbarbar ]; then
		exit 1
	fi
	FOO=bar b
	if [ $? != 0 ]; then
		exit 1
	fi
	if [ x$FOO != xfoo ]; then
		exit 1
	fi
---
name: fd-cloexec-1
description:
	Verify that file descriptors > 2 are private for Korn shells
file-setup: file 644 "test.sh"
	print -u3 Fowl
stdin:
	exec 3>&1
	"$__progname" test.sh
expected-exit: e != 0
expected-stderr:
	test.sh[1]: print: -u: 3: bad file descriptor
---
name: fd-cloexec-2
description:
	Verify that file descriptors > 2 are not private for POSIX shells
	See Debian Bug #154540, Closes: #499139
file-setup: file 644 "test.sh"
	print -u3 Fowl
stdin:
	test -n "$POSH_VERSION" || set -o sh
	exec 3>&1
	"$__progname" test.sh
expected-stdout:
	Fowl
---
name: comsub-1
description:
	COMSUB are currently parsed by hacking lex.c instead of
	recursively (see regression-6): matching parenthesēs bug
	Fails on: pdksh mksh bash2 bash3 zsh
	Passes on: bash4 ksh93
expected-fail: yes
stdin:
	echo $(case 1 in (1) echo yes;; (2) echo no;; esac)
	echo $(case 1 in 1) echo yes;; 2) echo no;; esac)
expected-stdout:
	yes
	yes
---
name: comsub-2
description:
	RedHat BZ#496791 – another case of missing recursion
	in parsing COMSUB expressions
	Fails on: pdksh mksh bash2 bash3¹ bash4¹ zsh
	Passes on: ksh93
	① bash[34] seem to choke on comment ending with backslash-newline
expected-fail: yes
stdin:
	# a comment with " ' \
	x=$(
	echo yes
	# a comment with " ' \
	)
	echo $x
expected-stdout:
	yes
---
name: test-stnze-1
description:
	Check that the short form [ $x ] works
stdin:
	i=0
	[ -n $x ]
	rv=$?; echo $((++i)) $rv
	[ $x ]
	rv=$?; echo $((++i)) $rv
	[ -n "$x" ]
	rv=$?; echo $((++i)) $rv
	[ "$x" ]
	rv=$?; echo $((++i)) $rv
	x=0
	[ -n $x ]
	rv=$?; echo $((++i)) $rv
	[ $x ]
	rv=$?; echo $((++i)) $rv
	[ -n "$x" ]
	rv=$?; echo $((++i)) $rv
	[ "$x" ]
	rv=$?; echo $((++i)) $rv
	x='1 -a 1 = 2'
	[ -n $x ]
	rv=$?; echo $((++i)) $rv
	[ $x ]
	rv=$?; echo $((++i)) $rv
	[ -n "$x" ]
	rv=$?; echo $((++i)) $rv
	[ "$x" ]
	rv=$?; echo $((++i)) $rv
expected-stdout:
	1 0
	2 1
	3 1
	4 1
	5 0
	6 0
	7 0
	8 0
	9 1
	10 1
	11 0
	12 0
---
name: test-stnze-2
description:
	Check that the short form [[ $x ]] works (ksh93 extension)
stdin:
	i=0
	[[ -n $x ]]
	rv=$?; echo $((++i)) $rv
	[[ $x ]]
	rv=$?; echo $((++i)) $rv
	[[ -n "$x" ]]
	rv=$?; echo $((++i)) $rv
	[[ "$x" ]]
	rv=$?; echo $((++i)) $rv
	x=0
	[[ -n $x ]]
	rv=$?; echo $((++i)) $rv
	[[ $x ]]
	rv=$?; echo $((++i)) $rv
	[[ -n "$x" ]]
	rv=$?; echo $((++i)) $rv
	[[ "$x" ]]
	rv=$?; echo $((++i)) $rv
	x='1 -a 1 = 2'
	[[ -n $x ]]
	rv=$?; echo $((++i)) $rv
	[[ $x ]]
	rv=$?; echo $((++i)) $rv
	[[ -n "$x" ]]
	rv=$?; echo $((++i)) $rv
	[[ "$x" ]]
	rv=$?; echo $((++i)) $rv
expected-stdout:
	1 1
	2 1
	3 1
	4 1
	5 0
	6 0
	7 0
	8 0
	9 0
	10 0
	11 0
	12 0
---
name: event-subst-1a
description:
	Check that '!' substitution in interactive mode works
category: !smksh
file-setup: file 755 "falsetto"
	#! /bin/sh
	echo molto bene
	exit 42
file-setup: file 755 "!false"
	#! /bin/sh
	echo si
arguments: !-i!
stdin:
	export PATH=.:$PATH
	falsetto
	echo yeap
	!false
expected-exit: 42
expected-stdout:
	molto bene
	yeap
	molto bene
expected-stderr-pattern:
	/.*/
---
name: event-subst-1b
description:
	Check that '!' substitution in interactive mode works
	even when a space separates it from the search command,
	which is not what GNU bash provides but required for the
	other regression tests below to check
category: !smksh
file-setup: file 755 "falsetto"
	#! /bin/sh
	echo molto bene
	exit 42
file-setup: file 755 "!"
	#! /bin/sh
	echo si
arguments: !-i!
stdin:
	export PATH=.:$PATH
	falsetto
	echo yeap
	! false
expected-exit: 42
expected-stdout:
	molto bene
	yeap
	molto bene
expected-stderr-pattern:
	/.*/
---
name: event-subst-2
description:
	Check that '!' substitution in interactive mode
	does not break things
category: !smksh
file-setup: file 755 "falsetto"
	#! /bin/sh
	echo molto bene
	exit 42
file-setup: file 755 "!"
	#! /bin/sh
	echo si
arguments: !-i!
env-setup: !ENV=./Env!
file-setup: file 644 "Env"
	PS1=X
stdin:
	export PATH=.:$PATH
	falsetto
	echo yeap
	!false
	echo meow
	! false
	echo = $?
	if
	! false; then echo foo; else echo bar; fi
expected-stdout:
	molto bene
	yeap
	molto bene
	meow
	molto bene
	= 42
	foo
expected-stderr-pattern:
	/.*/
---
name: event-subst-3
description:
	Check that '!' substitution in noninteractive mode is ignored
category: !smksh
file-setup: file 755 "falsetto"
	#! /bin/sh
	echo molto bene
	exit 42
file-setup: file 755 "!false"
	#! /bin/sh
	echo si
stdin:
	export PATH=.:$PATH
	falsetto
	echo yeap
	!false
	echo meow
	! false
	echo = $?
	if
	! false; then echo foo; else echo bar; fi
expected-stdout:
	molto bene
	yeap
	si
	meow
	= 0
	foo
---
name: nounset-1
description:
	Check that "set -u" matches (future) SUSv4 requirement
stdin:
	(set -u
	try() {
		local v
		eval v=\$$1
		if [[ -n $v ]]; then
			echo $1=nz
		else
			echo $1=zf
		fi
	}
	x=y
	(echo $x)
	echo =1
	(echo $y)
	echo =2
	(try x)
	echo =3
	(try y)
	echo =4
	(try 0)
	echo =5
	(try 2)
	echo =6
	(try)
	echo =7
	(echo at=$@)
	echo =8
	(echo asterisk=$*)
	echo =9
	(echo $?)
	echo =10
	(echo $!)
	echo =11
	(echo $-)
	echo =12
	#(echo $_)
	#echo =13
	(echo $#)
	echo =14
	(mypid=$$; try mypid)
	echo =15
	) 2>&1 | sed -e 's/^[^]]*]//' -e 's/^[^:]*: *//'
expected-stdout:
	y
	=1
	y: parameter not set
	=2
	x=nz
	=3
	y: parameter not set
	=4
	0=nz
	=5
	2: parameter not set
	=6
	1: parameter not set
	=7
	at=
	=8
	asterisk=
	=9
	0
	=10
	!: parameter not set
	=11
	ush
	=12
	0
	=14
	mypid=nz
	=15
---
name: nameref-1
description:
	Testsuite for nameref (bound variables)
stdin:
	bar=global
	typeset -n ir2=bar
	typeset -n ind=ir2
	echo !ind: ${!ind}
	echo ind: $ind
	echo !ir2: ${!ir2}
	echo ir2: $ir2
	typeset +n ind
	echo !ind: ${!ind}
	echo ind: $ind
	typeset -n ir2=ind
	echo !ir2: ${!ir2}
	echo ir2: $ir2
	set|grep ^ir2|sed 's/^/s1: /'
	typeset|grep ' ir2'|sed -e 's/^/s2: /' -e 's/nameref/typeset -n/'
	set -A blub -- e1 e2 e3
	typeset -n ind=blub
	typeset -n ir2=blub[2]
	echo !ind[1]: ${!ind[1]}
	echo !ir2: $!ir2
	echo ind[1]: ${ind[1]}
	echo ir2: $ir2
expected-stdout:
	!ind: bar
	ind: global
	!ir2: bar
	ir2: global
	!ind: ind
	ind: ir2
	!ir2: ind
	ir2: ir2
	s1: ir2=ind
	s2: typeset -n ir2
	!ind[1]: 1
	!ir2: ir2
	ind[1]: e2
	ir2: e3
---
name: nameref-2da
description:
	Testsuite for nameref (bound variables)
	Functions, argument given directly, after local
stdin:
	function foo {
		typeset bar=lokal baz=auch
		typeset -n v=bar
		echo entering
		echo !v: ${!v}
		echo !bar: ${!bar}
		echo !baz: ${!baz}
		echo bar: $bar
		echo v: $v
		v=123
		echo bar: $bar
		echo v: $v
		echo exiting
	}
	bar=global
	echo bar: $bar
	foo bar
	echo bar: $bar
expected-stdout:
	bar: global
	entering
	!v: bar
	!bar: bar
	!baz: baz
	bar: lokal
	v: lokal
	bar: 123
	v: 123
	exiting
	bar: global
---
name: nameref-3
description:
	Advanced testsuite for bound variables (ksh93 fails this)
stdin:
	typeset -n foo=bar[i]
	set -A bar -- b c a
	for i in 0 1 2 3; do
		print $i $foo .
	done
expected-stdout:
	0 b .
	1 c .
	2 a .
	3 .
---
name: better-parens-1a
description:
	Check support for ((…)) and $((…)) vs (…) and $(…)
stdin:
	if ( (echo fubar) | tr u x); then
		echo ja
	else
		echo nein
	fi
expected-stdout:
	fxbar
	ja
---
name: better-parens-1b
description:
	Check support for ((…)) and $((…)) vs (…) and $(…)
stdin:
	echo $( (echo fubar) | tr u x) $?
expected-stdout:
	fxbar 0
---
name: better-parens-2a
description:
	Check support for ((…)) and $((…)) vs (…) and $(…)
stdin:
	if ((echo fubar) | tr u x); then
		echo ja
	else
		echo nein
	fi
expected-stdout:
	fxbar
	ja
---
name: better-parens-2b
description:
	Check support for ((…)) and $((…)) vs (…) and $(…)
stdin:
	echo $((echo fubar) | tr u x) $?
expected-stdout:
	fxbar 0
---
name: better-parens-3a
description:
	Check support for ((…)) and $((…)) vs (…) and $(…)
stdin:
	if ( (echo fubar) | (tr u x)); then
		echo ja
	else
		echo nein
	fi
expected-stdout:
	fxbar
	ja
---
name: better-parens-3b
description:
	Check support for ((…)) and $((…)) vs (…) and $(…)
stdin:
	echo $( (echo fubar) | (tr u x)) $?
expected-stdout:
	fxbar 0
---
name: better-parens-4a
description:
	Check support for ((…)) and $((…)) vs (…) and $(…)
stdin:
	if ((echo fubar) | (tr u x)); then
		echo ja
	else
		echo nein
	fi
expected-stdout:
	fxbar
	ja
---
name: better-parens-4b
description:
	Check support for ((…)) and $((…)) vs (…) and $(…)
stdin:
	echo $((echo fubar) | (tr u x)) $?
expected-stdout:
	fxbar 0
---
name: echo-test-1
description:
	Test what the echo builtin does (mksh)
stdin:
	echo -n 'foo\x40bar'
	echo -e '\tbaz'
expected-stdout:
	foo@bar	baz
---
name: echo-test-2
description:
	Test what the echo builtin does (POSIX)
	Note: this follows Debian Policy 10.4 which mandates
	that -n shall be treated as an option, not XSI which
	mandates it shall be treated as string but escapes
	shall be expanded.
stdin:
	test -n "$POSH_VERSION" || set -o sh
	echo -n 'foo\x40bar'
	echo -e '\tbaz'
expected-stdout:
	foo\x40bar-e \tbaz
---
name: utilities-getopts-1
description:
	getopts sets OPTIND correctly for unparsed option
stdin:
	set -- -a -a -x
	while getopts :a optc; do
	    echo "OPTARG=$OPTARG, OPTIND=$OPTIND, optc=$optc."
	done
	echo done
expected-stdout:
	OPTARG=, OPTIND=2, optc=a.
	OPTARG=, OPTIND=3, optc=a.
	OPTARG=x, OPTIND=4, optc=?.
	done
---
name: utilities-getopts-2
description:
	Check OPTARG
stdin:
	set -- -a Mary -x
	while getopts a: optc; do
	    echo "OPTARG=$OPTARG, OPTIND=$OPTIND, optc=$optc."
	done
	echo done
expected-stdout:
	OPTARG=Mary, OPTIND=3, optc=a.
	OPTARG=, OPTIND=4, optc=?.
	done
expected-stderr-pattern: /.*-x.*option/
---
name: wcswidth-1
description:
	Check the new wcswidth feature
stdin:
	s=何
	set +U
	print octets: ${#s} .
	print 8-bit width: ${%s} .
	set -U
	print characters: ${#s} .
	print columns: ${%s} .
	s=�
	set +U
	print octets: ${#s} .
	print 8-bit width: ${%s} .
	set -U
	print characters: ${#s} .
	print columns: ${%s} .
expected-stdout:
	octets: 3 .
	8-bit width: -1 .
	characters: 1 .
	columns: 2 .
	octets: 3 .
	8-bit width: 3 .
	characters: 1 .
	columns: 1 .
---
name: wcswidth-2
description:
	Check some corner cases
stdin:
	print % $% .
	set -U
	x='a	b'
	print c ${%x} .
	set +U
	x='a	b'
	print d ${%x} .
expected-stdout:
	% $% .
	c -1 .
	d -1 .
---
name: wcswidth-3
description:
	Check some corner cases
stdin:
	print ${%} .
expected-stderr-pattern:
	/bad substitution/
expected-exit: 1
---
name: wcswidth-4a
description:
	Check some corner cases
stdin:
	print ${%*} .
expected-stderr-pattern:
	/bad substitution/
expected-exit: 1
---
name: wcswidth-4b
description:
	Check some corner cases
stdin:
	print ${%@} .
expected-stderr-pattern:
	/bad substitution/
expected-exit: 1
---
name: wcswidth-4c
description:
	Check some corner cases
stdin:
	:
	print ${%?} .
expected-stdout:
	1 .
---
name: realpath-1
description:
	Check proper return values for realpath
category: os:mirbsd
stdin:
	wd=$(realpath .)
	mkdir dir
	:>file
	:>dir/file
	ln -s dir lndir
	ln -s file lnfile
	ln -s nix lnnix
	ln -s . lnself
	i=0
	chk() {
		typeset x y
		x=$(realpath "$wd/$1" 2>&1); y=$?
		print $((++i)) "?$1" =${x##*$wd/} !$y
	}
	chk dir
	chk dir/
	chk dir/file
	chk dir/nix
	chk file
	chk file/
	chk file/file
	chk file/nix
	chk nix
	chk nix/
	chk nix/file
	chk nix/nix
	chk lndir
	chk lndir/
	chk lndir/file
	chk lndir/nix
	chk lnfile
	chk lnfile/
	chk lnfile/file
	chk lnfile/nix
	chk lnnix
	chk lnnix/
	chk lnnix/file
	chk lnnix/nix
	chk lnself/lnself/lnself/lnself/lnself/lnself/lnself/lnself/lnself/lnself/lnself/lnself/lnself/lnself/lnself/lnself/lnself/lnself/lnself/lnself/lnself/lnself/lnself/lnself/lnself/lnself/lnself/lnself/lnself/lnself/lnself/lnself/lnself/lnself
	rm lnself
expected-stdout:
	1 ?dir =dir !0
	2 ?dir/ =dir !0
	3 ?dir/file =dir/file !0
	4 ?dir/nix =dir/nix !0
	5 ?file =file !0
	6 ?file/ =file/: Not a directory !20
	7 ?file/file =file/file: Not a directory !20
	8 ?file/nix =file/nix: Not a directory !20
	9 ?nix =nix !0
	10 ?nix/ =nix !0
	11 ?nix/file =nix/file: No such file or directory !2
	12 ?nix/nix =nix/nix: No such file or directory !2
	13 ?lndir =dir !0
	14 ?lndir/ =dir !0
	15 ?lndir/file =dir/file !0
	16 ?lndir/nix =dir/nix !0
	17 ?lnfile =file !0
	18 ?lnfile/ =lnfile/: Not a directory !20
	19 ?lnfile/file =lnfile/file: Not a directory !20
	20 ?lnfile/nix =lnfile/nix: Not a directory !20
	21 ?lnnix =nix !0
	22 ?lnnix/ =nix !0
	23 ?lnnix/file =lnnix/file: No such file or directory !2
	24 ?lnnix/nix =lnnix/nix: No such file or directory !2
	25 ?lnself/lnself/lnself/lnself/lnself/lnself/lnself/lnself/lnself/lnself/lnself/lnself/lnself/lnself/lnself/lnself/lnself/lnself/lnself/lnself/lnself/lnself/lnself/lnself/lnself/lnself/lnself/lnself/lnself/lnself/lnself/lnself/lnself/lnself =lnself/lnself/lnself/lnself/lnself/lnself/lnself/lnself/lnself/lnself/lnself/lnself/lnself/lnself/lnself/lnself/lnself/lnself/lnself/lnself/lnself/lnself/lnself/lnself/lnself/lnself/lnself/lnself/lnself/lnself/lnself/lnself/lnself/lnself: Too many levels of symbolic links !62
---
