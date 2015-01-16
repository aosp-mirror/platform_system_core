/*
 * Copyright (C) 2014, The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <stdbool.h>
#include <sys/types.h>

/* We want chown to support user.group as well as user:group. */
#define SUPPORT_DOT

/* We don't localize /system/bin! */
#define WITHOUT_NLS

// NetBSD uses _DIAGASSERT to null-check arguments and the like.
#include <assert.h>
#define _DIAGASSERT(e) ((e) ? (void) 0 : __assert2(__FILE__, __LINE__, __func__, #e))

// TODO: update our <sys/cdefs.h> to support this properly.
#define __type_fit(t, a) (0 == 0)

// TODO: should this be in our <sys/cdefs.h>?
#define __arraycount(a) (sizeof(a) / sizeof(a[0]))

// This at least matches GNU dd(1) behavior.
#define SIGINFO SIGUSR1

#define S_ISWHT(x) false

__BEGIN_DECLS

/* From NetBSD <stdlib.h>. */
#define HN_DECIMAL              0x01
#define HN_NOSPACE              0x02
#define HN_B                    0x04
#define HN_DIVISOR_1000         0x08
#define HN_GETSCALE             0x10
#define HN_AUTOSCALE            0x20
int	humanize_number(char *, size_t, int64_t, const char *, int, int);
int	dehumanize_number(const char *, int64_t *);
char	*getbsize(int *, long *);
long long strsuftoll(const char *, const char *, long long, long long);
long long strsuftollx(const char *, const char *, long long, long long,
			char *, size_t);

/* From NetBSD <string.h>. */
void strmode(mode_t, char*);

/* From NetBSD <sys/param.h>. */
#define MAXBSIZE 65536

/* From NetBSD <sys/stat.h>. */
#define DEFFILEMODE (S_IRUSR | S_IWUSR)

/* From NetBSD <unistd.h>. */
void	swab(const void * __restrict, void * __restrict, ssize_t);

/* From NetBSD <util.h>. */
int		raise_default_signal(int);

__END_DECLS
