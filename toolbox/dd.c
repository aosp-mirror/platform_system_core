/*	$NetBSD: dd.c,v 1.37 2004/01/17 21:00:16 dbj Exp $	*/

/*-
 * Copyright (c) 1991, 1993, 1994
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Keith Muller of the University of California, San Diego and Lance
 * Visser of Convex Computer Corporation.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>
#ifndef lint
__COPYRIGHT("@(#) Copyright (c) 1991, 1993, 1994\n\
	The Regents of the University of California.  All rights reserved.\n");
#endif /* not lint */

#ifndef lint
#if 0
static char sccsid[] = "@(#)dd.c	8.5 (Berkeley) 4/2/94";
#else
__RCSID("$NetBSD: dd.c,v 1.37 2004/01/17 21:00:16 dbj Exp $");
#endif
#endif /* not lint */

#include <sys/param.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/time.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dd.h"

#define NO_CONV

//#include "extern.h"
void block(void);
void block_close(void);
void dd_out(int);
void def(void);
void def_close(void);
void jcl(char **);
void pos_in(void);
void pos_out(void);
void summary(void);
void summaryx(int);
void terminate(int);
void unblock(void);
void unblock_close(void);
ssize_t bwrite(int, const void *, size_t);

extern IO		in, out;
extern STAT		st;
extern void		(*cfunc)(void);
extern uint64_t		cpy_cnt;
extern uint64_t		cbsz;
extern u_int		ddflags;
extern u_int		files_cnt;
extern int		progress;
extern const u_char	*ctab;
extern const u_char	a2e_32V[], a2e_POSIX[];
extern const u_char	e2a_32V[], e2a_POSIX[];
extern const u_char	a2ibm_32V[], a2ibm_POSIX[];
extern u_char		casetab[];


#define MAX(a, b) ((a) > (b) ? (a) : (b))

static void dd_close(void);
static void dd_in(void);
static void getfdtype(IO *);
static int redup_clean_fd(int);
static void setup(void);


IO		in, out;		/* input/output state */
STAT		st;			/* statistics */
void		(*cfunc)(void);		/* conversion function */
uint64_t	cpy_cnt;		/* # of blocks to copy */
static off_t	pending = 0;		/* pending seek if sparse */
u_int		ddflags;		/* conversion options */
uint64_t	cbsz;			/* conversion block size */
u_int		files_cnt = 1;		/* # of files to copy */
int		progress = 0;		/* display sign of life */
const u_char	*ctab;			/* conversion table */
sigset_t	infoset;		/* a set blocking SIGINFO */

int
dd_main(int argc, char *argv[])
{
	int ch;

	while ((ch = getopt(argc, argv, "")) != -1) {
		switch (ch) {
		default:
			fprintf(stderr, "usage: dd [operand ...]\n");
			exit(1);
			/* NOTREACHED */
		}
	}
	argc -= (optind - 1);
	argv += (optind - 1);

	jcl(argv);
	setup();

//	(void)signal(SIGINFO, summaryx);
	(void)signal(SIGINT, terminate);
	(void)sigemptyset(&infoset);
//	(void)sigaddset(&infoset, SIGINFO);

	(void)atexit(summary);

	while (files_cnt--)
		dd_in();

	dd_close();
	exit(0);
	/* NOTREACHED */
}

static void
setup(void)
{

	if (in.name == NULL) {
		in.name = "stdin";
		in.fd = STDIN_FILENO;
	} else {
		in.fd = open(in.name, O_RDONLY, 0);
		if (in.fd < 0) {
			fprintf(stderr, "%s: cannot open for read: %s\n",
				in.name, strerror(errno));
			exit(1);
			/* NOTREACHED */
		}

		/* Ensure in.fd is outside the stdio descriptor range */
		in.fd = redup_clean_fd(in.fd);
	}

	getfdtype(&in);

	if (files_cnt > 1 && !(in.flags & ISTAPE)) {
		fprintf(stderr,
			"files is not supported for non-tape devices\n");
		exit(1);
		/* NOTREACHED */
	}

	if (out.name == NULL) {
		/* No way to check for read access here. */
		out.fd = STDOUT_FILENO;
		out.name = "stdout";
	} else {
#define	OFLAGS \
    (O_CREAT | (ddflags & (C_SEEK | C_NOTRUNC) ? 0 : O_TRUNC))
		out.fd = open(out.name, O_RDWR | OFLAGS /*, DEFFILEMODE */);
		/*
		 * May not have read access, so try again with write only.
		 * Without read we may have a problem if output also does
		 * not support seeks.
		 */
		if (out.fd < 0) {
			out.fd = open(out.name, O_WRONLY | OFLAGS /*, DEFFILEMODE */);
			out.flags |= NOREAD;
		}
		if (out.fd < 0) {
			fprintf(stderr, "%s: cannot open for write: %s\n",
				out.name, strerror(errno));
			exit(1);
			/* NOTREACHED */
		}

		/* Ensure out.fd is outside the stdio descriptor range */
		out.fd = redup_clean_fd(out.fd);
	}

	getfdtype(&out);

	/*
	 * Allocate space for the input and output buffers.  If not doing
	 * record oriented I/O, only need a single buffer.
	 */
	if (!(ddflags & (C_BLOCK|C_UNBLOCK))) {
		if ((in.db = malloc(out.dbsz + in.dbsz - 1)) == NULL) {
			exit(1);
			/* NOTREACHED */
		}
		out.db = in.db;
	} else if ((in.db =
	    malloc((u_int)(MAX(in.dbsz, cbsz) + cbsz))) == NULL ||
	    (out.db = malloc((u_int)(out.dbsz + cbsz))) == NULL) {
		exit(1);
		/* NOTREACHED */
	}
	in.dbp = in.db;
	out.dbp = out.db;

	/* Position the input/output streams. */
	if (in.offset)
		pos_in();
	if (out.offset)
		pos_out();

	/*
	 * Truncate the output file; ignore errors because it fails on some
	 * kinds of output files, tapes, for example.
	 */
	if ((ddflags & (C_OF | C_SEEK | C_NOTRUNC)) == (C_OF | C_SEEK))
		(void)ftruncate(out.fd, (off_t)out.offset * out.dbsz);

	/*
	 * If converting case at the same time as another conversion, build a
	 * table that does both at once.  If just converting case, use the
	 * built-in tables.
	 */
	if (ddflags & (C_LCASE|C_UCASE)) {
#ifdef	NO_CONV
		/* Should not get here, but just in case... */
		fprintf(stderr, "case conv and -DNO_CONV\n");
		exit(1);
		/* NOTREACHED */
#else	/* NO_CONV */
		u_int cnt;

		if (ddflags & C_ASCII || ddflags & C_EBCDIC) {
			if (ddflags & C_LCASE) {
				for (cnt = 0; cnt < 0377; ++cnt)
					casetab[cnt] = tolower(ctab[cnt]);
			} else {
				for (cnt = 0; cnt < 0377; ++cnt)
					casetab[cnt] = toupper(ctab[cnt]);
			}
		} else {
			if (ddflags & C_LCASE) {
				for (cnt = 0; cnt < 0377; ++cnt)
					casetab[cnt] = tolower(cnt);
			} else {
				for (cnt = 0; cnt < 0377; ++cnt)
					casetab[cnt] = toupper(cnt);
			}
		}

		ctab = casetab;
#endif	/* NO_CONV */
	}

	(void)gettimeofday(&st.start, NULL);	/* Statistics timestamp. */
}

static void
getfdtype(IO *io)
{
//	struct mtget mt;
	struct stat sb;

	if (fstat(io->fd, &sb)) {
		fprintf(stderr, "%s: cannot fstat: %s\n",
			io->name, strerror(errno));
		exit(1);
		/* NOTREACHED */
	}
	if (S_ISCHR(sb.st_mode))
		io->flags |= /*ioctl(io->fd, MTIOCGET, &mt) ? ISCHR : ISTAPE; */ ISCHR;
	else if (lseek(io->fd, (off_t)0, SEEK_CUR) == -1 && errno == ESPIPE)
		io->flags |= ISPIPE;		/* XXX fixed in 4.4BSD */
}

/*
 * Move the parameter file descriptor to a descriptor that is outside the
 * stdio descriptor range, if necessary.  This is required to avoid
 * accidentally outputting completion or error messages into the
 * output file that were intended for the tty.
 */
static int
redup_clean_fd(int fd)
{
	int newfd;

	if (fd != STDIN_FILENO && fd != STDOUT_FILENO &&
	    fd != STDERR_FILENO)
		/* File descriptor is ok, return immediately. */
		return fd;

	/*
	 * 3 is the first descriptor greater than STD*_FILENO.  Any
	 * free descriptor valued 3 or above is acceptable...
	 */
	newfd = fcntl(fd, F_DUPFD, 3);
	if (newfd < 0) {
		fprintf(stderr, "dupfd IO: %s\n", strerror(errno));
		exit(1);
		/* NOTREACHED */
	}

	close(fd);

	return newfd;
}

static void
dd_in(void)
{
	int flags;
	int64_t n;

	for (flags = ddflags;;) {
		if (cpy_cnt && (st.in_full + st.in_part) >= cpy_cnt)
			return;

		/*
		 * Clear the buffer first if doing "sync" on input.
		 * If doing block operations use spaces.  This will
		 * affect not only the C_NOERROR case, but also the
		 * last partial input block which should be padded
		 * with zero and not garbage.
		 */
		if (flags & C_SYNC) {
			if (flags & (C_BLOCK|C_UNBLOCK))
				(void)memset(in.dbp, ' ', in.dbsz);
			else
				(void)memset(in.dbp, 0, in.dbsz);
		}

		n = read(in.fd, in.dbp, in.dbsz);
		if (n == 0) {
			in.dbrcnt = 0;
			return;
		}

		/* Read error. */
		if (n < 0) {

			/*
			 * If noerror not specified, die.  POSIX requires that
			 * the warning message be followed by an I/O display.
			 */
			fprintf(stderr, "%s: read error: %s\n",
				in.name, strerror(errno));
			if (!(flags & C_NOERROR)) {
				exit(1);
				/* NOTREACHED */
			}
			summary();

			/*
			 * If it's not a tape drive or a pipe, seek past the
			 * error.  If your OS doesn't do the right thing for
			 * raw disks this section should be modified to re-read
			 * in sector size chunks.
			 */
			if (!(in.flags & (ISPIPE|ISTAPE)) &&
			    lseek(in.fd, (off_t)in.dbsz, SEEK_CUR))
				fprintf(stderr, "%s: seek error: %s\n",
					in.name, strerror(errno));

			/* If sync not specified, omit block and continue. */
			if (!(ddflags & C_SYNC))
				continue;

			/* Read errors count as full blocks. */
			in.dbcnt += in.dbrcnt = in.dbsz;
			++st.in_full;

		/* Handle full input blocks. */
		} else if (n == in.dbsz) {
			in.dbcnt += in.dbrcnt = n;
			++st.in_full;

		/* Handle partial input blocks. */
		} else {
			/* If sync, use the entire block. */
			if (ddflags & C_SYNC)
				in.dbcnt += in.dbrcnt = in.dbsz;
			else
				in.dbcnt += in.dbrcnt = n;
			++st.in_part;
		}

		/*
		 * POSIX states that if bs is set and no other conversions
		 * than noerror, notrunc or sync are specified, the block
		 * is output without buffering as it is read.
		 */
		if (ddflags & C_BS) {
			out.dbcnt = in.dbcnt;
			dd_out(1);
			in.dbcnt = 0;
			continue;
		}

/*		if (ddflags & C_SWAB) {
			if ((n = in.dbrcnt) & 1) {
				++st.swab;
				--n;
			}
			swab(in.dbp, in.dbp, n);
		}
*/
		in.dbp += in.dbrcnt;
		(*cfunc)();
	}
}

/*
 * Cleanup any remaining I/O and flush output.  If necesssary, output file
 * is truncated.
 */
static void
dd_close(void)
{

	if (cfunc == def)
		def_close();
	else if (cfunc == block)
		block_close();
	else if (cfunc == unblock)
		unblock_close();
	if (ddflags & C_OSYNC && out.dbcnt < out.dbsz) {
		(void)memset(out.dbp, 0, out.dbsz - out.dbcnt);
		out.dbcnt = out.dbsz;
	}
	/* If there are pending sparse blocks, make sure
	 * to write out the final block un-sparse
	 */
	if ((out.dbcnt == 0) && pending) {
		memset(out.db, 0, out.dbsz);
		out.dbcnt = out.dbsz;
		out.dbp = out.db + out.dbcnt;
		pending -= out.dbsz;
	}
	if (out.dbcnt)
		dd_out(1);

	/*
	 * Reporting nfs write error may be defered until next
	 * write(2) or close(2) system call.  So, we need to do an
	 * extra check.  If an output is stdout, the file structure
	 * may be shared among with other processes and close(2) just
	 * decreases the reference count.
	 */
	if (out.fd == STDOUT_FILENO && fsync(out.fd) == -1 && errno != EINVAL) {
		fprintf(stderr, "fsync stdout: %s\n", strerror(errno));
		exit(1);
		/* NOTREACHED */
	}
	if (close(out.fd) == -1) {
		fprintf(stderr, "close: %s\n", strerror(errno));
		exit(1);
		/* NOTREACHED */
	}
}

void
dd_out(int force)
{
	static int warned;
	int64_t cnt, n, nw;
	u_char *outp;

	/*
	 * Write one or more blocks out.  The common case is writing a full
	 * output block in a single write; increment the full block stats.
	 * Otherwise, we're into partial block writes.  If a partial write,
	 * and it's a character device, just warn.  If a tape device, quit.
	 *
	 * The partial writes represent two cases.  1: Where the input block
	 * was less than expected so the output block was less than expected.
	 * 2: Where the input block was the right size but we were forced to
	 * write the block in multiple chunks.  The original versions of dd(1)
	 * never wrote a block in more than a single write, so the latter case
	 * never happened.
	 *
	 * One special case is if we're forced to do the write -- in that case
	 * we play games with the buffer size, and it's usually a partial write.
	 */
	outp = out.db;
	for (n = force ? out.dbcnt : out.dbsz;; n = out.dbsz) {
		for (cnt = n;; cnt -= nw) {

			if (!force && ddflags & C_SPARSE) {
				int sparse, i;
				sparse = 1;	/* Is buffer sparse? */
				for (i = 0; i < cnt; i++)
					if (outp[i] != 0) {
						sparse = 0;
						break;
					}
				if (sparse) {
					pending += cnt;
					outp += cnt;
					nw = 0;
					break;
				}
			}
			if (pending != 0) {
				if (lseek(out.fd, pending, SEEK_CUR) ==
				    -1) {
					fprintf(stderr,
						"%s: seek error creating "
						"sparse file: %s\n",
						out.name, strerror(errno));
					exit(1);
				}
			}
			nw = bwrite(out.fd, outp, cnt);
			if (nw <= 0) {
				if (nw == 0) {
					fprintf(stderr, "%s: end of device\n",
						out.name);
					exit(1);
					/* NOTREACHED */
				}
				if (errno != EINTR) {
					fprintf(stderr, "%s: write error: %s\n",
						out.name, strerror(errno));
					/* NOTREACHED */
					exit(1);
				}
				nw = 0;
			}
			if (pending) {
				st.bytes += pending;
				st.sparse += pending/out.dbsz;
				st.out_full += pending/out.dbsz;
				pending = 0;
			}
			outp += nw;
			st.bytes += nw;
			if (nw == n) {
				if (n != out.dbsz)
					++st.out_part;
				else
					++st.out_full;
				break;
			}
			++st.out_part;
			if (nw == cnt)
				break;
			if (out.flags & ISCHR && !warned) {
				warned = 1;
				fprintf(stderr, "%s: short write on character "
					"device\n", out.name);
			}
			if (out.flags & ISTAPE) {
				fprintf(stderr,
					"%s: short write on tape device",
					out.name);
				exit(1);
				/* NOTREACHED */
			}
		}
		if ((out.dbcnt -= n) < out.dbsz)
			break;
	}

	/* Reassemble the output block. */
	if (out.dbcnt)
		(void)memmove(out.db, out.dbp - out.dbcnt, out.dbcnt);
	out.dbp = out.db + out.dbcnt;

	if (progress)
		(void)write(STDERR_FILENO, ".", 1);
}

/*
 * A protected against SIGINFO write
 */
ssize_t
bwrite(int fd, const void *buf, size_t len)
{
	sigset_t oset;
	ssize_t rv;
	int oerrno;

	(void)sigprocmask(SIG_BLOCK, &infoset, &oset);
	rv = write(fd, buf, len);
	oerrno = errno;
	(void)sigprocmask(SIG_SETMASK, &oset, NULL);
	errno = oerrno;
	return (rv);
}

/*
 * Position input/output data streams before starting the copy.  Device type
 * dependent.  Seekable devices use lseek, and the rest position by reading.
 * Seeking past the end of file can cause null blocks to be written to the
 * output.
 */
void
pos_in(void)
{
	int bcnt, cnt, nr, warned;

	/* If not a pipe or tape device, try to seek on it. */
	if (!(in.flags & (ISPIPE|ISTAPE))) {
		if (lseek(in.fd,
		    (off_t)in.offset * (off_t)in.dbsz, SEEK_CUR) == -1) {
			fprintf(stderr, "%s: seek error: %s",
				in.name, strerror(errno));
			exit(1);
			/* NOTREACHED */
		}
		return;
		/* NOTREACHED */
	}

	/*
	 * Read the data.  If a pipe, read until satisfy the number of bytes
	 * being skipped.  No differentiation for reading complete and partial
	 * blocks for other devices.
	 */
	for (bcnt = in.dbsz, cnt = in.offset, warned = 0; cnt;) {
		if ((nr = read(in.fd, in.db, bcnt)) > 0) {
			if (in.flags & ISPIPE) {
				if (!(bcnt -= nr)) {
					bcnt = in.dbsz;
					--cnt;
				}
			} else
				--cnt;
			continue;
		}

		if (nr == 0) {
			if (files_cnt > 1) {
				--files_cnt;
				continue;
			}
			fprintf(stderr, "skip reached end of input\n");
			exit(1);
			/* NOTREACHED */
		}

		/*
		 * Input error -- either EOF with no more files, or I/O error.
		 * If noerror not set die.  POSIX requires that the warning
		 * message be followed by an I/O display.
		 */
		if (ddflags & C_NOERROR) {
			if (!warned) {

				fprintf(stderr, "%s: error occurred\n",
					in.name);
				warned = 1;
				summary();
			}
			continue;
		}
		fprintf(stderr, "%s: read error: %s", in.name, strerror(errno));
		exit(1);
		/* NOTREACHED */
	}
}

void
pos_out(void)
{
//	struct mtop t_op;
	int cnt, n;

	/*
	 * If not a tape, try seeking on the file.  Seeking on a pipe is
	 * going to fail, but don't protect the user -- they shouldn't
	 * have specified the seek operand.
	 */
	if (!(out.flags & ISTAPE)) {
		if (lseek(out.fd,
		    (off_t)out.offset * (off_t)out.dbsz, SEEK_SET) == -1) {
			fprintf(stderr, "%s: seek error: %s\n",
				out.name, strerror(errno));
			exit(1);
			/* NOTREACHED */
		}
		return;
	}

	/* If no read access, try using mtio. */
	if (out.flags & NOREAD) {
/*		t_op.mt_op = MTFSR;
		t_op.mt_count = out.offset;

		if (ioctl(out.fd, MTIOCTOP, &t_op) < 0)*/
			fprintf(stderr, "%s: cannot read", out.name);
			exit(1);
			/* NOTREACHED */
		return;
	}

	/* Read it. */
	for (cnt = 0; cnt < out.offset; ++cnt) {
		if ((n = read(out.fd, out.db, out.dbsz)) > 0)
			continue;

		if (n < 0) {
			fprintf(stderr, "%s: cannot position by reading: %s\n",
				out.name, strerror(errno));
			exit(1);
			/* NOTREACHED */
		}

		/*
		 * If reach EOF, fill with NUL characters; first, back up over
		 * the EOF mark.  Note, cnt has not yet been incremented, so
		 * the EOF read does not count as a seek'd block.
		 */
/*		t_op.mt_op = MTBSR;
		t_op.mt_count = 1;
		if (ioctl(out.fd, MTIOCTOP, &t_op) == -1) */ {
			fprintf(stderr, "%s: cannot position\n", out.name);
			exit(1);
			/* NOTREACHED */
		}

		while (cnt++ < out.offset)
			if ((n = bwrite(out.fd, out.db, out.dbsz)) != out.dbsz) {
				fprintf(stderr, "%s: cannot position "
					"by writing: %s\n",
					out.name, strerror(errno));
				exit(1);
				/* NOTREACHED */
			}
		break;
	}
}

/*
 * def --
 * Copy input to output.  Input is buffered until reaches obs, and then
 * output until less than obs remains.  Only a single buffer is used.
 * Worst case buffer calculation is (ibs + obs - 1).
 */
void
def(void)
{
	uint64_t cnt;
	u_char *inp;
	const u_char *t;

	if ((t = ctab) != NULL)
		for (inp = in.dbp - (cnt = in.dbrcnt); cnt--; ++inp)
			*inp = t[*inp];

	/* Make the output buffer look right. */
	out.dbp = in.dbp;
	out.dbcnt = in.dbcnt;

	if (in.dbcnt >= out.dbsz) {
		/* If the output buffer is full, write it. */
		dd_out(0);

		/*
		 * Ddout copies the leftover output to the beginning of
		 * the buffer and resets the output buffer.  Reset the
		 * input buffer to match it.
	 	 */
		in.dbp = out.dbp;
		in.dbcnt = out.dbcnt;
	}
}

void
def_close(void)
{

	/* Just update the count, everything is already in the buffer. */
	if (in.dbcnt)
		out.dbcnt = in.dbcnt;
}

#ifdef	NO_CONV
/* Build a smaller version (i.e. for a miniroot) */
/* These can not be called, but just in case...  */
static const char no_block[] = "unblock and -DNO_CONV?\n";
void block(void)		{ fprintf(stderr, "%s", no_block + 2); exit(1); }
void block_close(void)		{ fprintf(stderr, "%s", no_block + 2); exit(1); }
void unblock(void)		{ fprintf(stderr, "%s", no_block); exit(1); }
void unblock_close(void)	{ fprintf(stderr, "%s", no_block); exit(1); }
#else	/* NO_CONV */

/*
 * Copy variable length newline terminated records with a max size cbsz
 * bytes to output.  Records less than cbs are padded with spaces.
 *
 * max in buffer:  MAX(ibs, cbsz)
 * max out buffer: obs + cbsz
 */
void
block(void)
{
	static int intrunc;
	int ch = 0;	/* pacify gcc */
	uint64_t cnt, maxlen;
	u_char *inp, *outp;
	const u_char *t;

	/*
	 * Record truncation can cross block boundaries.  If currently in a
	 * truncation state, keep tossing characters until reach a newline.
	 * Start at the beginning of the buffer, as the input buffer is always
	 * left empty.
	 */
	if (intrunc) {
		for (inp = in.db, cnt = in.dbrcnt;
		    cnt && *inp++ != '\n'; --cnt);
		if (!cnt) {
			in.dbcnt = 0;
			in.dbp = in.db;
			return;
		}
		intrunc = 0;
		/* Adjust the input buffer numbers. */
		in.dbcnt = cnt - 1;
		in.dbp = inp + cnt - 1;
	}

	/*
	 * Copy records (max cbsz size chunks) into the output buffer.  The
	 * translation is done as we copy into the output buffer.
	 */
	for (inp = in.dbp - in.dbcnt, outp = out.dbp; in.dbcnt;) {
		maxlen = MIN(cbsz, in.dbcnt);
		if ((t = ctab) != NULL)
			for (cnt = 0;
			    cnt < maxlen && (ch = *inp++) != '\n'; ++cnt)
				*outp++ = t[ch];
		else
			for (cnt = 0;
			    cnt < maxlen && (ch = *inp++) != '\n'; ++cnt)
				*outp++ = ch;
		/*
		 * Check for short record without a newline.  Reassemble the
		 * input block.
		 */
		if (ch != '\n' && in.dbcnt < cbsz) {
			(void)memmove(in.db, in.dbp - in.dbcnt, in.dbcnt);
			break;
		}

		/* Adjust the input buffer numbers. */
		in.dbcnt -= cnt;
		if (ch == '\n')
			--in.dbcnt;

		/* Pad short records with spaces. */
		if (cnt < cbsz)
			(void)memset(outp, ctab ? ctab[' '] : ' ', cbsz - cnt);
		else {
			/*
			 * If the next character wouldn't have ended the
			 * block, it's a truncation.
			 */
			if (!in.dbcnt || *inp != '\n')
				++st.trunc;

			/* Toss characters to a newline. */
			for (; in.dbcnt && *inp++ != '\n'; --in.dbcnt);
			if (!in.dbcnt)
				intrunc = 1;
			else
				--in.dbcnt;
		}

		/* Adjust output buffer numbers. */
		out.dbp += cbsz;
		if ((out.dbcnt += cbsz) >= out.dbsz)
			dd_out(0);
		outp = out.dbp;
	}
	in.dbp = in.db + in.dbcnt;
}

void
block_close(void)
{

	/*
	 * Copy any remaining data into the output buffer and pad to a record.
	 * Don't worry about truncation or translation, the input buffer is
	 * always empty when truncating, and no characters have been added for
	 * translation.  The bottom line is that anything left in the input
	 * buffer is a truncated record.  Anything left in the output buffer
	 * just wasn't big enough.
	 */
	if (in.dbcnt) {
		++st.trunc;
		(void)memmove(out.dbp, in.dbp - in.dbcnt, in.dbcnt);
		(void)memset(out.dbp + in.dbcnt,
		    ctab ? ctab[' '] : ' ', cbsz - in.dbcnt);
		out.dbcnt += cbsz;
	}
}

/*
 * Convert fixed length (cbsz) records to variable length.  Deletes any
 * trailing blanks and appends a newline.
 *
 * max in buffer:  MAX(ibs, cbsz) + cbsz
 * max out buffer: obs + cbsz
 */
void
unblock(void)
{
	uint64_t cnt;
	u_char *inp;
	const u_char *t;

	/* Translation and case conversion. */
	if ((t = ctab) != NULL)
		for (cnt = in.dbrcnt, inp = in.dbp - 1; cnt--; inp--)
			*inp = t[*inp];
	/*
	 * Copy records (max cbsz size chunks) into the output buffer.  The
	 * translation has to already be done or we might not recognize the
	 * spaces.
	 */
	for (inp = in.db; in.dbcnt >= cbsz; inp += cbsz, in.dbcnt -= cbsz) {
		for (t = inp + cbsz - 1; t >= inp && *t == ' '; --t);
		if (t >= inp) {
			cnt = t - inp + 1;
			(void)memmove(out.dbp, inp, cnt);
			out.dbp += cnt;
			out.dbcnt += cnt;
		}
		++out.dbcnt;
		*out.dbp++ = '\n';
		if (out.dbcnt >= out.dbsz)
			dd_out(0);
	}
	if (in.dbcnt)
		(void)memmove(in.db, in.dbp - in.dbcnt, in.dbcnt);
	in.dbp = in.db + in.dbcnt;
}

void
unblock_close(void)
{
	uint64_t cnt;
	u_char *t;

	if (in.dbcnt) {
		warnx("%s: short input record", in.name);
		for (t = in.db + in.dbcnt - 1; t >= in.db && *t == ' '; --t);
		if (t >= in.db) {
			cnt = t - in.db + 1;
			(void)memmove(out.dbp, in.db, cnt);
			out.dbp += cnt;
			out.dbcnt += cnt;
		}
		++out.dbcnt;
		*out.dbp++ = '\n';
	}
}

#endif	/* NO_CONV */

#define	tv2mS(tv) ((tv).tv_sec * 1000LL + ((tv).tv_usec + 500) / 1000)

void
summary(void)
{
	char buf[100];
	int64_t mS;
	struct timeval tv;

	if (progress)
		(void)write(STDERR_FILENO, "\n", 1);

	(void)gettimeofday(&tv, NULL);
	mS = tv2mS(tv) - tv2mS(st.start);
	if (mS == 0)
		mS = 1;
	/* Use snprintf(3) so that we don't reenter stdio(3). */
	(void)snprintf(buf, sizeof(buf),
	    "%llu+%llu records in\n%llu+%llu records out\n",
	    (unsigned long long)st.in_full,  (unsigned long long)st.in_part,
	    (unsigned long long)st.out_full, (unsigned long long)st.out_part);
	(void)write(STDERR_FILENO, buf, strlen(buf));
	if (st.swab) {
		(void)snprintf(buf, sizeof(buf), "%llu odd length swab %s\n",
		    (unsigned long long)st.swab,
		    (st.swab == 1) ? "block" : "blocks");
		(void)write(STDERR_FILENO, buf, strlen(buf));
	}
	if (st.trunc) {
		(void)snprintf(buf, sizeof(buf), "%llu truncated %s\n",
		    (unsigned long long)st.trunc,
		    (st.trunc == 1) ? "block" : "blocks");
		(void)write(STDERR_FILENO, buf, strlen(buf));
	}
	if (st.sparse) {
		(void)snprintf(buf, sizeof(buf), "%llu sparse output %s\n",
		    (unsigned long long)st.sparse,
		    (st.sparse == 1) ? "block" : "blocks");
		(void)write(STDERR_FILENO, buf, strlen(buf));
	}
	(void)snprintf(buf, sizeof(buf),
	    "%llu bytes transferred in %lu.%03d secs (%llu bytes/sec)\n",
	    (unsigned long long) st.bytes,
	    (long) (mS / 1000),
	    (int) (mS % 1000),
	    (unsigned long long) (st.bytes * 1000LL / mS));
	(void)write(STDERR_FILENO, buf, strlen(buf));
}

void
terminate(int notused)
{

	exit(0);
	/* NOTREACHED */
}

static int	c_arg(const void *, const void *);
#ifndef	NO_CONV
static int	c_conv(const void *, const void *);
#endif
static void	f_bs(char *);
static void	f_cbs(char *);
static void	f_conv(char *);
static void	f_count(char *);
static void	f_files(char *);
static void	f_ibs(char *);
static void	f_if(char *);
static void	f_obs(char *);
static void	f_of(char *);
static void	f_seek(char *);
static void	f_skip(char *);
static void	f_progress(char *);

static const struct arg {
	const char *name;
	void (*f)(char *);
	u_int set, noset;
} args[] = {
     /* the array needs to be sorted by the first column so
	bsearch() can be used to find commands quickly */
	{ "bs",		f_bs,		C_BS,	 C_BS|C_IBS|C_OBS|C_OSYNC },
	{ "cbs",	f_cbs,		C_CBS,	 C_CBS },
	{ "conv",	f_conv,		0,	 0 },
	{ "count",	f_count,	C_COUNT, C_COUNT },
	{ "files",	f_files,	C_FILES, C_FILES },
	{ "ibs",	f_ibs,		C_IBS,	 C_BS|C_IBS },
	{ "if",		f_if,		C_IF,	 C_IF },
	{ "obs",	f_obs,		C_OBS,	 C_BS|C_OBS },
	{ "of",		f_of,		C_OF,	 C_OF },
	{ "progress",	f_progress,	0,	 0 },
	{ "seek",	f_seek,		C_SEEK,	 C_SEEK },
	{ "skip",	f_skip,		C_SKIP,	 C_SKIP },
};

/*
 * args -- parse JCL syntax of dd.
 */
void
jcl(char **argv)
{
	struct arg *ap, tmp;
	char *oper, *arg;

	in.dbsz = out.dbsz = 512;

	while ((oper = *++argv) != NULL) {
		if ((arg = strchr(oper, '=')) == NULL) {
			fprintf(stderr, "unknown operand %s\n", oper);
			exit(1);
			/* NOTREACHED */
		}
		*arg++ = '\0';
		if (!*arg) {
			fprintf(stderr, "no value specified for %s\n", oper);
			exit(1);
			/* NOTREACHED */
		}
		tmp.name = oper;
		if (!(ap = (struct arg *)bsearch(&tmp, args,
		    sizeof(args)/sizeof(struct arg), sizeof(struct arg),
		    c_arg))) {
			fprintf(stderr, "unknown operand %s\n", tmp.name);
			exit(1);
			/* NOTREACHED */
		}
		if (ddflags & ap->noset) {
			fprintf(stderr,
			    "%s: illegal argument combination or already set\n",
			    tmp.name);
			exit(1);
			/* NOTREACHED */
		}
		ddflags |= ap->set;
		ap->f(arg);
	}

	/* Final sanity checks. */

	if (ddflags & C_BS) {
		/*
		 * Bs is turned off by any conversion -- we assume the user
		 * just wanted to set both the input and output block sizes
		 * and didn't want the bs semantics, so we don't warn.
		 */
		if (ddflags & (C_BLOCK | C_LCASE | C_SWAB | C_UCASE |
		    C_UNBLOCK | C_OSYNC | C_ASCII | C_EBCDIC | C_SPARSE)) {
			ddflags &= ~C_BS;
			ddflags |= C_IBS|C_OBS;
		}

		/* Bs supersedes ibs and obs. */
		if (ddflags & C_BS && ddflags & (C_IBS|C_OBS))
			fprintf(stderr, "bs supersedes ibs and obs\n");
	}

	/*
	 * Ascii/ebcdic and cbs implies block/unblock.
	 * Block/unblock requires cbs and vice-versa.
	 */
	if (ddflags & (C_BLOCK|C_UNBLOCK)) {
		if (!(ddflags & C_CBS)) {
			fprintf(stderr, "record operations require cbs\n");
			exit(1);
			/* NOTREACHED */
		}
		cfunc = ddflags & C_BLOCK ? block : unblock;
	} else if (ddflags & C_CBS) {
		if (ddflags & (C_ASCII|C_EBCDIC)) {
			if (ddflags & C_ASCII) {
				ddflags |= C_UNBLOCK;
				cfunc = unblock;
			} else {
				ddflags |= C_BLOCK;
				cfunc = block;
			}
		} else {
			fprintf(stderr,
			    "cbs meaningless if not doing record operations\n");
			exit(1);
			/* NOTREACHED */
		}
	} else
		cfunc = def;

	/* Read, write and seek calls take off_t as arguments.
	 *
	 * The following check is not done because an off_t is a quad
	 *  for current NetBSD implementations.
	 *
	 * if (in.offset > INT_MAX/in.dbsz || out.offset > INT_MAX/out.dbsz)
	 *	errx(1, "seek offsets cannot be larger than %d", INT_MAX);
	 */
}

static int
c_arg(const void *a, const void *b)
{

	return (strcmp(((const struct arg *)a)->name,
	    ((const struct arg *)b)->name));
}

static long long strsuftoll(const char* name, const char* arg, int def, unsigned int max)
{
	long long result;
	
	if (sscanf(arg, "%lld", &result) == 0)
		result = def;
	return result;
}

static void
f_bs(char *arg)
{

	in.dbsz = out.dbsz = strsuftoll("block size", arg, 1, UINT_MAX);
}

static void
f_cbs(char *arg)
{

	cbsz = strsuftoll("conversion record size", arg, 1, UINT_MAX);
}

static void
f_count(char *arg)
{

	cpy_cnt = strsuftoll("block count", arg, 0, LLONG_MAX);
	if (!cpy_cnt)
		terminate(0);
}

static void
f_files(char *arg)
{

	files_cnt = (u_int)strsuftoll("file count", arg, 0, UINT_MAX);
	if (!files_cnt)
		terminate(0);
}

static void
f_ibs(char *arg)
{

	if (!(ddflags & C_BS))
		in.dbsz = strsuftoll("input block size", arg, 1, UINT_MAX);
}

static void
f_if(char *arg)
{

	in.name = arg;
}

static void
f_obs(char *arg)
{

	if (!(ddflags & C_BS))
		out.dbsz = strsuftoll("output block size", arg, 1, UINT_MAX);
}

static void
f_of(char *arg)
{

	out.name = arg;
}

static void
f_seek(char *arg)
{

	out.offset = strsuftoll("seek blocks", arg, 0, LLONG_MAX);
}

static void
f_skip(char *arg)
{

	in.offset = strsuftoll("skip blocks", arg, 0, LLONG_MAX);
}

static void
f_progress(char *arg)
{

	if (*arg != '0')
		progress = 1;
}

#ifdef	NO_CONV
/* Build a small version (i.e. for a ramdisk root) */
static void
f_conv(char *arg)
{

	fprintf(stderr, "conv option disabled\n");
	exit(1);
	/* NOTREACHED */
}
#else	/* NO_CONV */

static const struct conv {
	const char *name;
	u_int set, noset;
	const u_char *ctab;
} clist[] = {
	{ "ascii",	C_ASCII,	C_EBCDIC,	e2a_POSIX },
	{ "block",	C_BLOCK,	C_UNBLOCK,	NULL },
	{ "ebcdic",	C_EBCDIC,	C_ASCII,	a2e_POSIX },
	{ "ibm",	C_EBCDIC,	C_ASCII,	a2ibm_POSIX },
	{ "lcase",	C_LCASE,	C_UCASE,	NULL },
	{ "noerror",	C_NOERROR,	0,		NULL },
	{ "notrunc",	C_NOTRUNC,	0,		NULL },
	{ "oldascii",	C_ASCII,	C_EBCDIC,	e2a_32V },
	{ "oldebcdic",	C_EBCDIC,	C_ASCII,	a2e_32V },
	{ "oldibm",	C_EBCDIC,	C_ASCII,	a2ibm_32V },
	{ "osync",	C_OSYNC,	C_BS,		NULL },
	{ "sparse",	C_SPARSE,	0,		NULL },
	{ "swab",	C_SWAB,		0,		NULL },
	{ "sync",	C_SYNC,		0,		NULL },
	{ "ucase",	C_UCASE,	C_LCASE,	NULL },
	{ "unblock",	C_UNBLOCK,	C_BLOCK,	NULL },
	/* If you add items to this table, be sure to add the
	 * conversions to the C_BS check in the jcl routine above.
	 */
};

static void
f_conv(char *arg)
{
	struct conv *cp, tmp;

	while (arg != NULL) {
		tmp.name = strsep(&arg, ",");
		if (!(cp = (struct conv *)bsearch(&tmp, clist,
		    sizeof(clist)/sizeof(struct conv), sizeof(struct conv),
		    c_conv))) {
			errx(EXIT_FAILURE, "unknown conversion %s", tmp.name);
			/* NOTREACHED */
		}
		if (ddflags & cp->noset) {
			errx(EXIT_FAILURE, "%s: illegal conversion combination", tmp.name);
			/* NOTREACHED */
		}
		ddflags |= cp->set;
		if (cp->ctab)
			ctab = cp->ctab;
	}
}

static int
c_conv(const void *a, const void *b)
{

	return (strcmp(((const struct conv *)a)->name,
	    ((const struct conv *)b)->name));
}

#endif	/* NO_CONV */


