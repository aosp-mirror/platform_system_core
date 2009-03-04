/* $NetBSD: cat.c,v 1.43 2004/01/04 03:31:28 jschauma Exp $	*/

/*
 * Copyright (c) 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Kevin Fall.
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

#include <sys/param.h>
#include <sys/stat.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CAT_BUFSIZ (4096)

static int bflag, eflag, fflag, lflag, nflag, sflag, tflag, vflag;
static int rval;
static const char *filename;

static void
cook_buf(FILE *fp)
{
	int ch, gobble, line, prev;
	int stdout_err = 0;

	line = gobble = 0;
	for (prev = '\n'; (ch = getc(fp)) != EOF; prev = ch) {
		if (prev == '\n') {
			if (ch == '\n') {
				if (sflag) {
					if (!gobble && putchar(ch) == EOF)
						break;
					gobble = 1;
					continue;
				}
				if (nflag) {
					if (!bflag) {
						if (fprintf(stdout,
						    "%6d\t", ++line) < 0) {
							stdout_err++;
							break;
						}
					} else if (eflag) {
						if (fprintf(stdout,
						    "%6s\t", "") < 0) {
							stdout_err++;
							break;
						}
					}
				}
			} else if (nflag) {
				if (fprintf(stdout, "%6d\t", ++line) < 0) {
					stdout_err++;
					break;
				}
			}
		}
		gobble = 0;
		if (ch == '\n') {
			if (eflag)
				if (putchar('$') == EOF)
					break;
		} else if (ch == '\t') {
			if (tflag) {
				if (putchar('^') == EOF || putchar('I') == EOF)
					break;
				continue;
			}
		} else if (vflag) {
			if (!isascii(ch)) {
				if (putchar('M') == EOF || putchar('-') == EOF)
					break;
				ch = (ch) & 0x7f;
			}
			if (iscntrl(ch)) {
				if (putchar('^') == EOF ||
				    putchar(ch == '\177' ? '?' :
				    ch | 0100) == EOF)
					break;
				continue;
			}
		}
		if (putchar(ch) == EOF)
			break;
	}
	if (stdout_err) {
		perror(filename);
		rval = 1;
	}
}

static void
cook_args(char **argv)
{
	FILE *fp;

	fp = stdin;
	filename = "stdin";
	do {
		if (*argv) {
			if (!strcmp(*argv, "-"))
				fp = stdin;
			else if ((fp = fopen(*argv,
			    fflag ? "rf" : "r")) == NULL) {
				perror("fopen");
				rval = 1;
				++argv;
				continue;
			}
			filename = *argv++;
		}
		cook_buf(fp);
		if (fp != stdin)
			fclose(fp);
	} while (*argv);
}

static void
raw_cat(int rfd)
{
	static char *buf;
	static char fb_buf[CAT_BUFSIZ];
	static size_t bsize;

	struct stat sbuf;
	ssize_t nr, nw, off;
	int wfd;

	wfd = fileno(stdout);
	if (buf == NULL) {
		if (fstat(wfd, &sbuf) == 0) {
			bsize = sbuf.st_blksize > CAT_BUFSIZ ?
			    sbuf.st_blksize : CAT_BUFSIZ;
			buf = malloc(bsize);
		}
		if (buf == NULL) {
			buf = fb_buf;
			bsize = CAT_BUFSIZ;
		}
	}
	while ((nr = read(rfd, buf, bsize)) > 0)
		for (off = 0; nr; nr -= nw, off += nw)
			if ((nw = write(wfd, buf + off, (size_t)nr)) < 0)
			{
				perror("write");
				exit(EXIT_FAILURE);
			}
	if (nr < 0) {
		fprintf(stderr,"%s: invalid length\n", filename);
		rval = 1;
	}
}

static void
raw_args(char **argv)
{
	int fd;

	fd = fileno(stdin);
	filename = "stdin";
	do {
		if (*argv) {
			if (!strcmp(*argv, "-"))
				fd = fileno(stdin);
			else if (fflag) {
				struct stat st;
				fd = open(*argv, O_RDONLY|O_NONBLOCK, 0);
				if (fd < 0)
					goto skip;

				if (fstat(fd, &st) == -1) {
					close(fd);
					goto skip;
				}
				if (!S_ISREG(st.st_mode)) {
					close(fd);
					errno = EINVAL;
					goto skipnomsg;
				}
			}
			else if ((fd = open(*argv, O_RDONLY, 0)) < 0) {
skip:
				perror(*argv);
skipnomsg:
				rval = 1;
				++argv;
				continue;
			}
			filename = *argv++;
		}
		raw_cat(fd);
		if (fd != fileno(stdin))
			close(fd);
	} while (*argv);
}

int
cat_main(int argc, char *argv[])
{
	int ch;
	struct flock stdout_lock;

	while ((ch = getopt(argc, argv, "beflnstv")) != -1)
		switch (ch) {
		case 'b':
			bflag = nflag = 1;	/* -b implies -n */
			break;
		case 'e':
			eflag = vflag = 1;	/* -e implies -v */
			break;
		case 'f':
			fflag = 1;
			break;
		case 'l':
			lflag = 1;
			break;
		case 'n':
			nflag = 1;
			break;
		case 's':
			sflag = 1;
			break;
		case 't':
			tflag = vflag = 1;	/* -t implies -v */
			break;
		case 'v':
			vflag = 1;
			break;
		default:
		case '?':
			fprintf(stderr,
				"usage: cat [-beflnstv] [-] [file ...]\n");
			exit(EXIT_FAILURE);
		}
	argv += optind;

	if (lflag) {
		stdout_lock.l_len = 0;
		stdout_lock.l_start = 0;
		stdout_lock.l_type = F_WRLCK;
		stdout_lock.l_whence = SEEK_SET;
		if (fcntl(STDOUT_FILENO, F_SETLKW, &stdout_lock) == -1)
		{
			perror("fcntl");
			exit(EXIT_FAILURE);
		}
	}

	if (bflag || eflag || nflag || sflag || tflag || vflag)
		cook_args(argv);
	else
		raw_args(argv);
	if (fclose(stdout))
	{
		perror("fclose");
		exit(EXIT_FAILURE);
	}
	exit(rval);
}
