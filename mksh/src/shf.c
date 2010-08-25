/*	$OpenBSD: shf.c,v 1.15 2006/04/02 00:48:33 deraadt Exp $	*/

/*-
 * Copyright (c) 2003, 2004, 2005, 2006, 2007, 2008, 2009
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

__RCSID("$MirOS: src/bin/mksh/shf.c,v 1.36 2010/07/19 22:41:04 tg Exp $");

/* flags to shf_emptybuf() */
#define EB_READSW	0x01	/* about to switch to reading */
#define EB_GROW		0x02	/* grow buffer if necessary (STRING+DYNAMIC) */

/*
 * Replacement stdio routines. Stdio is too flakey on too many machines
 * to be useful when you have multiple processes using the same underlying
 * file descriptors.
 */

static int shf_fillbuf(struct shf *);
static int shf_emptybuf(struct shf *, int);

/* Open a file. First three args are for open(), last arg is flags for
 * this package. Returns NULL if file could not be opened, or if a dup
 * fails.
 */
struct shf *
shf_open(const char *name, int oflags, int mode, int sflags)
{
	struct shf *shf;
	int bsize = sflags & SHF_UNBUF ? (sflags & SHF_RD ? 1 : 0) : SHF_BSIZE;
	int fd;

	/* Done before open so if alloca fails, fd won't be lost. */
	shf = alloc(sizeof(struct shf) + bsize, ATEMP);
	shf->areap = ATEMP;
	shf->buf = (unsigned char *)&shf[1];
	shf->bsize = bsize;
	shf->flags = SHF_ALLOCS;
	/* Rest filled in by reopen. */

	fd = open(name, oflags, mode);
	if (fd < 0) {
		afree(shf, shf->areap);
		return (NULL);
	}
	if ((sflags & SHF_MAPHI) && fd < FDBASE) {
		int nfd;

		nfd = fcntl(fd, F_DUPFD, FDBASE);
		close(fd);
		if (nfd < 0) {
			afree(shf, shf->areap);
			return (NULL);
		}
		fd = nfd;
	}
	sflags &= ~SHF_ACCMODE;
	sflags |= (oflags & O_ACCMODE) == O_RDONLY ? SHF_RD :
	    ((oflags & O_ACCMODE) == O_WRONLY ? SHF_WR : SHF_RDWR);

	return (shf_reopen(fd, sflags, shf));
}

/* Set up the shf structure for a file descriptor. Doesn't fail. */
struct shf *
shf_fdopen(int fd, int sflags, struct shf *shf)
{
	int bsize = sflags & SHF_UNBUF ? (sflags & SHF_RD ? 1 : 0) : SHF_BSIZE;

	/* use fcntl() to figure out correct read/write flags */
	if (sflags & SHF_GETFL) {
		int flags = fcntl(fd, F_GETFL, 0);

		if (flags < 0)
			/* will get an error on first read/write */
			sflags |= SHF_RDWR;
		else {
			switch (flags & O_ACCMODE) {
			case O_RDONLY:
				sflags |= SHF_RD;
				break;
			case O_WRONLY:
				sflags |= SHF_WR;
				break;
			case O_RDWR:
				sflags |= SHF_RDWR;
				break;
			}
		}
	}

	if (!(sflags & (SHF_RD | SHF_WR)))
		internal_errorf("shf_fdopen: missing read/write");

	if (shf) {
		if (bsize) {
			shf->buf = alloc(bsize, ATEMP);
			sflags |= SHF_ALLOCB;
		} else
			shf->buf = NULL;
	} else {
		shf = alloc(sizeof(struct shf) + bsize, ATEMP);
		shf->buf = (unsigned char *)&shf[1];
		sflags |= SHF_ALLOCS;
	}
	shf->areap = ATEMP;
	shf->fd = fd;
	shf->rp = shf->wp = shf->buf;
	shf->rnleft = 0;
	shf->rbsize = bsize;
	shf->wnleft = 0; /* force call to shf_emptybuf() */
	shf->wbsize = sflags & SHF_UNBUF ? 0 : bsize;
	shf->flags = sflags;
	shf->errno_ = 0;
	shf->bsize = bsize;
	if (sflags & SHF_CLEXEC)
		fcntl(fd, F_SETFD, FD_CLOEXEC);
	return (shf);
}

/* Set up an existing shf (and buffer) to use the given fd */
struct shf *
shf_reopen(int fd, int sflags, struct shf *shf)
{
	int bsize = sflags & SHF_UNBUF ? (sflags & SHF_RD ? 1 : 0) : SHF_BSIZE;

	/* use fcntl() to figure out correct read/write flags */
	if (sflags & SHF_GETFL) {
		int flags = fcntl(fd, F_GETFL, 0);

		if (flags < 0)
			/* will get an error on first read/write */
			sflags |= SHF_RDWR;
		else {
			switch (flags & O_ACCMODE) {
			case O_RDONLY:
				sflags |= SHF_RD;
				break;
			case O_WRONLY:
				sflags |= SHF_WR;
				break;
			case O_RDWR:
				sflags |= SHF_RDWR;
				break;
			}
		}
	}

	if (!(sflags & (SHF_RD | SHF_WR)))
		internal_errorf("shf_reopen: missing read/write");
	if (!shf || !shf->buf || shf->bsize < bsize)
		internal_errorf("shf_reopen: bad shf/buf/bsize");

	/* assumes shf->buf and shf->bsize already set up */
	shf->fd = fd;
	shf->rp = shf->wp = shf->buf;
	shf->rnleft = 0;
	shf->rbsize = bsize;
	shf->wnleft = 0; /* force call to shf_emptybuf() */
	shf->wbsize = sflags & SHF_UNBUF ? 0 : bsize;
	shf->flags = (shf->flags & (SHF_ALLOCS | SHF_ALLOCB)) | sflags;
	shf->errno_ = 0;
	if (sflags & SHF_CLEXEC)
		fcntl(fd, F_SETFD, FD_CLOEXEC);
	return (shf);
}

/* Open a string for reading or writing. If reading, bsize is the number
 * of bytes that can be read. If writing, bsize is the maximum number of
 * bytes that can be written. If shf is not null, it is filled in and
 * returned, if it is null, shf is allocated. If writing and buf is null
 * and SHF_DYNAMIC is set, the buffer is allocated (if bsize > 0, it is
 * used for the initial size). Doesn't fail.
 * When writing, a byte is reserved for a trailing null - see shf_sclose().
 */
struct shf *
shf_sopen(char *buf, int bsize, int sflags, struct shf *shf)
{
	/* can't have a read+write string */
	if (!(!(sflags & SHF_RD) ^ !(sflags & SHF_WR)))
		internal_errorf("shf_sopen: flags 0x%x", sflags);

	if (!shf) {
		shf = alloc(sizeof(struct shf), ATEMP);
		sflags |= SHF_ALLOCS;
	}
	shf->areap = ATEMP;
	if (!buf && (sflags & SHF_WR) && (sflags & SHF_DYNAMIC)) {
		if (bsize <= 0)
			bsize = 64;
		sflags |= SHF_ALLOCB;
		buf = alloc(bsize, shf->areap);
	}
	shf->fd = -1;
	shf->buf = shf->rp = shf->wp = (unsigned char *)buf;
	shf->rnleft = bsize;
	shf->rbsize = bsize;
	shf->wnleft = bsize - 1;	/* space for a '\0' */
	shf->wbsize = bsize;
	shf->flags = sflags | SHF_STRING;
	shf->errno_ = 0;
	shf->bsize = bsize;

	return (shf);
}

/* Flush and close file descriptor, free the shf structure */
int
shf_close(struct shf *shf)
{
	int ret = 0;

	if (shf->fd >= 0) {
		ret = shf_flush(shf);
		if (close(shf->fd) < 0)
			ret = EOF;
	}
	if (shf->flags & SHF_ALLOCS)
		afree(shf, shf->areap);
	else if (shf->flags & SHF_ALLOCB)
		afree(shf->buf, shf->areap);

	return (ret);
}

/* Flush and close file descriptor, don't free file structure */
int
shf_fdclose(struct shf *shf)
{
	int ret = 0;

	if (shf->fd >= 0) {
		ret = shf_flush(shf);
		if (close(shf->fd) < 0)
			ret = EOF;
		shf->rnleft = 0;
		shf->rp = shf->buf;
		shf->wnleft = 0;
		shf->fd = -1;
	}

	return (ret);
}

/* Close a string - if it was opened for writing, it is null terminated;
 * returns a pointer to the string and frees shf if it was allocated
 * (does not free string if it was allocated).
 */
char *
shf_sclose(struct shf *shf)
{
	unsigned char *s = shf->buf;

	/* null terminate */
	if (shf->flags & SHF_WR) {
		shf->wnleft++;
		shf_putc('\0', shf);
	}
	if (shf->flags & SHF_ALLOCS)
		afree(shf, shf->areap);
	return ((char *)s);
}

/* Un-read what has been read but not examined, or write what has been
 * buffered. Returns 0 for success, EOF for (write) error.
 */
int
shf_flush(struct shf *shf)
{
	if (shf->flags & SHF_STRING)
		return ((shf->flags & SHF_WR) ? EOF : 0);

	if (shf->fd < 0)
		internal_errorf("shf_flush: no fd");

	if (shf->flags & SHF_ERROR) {
		errno = shf->errno_;
		return (EOF);
	}

	if (shf->flags & SHF_READING) {
		shf->flags &= ~(SHF_EOF | SHF_READING);
		if (shf->rnleft > 0) {
			lseek(shf->fd, (off_t)-shf->rnleft, SEEK_CUR);
			shf->rnleft = 0;
			shf->rp = shf->buf;
		}
		return (0);
	} else if (shf->flags & SHF_WRITING)
		return (shf_emptybuf(shf, 0));

	return (0);
}

/* Write out any buffered data. If currently reading, flushes the read
 * buffer. Returns 0 for success, EOF for (write) error.
 */
static int
shf_emptybuf(struct shf *shf, int flags)
{
	int ret = 0;

	if (!(shf->flags & SHF_STRING) && shf->fd < 0)
		internal_errorf("shf_emptybuf: no fd");

	if (shf->flags & SHF_ERROR) {
		errno = shf->errno_;
		return (EOF);
	}

	if (shf->flags & SHF_READING) {
		if (flags & EB_READSW) /* doesn't happen */
			return (0);
		ret = shf_flush(shf);
		shf->flags &= ~SHF_READING;
	}
	if (shf->flags & SHF_STRING) {
		unsigned char *nbuf;

		/* Note that we assume SHF_ALLOCS is not set if SHF_ALLOCB
		 * is set... (changing the shf pointer could cause problems)
		 */
		if (!(flags & EB_GROW) || !(shf->flags & SHF_DYNAMIC) ||
		    !(shf->flags & SHF_ALLOCB))
			return (EOF);
		/* allocate more space for buffer */
		nbuf = aresize(shf->buf, 2 * shf->wbsize, shf->areap);
		shf->rp = nbuf + (shf->rp - shf->buf);
		shf->wp = nbuf + (shf->wp - shf->buf);
		shf->rbsize += shf->wbsize;
		shf->wnleft += shf->wbsize;
		shf->wbsize *= 2;
		shf->buf = nbuf;
	} else {
		if (shf->flags & SHF_WRITING) {
			int ntowrite = shf->wp - shf->buf;
			unsigned char *buf = shf->buf;
			int n;

			while (ntowrite > 0) {
				n = write(shf->fd, buf, ntowrite);
				if (n < 0) {
					if (errno == EINTR &&
					    !(shf->flags & SHF_INTERRUPT))
						continue;
					shf->flags |= SHF_ERROR;
					shf->errno_ = errno;
					shf->wnleft = 0;
					if (buf != shf->buf) {
						/* allow a second flush
						 * to work */
						memmove(shf->buf, buf,
						    ntowrite);
						shf->wp = shf->buf + ntowrite;
					}
					return (EOF);
				}
				buf += n;
				ntowrite -= n;
			}
			if (flags & EB_READSW) {
				shf->wp = shf->buf;
				shf->wnleft = 0;
				shf->flags &= ~SHF_WRITING;
				return (0);
			}
		}
		shf->wp = shf->buf;
		shf->wnleft = shf->wbsize;
	}
	shf->flags |= SHF_WRITING;

	return (ret);
}

/* Fill up a read buffer. Returns EOF for a read error, 0 otherwise. */
static int
shf_fillbuf(struct shf *shf)
{
	if (shf->flags & SHF_STRING)
		return (0);

	if (shf->fd < 0)
		internal_errorf("shf_fillbuf: no fd");

	if (shf->flags & (SHF_EOF | SHF_ERROR)) {
		if (shf->flags & SHF_ERROR)
			errno = shf->errno_;
		return (EOF);
	}

	if ((shf->flags & SHF_WRITING) && shf_emptybuf(shf, EB_READSW) == EOF)
		return (EOF);

	shf->flags |= SHF_READING;

	shf->rp = shf->buf;
	while (1) {
		shf->rnleft = blocking_read(shf->fd, (char *) shf->buf,
		    shf->rbsize);
		if (shf->rnleft < 0 && errno == EINTR &&
		    !(shf->flags & SHF_INTERRUPT))
			continue;
		break;
	}
	if (shf->rnleft <= 0) {
		if (shf->rnleft < 0) {
			shf->flags |= SHF_ERROR;
			shf->errno_ = errno;
			shf->rnleft = 0;
			shf->rp = shf->buf;
			return (EOF);
		}
		shf->flags |= SHF_EOF;
	}
	return (0);
}

/* Read a buffer from shf. Returns the number of bytes read into buf,
 * if no bytes were read, returns 0 if end of file was seen, EOF if
 * a read error occurred.
 */
int
shf_read(char *buf, int bsize, struct shf *shf)
{
	int orig_bsize = bsize;
	int ncopy;

	if (!(shf->flags & SHF_RD))
		internal_errorf("shf_read: flags %x", shf->flags);

	if (bsize <= 0)
		internal_errorf("shf_read: bsize %d", bsize);

	while (bsize > 0) {
		if (shf->rnleft == 0 &&
		    (shf_fillbuf(shf) == EOF || shf->rnleft == 0))
			break;
		ncopy = shf->rnleft;
		if (ncopy > bsize)
			ncopy = bsize;
		memcpy(buf, shf->rp, ncopy);
		buf += ncopy;
		bsize -= ncopy;
		shf->rp += ncopy;
		shf->rnleft -= ncopy;
	}
	/* Note: fread(3S) returns 0 for errors - this doesn't */
	return (orig_bsize == bsize ? (shf_error(shf) ? EOF : 0) :
	    orig_bsize - bsize);
}

/* Read up to a newline or EOF. The newline is put in buf; buf is always
 * null terminated. Returns NULL on read error or if nothing was read before
 * end of file, returns a pointer to the null byte in buf otherwise.
 */
char *
shf_getse(char *buf, int bsize, struct shf *shf)
{
	unsigned char *end;
	int ncopy;
	char *orig_buf = buf;

	if (!(shf->flags & SHF_RD))
		internal_errorf("shf_getse: flags %x", shf->flags);

	if (bsize <= 0)
		return (NULL);

	--bsize;	/* save room for null */
	do {
		if (shf->rnleft == 0) {
			if (shf_fillbuf(shf) == EOF)
				return (NULL);
			if (shf->rnleft == 0) {
				*buf = '\0';
				return (buf == orig_buf ? NULL : buf);
			}
		}
		end = (unsigned char *)memchr((char *) shf->rp, '\n',
		    shf->rnleft);
		ncopy = end ? end - shf->rp + 1 : shf->rnleft;
		if (ncopy > bsize)
			ncopy = bsize;
		memcpy(buf, (char *) shf->rp, ncopy);
		shf->rp += ncopy;
		shf->rnleft -= ncopy;
		buf += ncopy;
		bsize -= ncopy;
	} while (!end && bsize);
	*buf = '\0';
	return (buf);
}

/* Returns the char read. Returns EOF for error and end of file. */
int
shf_getchar(struct shf *shf)
{
	if (!(shf->flags & SHF_RD))
		internal_errorf("shf_getchar: flags %x", shf->flags);

	if (shf->rnleft == 0 && (shf_fillbuf(shf) == EOF || shf->rnleft == 0))
		return (EOF);
	--shf->rnleft;
	return (*shf->rp++);
}

/* Put a character back in the input stream. Returns the character if
 * successful, EOF if there is no room.
 */
int
shf_ungetc(int c, struct shf *shf)
{
	if (!(shf->flags & SHF_RD))
		internal_errorf("shf_ungetc: flags %x", shf->flags);

	if ((shf->flags & SHF_ERROR) || c == EOF ||
	    (shf->rp == shf->buf && shf->rnleft))
		return (EOF);

	if ((shf->flags & SHF_WRITING) && shf_emptybuf(shf, EB_READSW) == EOF)
		return (EOF);

	if (shf->rp == shf->buf)
		shf->rp = shf->buf + shf->rbsize;
	if (shf->flags & SHF_STRING) {
		/* Can unget what was read, but not something different - we
		 * don't want to modify a string.
		 */
		if (shf->rp[-1] != c)
			return (EOF);
		shf->flags &= ~SHF_EOF;
		shf->rp--;
		shf->rnleft++;
		return (c);
	}
	shf->flags &= ~SHF_EOF;
	*--(shf->rp) = c;
	shf->rnleft++;
	return (c);
}

/* Write a character. Returns the character if successful, EOF if
 * the char could not be written.
 */
int
shf_putchar(int c, struct shf *shf)
{
	if (!(shf->flags & SHF_WR))
		internal_errorf("shf_putchar: flags %x", shf->flags);

	if (c == EOF)
		return (EOF);

	if (shf->flags & SHF_UNBUF) {
		unsigned char cc = (unsigned char)c;
		int n;

		if (shf->fd < 0)
			internal_errorf("shf_putchar: no fd");
		if (shf->flags & SHF_ERROR) {
			errno = shf->errno_;
			return (EOF);
		}
		while ((n = write(shf->fd, &cc, 1)) != 1)
			if (n < 0) {
				if (errno == EINTR &&
				    !(shf->flags & SHF_INTERRUPT))
					continue;
				shf->flags |= SHF_ERROR;
				shf->errno_ = errno;
				return (EOF);
			}
	} else {
		/* Flush deals with strings and sticky errors */
		if (shf->wnleft == 0 && shf_emptybuf(shf, EB_GROW) == EOF)
			return (EOF);
		shf->wnleft--;
		*shf->wp++ = c;
	}

	return (c);
}

/* Write a string. Returns the length of the string if successful, EOF if
 * the string could not be written.
 */
int
shf_puts(const char *s, struct shf *shf)
{
	if (!s)
		return (EOF);

	return (shf_write(s, strlen(s), shf));
}

/* Write a buffer. Returns nbytes if successful, EOF if there is an error. */
int
shf_write(const char *buf, int nbytes, struct shf *shf)
{
	int n, ncopy, orig_nbytes = nbytes;

	if (!(shf->flags & SHF_WR))
		internal_errorf("shf_write: flags %x", shf->flags);

	if (nbytes < 0)
		internal_errorf("shf_write: nbytes %d", nbytes);

	/* Don't buffer if buffer is empty and we're writting a large amount. */
	if ((ncopy = shf->wnleft) &&
	    (shf->wp != shf->buf || nbytes < shf->wnleft)) {
		if (ncopy > nbytes)
			ncopy = nbytes;
		memcpy(shf->wp, buf, ncopy);
		nbytes -= ncopy;
		buf += ncopy;
		shf->wp += ncopy;
		shf->wnleft -= ncopy;
	}
	if (nbytes > 0) {
		if (shf->flags & SHF_STRING) {
			/* resize buffer until there's enough space left */
			while (nbytes > shf->wnleft)
				if (shf_emptybuf(shf, EB_GROW) == EOF)
					return (EOF);
			/* then write everything into the buffer */
		} else {
			/* flush deals with sticky errors */
			if (shf_emptybuf(shf, EB_GROW) == EOF)
				return (EOF);
			/* write chunks larger than window size directly */
			if (nbytes > shf->wbsize) {
				ncopy = nbytes;
				if (shf->wbsize)
					ncopy -= nbytes % shf->wbsize;
				nbytes -= ncopy;
				while (ncopy > 0) {
					n = write(shf->fd, buf, ncopy);
					if (n < 0) {
						if (errno == EINTR &&
						    !(shf->flags & SHF_INTERRUPT))
							continue;
						shf->flags |= SHF_ERROR;
						shf->errno_ = errno;
						shf->wnleft = 0;
						/*
						 * Note: fwrite(3) returns 0
						 * for errors - this doesn't
						 */
						return (EOF);
					}
					buf += n;
					ncopy -= n;
				}
			}
			/* ... and buffer the rest */
		}
		if (nbytes > 0) {
			/* write remaining bytes to buffer */
			memcpy(shf->wp, buf, nbytes);
			shf->wp += nbytes;
			shf->wnleft -= nbytes;
		}
	}

	return (orig_nbytes);
}

int
shf_fprintf(struct shf *shf, const char *fmt, ...)
{
	va_list args;
	int n;

	va_start(args, fmt);
	n = shf_vfprintf(shf, fmt, args);
	va_end(args);

	return (n);
}

int
shf_snprintf(char *buf, int bsize, const char *fmt, ...)
{
	struct shf shf;
	va_list args;
	int n;

	if (!buf || bsize <= 0)
		internal_errorf("shf_snprintf: buf %p, bsize %d", buf, bsize);

	shf_sopen(buf, bsize, SHF_WR, &shf);
	va_start(args, fmt);
	n = shf_vfprintf(&shf, fmt, args);
	va_end(args);
	shf_sclose(&shf); /* null terminates */
	return (n);
}

char *
shf_smprintf(const char *fmt, ...)
{
	struct shf shf;
	va_list args;

	shf_sopen(NULL, 0, SHF_WR|SHF_DYNAMIC, &shf);
	va_start(args, fmt);
	shf_vfprintf(&shf, fmt, args);
	va_end(args);
	return (shf_sclose(&shf)); /* null terminates */
}

#undef FP			/* if you want floating point stuff */

#ifndef DMAXEXP
# define DMAXEXP	128	/* should be big enough */
#endif

#define BUF_SIZE	128
/* must be > MAX(DMAXEXP, log10(pow(2, DSIGNIF))) + ceil(log10(DMAXEXP)) + 8
 * (I think); since it's hard to express as a constant, just use a large buffer
 */
#define FPBUF_SIZE	(DMAXEXP+16)

#define	FL_HASH		0x001	/* '#' seen */
#define FL_PLUS		0x002	/* '+' seen */
#define FL_RIGHT	0x004	/* '-' seen */
#define FL_BLANK	0x008	/* ' ' seen */
#define FL_SHORT	0x010	/* 'h' seen */
#define FL_LONG		0x020	/* 'l' seen */
#define FL_ZERO		0x040	/* '0' seen */
#define FL_DOT		0x080	/* '.' seen */
#define FL_UPPER	0x100	/* format character was uppercase */
#define FL_NUMBER	0x200	/* a number was formated %[douxefg] */


int
shf_vfprintf(struct shf *shf, const char *fmt, va_list args)
{
	const char *s;
	char c, *cp;
	int tmp = 0, field, precision, len, flags;
	unsigned long lnum;
	/* %#o produces the longest output */
	char numbuf[(8 * sizeof(long) + 2) / 3 + 1];
	/* this stuff for dealing with the buffer */
	int nwritten = 0;

	if (!fmt)
		return (0);

	while ((c = *fmt++)) {
		if (c != '%') {
			shf_putc(c, shf);
			nwritten++;
			continue;
		}
		/*
		 * This will accept flags/fields in any order - not
		 * just the order specified in printf(3), but this is
		 * the way _doprnt() seems to work (on bsd and sysV).
		 * The only restriction is that the format character must
		 * come last :-).
		 */
		flags = field = precision = 0;
		for ( ; (c = *fmt++) ; ) {
			switch (c) {
			case '#':
				flags |= FL_HASH;
				continue;

			case '+':
				flags |= FL_PLUS;
				continue;

			case '-':
				flags |= FL_RIGHT;
				continue;

			case ' ':
				flags |= FL_BLANK;
				continue;

			case '0':
				if (!(flags & FL_DOT))
					flags |= FL_ZERO;
				continue;

			case '.':
				flags |= FL_DOT;
				precision = 0;
				continue;

			case '*':
				tmp = va_arg(args, int);
				if (flags & FL_DOT)
					precision = tmp;
				else if ((field = tmp) < 0) {
					field = -field;
					flags |= FL_RIGHT;
				}
				continue;

			case 'l':
				flags |= FL_LONG;
				continue;

			case 'h':
				flags |= FL_SHORT;
				continue;
			}
			if (ksh_isdigit(c)) {
				tmp = c - '0';
				while (c = *fmt++, ksh_isdigit(c))
					tmp = tmp * 10 + c - '0';
				--fmt;
				if (tmp < 0)		/* overflow? */
					tmp = 0;
				if (flags & FL_DOT)
					precision = tmp;
				else
					field = tmp;
				continue;
			}
			break;
		}

		if (precision < 0)
			precision = 0;

		if (!c)		/* nasty format */
			break;

		if (c >= 'A' && c <= 'Z') {
			flags |= FL_UPPER;
			c = ksh_tolower(c);
		}

		switch (c) {
		case 'p': /* pointer */
			flags &= ~(FL_LONG | FL_SHORT);
			flags |= (sizeof(char *) > sizeof(int)) ?
			    /* hope it fits.. */ FL_LONG : 0;
			/* aaahhh... */
		case 'd':
		case 'i':
		case 'o':
		case 'u':
		case 'x':
			flags |= FL_NUMBER;
			cp = numbuf + sizeof(numbuf);
			/*-
			 * XXX any better way to do this?
			 * XXX hopefully the compiler optimises this out
			 *
			 * For shorts, we want sign extend for %d but not
			 * for %[oxu] - on 16 bit machines it doesn't matter.
			 * Assumes C compiler has converted shorts to ints
			 * before pushing them. XXX optimise this -tg
			 */
			if (flags & FL_LONG)
				lnum = va_arg(args, unsigned long);
			else if ((sizeof(int) < sizeof(long)) && (c == 'd'))
				lnum = (long)va_arg(args, int);
			else
				lnum = va_arg(args, unsigned int);
			switch (c) {
			case 'd':
			case 'i':
				if (0 > (long)lnum) {
					lnum = -(long)lnum;
					tmp = 1;
				} else
					tmp = 0;
				/* FALLTHROUGH */
			case 'u':
				do {
					*--cp = lnum % 10 + '0';
					lnum /= 10;
				} while (lnum);

				if (c != 'u') {
					if (tmp)
						*--cp = '-';
					else if (flags & FL_PLUS)
						*--cp = '+';
					else if (flags & FL_BLANK)
						*--cp = ' ';
				}
				break;

			case 'o':
				do {
					*--cp = (lnum & 0x7) + '0';
					lnum >>= 3;
				} while (lnum);

				if ((flags & FL_HASH) && *cp != '0')
					*--cp = '0';
				break;

			case 'p':
			case 'x': {
				const char *digits = (flags & FL_UPPER) ?
				    digits_uc : digits_lc;
				do {
					*--cp = digits[lnum & 0xf];
					lnum >>= 4;
				} while (lnum);

				if (flags & FL_HASH) {
					*--cp = (flags & FL_UPPER) ? 'X' : 'x';
					*--cp = '0';
				}
			}
			}
			len = numbuf + sizeof(numbuf) - (s = cp);
			if (flags & FL_DOT) {
				if (precision > len) {
					field = precision;
					flags |= FL_ZERO;
				} else
					precision = len; /* no loss */
			}
			break;

		case 's':
			if (!(s = va_arg(args, const char *)))
				s = "(null)";
			len = utf_mbswidth(s);
			break;

		case 'c':
			flags &= ~FL_DOT;
			numbuf[0] = (char)(va_arg(args, int));
			s = numbuf;
			len = 1;
			break;

		case '%':
		default:
			numbuf[0] = c;
			s = numbuf;
			len = 1;
			break;
		}

		/*
		 * At this point s should point to a string that is to be
		 * formatted, and len should be the length of the string.
		 */
		if (!(flags & FL_DOT) || len < precision)
			precision = len;
		if (field > precision) {
			field -= precision;
			if (!(flags & FL_RIGHT)) {
				field = -field;
				/* skip past sign or 0x when padding with 0 */
				if ((flags & FL_ZERO) && (flags & FL_NUMBER)) {
					if (*s == '+' || *s == '-' ||
					    *s == ' ') {
						shf_putc(*s, shf);
						s++;
						precision--;
						nwritten++;
					} else if (*s == '0') {
						shf_putc(*s, shf);
						s++;
						nwritten++;
						if (--precision > 0 &&
						    (*s | 0x20) == 'x') {
							shf_putc(*s, shf);
							s++;
							precision--;
							nwritten++;
						}
					}
					c = '0';
				} else
					c = flags & FL_ZERO ? '0' : ' ';
				if (field < 0) {
					nwritten += -field;
					for ( ; field < 0 ; field++)
						shf_putc(c, shf);
				}
			} else
				c = ' ';
		} else
			field = 0;

		if (precision > 0) {
			const char *q;

			nwritten += precision;
			q = utf_skipcols(s, precision);
			do {
				shf_putc(*s, shf);
			} while (++s < q);
		}
		if (field > 0) {
			nwritten += field;
			for ( ; field > 0 ; --field)
				shf_putc(c, shf);
		}
	}

	return (shf_error(shf) ? EOF : nwritten);
}

#ifdef MKSH_SMALL
int
shf_getc(struct shf *shf)
{
	return ((shf)->rnleft > 0 ? (shf)->rnleft--, *(shf)->rp++ :
	    shf_getchar(shf));
}

int
shf_putc(int c, struct shf *shf)
{
	return ((shf)->wnleft == 0 ? shf_putchar((c), (shf)) :
	    ((shf)->wnleft--, *(shf)->wp++ = (c)));
}
#endif
