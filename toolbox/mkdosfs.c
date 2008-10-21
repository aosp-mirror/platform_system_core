/*	$NetBSD: newfs_msdos.c,v 1.18.2.1 2005/05/01 18:44:02 tron Exp $	*/

/*
 * Copyright (c) 1998 Robert Nordier
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR(S) ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR(S) BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#define __USE_FILE_OFFSET64

#include <sys/cdefs.h>

#include <sys/types.h>
#include <sys/param.h>
#ifdef __FreeBSD__
#include <sys/diskslice.h>
#endif
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/ioctl.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <paths.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#ifdef __NetBSD__
#include <disktab.h>
#include <util.h>
#endif

#define MAXU16	  0xffff	/* maximum unsigned 16-bit quantity */
#define BPN	  4		/* bits per nibble */
#define NPB	  2		/* nibbles per byte */

#define DOSMAGIC  0xaa55	/* DOS magic number */
#define MINBPS	  128		/* minimum bytes per sector */
#define MAXSPC	  128		/* maximum sectors per cluster */
#define MAXNFT	  16		/* maximum number of FATs */
#define DEFBLK	  4096		/* default block size */
#define DEFBLK16  2048		/* default block size FAT16 */
#define DEFRDE	  512		/* default root directory entries */
#define RESFTE	  2		/* reserved FAT entries */
#define MINCLS12  1		/* minimum FAT12 clusters */
#define MINCLS16  0x1000	/* minimum FAT16 clusters */
#define MINCLS32  2		/* minimum FAT32 clusters */
#define MAXCLS12  0xfed 	/* maximum FAT12 clusters */
#define MAXCLS16  0xfff5	/* maximum FAT16 clusters */
#define MAXCLS32  0xffffff5	/* maximum FAT32 clusters */

#define mincls(fat)  ((fat) == 12 ? MINCLS12 :	\
		      (fat) == 16 ? MINCLS16 :	\
				    MINCLS32)

#define maxcls(fat)  ((fat) == 12 ? MAXCLS12 :	\
		      (fat) == 16 ? MAXCLS16 :	\
				    MAXCLS32)

#define mk1(p, x)				\
    (p) = (u_int8_t)(x)

#define mk2(p, x)				\
    (p)[0] = (u_int8_t)(x),			\
    (p)[1] = (u_int8_t)((x) >> 010)

#define mk4(p, x)				\
    (p)[0] = (u_int8_t)(x),			\
    (p)[1] = (u_int8_t)((x) >> 010),		\
    (p)[2] = (u_int8_t)((x) >> 020),		\
    (p)[3] = (u_int8_t)((x) >> 030)

#define argto1(arg, lo, msg)  argtou(arg, lo, 0xff, msg)
#define argto2(arg, lo, msg)  argtou(arg, lo, 0xffff, msg)
#define argto4(arg, lo, msg)  argtou(arg, lo, 0xffffffff, msg)
#define argtox(arg, lo, msg)  argtou(arg, lo, UINT_MAX, msg)

#ifndef MAX
#define MAX(x, y) ((x) > (y) ? (x) : (y))
#endif
#ifndef MIN
#define MIN(x, y) ((x) < (y) ? (x) : (y))
#endif

static int powerof2(int x) {
    int i;
    for (i = 0; i < 32; i++) {
        if (x & 1) {
            x >>= 1;
            // if x is zero, then original x was a power of two
            return (x == 0);
        }
        x >>= 1;
    }
    
    return 0;
}

#ifndef howmany
#define   howmany(x, y)   (((x)+((y)-1))/(y))
#endif
 
#pragma pack(push, 1)
struct bs {
    u_int8_t jmp[3];		/* bootstrap entry point */
    u_int8_t oem[8];		/* OEM name and version */
};
#define BS_SIZE 11

struct bsbpb {
    u_int8_t bps[2];		/* bytes per sector */
    u_int8_t spc;		/* sectors per cluster */
    u_int8_t res[2];		/* reserved sectors */
    u_int8_t nft;		/* number of FATs */
    u_int8_t rde[2];		/* root directory entries */
    u_int8_t sec[2];		/* total sectors */
    u_int8_t mid;		/* media descriptor */
    u_int8_t spf[2];		/* sectors per FAT */
    u_int8_t spt[2];		/* sectors per track */
    u_int8_t hds[2];		/* drive heads */
    u_int8_t hid[4];		/* hidden sectors */
    u_int8_t bsec[4];		/* big total sectors */
};
#define BSBPB_SIZE 25

struct bsxbpb {
    u_int8_t bspf[4];		/* big sectors per FAT */
    u_int8_t xflg[2];		/* FAT control flags */
    u_int8_t vers[2];		/* file system version */
    u_int8_t rdcl[4];		/* root directory start cluster */
    u_int8_t infs[2];		/* file system info sector */
    u_int8_t bkbs[2];		/* backup boot sector */
    u_int8_t rsvd[12];		/* reserved */
};
#define BSXBPB_SIZE 28

struct bsx {
    u_int8_t drv;		/* drive number */
    u_int8_t rsvd;		/* reserved */
    u_int8_t sig;		/* extended boot signature */
    u_int8_t volid[4];		/* volume ID number */
    u_int8_t label[11]; 	/* volume label */
    u_int8_t type[8];		/* file system type */
};
#define BSX_SIZE 26

struct de {
    u_int8_t namext[11];	/* name and extension */
    u_int8_t attr;		/* attributes */
    u_int8_t rsvd[10];		/* reserved */
    u_int8_t time[2];		/* creation time */
    u_int8_t date[2];		/* creation date */
    u_int8_t clus[2];		/* starting cluster */
    u_int8_t size[4];		/* size */
#define DE_SIZE 32
};
#pragma pack(pop)

struct bpb {
    u_int bps;			/* bytes per sector */
    u_int spc;			/* sectors per cluster */
    u_int res;			/* reserved sectors */
    u_int nft;			/* number of FATs */
    u_int rde;			/* root directory entries */
    u_int sec;			/* total sectors */
    u_int mid;			/* media descriptor */
    u_int spf;			/* sectors per FAT */
    u_int spt;			/* sectors per track */
    u_int hds;			/* drive heads */
    u_int hid;			/* hidden sectors */
    u_int bsec; 		/* big total sectors */
    u_int bspf; 		/* big sectors per FAT */
    u_int rdcl; 		/* root directory start cluster */
    u_int infs; 		/* file system info sector */
    u_int bkbs; 		/* backup boot sector */
};

static u_int8_t bootcode[] = {
    0xfa,			/* cli		    */
    0x31, 0xc0, 		/* xor	   ax,ax    */
    0x8e, 0xd0, 		/* mov	   ss,ax    */
    0xbc, 0x00, 0x7c,		/* mov	   sp,7c00h */
    0xfb,			/* sti		    */
    0x8e, 0xd8, 		/* mov	   ds,ax    */
    0xe8, 0x00, 0x00,		/* call    $ + 3    */
    0x5e,			/* pop	   si	    */
    0x83, 0xc6, 0x19,		/* add	   si,+19h  */
    0xbb, 0x07, 0x00,		/* mov	   bx,0007h */
    0xfc,			/* cld		    */
    0xac,			/* lodsb	    */
    0x84, 0xc0, 		/* test    al,al    */
    0x74, 0x06, 		/* jz	   $ + 8    */
    0xb4, 0x0e, 		/* mov	   ah,0eh   */
    0xcd, 0x10, 		/* int	   10h	    */
    0xeb, 0xf5, 		/* jmp	   $ - 9    */
    0x30, 0xe4, 		/* xor	   ah,ah    */
    0xcd, 0x16, 		/* int	   16h	    */
    0xcd, 0x19, 		/* int	   19h	    */
    0x0d, 0x0a,
    'N', 'o', 'n', '-', 's', 'y', 's', 't',
    'e', 'm', ' ', 'd', 'i', 's', 'k',
    0x0d, 0x0a,
    'P', 'r', 'e', 's', 's', ' ', 'a', 'n',
    'y', ' ', 'k', 'e', 'y', ' ', 't', 'o',
    ' ', 'r', 'e', 'b', 'o', 'o', 't',
    0x0d, 0x0a,
    0
};

static void print_bpb(struct bpb *);
static u_int ckgeom(const char *, u_int, const char *);
static u_int argtou(const char *, u_int, u_int, const char *);
static int oklabel(const char *);
static void mklabel(u_int8_t *, const char *);
static void setstr(u_int8_t *, const char *, size_t);
static void usage(char* progname);

/*
 * Construct a FAT12, FAT16, or FAT32 file system.
 */
int
mkdosfs_main(int argc, char *argv[])
{
    static char opts[] = "NB:F:I:L:O:S:a:b:c:e:f:h:i:k:m:n:o:r:s:u:";
    static const char *opt_B, *opt_L, *opt_O;
    static u_int opt_F, opt_I, opt_S, opt_a, opt_b, opt_c, opt_e;
    static u_int opt_h, opt_i, opt_k, opt_m, opt_n, opt_o, opt_r;
    static u_int opt_s, opt_u;
    static int opt_N;
    static int Iflag, mflag, oflag;
    char buf[MAXPATHLEN];
    struct stat sb;
    struct timeval tv;
    struct bpb bpb;
    struct tm *tm;
    struct bs *bs;
    struct bsbpb *bsbpb;
    struct bsxbpb *bsxbpb;
    struct bsx *bsx;
    struct de *de;
    u_int8_t *img;
    const char *fname, *dtype, *bname;
    ssize_t n;
    time_t now;
    u_int fat, bss, rds, cls, dir, lsn, x, x1, x2;
    int ch, fd, fd1;
    char* progname = argv[0];

    while ((ch = getopt(argc, argv, opts)) != -1)
	switch (ch) {
	case 'N':
	    opt_N = 1;
	    break;
	case 'B':
	    opt_B = optarg;
	    break;
	case 'F':
	    if (strcmp(optarg, "12") &&
		strcmp(optarg, "16") &&
		strcmp(optarg, "32"))
		fprintf(stderr, "%s: bad FAT type\n", optarg);
	    opt_F = atoi(optarg);
	    break;
	case 'I':
	    opt_I = argto4(optarg, 0, "volume ID");
	    Iflag = 1;
	    break;
	case 'L':
	    if (!oklabel(optarg))
		fprintf(stderr, "%s: bad volume label\n", optarg);
	    opt_L = optarg;
	    break;
	case 'O':
	    if (strlen(optarg) > 8)
		fprintf(stderr, "%s: bad OEM string\n", optarg);
	    opt_O = optarg;
	    break;
	case 'S':
	    opt_S = argto2(optarg, 1, "bytes/sector");
	    break;
	case 'a':
	    opt_a = argto4(optarg, 1, "sectors/FAT");
	    break;
	case 'b':
	    opt_b = argtox(optarg, 1, "block size");
	    opt_c = 0;
	    break;
	case 'c':
	    opt_c = argto1(optarg, 1, "sectors/cluster");
	    opt_b = 0;
	    break;
	case 'e':
	    opt_e = argto2(optarg, 1, "directory entries");
	    break;
	case 'h':
	    opt_h = argto2(optarg, 1, "drive heads");
	    break;
	case 'i':
	    opt_i = argto2(optarg, 1, "info sector");
	    break;
	case 'k':
	    opt_k = argto2(optarg, 1, "backup sector");
	    break;
	case 'm':
	    opt_m = argto1(optarg, 0, "media descriptor");
	    mflag = 1;
	    break;
	case 'n':
	    opt_n = argto1(optarg, 1, "number of FATs");
	    break;
	case 'o':
	    opt_o = argto4(optarg, 0, "hidden sectors");
	    oflag = 1;
	    break;
	case 'r':
	    opt_r = argto2(optarg, 1, "reserved sectors");
	    break;
	case 's':
	    opt_s = argto4(optarg, 1, "file system size");
	    break;
	case 'u':
	    opt_u = argto2(optarg, 1, "sectors/track");
	    break;
	default:
	    usage(progname);
	}
    argc -= optind;
    argv += optind;
    if (argc < 1 || argc > 2)
	usage(progname);
    fname = *argv++;
    if (!strchr(fname, '/')) {
	snprintf(buf, sizeof(buf), "%sr%s", _PATH_DEV, fname);
	if (!(fname = strdup(buf)))
	    fprintf(stderr, NULL);
    }
    dtype = *argv;
    if ((fd = open(fname, opt_N ? O_RDONLY : O_RDWR)) == -1 ||
	fstat(fd, &sb))
	fprintf(stderr, "%s\n", fname);
    memset(&bpb, 0, sizeof(bpb));

    if (opt_h)
	bpb.hds = opt_h;
    if (opt_u)
	bpb.spt = opt_u;
    if (opt_S)
	bpb.bps = opt_S;
    if (opt_s)
	bpb.bsec = opt_s;
    if (oflag)
	bpb.hid = opt_o;

    bpb.bps = 512;  // 512 bytes/sector
    bpb.spc = 8;    // 4K clusters
    

	fprintf(stderr, "opening %s\n", fname);
	if ((fd1 = open(fname, O_RDONLY)) == -1) {
	    fprintf(stderr, "failed to open %s\n", fname);
	    exit(1);
	}

    lseek(fd1, 0, SEEK_SET);
    off_t length = lseek(fd1, 0, SEEK_END);
    fprintf(stderr, "lseek returned %ld\n", length);
    if (length > 0) {
        bpb.bsec = length / bpb.bps;
        bpb.spt = bpb.bsec;
        // use FAT32 for 2 gig or greater 
        if (length >= 2 *1024 *1024 *1024) {
            fat = 32;
        } else {
            fat = 16;
        }
    }
    close(fd1);
    fd1 = -1;

    if (!powerof2(bpb.bps))
	fprintf(stderr, "bytes/sector (%u) is not a power of 2\n", bpb.bps);
    if (bpb.bps < MINBPS)
	fprintf(stderr, "bytes/sector (%u) is too small; minimum is %u\n",
	     bpb.bps, MINBPS);

    if (!(fat = opt_F)) {
	if (!opt_e && (opt_i || opt_k))
	    fat = 32;
    }

    if ((fat == 32 && opt_e) || (fat != 32 && (opt_i || opt_k)))
	fprintf(stderr, "-%c is not a legal FAT%s option\n",
	     fat == 32 ? 'e' : opt_i ? 'i' : 'k',
	     fat == 32 ? "32" : "12/16");
    if (fat == 32)
	bpb.rde = 0;
    if (opt_b) {
	if (!powerof2(opt_b))
	    fprintf(stderr, "block size (%u) is not a power of 2\n", opt_b);
	if (opt_b < bpb.bps)
	    fprintf(stderr, "block size (%u) is too small; minimum is %u\n",
		 opt_b, bpb.bps);
	if (opt_b > bpb.bps * MAXSPC)
	    fprintf(stderr, "block size (%u) is too large; maximum is %u\n",
		 opt_b, bpb.bps * MAXSPC);
	bpb.spc = opt_b / bpb.bps;
    }
    if (opt_c) {
	if (!powerof2(opt_c))
	    fprintf(stderr, "sectors/cluster (%u) is not a power of 2\n", opt_c);
	bpb.spc = opt_c;
    }
    if (opt_r)
	bpb.res = opt_r;
    if (opt_n) {
	if (opt_n > MAXNFT)
	    fprintf(stderr, "number of FATs (%u) is too large; maximum is %u\n",
		 opt_n, MAXNFT);
	bpb.nft = opt_n;
    }
    if (opt_e)
	bpb.rde = opt_e;
    if (mflag) {
	if (opt_m < 0xf0)
	    fprintf(stderr, "illegal media descriptor (%#x)\n", opt_m);
	bpb.mid = opt_m;
    }
    if (opt_a)
	bpb.bspf = opt_a;
    if (opt_i)
	bpb.infs = opt_i;
    if (opt_k)
	bpb.bkbs = opt_k;
    bss = 1;
    bname = NULL;
    fd1 = -1;
    if (opt_B) {
	bname = opt_B;
	if (!strchr(bname, '/')) {
	    snprintf(buf, sizeof(buf), "/boot/%s", bname);
	    if (!(bname = strdup(buf)))
		fprintf(stderr, NULL);
	}
	if ((fd1 = open(bname, O_RDONLY)) == -1 || fstat(fd1, &sb))
	    fprintf(stderr, "%s", bname);
	if (!S_ISREG(sb.st_mode) || sb.st_size % bpb.bps ||
	    sb.st_size < bpb.bps || sb.st_size > bpb.bps * MAXU16)
	    fprintf(stderr, "%s: inappropriate file type or format\n", bname);
	bss = sb.st_size / bpb.bps;
    }
    if (!bpb.nft)
	bpb.nft = 2;
    if (!fat) {
	if (bpb.bsec < (bpb.res ? bpb.res : bss) +
	    howmany((RESFTE + (bpb.spc ? MINCLS16 : MAXCLS12 + 1)) *
		    ((bpb.spc ? 16 : 12) / BPN), bpb.bps * NPB) *
	    bpb.nft +
	    howmany(bpb.rde ? bpb.rde : DEFRDE,
		    bpb.bps / DE_SIZE) +
	    (bpb.spc ? MINCLS16 : MAXCLS12 + 1) *
	    (bpb.spc ? bpb.spc : howmany(DEFBLK, bpb.bps)))
	    fat = 12;
	else if (bpb.rde || bpb.bsec <
		 (bpb.res ? bpb.res : bss) +
		 howmany((RESFTE + MAXCLS16) * 2, bpb.bps) * bpb.nft +
		 howmany(DEFRDE, bpb.bps / DE_SIZE) +
		 (MAXCLS16 + 1) *
		 (bpb.spc ? bpb.spc : howmany(8192, bpb.bps)))
	    fat = 16;
	else
	    fat = 32;
    }
    x = bss;
    if (fat == 32) {
	if (!bpb.infs) {
	    if (x == MAXU16 || x == bpb.bkbs)
		fprintf(stderr, "no room for info sector\n");
	    bpb.infs = x;
	}
	if (bpb.infs != MAXU16 && x <= bpb.infs)
	    x = bpb.infs + 1;
	if (!bpb.bkbs) {
	    if (x == MAXU16)
		fprintf(stderr, "no room for backup sector\n");
	    bpb.bkbs = x;
	} else if (bpb.bkbs != MAXU16 && bpb.bkbs == bpb.infs)
	    fprintf(stderr, "backup sector would overwrite info sector\n");
	if (bpb.bkbs != MAXU16 && x <= bpb.bkbs)
	    x = bpb.bkbs + 1;
    }
    if (!bpb.res)
	bpb.res = fat == 32 ? MAX(x, MAX(16384 / bpb.bps, 4)) : x;
    else if (bpb.res < x)
	fprintf(stderr, "too few reserved sectors (need %d have %d)\n", x, bpb.res);
    if (fat != 32 && !bpb.rde)
	bpb.rde = DEFRDE;
    rds = howmany(bpb.rde, bpb.bps / DE_SIZE);
    if (!bpb.spc)
	for (bpb.spc = howmany(fat == 16 ? DEFBLK16 : DEFBLK, bpb.bps);
	     bpb.spc < MAXSPC &&
	     bpb.res +
	     howmany((RESFTE + maxcls(fat)) * (fat / BPN),
		     bpb.bps * NPB) * bpb.nft +
	     rds +
	     (u_int64_t)(maxcls(fat) + 1) * bpb.spc <= bpb.bsec;
	     bpb.spc <<= 1);
    if (fat != 32 && bpb.bspf > MAXU16)
	fprintf(stderr, "too many sectors/FAT for FAT12/16\n");
    x1 = bpb.res + rds;
    x = bpb.bspf ? bpb.bspf : 1;
    if (x1 + (u_int64_t)x * bpb.nft > bpb.bsec)
	fprintf(stderr, "meta data exceeds file system size\n");
    x1 += x * bpb.nft;
    x = (u_int64_t)(bpb.bsec - x1) * bpb.bps * NPB /
	(bpb.spc * bpb.bps * NPB + fat / BPN * bpb.nft);
    x2 = howmany((RESFTE + MIN(x, maxcls(fat))) * (fat / BPN),
		 bpb.bps * NPB);
    if (!bpb.bspf) {
	bpb.bspf = x2;
	x1 += (bpb.bspf - 1) * bpb.nft;
    }
    cls = (bpb.bsec - x1) / bpb.spc;
    x = (u_int64_t)bpb.bspf * bpb.bps * NPB / (fat / BPN) - RESFTE;
    if (cls > x)
	cls = x;
    if (bpb.bspf < x2)
	fprintf(stderr, "warning: sectors/FAT limits file system to %u clusters\n",
	      cls);
    if (cls < mincls(fat))
	fprintf(stderr, "%u clusters too few clusters for FAT%u, need %u\n", cls, fat,
	    mincls(fat));
    if (cls > maxcls(fat)) {
	cls = maxcls(fat);
	bpb.bsec = x1 + (cls + 1) * bpb.spc - 1;
	fprintf(stderr, "warning: FAT type limits file system to %u sectors\n",
	      bpb.bsec);
    }
    printf("%s: %u sector%s in %u FAT%u cluster%s "
	   "(%u bytes/cluster)\n", fname, cls * bpb.spc,
	   cls * bpb.spc == 1 ? "" : "s", cls, fat,
	   cls == 1 ? "" : "s", bpb.bps * bpb.spc);
    if (!bpb.mid)
	bpb.mid = !bpb.hid ? 0xf0 : 0xf8;
    if (fat == 32)
	bpb.rdcl = RESFTE;
    if (bpb.hid + bpb.bsec <= MAXU16) {
	bpb.sec = bpb.bsec;
	bpb.bsec = 0;
    }
    if (fat != 32) {
	bpb.spf = bpb.bspf;
	bpb.bspf = 0;
    }
    ch = 0;
    if (fat == 12)
	ch = 1;			/* 001 Primary DOS with 12 bit FAT */
    else if (fat == 16) {
	if (bpb.bsec == 0)
	    ch = 4;		/* 004 Primary DOS with 16 bit FAT <32M */
	else
	    ch = 6;		/* 006 Primary 'big' DOS, 16-bit FAT (> 32MB) */
				/*
				 * XXX: what about:
				 * 014 DOS (16-bit FAT) - LBA
				 *  ?
				 */
    } else if (fat == 32) {
	ch = 11;		/* 011 Primary DOS with 32 bit FAT */
				/*
				 * XXX: what about:
				 * 012 Primary DOS with 32 bit FAT - LBA
				 *  ?
				 */
    }
    if (ch != 0)
	printf("MBR type: %d\n", ch);
    print_bpb(&bpb);
    if (!opt_N) {
	gettimeofday(&tv, NULL);
	now = tv.tv_sec;
	tm = localtime(&now);
	if (!(img = malloc(bpb.bps)))
	    fprintf(stderr, NULL);
	dir = bpb.res + (bpb.spf ? bpb.spf : bpb.bspf) * bpb.nft;

	for (lsn = 0; lsn < dir + (fat == 32 ? bpb.spc : rds); lsn++) {
	    x = lsn;
	    if (opt_B &&
		fat == 32 && bpb.bkbs != MAXU16 &&
		bss <= bpb.bkbs && x >= bpb.bkbs) {
		x -= bpb.bkbs;
		if (!x && lseek(fd1, 0, SEEK_SET))
		    fprintf(stderr, "lseek failed for %s\n", bname);
	    }
	    if (opt_B && x < bss) {
		if ((n = read(fd1, img, bpb.bps)) == -1)
		    fprintf(stderr, "%s\n", bname);
		if (n != bpb.bps)
		    fprintf(stderr, "%s: can't read sector %u\n", bname, x);
	    } else
		memset(img, 0, bpb.bps);
	    if (!lsn ||
	      (fat == 32 && bpb.bkbs != MAXU16 && lsn == bpb.bkbs)) {
		x1 = BS_SIZE;
		bsbpb = (struct bsbpb *)(img + x1);
		mk2(bsbpb->bps, bpb.bps);
		mk1(bsbpb->spc, bpb.spc);
		mk2(bsbpb->res, bpb.res);
		mk1(bsbpb->nft, bpb.nft);
		mk2(bsbpb->rde, bpb.rde);
		mk2(bsbpb->sec, bpb.sec);
		mk1(bsbpb->mid, bpb.mid);
		mk2(bsbpb->spf, bpb.spf);
		mk2(bsbpb->spt, bpb.spt);
		mk2(bsbpb->hds, bpb.hds);
		mk4(bsbpb->hid, bpb.hid);
		mk4(bsbpb->bsec, bpb.bsec);
		x1 += BSBPB_SIZE;
		if (fat == 32) {
		    bsxbpb = (struct bsxbpb *)(img + x1);
		    mk4(bsxbpb->bspf, bpb.bspf);
		    mk2(bsxbpb->xflg, 0);
		    mk2(bsxbpb->vers, 0);
		    mk4(bsxbpb->rdcl, bpb.rdcl);
		    mk2(bsxbpb->infs, bpb.infs);
		    mk2(bsxbpb->bkbs, bpb.bkbs);
		    x1 += BSXBPB_SIZE;
		}
		bsx = (struct bsx *)(img + x1);
		mk1(bsx->sig, 0x29);
		if (Iflag)
		    x = opt_I;
		else
		    x = (((u_int)(1 + tm->tm_mon) << 8 |
			  (u_int)tm->tm_mday) +
			 ((u_int)tm->tm_sec << 8 |
			  (u_int)(tv.tv_usec / 10))) << 16 |
			((u_int)(1900 + tm->tm_year) +
			 ((u_int)tm->tm_hour << 8 |
			  (u_int)tm->tm_min));
		mk4(bsx->volid, x);
		mklabel(bsx->label, opt_L ? opt_L : "NO_NAME");
		snprintf(buf, sizeof(buf), "FAT%u", fat);
		setstr(bsx->type, buf, sizeof(bsx->type));
		if (!opt_B) {
		    x1 += BSX_SIZE;
		    bs = (struct bs *)img;
		    mk1(bs->jmp[0], 0xeb);
		    mk1(bs->jmp[1], x1 - 2);
		    mk1(bs->jmp[2], 0x90);
		    setstr(bs->oem, opt_O ? opt_O : "NetBSD",
			   sizeof(bs->oem));
		    memcpy(img + x1, bootcode, sizeof(bootcode));
		    mk2(img + bpb.bps - 2, DOSMAGIC);
		}
	    } else if (fat == 32 && bpb.infs != MAXU16 &&
		       (lsn == bpb.infs ||
			(bpb.bkbs != MAXU16 &&
			 lsn == bpb.bkbs + bpb.infs))) {
		mk4(img, 0x41615252);
		mk4(img + bpb.bps - 28, 0x61417272);
		mk4(img + bpb.bps - 24, 0xffffffff);
		mk4(img + bpb.bps - 20, bpb.rdcl);
		mk2(img + bpb.bps - 2, DOSMAGIC);
	    } else if (lsn >= bpb.res && lsn < dir &&
		       !((lsn - bpb.res) %
			 (bpb.spf ? bpb.spf : bpb.bspf))) {
		mk1(img[0], bpb.mid);
		for (x = 1; x < fat * (fat == 32 ? 3 : 2) / 8; x++)
		    mk1(img[x], fat == 32 && x % 4 == 3 ? 0x0f : 0xff);
	    } else if (lsn == dir && opt_L) {
		de = (struct de *)img;
		mklabel(de->namext, opt_L);
		mk1(de->attr, 050);
		x = (u_int)tm->tm_hour << 11 |
		    (u_int)tm->tm_min << 5 |
		    (u_int)tm->tm_sec >> 1;
		mk2(de->time, x);
		x = (u_int)(tm->tm_year - 80) << 9 |
		    (u_int)(tm->tm_mon + 1) << 5 |
		    (u_int)tm->tm_mday;
		mk2(de->date, x);
	    }
	    if ((n = write(fd, img, bpb.bps)) == -1)
		fprintf(stderr, "%s\n", fname);
	    if (n != bpb.bps)
		fprintf(stderr, "%s: can't write sector %u\n", fname, lsn);
	}
    }
    return 0;
}

/*
 * Print out BPB values.
 */
static void
print_bpb(struct bpb *bpb)
{
    printf("bps=%u spc=%u res=%u nft=%u", bpb->bps, bpb->spc, bpb->res,
	   bpb->nft);
    if (bpb->rde)
	printf(" rde=%u", bpb->rde);
    if (bpb->sec)
	printf(" sec=%u", bpb->sec);
    printf(" mid=%#x", bpb->mid);
    if (bpb->spf)
	printf(" spf=%u", bpb->spf);
    printf(" spt=%u hds=%u hid=%u", bpb->spt, bpb->hds, bpb->hid);
    if (bpb->bsec)
	printf(" bsec=%u", bpb->bsec);
    if (!bpb->spf) {
	printf(" bspf=%u rdcl=%u", bpb->bspf, bpb->rdcl);
	printf(" infs=");
	printf(bpb->infs == MAXU16 ? "%#x" : "%u", bpb->infs);
	printf(" bkbs=");
	printf(bpb->bkbs == MAXU16 ? "%#x" : "%u", bpb->bkbs);
    }
    printf("\n");
}

/*
 * Check a disk geometry value.
 */
static u_int
ckgeom(const char *fname, u_int val, const char *msg)
{
    if (!val)
	fprintf(stderr, "%s: no default %s\n", fname, msg);
    if (val > MAXU16)
	fprintf(stderr, "%s: illegal %s\n", fname, msg);
    return val;
}

/*
 * Convert and check a numeric option argument.
 */
static u_int
argtou(const char *arg, u_int lo, u_int hi, const char *msg)
{
    char *s;
    u_long x;

    errno = 0;
    x = strtoul(arg, &s, 0);
    if (errno || !*arg || *s || x < lo || x > hi)
	fprintf(stderr, "%s: bad %s\n", arg, msg);
    return x;
}

/*
 * Check a volume label.
 */
static int
oklabel(const char *src)
{
    int c, i;

    for (i = 0; i <= 11; i++) {
	c = (u_char)*src++;
	if (c < ' ' + !i || strchr("\"*+,./:;<=>?[\\]|", c))
	    break;
    }
    return i && !c;
}

/*
 * Make a volume label.
 */
static void
mklabel(u_int8_t *dest, const char *src)
{
    int c, i;

    for (i = 0; i < 11; i++) {
	c = *src ? toupper((unsigned char)*src++) : ' ';
	*dest++ = !i && c == '\xe5' ? 5 : c;
    }
}

/*
 * Copy string, padding with spaces.
 */
static void
setstr(u_int8_t *dest, const char *src, size_t len)
{
    while (len--)
	*dest++ = *src ? *src++ : ' ';
}

/*
 * Print usage message.
 */
static void
usage(char* progname)
{
    fprintf(stderr,
	    "usage: %s [ -options ] special [disktype]\n", progname);
    fprintf(stderr, "where the options are:\n");
    fprintf(stderr, "\t-N don't create file system: "
	    "just print out parameters\n");
    fprintf(stderr, "\t-B get bootstrap from file\n");
    fprintf(stderr, "\t-F FAT type (12, 16, or 32)\n");
    fprintf(stderr, "\t-I volume ID\n");
    fprintf(stderr, "\t-L volume label\n");
    fprintf(stderr, "\t-O OEM string\n");
    fprintf(stderr, "\t-S bytes/sector\n");
    fprintf(stderr, "\t-a sectors/FAT\n");
    fprintf(stderr, "\t-b block size\n");
    fprintf(stderr, "\t-c sectors/cluster\n");
    fprintf(stderr, "\t-e root directory entries\n");
    fprintf(stderr, "\t-h drive heads\n");
    fprintf(stderr, "\t-i file system info sector\n");
    fprintf(stderr, "\t-k backup boot sector\n");
    fprintf(stderr, "\t-m media descriptor\n");
    fprintf(stderr, "\t-n number of FATs\n");
    fprintf(stderr, "\t-o hidden sectors\n");
    fprintf(stderr, "\t-r reserved sectors\n");
    fprintf(stderr, "\t-s file system size (sectors)\n");
    fprintf(stderr, "\t-u sectors/track\n");
    exit(1);
}


