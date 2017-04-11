/* gzip.c - gzip/gunzip/zcat tools for gzip data
 *
 * Copyright 2017 The Android Open Source Project
 *
 * GZIP RFC: http://www.ietf.org/rfc/rfc1952.txt

TODO: port to toybox.

*/

#define _GNU_SOURCE

#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <zlib.h>

// toybox-style flags/globals.
#define FLAG_c 1
#define FLAG_d 2
#define FLAG_f 4
#define FLAG_k 8
static struct {
  int optflags;
} toys;
static struct {
  int level;
} TT;

static void xstat(const char *path, struct stat *sb)
{
  if (stat(path, sb)) error(1, errno, "stat %s", path);
}

static void fix_time(const char *path, struct stat *sb)
{
  struct timespec times[] = { sb->st_atim, sb->st_mtim };

  if (utimensat(AT_FDCWD, path, times, 0)) error(1, errno, "utimes");
}

static FILE *xfdopen(const char *name, int flags, mode_t open_mode,
    const char *mode)
{
  FILE *fp;
  int fd;

  if (!strcmp(name, "-")) fd = dup((*mode == 'r') ? 0 : 1);
  else fd = open(name, flags, open_mode);

  if (fd == -1) error(1, errno, "open %s (%s)", name, mode);
  fp = fdopen(fd, mode);
  if (fp == NULL) error(1, errno, "fopen %s (%s)", name, mode);
  return fp;
}

static gzFile xgzopen(const char *name, int flags, mode_t open_mode,
    const char *mode)
{
  gzFile f;
  int fd;

  if (!strcmp(name, "-")) fd = dup((*mode == 'r') ? 0 : 1);
  else fd = open(name, flags, open_mode);

  if (fd == -1) error(1, errno, "open %s (%s)", name, mode);
  f = gzdopen(fd, mode);
  if (f == NULL) error(1, errno, "gzdopen %s (%s)", name, mode);
  return f;
}

static void gzfatal(gzFile f, char *what)
{
  int err;
  const char *msg = gzerror(f, &err);

  error(1, (err == Z_ERRNO) ? errno : 0, "%s: %s", what, msg);
}

static void gunzip(char *arg)
{
  struct stat sb;
  char buf[BUFSIZ];
  int len, both_files;
  char *in_name, *out_name;
  gzFile in;
  FILE *out;

  // "gunzip x.gz" will decompress "x.gz" to "x".
  len = strlen(arg);
  if (len > 3 && !strcmp(arg+len-3, ".gz")) {
    in_name = strdup(arg);
    out_name = strdup(arg);
    out_name[len-3] = '\0';
  } else if (!strcmp(arg, "-")) {
    // "-" means stdin; assume output to stdout.
    // TODO: require -f to read compressed data from tty?
    in_name = strdup("-");
    out_name = strdup("-");
  } else error(1, 0, "unknown suffix");

  if (toys.optflags&FLAG_c) {
    free(out_name);
    out_name = strdup("-");
  }

  both_files = strcmp(in_name, "-") && strcmp(out_name, "-");
  if (both_files) xstat(in_name, &sb);

  in = xgzopen(in_name, O_RDONLY, 0, "r");
  out = xfdopen(out_name, O_CREAT|O_WRONLY|((toys.optflags&FLAG_f)?0:O_EXCL),
      both_files?sb.st_mode:0666, "w");

  while ((len = gzread(in, buf, sizeof(buf))) > 0) {
    if (fwrite(buf, 1, len, out) != (size_t) len) error(1, errno, "fwrite");
  }
  if (len < 0) gzfatal(in, "gzread");
  if (fclose(out)) error(1, errno, "fclose");
  if (gzclose(in) != Z_OK) error(1, 0, "gzclose");

  if (both_files) fix_time(out_name, &sb);
  if (!(toys.optflags&(FLAG_c|FLAG_k))) unlink(in_name);
  free(in_name);
  free(out_name);
}

static void gzip(char *in_name)
{
  char buf[BUFSIZ];
  size_t len;
  char *out_name;
  FILE *in;
  gzFile out;
  struct stat sb;
  int both_files;

  if (toys.optflags&FLAG_c) {
    out_name = strdup("-");
  } else {
    if (asprintf(&out_name, "%s.gz", in_name) == -1) {
      error(1, errno, "asprintf");
    }
  }

  both_files = strcmp(in_name, "-") && strcmp(out_name, "-");
  if (both_files) xstat(in_name, &sb);

  snprintf(buf, sizeof(buf), "w%d", TT.level);
  in = xfdopen(in_name, O_RDONLY, 0, "r");
  out = xgzopen(out_name, O_CREAT|O_WRONLY|((toys.optflags&FLAG_f)?0:O_EXCL),
      both_files?sb.st_mode:0, buf);

  while ((len = fread(buf, 1, sizeof(buf), in)) > 0) {
    if (gzwrite(out, buf, len) != (int) len) gzfatal(out, "gzwrite");
  }
  if (ferror(in)) error(1, errno, "fread");
  if (fclose(in)) error(1, errno, "fclose");
  if (gzclose(out) != Z_OK) error(1, 0, "gzclose");

  if (both_files) fix_time(out_name, &sb);
  if (!(toys.optflags&(FLAG_c|FLAG_k))) unlink(in_name);
  free(out_name);
}

static void do_file(char *arg)
{
  if (toys.optflags&FLAG_d) gunzip(arg);
  else gzip(arg);
}

static void usage()
{
  char *cmd = basename(getprogname());

  printf("usage: %s [-c] [-d] [-f] [-#] [FILE...]\n", cmd);
  printf("\n");
  if (!strcmp(cmd, "zcat")) {
    printf("Decompress files to stdout. Like `gzip -dc`.\n");
    printf("\n");
    printf("-c\tOutput to stdout\n");
    printf("-f\tForce: allow read from tty\n");
  } else if (!strcmp(cmd, "gunzip")) {
    printf("Decompress files. With no files, decompresses stdin to stdout.\n");
    printf("On success, the input files are removed and replaced by new\n");
    printf("files without the .gz suffix.\n");
    printf("\n");
    printf("-c\tOutput to stdout\n");
    printf("-f\tForce: allow read from tty\n");
    printf("-k\tKeep input files (don't remove)\n");
  } else { // gzip
    printf("Compress files. With no files, compresses stdin to stdout.\n");
    printf("On success, the input files are removed and replaced by new\n");
    printf("files with the .gz suffix.\n");
    printf("\n");
    printf("-c\tOutput to stdout\n");
    printf("-d\tDecompress (act as gunzip)\n");
    printf("-f\tForce: allow overwrite of output file\n");
    printf("-k\tKeep input files (don't remove)\n");
    printf("-#\tCompression level 1-9 (1:fastest, 6:default, 9:best)\n");
  }
  printf("\n");
}

int main(int argc, char *argv[])
{
  char *cmd = basename(argv[0]);
  int opt_ch;

  toys.optflags = 0;
  TT.level = 6;

  if (!strcmp(cmd, "gunzip")) {
    // gunzip == gzip -d
    toys.optflags = FLAG_d;
  } else if (!strcmp(cmd, "zcat")) {
    // zcat == gzip -dc
    toys.optflags = (FLAG_c|FLAG_d);
  }

  while ((opt_ch = getopt(argc, argv, "cdfhk123456789")) != -1) {
    switch (opt_ch) {
    case 'c': toys.optflags |= FLAG_c; break;
    case 'd': toys.optflags |= FLAG_d; break;
    case 'f': toys.optflags |= FLAG_f; break;
    case 'k': toys.optflags |= FLAG_k; break;

    case '1':
    case '2':
    case '3':
    case '4':
    case '5':
    case '6':
    case '7':
    case '8':
    case '9':
      TT.level = opt_ch - '0';
      break;

    default:
      usage();
      return 1;
    }
  }

  if (optind == argc) {
    // With no arguments, we go from stdin to stdout.
    toys.optflags |= FLAG_c;
    do_file("-");
    return 0;
  }

  // Otherwise process each file in turn.
  while (optind < argc) do_file(argv[optind++]);
  return 0;
}
