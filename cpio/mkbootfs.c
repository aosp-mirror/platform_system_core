
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>

#include <stdarg.h>
#include <fcntl.h>

#include <private/android_filesystem_config.h>

/* NOTES
**
** - see buffer-format.txt from the linux kernel docs for
**   an explanation of this file format
** - dotfiles are ignored
** - directories named 'root' are ignored
** - device notes, pipes, etc are not supported (error)
*/

void die(const char *why, ...)
{
    va_list ap;

    va_start(ap, why);
    fprintf(stderr,"error: ");
    vfprintf(stderr, why, ap);
    fprintf(stderr,"\n");
    va_end(ap);
    exit(1);
}

static int verbose = 0;
static int total_size = 0;

static void fix_stat(const char *path, struct stat *s)
{
    fs_config(path, S_ISDIR(s->st_mode), &s->st_uid, &s->st_gid, &s->st_mode);
}

static void _eject(struct stat *s, char *out, int olen, char *data, unsigned datasize)
{
    // Nothing is special about this value, just picked something in the
    // approximate range that was being used already, and avoiding small
    // values which may be special.
    static unsigned next_inode = 300000;

    while(total_size & 3) {
        total_size++;
        putchar(0);
    }

    fix_stat(out, s);
//    fprintf(stderr, "_eject %s: mode=0%o\n", out, s->st_mode);

    printf("%06x%08x%08x%08x%08x%08x%08x"
           "%08x%08x%08x%08x%08x%08x%08x%s%c",
           0x070701,
           next_inode++,  //  s.st_ino,
           s->st_mode,
           0, // s.st_uid,
           0, // s.st_gid,
           1, // s.st_nlink,
           0, // s.st_mtime,
           datasize,
           0, // volmajor
           0, // volminor
           0, // devmajor
           0, // devminor,
           olen + 1,
           0,
           out,
           0
           );

    total_size += 6 + 8*13 + olen + 1;

    if(strlen(out) != olen) die("ACK!");

    while(total_size & 3) {
        total_size++;
        putchar(0);
    }

    if(datasize) {
        fwrite(data, datasize, 1, stdout);
        total_size += datasize;
    }
}

static void _eject_trailer()
{
    struct stat s;
    memset(&s, 0, sizeof(s));
    _eject(&s, "TRAILER!!!", 10, 0, 0);

    while(total_size & 0xff) {
        total_size++;
        putchar(0);
    }
}

static void _archive(char *in, char *out, int ilen, int olen);

static int compare(const void* a, const void* b) {
  return strcmp(*(const char**)a, *(const char**)b);
}

static void _archive_dir(char *in, char *out, int ilen, int olen)
{
    int i, t;
    DIR *d;
    struct dirent *de;

    if(verbose) {
        fprintf(stderr,"_archive_dir('%s','%s',%d,%d)\n",
                in, out, ilen, olen);
    }

    d = opendir(in);
    if(d == 0) die("cannot open directory '%s'", in);

    int size = 32;
    int entries = 0;
    char** names = malloc(size * sizeof(char*));
    if (names == NULL) {
      fprintf(stderr, "failed to allocate dir names array (size %d)\n", size);
      exit(1);
    }

    while((de = readdir(d)) != 0){
            /* xxx: feature? maybe some dotfiles are okay */
        if(de->d_name[0] == '.') continue;

            /* xxx: hack. use a real exclude list */
        if(!strcmp(de->d_name, "root")) continue;

        if (entries >= size) {
          size *= 2;
          names = realloc(names, size * sizeof(char*));
          if (names == NULL) {
            fprintf(stderr, "failed to reallocate dir names array (size %d)\n",
                    size);
            exit(1);
          }
        }
        names[entries] = strdup(de->d_name);
        if (names[entries] == NULL) {
          fprintf(stderr, "failed to strdup name \"%s\"\n",
                  de->d_name);
          exit(1);
        }
        ++entries;
    }

    qsort(names, entries, sizeof(char*), compare);

    for (i = 0; i < entries; ++i) {
        t = strlen(names[i]);
        in[ilen] = '/';
        memcpy(in + ilen + 1, names[i], t + 1);

        if(olen > 0) {
            out[olen] = '/';
            memcpy(out + olen + 1, names[i], t + 1);
            _archive(in, out, ilen + t + 1, olen + t + 1);
        } else {
            memcpy(out, names[i], t + 1);
            _archive(in, out, ilen + t + 1, t);
        }

        in[ilen] = 0;
        out[olen] = 0;

        free(names[i]);
    }
    free(names);
}

static void _archive(char *in, char *out, int ilen, int olen)
{
    struct stat s;

    if(verbose) {
        fprintf(stderr,"_archive('%s','%s',%d,%d)\n",
                in, out, ilen, olen);
    }

    if(lstat(in, &s)) die("could not stat '%s'\n", in);

    if(S_ISREG(s.st_mode)){
        char *tmp;
        int fd;

        fd = open(in, O_RDONLY);
        if(fd < 0) die("cannot open '%s' for read", in);

        tmp = (char*) malloc(s.st_size);
        if(tmp == 0) die("cannot allocate %d bytes", s.st_size);

        if(read(fd, tmp, s.st_size) != s.st_size) {
            die("cannot read %d bytes", s.st_size);
        }

        _eject(&s, out, olen, tmp, s.st_size);

        free(tmp);
        close(fd);
    } else if(S_ISDIR(s.st_mode)) {
        _eject(&s, out, olen, 0, 0);
        _archive_dir(in, out, ilen, olen);
    } else if(S_ISLNK(s.st_mode)) {
        char buf[1024];
        int size;
        size = readlink(in, buf, 1024);
        if(size < 0) die("cannot read symlink '%s'", in);
        _eject(&s, out, olen, buf, size);
    } else {
        die("Unknown '%s' (mode %d)?\n", in, s.st_mode);
    }
}

void archive(const char *start, const char *prefix)
{
    char in[8192];
    char out[8192];

    strcpy(in, start);
    strcpy(out, prefix);

    _archive_dir(in, out, strlen(in), strlen(out));
}

int main(int argc, char *argv[])
{
    argc--;
    argv++;

    if(argc == 0) die("no directories to process?!");

    while(argc-- > 0){
        char *x = strchr(*argv, '=');
        if(x != 0) {
            *x++ = 0;
        } else {
            x = "";
        }

        archive(*argv, x);

        argv++;
    }

    _eject_trailer();

    return 0;
}
