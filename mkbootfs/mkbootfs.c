
#include <ctype.h>
#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <unistd.h>

#include <linux/kdev_t.h>

#include <private/android_filesystem_config.h>
#include <private/fs_config.h>

/* NOTES
**
** - see https://www.kernel.org/doc/Documentation/early-userspace/buffer-format.txt
**   for an explanation of this file format
** - dotfiles are ignored
** - directories named 'root' are ignored
*/

struct fs_config_entry {
    char* name;
    int uid, gid, mode;
};

static struct fs_config_entry* canned_config = NULL;
static const char* target_out_path = NULL;

#define TRAILER "TRAILER!!!"

static int total_size = 0;

static void fix_stat(const char *path, struct stat *s)
{
    uint64_t capabilities;
    if (canned_config) {
        // Use the list of file uid/gid/modes loaded from the file
        // given with -f.

        struct fs_config_entry* empty_path_config = NULL;
        struct fs_config_entry* p;
        for (p = canned_config; p->name; ++p) {
            if (!p->name[0]) {
                empty_path_config = p;
            }
            if (strcmp(p->name, path) == 0) {
                s->st_uid = p->uid;
                s->st_gid = p->gid;
                s->st_mode = p->mode | (s->st_mode & ~07777);
                return;
            }
        }
        s->st_uid = empty_path_config->uid;
        s->st_gid = empty_path_config->gid;
        s->st_mode = empty_path_config->mode | (s->st_mode & ~07777);
    } else {
        // Use the compiled-in fs_config() function.
        unsigned st_mode = s->st_mode;
        int is_dir = S_ISDIR(s->st_mode) || strcmp(path, TRAILER) == 0;
        fs_config(path, is_dir, target_out_path, &s->st_uid, &s->st_gid, &st_mode, &capabilities);
        s->st_mode = (typeof(s->st_mode)) st_mode;
    }

    if (S_ISREG(s->st_mode) || S_ISDIR(s->st_mode) || S_ISLNK(s->st_mode)) {
        s->st_rdev = 0;
    }
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
           major(s->st_rdev),
           minor(s->st_rdev),
           olen + 1,
           0,
           out,
           0
           );

    total_size += 6 + 8*13 + olen + 1;

    if(strlen(out) != (unsigned int)olen) errx(1, "ACK!");

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
    _eject(&s, TRAILER, 10, 0, 0);

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
    struct dirent *de;

    DIR* d = opendir(in);
    if (d == NULL) err(1, "cannot open directory '%s'", in);

    int size = 32;
    int entries = 0;
    char** names = malloc(size * sizeof(char*));
    if (names == NULL) {
      errx(1, "failed to allocate dir names array (size %d)", size);
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
            errx(1, "failed to reallocate dir names array (size %d)", size);
          }
        }
        names[entries] = strdup(de->d_name);
        if (names[entries] == NULL) {
          errx(1, "failed to strdup name \"%s\"", de->d_name);
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

    closedir(d);
}

static void _archive(char *in, char *out, int ilen, int olen)
{
    struct stat s;
    if(lstat(in, &s)) err(1, "could not stat '%s'", in);

    if(S_ISREG(s.st_mode)){
        int fd = open(in, O_RDONLY);
        if(fd < 0) err(1, "cannot open '%s' for read", in);

        char* tmp = (char*) malloc(s.st_size);
        if(tmp == 0) errx(1, "cannot allocate %zd bytes", s.st_size);

        if(read(fd, tmp, s.st_size) != s.st_size) {
            err(1, "cannot read %zd bytes", s.st_size);
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
        if(size < 0) err(1, "cannot read symlink '%s'", in);
        _eject(&s, out, olen, buf, size);
    } else if(S_ISBLK(s.st_mode) || S_ISCHR(s.st_mode) ||
              S_ISFIFO(s.st_mode) || S_ISSOCK(s.st_mode)) {
        _eject(&s, out, olen, NULL, 0);
    } else {
        errx(1, "Unknown '%s' (mode %d)?", in, s.st_mode);
    }
}

static void archive(const char* start, const char* prefix) {
    char in[8192];
    char out[8192];

    strcpy(in, start);
    strcpy(out, prefix);

    _archive_dir(in, out, strlen(in), strlen(out));
}

static void read_canned_config(char* filename)
{
    int allocated = 8;
    int used = 0;

    canned_config =
        (struct fs_config_entry*)malloc(allocated * sizeof(struct fs_config_entry));

    FILE* fp = fopen(filename, "r");
    if (fp == NULL) err(1, "failed to open canned file '%s'", filename);

    char* line = NULL;
    size_t allocated_len;
    while (getline(&line, &allocated_len, fp) != -1) {
        if (!line[0]) break;
        if (used >= allocated) {
            allocated *= 2;
            canned_config = (struct fs_config_entry*)realloc(
                canned_config, allocated * sizeof(struct fs_config_entry));
            if (canned_config == NULL) errx(1, "failed to reallocate memory");
        }

        struct fs_config_entry* cc = canned_config + used;

        if (isspace(line[0])) {
            cc->name = strdup("");
            cc->uid = atoi(strtok(line, " \n"));
        } else {
            cc->name = strdup(strtok(line, " \n"));
            cc->uid = atoi(strtok(NULL, " \n"));
        }
        cc->gid = atoi(strtok(NULL, " \n"));
        cc->mode = strtol(strtok(NULL, " \n"), NULL, 8);
        ++used;
    }
    if (used >= allocated) {
        ++allocated;
        canned_config = (struct fs_config_entry*)realloc(
            canned_config, allocated * sizeof(struct fs_config_entry));
        if (canned_config == NULL) errx(1, "failed to reallocate memory");
    }
    canned_config[used].name = NULL;

    free(line);
    fclose(fp);
}

static void devnodes_desc_error(const char* filename, unsigned long line_num,
                              const char* msg)
{
    errx(1, "failed to read nodes desc file '%s' line %lu: %s", filename, line_num, msg);
}

static int append_devnodes_desc_dir(char* path, char* args)
{
    struct stat s;

    if (sscanf(args, "%o %d %d", &s.st_mode, &s.st_uid, &s.st_gid) != 3) return -1;

    s.st_mode |= S_IFDIR;

    _eject(&s, path, strlen(path), NULL, 0);

    return 0;
}

static int append_devnodes_desc_nod(char* path, char* args)
{
    int minor, major;
    struct stat s;
    char dev;

    if (sscanf(args, "%o %d %d %c %d %d", &s.st_mode, &s.st_uid, &s.st_gid,
               &dev, &major, &minor) != 6) return -1;

    s.st_rdev = MKDEV(major, minor);
    switch (dev) {
    case 'b':
        s.st_mode |= S_IFBLK;
        break;
    case 'c':
        s.st_mode |= S_IFCHR;
        break;
    default:
        return -1;
    }

    _eject(&s, path, strlen(path), NULL, 0);

    return 0;
}

static void append_devnodes_desc(const char* filename)
{
    FILE* fp = fopen(filename, "re");
    if (!fp) err(1, "failed to open nodes description file '%s'", filename);

    unsigned long line_num = 0;

    char* line = NULL;
    size_t allocated_len;
    while (getline(&line, &allocated_len, fp) != -1) {
        char *type, *path, *args;

        line_num++;

        if (*line == '#') continue;

        if (!(type = strtok(line, " \t"))) {
            devnodes_desc_error(filename, line_num, "a type is missing");
        }

        if (*type == '\n') continue;

        if (!(path = strtok(NULL, " \t"))) {
            devnodes_desc_error(filename, line_num, "a path is missing");
        }

        if (!(args = strtok(NULL, "\n"))) {
            devnodes_desc_error(filename, line_num, "args are missing");
        }

        if (!strcmp(type, "dir")) {
            if (append_devnodes_desc_dir(path, args)) {
                devnodes_desc_error(filename, line_num, "bad arguments for dir");
            }
        } else if (!strcmp(type, "nod")) {
            if (append_devnodes_desc_nod(path, args)) {
                devnodes_desc_error(filename, line_num, "bad arguments for nod");
            }
        } else {
            devnodes_desc_error(filename, line_num, "type unknown");
        }
    }

    free(line);
    fclose(fp);
}

static const struct option long_options[] = {
    { "dirname",    required_argument,  NULL,   'd' },
    { "file",       required_argument,  NULL,   'f' },
    { "help",       no_argument,        NULL,   'h' },
    { "nodes",      required_argument,  NULL,   'n' },
    { NULL,         0,                  NULL,   0   },
};

static void usage(void)
{
    fprintf(stderr,
            "Usage: mkbootfs [-n FILE] [-d DIR|-f FILE] DIR...\n"
            "\n"
            "\t-d, --dirname=DIR: fs-config directory\n"
            "\t-f, --file=FILE: Canned configuration file\n"
            "\t-h, --help: Print this help\n"
            "\t-n, --nodes=FILE: Dev nodes description file\n"
            "\n"
            "Dev nodes description:\n"
            "\t[dir|nod] [perms] [uid] [gid] [c|b] [major] [minor]\n"
            "\tExample:\n"
            "\t\t# My device nodes\n"
            "\t\tdir dev 0755 0 0\n"
            "\t\tnod dev/null 0600 0 0 c 1 3\n"
    );
}

int main(int argc, char *argv[])
{
    int opt, unused;

    while ((opt = getopt_long(argc, argv, "hd:f:n:", long_options, &unused)) != -1) {
        switch (opt) {
        case 'd':
            target_out_path = argv[optind - 1];
            break;
        case 'f':
            read_canned_config(argv[optind - 1]);
            break;
        case 'h':
            usage();
            return 0;
        case 'n':
            append_devnodes_desc(argv[optind - 1]);
            break;
        default:
            usage();
            errx(1, "Unknown option %s", argv[optind - 1]);
        }
    }

    int num_dirs = argc - optind;
    argv += optind;

    if (num_dirs <= 0) {
        usage();
        errx(1, "no directories to process?!");
    }

    while(num_dirs-- > 0){
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
