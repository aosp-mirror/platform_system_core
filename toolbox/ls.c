#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>

#include <sys/stat.h>
#include <unistd.h>
#include <time.h>

#include <pwd.h>
#include <grp.h>

#include <linux/kdev_t.h>

// bits for flags argument
#define LIST_LONG           (1 << 0)
#define LIST_ALL            (1 << 1)
#define LIST_RECURSIVE      (1 << 2)
#define LIST_DIRECTORIES    (1 << 3)

// fwd
static int listpath(const char *name, int flags);

static char mode2kind(unsigned mode)
{
    switch(mode & S_IFMT){
    case S_IFSOCK: return 's';
    case S_IFLNK: return 'l';
    case S_IFREG: return '-';
    case S_IFDIR: return 'd';
    case S_IFBLK: return 'b';
    case S_IFCHR: return 'c';
    case S_IFIFO: return 'p';
    default: return '?';
    }
}

static void mode2str(unsigned mode, char *out)
{
    *out++ = mode2kind(mode);
    
    *out++ = (mode & 0400) ? 'r' : '-';
    *out++ = (mode & 0200) ? 'w' : '-';
    if(mode & 04000) {
        *out++ = (mode & 0100) ? 's' : 'S';
    } else {
        *out++ = (mode & 0100) ? 'x' : '-';
    }
    *out++ = (mode & 040) ? 'r' : '-';
    *out++ = (mode & 020) ? 'w' : '-';
    if(mode & 02000) {
        *out++ = (mode & 010) ? 's' : 'S';
    } else {
        *out++ = (mode & 010) ? 'x' : '-';
    }
    *out++ = (mode & 04) ? 'r' : '-';
    *out++ = (mode & 02) ? 'w' : '-';
    if(mode & 01000) {
        *out++ = (mode & 01) ? 't' : 'T';
    } else {
        *out++ = (mode & 01) ? 'x' : '-';
    }
    *out = 0;
}

static void user2str(unsigned uid, char *out)
{
    struct passwd *pw = getpwuid(uid);
    if(pw) {
        strcpy(out, pw->pw_name);
    } else {
        sprintf(out, "%d", uid);
    }
}

static void group2str(unsigned gid, char *out)
{
    struct group *gr = getgrgid(gid);
    if(gr) {
        strcpy(out, gr->gr_name);
    } else {
        sprintf(out, "%d", gid);
    }
}

static int listfile(const char *path, int flags)
{
    struct stat s;
    char date[32];
    char mode[16];
    char user[16];
    char group[16];
    const char *name;

    /* name is anything after the final '/', or the whole path if none*/
    name = strrchr(path, '/');
    if(name == 0) {
        name = path;
    } else {
        name++;
    }

    if(lstat(path, &s) < 0) {
        return -1;
    }

    mode2str(s.st_mode, mode);
    user2str(s.st_uid, user);
    group2str(s.st_gid, group);

    strftime(date, 32, "%Y-%m-%d %H:%M", localtime((const time_t*)&s.st_mtime));
    date[31] = 0;
    
// 12345678901234567890123456789012345678901234567890123456789012345678901234567890
// MMMMMMMM UUUUUUUU GGGGGGGGG XXXXXXXX YYYY-MM-DD HH:MM NAME (->LINK)

    switch(s.st_mode & S_IFMT) {
    case S_IFBLK:
    case S_IFCHR:
        printf("%s %-8s %-8s %3d, %3d %s %s\n",
               mode, user, group, 
               (int) MAJOR(s.st_rdev), (int) MINOR(s.st_rdev),
               date, name);
        break;
    case S_IFREG:
        printf("%s %-8s %-8s %8d %s %s\n",
               mode, user, group, (int) s.st_size, date, name);
        break;
    case S_IFLNK: {
        char linkto[256];
        int len;

        len = readlink(path, linkto, 256);
        if(len < 0) return -1;
        
        if(len > 255) {
            linkto[252] = '.';
            linkto[253] = '.';
            linkto[254] = '.';
            linkto[255] = 0;
        } else {
            linkto[len] = 0;
        }
        
        printf("%s %-8s %-8s          %s %s -> %s\n",
               mode, user, group, date, name, linkto);
        break;
    }
    default:
        printf("%s %-8s %-8s          %s %s\n",
               mode, user, group, date, name);

    }
    return 0;
}

static int listdir(const char *name, int flags)
{
    char tmp[4096];
    DIR *d;
    struct dirent *de;
    
    d = opendir(name);
    if(d == 0) {
        fprintf(stderr, "opendir failed, %s\n", strerror(errno));
        return -1;
    }

    while((de = readdir(d)) != 0){
        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
        if(de->d_name[0] == '.' && (flags & LIST_ALL) == 0) continue;
        if ((flags & LIST_LONG) != 0) {
            sprintf(tmp, "%s/%s", name, de->d_name);
            listfile(tmp, flags);
        } else {
            printf("%s\n", de->d_name);
        }
    }

    if (flags & LIST_RECURSIVE) {
        rewinddir(d);

        while ((de = readdir(d)) != 0) {
            struct stat s;
            int err;

            if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
                continue;
            if (de->d_name[0] == '.' && (flags & LIST_ALL) == 0)
                continue;

            if (!strcmp(name, "/")) sprintf(tmp, "/%s", de->d_name);
            else sprintf(tmp, "%s/%s", name, de->d_name);

            /*
             * If the name ends in a '/', use stat() so we treat it like a
             * directory even if it's a symlink.
             */
            if (tmp[strlen(tmp)-1] == '/')
                err = stat(tmp, &s);
            else
                err = lstat(tmp, &s);

            if (err < 0) {
                perror(tmp);
                closedir(d);
                return -1;
            }

            if (S_ISDIR(s.st_mode)) {
                printf("\n%s:\n", tmp);
                listdir(tmp, flags);
            }
        }
    }

    closedir(d);
    return 0;
}

static int listpath(const char *name, int flags)
{
    struct stat s;
    int err;

    /*
     * If the name ends in a '/', use stat() so we treat it like a
     * directory even if it's a symlink.
     */
    if (name[strlen(name)-1] == '/')
        err = stat(name, &s);
    else
        err = lstat(name, &s);

    if (err < 0) {
        perror(name);
        return -1;
    }

    if ((flags & LIST_DIRECTORIES) == 0 && S_ISDIR(s.st_mode)) {
        if (flags & LIST_RECURSIVE)
            printf("\n%s:\n", name);
        return listdir(name, flags);
    } else {
        if ((flags & LIST_LONG) != 0) {
            /* yeah this calls stat() again*/
            return listfile(name, flags);
        } else {
            printf("%s\n", name);
            return 0;
        }
    }
}

int ls_main(int argc, char **argv)
{
    int flags = 0;
    int listed = 0;
    
    if(argc > 1) {
        int i;
        int err = 0;

        for (i = 1; i < argc; i++) {
            if(!strcmp(argv[i], "-l")) {
                flags |= LIST_LONG;
            } else if (!strcmp(argv[i], "-a")) {
                flags |= LIST_ALL;
            } else if (!strcmp(argv[i], "-R")) {
                flags |= LIST_RECURSIVE;
            } else if (!strcmp(argv[i], "-d")) {
                flags |= LIST_DIRECTORIES;
            } else {
                listed++;
                if(listpath(argv[i], flags) != 0) {
                    err = EXIT_FAILURE;
                }
            }
        }

        if (listed  > 0) return err;
    }
    
    // list working directory if no files or directories were specified    
    return listpath(".", flags);
}
