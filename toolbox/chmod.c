#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <sys/limits.h>
#include <sys/stat.h>

#include <unistd.h>
#include <time.h>

void recurse_chmod(char* path, int mode)
{
    struct dirent *dp;
    DIR *dir = opendir(path);
    if (dir == NULL) {
        // not a directory, carry on
        return;
    }
    char *subpath = malloc(sizeof(char)*PATH_MAX);
    int pathlen = strlen(path);

    while ((dp = readdir(dir)) != NULL) {
        if (strcmp(dp->d_name, ".") == 0 ||
            strcmp(dp->d_name, "..") == 0) continue;

        if (strlen(dp->d_name) + pathlen + 2/*NUL and slash*/ > PATH_MAX) {
            fprintf(stderr, "Invalid path specified: too long\n");
            exit(1);
        }

        strcpy(subpath, path);
        strcat(subpath, "/");
        strcat(subpath, dp->d_name);

        if (chmod(subpath, mode) < 0) {
            fprintf(stderr, "Unable to chmod %s: %s\n", subpath, strerror(errno));
            exit(1);
        }

        recurse_chmod(subpath, mode);
    }
    free(subpath);
    closedir(dir);
}

static int usage()
{
    fprintf(stderr, "Usage: chmod [OPTION] <MODE> <FILE>\n");
    fprintf(stderr, "  -R, --recursive         change files and directories recursively\n");
    fprintf(stderr, "  --help                  display this help and exit\n");

    return 10;
}

int chmod_main(int argc, char **argv)
{
    int i;

    if (argc < 3 || strcmp(argv[1], "--help") == 0) {
        return usage();
    }

    int recursive = (strcmp(argv[1], "-R") == 0 ||
                     strcmp(argv[1], "--recursive") == 0) ? 1 : 0;

    if (recursive && argc < 4) {
        return usage();
    }

    if (recursive) {
        argc--;
        argv++;
    }

    int mode = 0;
    const char* s = argv[1];
    while (*s) {
        if (*s >= '0' && *s <= '7') {
            mode = (mode<<3) | (*s-'0');
        }
        else {
            fprintf(stderr, "Bad mode\n");
            return 10;
        }
        s++;
    }

    for (i = 2; i < argc; i++) {
        if (chmod(argv[i], mode) < 0) {
            fprintf(stderr, "Unable to chmod %s: %s\n", argv[i], strerror(errno));
            return 10;
        }
        if (recursive) {
            recurse_chmod(argv[i], mode);
        }
    }
    return 0;
}

