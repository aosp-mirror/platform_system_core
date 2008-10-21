#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>

#include <unistd.h>
#include <time.h>

int chmod_main(int argc, char **argv)
{
    int i;

    if (argc < 3) {
        fprintf(stderr, "Usage: chmod <MODE> <FILE>\n");
        return 10;
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
    }
    return 0;
}

