#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>


int mv_main(int argc, char *argv[])
{
    const char* dest;
    struct stat st;
    int i;

    if (argc < 3) {
        fprintf(stderr,"USAGE: %s <source...> <destination>\n", argv[0]);
        return -1;
    }

    /* check if destination exists */
    dest = argv[argc - 1];
    if (stat(dest, &st)) {
        /* an error, unless the destination was missing */
        if (errno != ENOENT) {
            fprintf(stderr, "failed on %s - %s\n", dest, strerror(errno));
            return -1;
        }
        st.st_mode = 0;
    }

    for (i = 1; i < argc - 1; i++) {
        const char *source = argv[i];
        char fullDest[PATH_MAX + 1 + PATH_MAX + 1];
        /* assume we build "dest/source", and let rename() fail on pathsize */
        if (strlen(dest) + 1 + strlen(source) + 1 > sizeof(fullDest)) {
            fprintf(stderr, "path too long\n");
            return -1;
        }
        strcpy(fullDest, dest);

        /* if destination is a directory, concat the source file name */
        if (S_ISDIR(st.st_mode)) {
            const char *fileName = strrchr(source, '/');
            if (fullDest[strlen(fullDest)-1] != '/') {
                strcat(fullDest, "/");
            }
            strcat(fullDest, fileName ? fileName + 1 : source);
        }

        /* attempt to move it */
        if (rename(source, fullDest)) {
            fprintf(stderr, "failed on '%s' - %s\n", source, strerror(errno));
            return -1;
        }
    }

    return 0;
}

