#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <selinux/selinux.h>

int chcon_main(int argc, char **argv)
{
    int rc, i;

    if (argc < 3) {
        fprintf(stderr, "usage:  %s context path...\n", argv[0]);
        exit(1);
    }

    for (i = 2; i < argc; i++) {
        rc = setfilecon(argv[i], argv[1]);
        if (rc < 0) {
            fprintf(stderr, "%s:  Could not label %s with %s:  %s\n",
                    argv[0], argv[i], argv[1], strerror(errno));
            exit(2);
        }
    }
    exit(0);
}
