#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <selinux/selinux.h>

int runcon_main(int argc, char **argv)
{
    int rc;

    if (argc < 3) {
        fprintf(stderr, "usage:  %s context program args...\n", argv[0]);
        exit(1);
    }

    rc = setexeccon(argv[1]);
    if (rc < 0) {
        fprintf(stderr, "Could not set context to %s:  %s\n", argv[1], strerror(errno));
        exit(2);
    }

    argv += 2;
    argc -= 2;
    execvp(argv[0], argv);
    fprintf(stderr, "Could not exec %s:  %s\n", argv[0], strerror(errno));
    exit(3);
}
