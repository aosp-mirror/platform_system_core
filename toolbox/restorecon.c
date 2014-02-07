#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <selinux/selinux.h>
#include <selinux/android.h>

static const char *progname;

static void usage(void)
{
    fprintf(stderr, "usage:  %s [-FnrRv] pathname...\n", progname);
    exit(1);
}

int restorecon_main(int argc, char **argv)
{
    int ch, i, rc;
    unsigned int flags = 0;

    progname = argv[0];

    do {
        ch = getopt(argc, argv, "FnrRv");
        if (ch == EOF)
            break;
        switch (ch) {
        case 'F':
            flags |= SELINUX_ANDROID_RESTORECON_FORCE;
            break;
        case 'n':
            flags |= SELINUX_ANDROID_RESTORECON_NOCHANGE;
            break;
        case 'r':
        case 'R':
            flags |= SELINUX_ANDROID_RESTORECON_RECURSE;
            break;
        case 'v':
            flags |= SELINUX_ANDROID_RESTORECON_VERBOSE;
            break;
        default:
            usage();
        }
    } while (1);

    argc -= optind;
    argv += optind;
    if (!argc)
        usage();

    for (i = 0; i < argc; i++) {
        rc = selinux_android_restorecon(argv[i], flags);
        if (rc < 0)
            fprintf(stderr, "Could not restorecon %s:  %s\n", argv[i],
                    strerror(errno));
    }

    return 0;
}
