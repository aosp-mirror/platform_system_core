#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <selinux/selinux.h>
#include <errno.h>

static int do_setsebool(int nargs, char **args) {
    const char *name = args[1];
    const char *value = args[2];
    SELboolean b;

    if (is_selinux_enabled() <= 0)
        return 0;

    b.name = name;
    if (!strcmp(value, "1") || !strcasecmp(value, "true") || !strcasecmp(value, "on"))
        b.value = 1;
    else if (!strcmp(value, "0") || !strcasecmp(value, "false") || !strcasecmp(value, "off"))
        b.value = 0;
    else {
        fprintf(stderr, "setsebool: invalid value %s\n", value);
        return -1;
    }

    if (security_set_boolean_list(1, &b, 0) < 0)
    {
        fprintf(stderr, "setsebool: could not set %s to %s:  %s", name, value, strerror(errno));
        return -1;
    }

    return 0;
}

int setsebool_main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "Usage:  %s name value\n", argv[0]);
        exit(1);
    }

    return do_setsebool(argc, argv);
}
