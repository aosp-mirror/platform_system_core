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
    SELboolean *b = alloca(nargs * sizeof(SELboolean));
    char *v;
    int i;

    if (is_selinux_enabled() <= 0)
        return 0;

    for (i = 1; i < nargs; i++) {
        char *name = args[i];
        v = strchr(name, '=');
        if (!v) {
            fprintf(stderr, "setsebool: argument %s had no =\n", name);
            return -1;
        }
        *v++ = 0;
        b[i-1].name = name;
        if (!strcmp(v, "1") || !strcasecmp(v, "true") || !strcasecmp(v, "on"))
            b[i-1].value = 1;
        else if (!strcmp(v, "0") || !strcasecmp(v, "false") || !strcasecmp(v, "off"))
            b[i-1].value = 0;
        else {
            fprintf(stderr, "setsebool: invalid value %s\n", v);
            return -1;
        }
    }

    if (security_set_boolean_list(nargs - 1, b, 0) < 0)
    {
        fprintf(stderr, "setsebool: unable to set booleans: %s", strerror(errno));
        return -1;
    }

    return 0;
}

int setsebool_main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "Usage:  %s name=value...\n", argv[0]);
        exit(1);
    }

    return do_setsebool(argc, argv);
}
