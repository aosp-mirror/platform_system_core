#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <cutils/iosched_policy.h>

static char *classes[] = {"none", "rt", "be", "idle", NULL};

int ionice_main(int argc, char *argv[])
{
    IoSchedClass clazz = IoSchedClass_NONE;
    int ioprio = 0;
    int pid;

    if(argc != 2 && argc != 4) {
        fprintf(stderr, "usage: ionice <pid> [none|rt|be|idle] [prio]\n");
        return 1;
    }

    if (!(pid = atoi(argv[1]))) {
        fprintf(stderr, "Invalid pid specified\n");
        return 1;
    }

    if (argc == 2) {
        if (android_get_ioprio(pid, &clazz, &ioprio)) {
            fprintf(stderr, "Failed to read priority (%s)\n", strerror(errno));
            return 1;
        }
        fprintf(stdout, "Pid %d, class %s (%d), prio %d\n", pid, classes[clazz], clazz, ioprio);
        return 0;
    }

    if (!strcmp(argv[2], "none")) {
        clazz = IoSchedClass_NONE;
    } else if (!strcmp(argv[2], "rt")) {
        clazz = IoSchedClass_RT;
    } else if (!strcmp(argv[2], "be")) {
        clazz = IoSchedClass_BE;
    } else if (!strcmp(argv[2], "idle")) {
        clazz = IoSchedClass_IDLE;
    } else {
        fprintf(stderr, "Unsupported class '%s'\n", argv[2]);
        return 1;
    }

    ioprio = atoi(argv[3]);

    printf("Setting pid %d i/o class to %d, prio %d\n", pid, clazz, ioprio);
    if (android_set_ioprio(pid, clazz, ioprio)) {
        fprintf(stderr, "Failed to set priority (%s)\n", strerror(errno));
        return 1;
    }

    return 0;
}
