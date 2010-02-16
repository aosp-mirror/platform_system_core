#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>

#include <unistd.h>
#include <time.h>

int chown_main(int argc, char **argv)
{
    int i;

    if (argc < 3) {
        fprintf(stderr, "Usage: chown <USER>[.GROUP] <FILE1> [FILE2] ...\n");
        return 10;
    }

    // Copy argv[1] to 'user' so we can truncate it at the period
    // if a group id specified.
    char user[32];
    char *group = NULL;
    strncpy(user, argv[1], sizeof(user));
    if ((group = strchr(user, '.')) != NULL) {
        *group++ = '\0';
    }

    // Lookup uid (and gid if specified)
    struct passwd *pw;
    struct group *grp = NULL;
    uid_t uid;
    gid_t gid = -1; // passing -1 to chown preserves current group

    pw = getpwnam(user);
    if (pw != NULL) {
        uid = pw->pw_uid;
    } else {
        char* endptr;
        uid = (int) strtoul(user, &endptr, 0);
        if (endptr == user) {  // no conversion
          fprintf(stderr, "No such user '%s'\n", user);
          return 10;
        }
    }

    if (group != NULL) {
        grp = getgrnam(group);
        if (grp != NULL) {
            gid = grp->gr_gid;
        } else {
            char* endptr;
            gid = (int) strtoul(group, &endptr, 0);
            if (endptr == group) {  // no conversion
                fprintf(stderr, "No such group '%s'\n", group);
                return 10;
            }
        }
    }

    for (i = 2; i < argc; i++) {
        if (chown(argv[i], uid, gid) < 0) {
            fprintf(stderr, "Unable to chmod %s: %s\n", argv[i], strerror(errno));
            return 10;
        }
    }

    return 0;
}
