#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>

static void print_uid(uid_t uid)
{
    struct passwd *pw = getpwuid(uid);

    if (pw) {
        printf("%d(%s)", uid, pw->pw_name);
    } else {
        printf("%d",uid);
    }
}

static void print_gid(gid_t gid)
{
    struct group *gr = getgrgid(gid);
    if (gr) {
        printf("%d(%s)", gid, gr->gr_name);
    } else {
        printf("%d",gid);
    }
}

int id_main(int argc, char **argv)
{
    gid_t list[64];
    int n, max;

    max = getgroups(64, list);
    if (max < 0) max = 0;

    printf("uid=");
    print_uid(getuid());
    printf(" gid=");
    print_gid(getgid());
    if (max) {
        printf(" groups=");
        print_gid(list[0]);
        for(n = 1; n < max; n++) {
            printf(",");
            print_gid(list[n]);
        }
    }
    printf("\n");
    return 0;
}
