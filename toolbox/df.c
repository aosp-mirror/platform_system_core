#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/statfs.h>

static int ok = EXIT_SUCCESS;

static void printsize(long long n)
{
    char unit = 'K';
    n /= 1024;
    if (n > 1024) {
        n /= 1024;
        unit = 'M';
    }
    if (n > 1024) {
        n /= 1024;
        unit = 'G';
    }
    printf("%4lld%c", n, unit);
}

static void df(char *s, int always) {
    struct statfs st;

    if (statfs(s, &st) < 0) {
        fprintf(stderr, "%s: %s\n", s, strerror(errno));
        ok = EXIT_FAILURE;
    } else {
        if (st.f_blocks == 0 && !always)
            return;        
        printf("%-20s  ", s);
        printsize((long long)st.f_blocks * (long long)st.f_bsize);
        printf("  ");
        printsize((long long)(st.f_blocks - (long long)st.f_bfree) * st.f_bsize);
        printf("  ");
        printsize((long long)st.f_bfree * (long long)st.f_bsize);
        printf("   %d\n", (int) st.f_bsize);
    }
}

int df_main(int argc, char *argv[]) {
    printf("Filesystem             Size   Used   Free   Blksize\n");
    if (argc == 1) {
        char s[2000];
        FILE *f = fopen("/proc/mounts", "r");

        while (fgets(s, 2000, f)) {
            char *c, *e = s;

            for (c = s; *c; c++) {
                if (*c == ' ') {
                    e = c + 1;
                    break;
                }
            }

            for (c = e; *c; c++) {
                if (*c == ' ') {
                    *c = '\0';
                    break;
                }
            }

            df(e, 0);
        }

        fclose(f);
    } else {
        int i;

        for (i = 1; i < argc; i++) {
            df(argv[i], 1);
        }
    }

    exit(ok);
}
