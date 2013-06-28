#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <fcntl.h>
#include <time.h>

static void usage(void)
{
        fprintf(stderr, "touch: usage: touch [-alm] [-t YYYYMMDD[.hhmmss]] <file>\n");
        exit(1);
}

static time_t parse_time(char *s)
{
    struct tm tm;
    int day = atoi(s);
    int hour = 0;

    while (*s && *s != '.') {
        s++;
    }

    if (*s) {
        s++;
        hour = atoi(s);
    }

    tm.tm_year = day / 10000 - 1900;
    tm.tm_mon = (day % 10000) / 100 - 1;
    tm.tm_mday = day % 100;
    tm.tm_hour = hour / 10000;
    tm.tm_min = (hour % 10000) / 100;
    tm.tm_sec = hour % 100;
    tm.tm_isdst = -1;

    return mktime(&tm);
}

int touch_main(int argc, char *argv[])
{
        int i, fd, aflag = 0, mflag = 0, debug = 0, flags = 0;
        struct timespec specified_time, times[2];
        char *file = 0;

        specified_time.tv_nsec = UTIME_NOW;

        for (i = 1; i < argc; i++) {
            if (argv[i][0] == '-') {
                /* an option */
                const char *arg = argv[i]+1;
                while (arg[0]) {
                    switch (arg[0]) {
                    case 'a': aflag = 1; break;
                    case 'm': mflag = 1; break;
                    case 't':
                        if ((i+1) >= argc)
                            usage();
                        specified_time.tv_sec = parse_time(argv[++i]);
                        if (specified_time.tv_sec == -1) {
                            fprintf(stderr, "touch: invalid timestamp specified\n");
                            exit(1);
                        }
                        specified_time.tv_nsec = 0;
                        break;
                    case 'l': flags |= AT_SYMLINK_NOFOLLOW; break;
                    case 'd': debug = 1; break;
                    default:
                        usage();
                    }
                    arg++;
                }
            } else {
                /* not an option, and only accept one filename */
                if (i+1 != argc)
                    usage();
                file = argv[i];
            }
        }

        if (! file) {
            fprintf(stderr, "touch: no file specified\n");
            exit(1);
        }

        if (access(file, F_OK))
            if ((fd=creat(file, 0666)) != -1)
                close(fd);

        if ((mflag == 0) && (aflag == 0))
            aflag = mflag = 1;

        if (aflag)
            times[0] = specified_time;
        else
            times[0].tv_nsec = UTIME_OMIT;

        if (mflag)
            times[1] = specified_time;
        else
            times[1].tv_nsec = UTIME_OMIT;

        if (debug) {
            fprintf(stderr, "file = %s\n", file);
            fprintf(stderr, "times[0].tv_sec = %ld, times[0].tv_nsec = %ld\n", times[0].tv_sec, times[0].tv_nsec);
            fprintf(stderr, "times[1].tv_sec = %ld, times[1].tv_nsec = %ld\n", times[1].tv_sec, times[1].tv_nsec);
            fprintf(stderr, "flags = 0x%8.8x\n", flags);
        }

        return utimensat(AT_FDCWD, file, times, flags);
}

