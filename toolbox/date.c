#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <linux/android_alarm.h>
#include <sys/ioctl.h>

static void settime(char *s) {
    struct tm tm;
    int day = atoi(s);
    int hour;
    time_t t;
    int fd;
    struct timespec ts;

    while (*s && *s != '.')
        s++;

    if (*s)
        s++;

    hour = atoi(s);

    tm.tm_year = day / 10000 - 1900;
    tm.tm_mon = (day % 10000) / 100 - 1;
    tm.tm_mday = (day % 100);
    tm.tm_hour = hour / 10000;
    tm.tm_min = (hour % 10000) / 100;
    tm.tm_sec = (hour % 100);
    tm.tm_isdst = -1;

    t = mktime(&tm);
    
    fd = open("/dev/alarm", O_RDWR);
    ts.tv_sec = t;
    ts.tv_nsec = 0;
    ioctl(fd, ANDROID_ALARM_SET_RTC, &ts);
}

int date_main(int argc, char *argv[])
{
	int c;
    int res;
	struct tm tm;
	time_t t;
	struct timeval tv;
    struct timespec ts;
	char strbuf[260];
    int fd;

    int useutc = 0;

    tzset();

    do {
        c = getopt(argc, argv, "us:");
        if (c == EOF)
            break;
        switch (c) {
        case 'u':
            useutc = 1;
            break;
        case 's':
            settime(optarg);
            break;
        case '?':
            fprintf(stderr, "%s: invalid option -%c\n",
                argv[0], optopt);
            exit(1);
        }
    } while (1);
    if(optind + 2 < argc) {
        fprintf(stderr,"%s [-u] [date]\n", argv[0]);
        return 1;
    }

    int hasfmt = argc == optind + 1 && argv[optind][0] == '+';
    if(optind == argc || hasfmt) {
        char buf[2000];
        time(&t);
        if (useutc) {
            gmtime_r(&t, &tm);
            strftime(strbuf, sizeof(strbuf),
                     (hasfmt ? argv[optind] + 1 : "%a %b %e %H:%M:%S GMT %Y"),
                     &tm);
        } else {
            localtime_r(&t, &tm);
            strftime(strbuf, sizeof(strbuf),
                     (hasfmt ? argv[optind] + 1 : "%a %b %e %H:%M:%S %Z %Y"),
                     &tm);
        }
        printf("%s\n", strbuf);
    }
    else if(optind + 1 == argc) {
#if 0
        struct tm *tmptr;
        tmptr = getdate(argv[optind]);
        if(tmptr == NULL) {
            fprintf(stderr,"getdate_r failed\n");
            return 1;
        }
        tm = *tmptr;
#if 0
        if(getdate_r(argv[optind], &tm) < 0) {
            fprintf(stderr,"getdate_r failed %s\n", strerror(errno));
            return 1;
        }
#endif
#endif
        //strptime(argv[optind], NULL, &tm);
        //tv.tv_sec = mktime(&tm);
        //tv.tv_usec = 0;
        strtotimeval(argv[optind], &tv);
        printf("time %s -> %d.%d\n", argv[optind], tv.tv_sec, tv.tv_usec);
        fd = open("/dev/alarm", O_RDWR);
        ts.tv_sec = tv.tv_sec;
        ts.tv_nsec = tv.tv_usec * 1000;
        res = ioctl(fd, ANDROID_ALARM_SET_RTC, &ts);
        //res = settimeofday(&tv, NULL);
        if(res < 0) {
            fprintf(stderr,"settimeofday failed %s\n", strerror(errno));
            return 1;
        }
    }
    else {
        fprintf(stderr,"%s [-s 20070325.123456] [-u] [date]\n", argv[0]);
        return 1;
    }

    return 0;
}
