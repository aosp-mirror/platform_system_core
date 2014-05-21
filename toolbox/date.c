#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <linux/android_alarm.h>
#include <linux/rtc.h>
#include <sys/ioctl.h>

static int settime_alarm(struct timespec *ts) {
    int fd, ret;

    fd = open("/dev/alarm", O_RDWR);
    if (fd < 0)
        return fd;

    ret = ioctl(fd, ANDROID_ALARM_SET_RTC, ts);
    close(fd);
    return ret;
}

static int settime_alarm_tm(struct tm *tm) {
    time_t t;
    struct timespec ts;

    t = mktime(tm);
    ts.tv_sec = t;
    ts.tv_nsec = 0;
    return settime_alarm(&ts);
}

static int settime_alarm_timeval(struct timeval *tv) {
    struct timespec ts;

    ts.tv_sec = tv->tv_sec;
    ts.tv_nsec = tv->tv_usec * 1000;
    return settime_alarm(&ts);
}

static int settime_rtc_tm(struct tm *tm) {
    int fd, ret;
    struct timeval tv;
    struct rtc_time rtc;

    fd = open("/dev/rtc0", O_RDWR);
    if (fd < 0)
        return fd;

    tv.tv_sec = mktime(tm);
    tv.tv_usec = 0;

    ret = settimeofday(&tv, NULL);
    if (ret < 0)
        goto done;

    memset(&rtc, 0, sizeof(rtc));
    rtc.tm_sec = tm->tm_sec;
    rtc.tm_min = tm->tm_min;
    rtc.tm_hour = tm->tm_hour;
    rtc.tm_mday = tm->tm_mday;
    rtc.tm_mon = tm->tm_mon;
    rtc.tm_year = tm->tm_year;
    rtc.tm_wday = tm->tm_wday;
    rtc.tm_yday = tm->tm_yday;
    rtc.tm_isdst = tm->tm_isdst;

    ret = ioctl(fd, RTC_SET_TIME, rtc);
done:
    close(fd);
    return ret;
}

static int settime_rtc_timeval(struct timeval *tv) {
    struct tm tm, *err;
    time_t t = tv->tv_sec;

    err = gmtime_r(&t, &tm);
    if (!err)
        return -1;

    return settime_rtc_tm(&tm);
}

static void settime(char *s) {
    struct tm tm;
    int day = atoi(s);
    int hour;

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

    if (settime_alarm_tm(&tm) < 0)
        settime_rtc_tm(&tm);
}

static char *parse_time(const char *str, struct timeval *ts) {
  char *s;
  long fs = 0; /* fractional seconds */

  ts->tv_sec = strtoumax(str, &s, 10);

  if (*s == '.') {
    s++;
    int count = 0;

    /* read up to 6 digits (microseconds) */
    while (*s && isdigit(*s)) {
      if (++count < 7) {
        fs = fs*10 + (*s - '0');
      }
      s++;
    }

    for (; count < 6; count++) {
      fs *= 10;
    }
  }

  ts->tv_usec = fs;
  return s;
}

int date_main(int argc, char *argv[])
{
    int c;
    int res;
    struct tm tm;
    time_t t;
    struct timeval tv;
    char strbuf[260];

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
        parse_time(argv[optind], &tv);
        printf("time %s -> %lu.%lu\n", argv[optind], tv.tv_sec, tv.tv_usec);
        res = settime_alarm_timeval(&tv);
        if (res < 0)
            res = settime_rtc_timeval(&tv);
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
