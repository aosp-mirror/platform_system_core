#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <asm/ioctl.h>
//#include <linux/rtc.h>
#include <linux/android_alarm.h>

int alarm_main(int argc, char *argv[])
{
	int c;
    int res;
	struct tm tm;
	time_t t;
	struct timespec ts;
//	struct rtc_time rtc_time;
	char strbuf[26];
	int afd;
	int nfd;
//	struct timeval timeout = { 0, 0 };
    int wait = 0;
	fd_set rfds;
	const char wake_lock_id[] = "alarm_test"; 
	int waitalarmmask = 0;

    int useutc = 0;
	android_alarm_type_t alarmtype_low = ANDROID_ALARM_RTC_WAKEUP;
	android_alarm_type_t alarmtype_high = ANDROID_ALARM_RTC_WAKEUP;
	android_alarm_type_t alarmtype = 0;

    do {
        //c = getopt(argc, argv, "uw:");
        c = getopt(argc, argv, "uwat:");
        if (c == EOF)
            break;
        switch (c) {
        case 'u':
            useutc = 1;
            break;
		case 't':
			alarmtype_low = alarmtype_high = strtol(optarg, NULL, 0);
			break;
		case 'a':
			alarmtype_low = ANDROID_ALARM_RTC_WAKEUP;
			alarmtype_high = ANDROID_ALARM_TYPE_COUNT - 1;
			break;
        case 'w':
            //timeout.tv_sec = strtol(optarg, NULL, 0);
            wait = 1;
            break;
        case '?':
            fprintf(stderr, "%s: invalid option -%c\n",
                argv[0], optopt);
            exit(1);
        }
    } while (1);
    if(optind + 2 < argc) {
        fprintf(stderr,"%s [-uwa] [-t type] [seconds]\n", argv[0]);
        return 1;
    }

    afd = open("/dev/alarm", O_RDWR);
    if(afd < 0) {
        fprintf(stderr, "Unable to open rtc: %s\n", strerror(errno));
        return 1;
    }

    if(optind == argc) {
		for(alarmtype = alarmtype_low; alarmtype <= alarmtype_high; alarmtype++) {
			waitalarmmask |= 1U << alarmtype;
		}
#if 0
        res = ioctl(fd, RTC_ALM_READ, &tm);
        if(res < 0) {
            fprintf(stderr, "Unable to read alarm: %s\n", strerror(errno));
			return 1;
        }
#endif
#if 0
		t = timegm(&tm);
        if(useutc)
            gmtime_r(&t, &tm);
        else
            localtime_r(&t, &tm);
#endif
#if 0
        asctime_r(&tm, strbuf);
        printf("%s", strbuf);
#endif
    }
    else if(optind + 1 == argc) {
#if 0
        res = ioctl(fd, RTC_RD_TIME, &tm);
        if(res < 0) {
            fprintf(stderr, "Unable to set alarm: %s\n", strerror(errno));
			return 1;
        }
        asctime_r(&tm, strbuf);
        printf("Now: %s", strbuf);
        time(&tv.tv_sec);
#endif
#if 0
		time(&ts.tv_sec);
		ts.tv_nsec = 0;
		
        //strptime(argv[optind], NULL, &tm);
        //tv.tv_sec = mktime(&tm);
        //tv.tv_usec = 0;
#endif
		for(alarmtype = alarmtype_low; alarmtype <= alarmtype_high; alarmtype++) {
			waitalarmmask |= 1U << alarmtype;
		    res = ioctl(afd, ANDROID_ALARM_GET_TIME(alarmtype), &ts);
		    if(res < 0) {
		        fprintf(stderr, "Unable to get current time: %s\n", strerror(errno));
				return 1;
		    }
		    ts.tv_sec += strtol(argv[optind], NULL, 0);
		    //strtotimeval(argv[optind], &tv);
			gmtime_r(&ts.tv_sec, &tm);
		    printf("time %s -> %ld.%09ld\n", argv[optind], ts.tv_sec, ts.tv_nsec);
		    asctime_r(&tm, strbuf);
		    printf("Requested %s", strbuf);
			
		    res = ioctl(afd, ANDROID_ALARM_SET(alarmtype), &ts);
		    if(res < 0) {
		        fprintf(stderr, "Unable to set alarm: %s\n", strerror(errno));
				return 1;
		    }
		}
#if 0
        res = ioctl(fd, RTC_ALM_SET, &tm);
        if(res < 0) {
            fprintf(stderr, "Unable to set alarm: %s\n", strerror(errno));
			return 1;
        }
        res = ioctl(fd, RTC_AIE_ON);
        if(res < 0) {
            fprintf(stderr, "Unable to enable alarm: %s\n", strerror(errno));
			return 1;
        }
#endif
    }
    else {
        fprintf(stderr,"%s [-u] [date]\n", argv[0]);
        return 1;
    }

	if(wait) {
		while(waitalarmmask) {
			printf("wait for alarm %x\n", waitalarmmask);
			res = ioctl(afd, ANDROID_ALARM_WAIT);
			if(res < 0) {
				fprintf(stderr, "alarm wait failed\n");
			}
			printf("got alarm %x\n", res);
			waitalarmmask &= ~res;
			nfd = open("/sys/android_power/acquire_full_wake_lock", O_RDWR);
			write(nfd, wake_lock_id, sizeof(wake_lock_id) - 1);
			close(nfd);
			//sleep(5);
			nfd = open("/sys/android_power/release_wake_lock", O_RDWR);
			write(nfd, wake_lock_id, sizeof(wake_lock_id) - 1);
			close(nfd);
		}
		printf("done\n");
	}
#if 0	
	FD_ZERO(&rfds);
	FD_SET(fd, &rfds);
	res = select(fd + 1, &rfds, NULL, NULL, &timeout);
    if(res < 0) {
        fprintf(stderr, "select failed: %s\n", strerror(errno));
		return 1;
    }
	if(res > 0) {
		int event;
		read(fd, &event, sizeof(event));
		fprintf(stderr, "got %x\n", event);
	}
	else {
		fprintf(stderr, "timeout waiting for alarm\n");
	}
#endif

    close(afd);

    return 0;
}
