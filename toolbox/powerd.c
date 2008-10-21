#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/select.h>
#include <sys/inotify.h>

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

//#include <linux/input.h> // this does not compile

// from <linux/input.h>

struct input_event {
	struct timeval time;
	__u16 type;
	__u16 code;
	__s32 value;
};

#define EVIOCGVERSION		_IOR('E', 0x01, int)			/* get driver version */
#define EVIOCGID		_IOR('E', 0x02, struct input_id)	/* get device ID */
#define EVIOCGKEYCODE		_IOR('E', 0x04, int[2])			/* get keycode */
#define EVIOCSKEYCODE		_IOW('E', 0x04, int[2])			/* set keycode */

#define EVIOCGNAME(len)		_IOC(_IOC_READ, 'E', 0x06, len)		/* get device name */
#define EVIOCGPHYS(len)		_IOC(_IOC_READ, 'E', 0x07, len)		/* get physical location */
#define EVIOCGUNIQ(len)		_IOC(_IOC_READ, 'E', 0x08, len)		/* get unique identifier */

#define EVIOCGKEY(len)		_IOC(_IOC_READ, 'E', 0x18, len)		/* get global keystate */
#define EVIOCGLED(len)		_IOC(_IOC_READ, 'E', 0x19, len)		/* get all LEDs */
#define EVIOCGSND(len)		_IOC(_IOC_READ, 'E', 0x1a, len)		/* get all sounds status */
#define EVIOCGSW(len)		_IOC(_IOC_READ, 'E', 0x1b, len)		/* get all switch states */

#define EVIOCGBIT(ev,len)	_IOC(_IOC_READ, 'E', 0x20 + ev, len)	/* get event bits */
#define EVIOCGABS(abs)		_IOR('E', 0x40 + abs, struct input_absinfo)		/* get abs value/limits */
#define EVIOCSABS(abs)		_IOW('E', 0xc0 + abs, struct input_absinfo)		/* set abs value/limits */

#define EVIOCSFF		_IOC(_IOC_WRITE, 'E', 0x80, sizeof(struct ff_effect))	/* send a force effect to a force feedback device */
#define EVIOCRMFF		_IOW('E', 0x81, int)			/* Erase a force effect */
#define EVIOCGEFFECTS		_IOR('E', 0x84, int)			/* Report number of effects playable at the same time */

#define EVIOCGRAB		_IOW('E', 0x90, int)			/* Grab/Release device */

/*
 * Event types
 */

#define EV_SYN			0x00
#define EV_KEY			0x01
#define EV_REL			0x02
#define EV_ABS			0x03
#define EV_MSC			0x04
#define EV_SW			0x05
#define EV_LED			0x11
#define EV_SND			0x12
#define EV_REP			0x14
#define EV_FF			0x15
#define EV_PWR			0x16
#define EV_FF_STATUS		0x17
#define EV_MAX			0x1f

#define KEY_POWER		116
#define KEY_SLEEP		142
#define SW_0		0x00

// end <linux/input.h>

struct notify_entry {
    int id;
    int (*handler)(struct notify_entry *entry, struct inotify_event *event);
    const char *filename;
};

int charging_state_notify_handler(struct notify_entry *entry, struct inotify_event *event)
{
    static int state = -1;
    int last_state;
    char buf[40];
    int read_len;
    int fd;

    last_state = state;
    fd = open(entry->filename, O_RDONLY);
    read_len = read(fd, buf, sizeof(buf));
    if(read_len > 0) {
        //printf("charging_state_notify_handler: \"%s\"\n", buf);
        state = !(strncmp(buf, "Unknown", 7) == 0 
                  || strncmp(buf, "Discharging", 11) == 0);
    }
    close(fd);
    //printf("charging_state_notify_handler: %d -> %d\n", last_state, state);
    return state > last_state;
}

struct notify_entry watched_files[] = {
    {
        .filename = "/sys/android_power/charging_state",
        .handler = charging_state_notify_handler
    }
};

int call_notify_handler(struct inotify_event *event)
{
    unsigned int start, i;
    start = event->wd - watched_files[0].id;
    if(start >= ARRAY_SIZE(watched_files))
        start = 0;
    //printf("%d: %08x \"%s\"\n", event->wd, event->mask, event->len ? event->name : "");
    for(i = start; i < ARRAY_SIZE(watched_files); i++) {
        if(event->wd == watched_files[i].id) {
            if(watched_files[i].handler) {
                return watched_files[i].handler(&watched_files[i], event);
            }
            return 1;
        }
    }
    for(i = 0; i < start; i++) {
        if(event->wd == watched_files[i].id) {
            if(watched_files[i].handler) {
                return watched_files[i].handler(&watched_files[i], event);
            }
            return 1;
        }
    }
    return 0;
}

int handle_inotify_event(int nfd)
{
    int res;
    int wake_up = 0;
    struct inotify_event *event;
    char event_buf[512];
    int event_pos = 0;

    res = read(nfd, event_buf, sizeof(event_buf));
    if(res < (int)sizeof(*event)) {
        if(errno == EINTR)
            return 0;
        fprintf(stderr, "could not get event, %s\n", strerror(errno));
        return 0;
    }
    printf("got %d bytes of event information\n", res);
    while(res >= (int)sizeof(*event)) {
        int event_size;
        event = (struct inotify_event *)(event_buf + event_pos);
        wake_up |= call_notify_handler(event);
        event_size = sizeof(*event) + event->len;
        res -= event_size;
        event_pos += event_size;
    }
    return wake_up;
}

int powerd_main(int argc, char *argv[])
{
    int c;
    unsigned int i;
    int res;
    struct timeval tv;
    int eventfd;
    int notifyfd;
    int powerfd;
    int powerfd_is_sleep;
    int user_activity_fd;
    int acquire_partial_wake_lock_fd;
    int acquire_full_wake_lock_fd;
    int release_wake_lock_fd;
    char *eventdev = "/dev/input/event0";
    const char *android_sleepdev = "/sys/android_power/request_sleep";
    const char *android_autooff_dev = "/sys/android_power/auto_off_timeout";
    const char *android_user_activity_dev = "/sys/android_power/last_user_activity";
    const char *android_acquire_partial_wake_lock_dev = "/sys/android_power/acquire_partial_wake_lock";
    const char *android_acquire_full_wake_lock_dev = "/sys/android_power/acquire_full_wake_lock";
    const char *android_release_wake_lock_dev = "/sys/android_power/release_wake_lock";
    const char *powerdev = "/sys/power/state";
    const char suspendstring[] = "standby";
    const char wakelockstring[] = "powerd";
    fd_set rfds;
    struct input_event event;
    struct input_event light_event;
    struct input_event light_event2;
    int gotkey = 1;
    time_t idle_time = 5;
    const char *idle_time_string = "5";
    time_t lcd_light_time = 0;
    time_t key_light_time = 0;
    int verbose = 1;
    int event_sleep = 0;
    int got_power_key_down = 0;
    struct timeval power_key_down_time = { 0, 0 };

    light_event.type = EV_LED;
    light_event.code = 4; // bright lcd backlight
    light_event.value = 0; // light off -- sleep after timeout

    light_event2.type = EV_LED;
    light_event2.code = 8; // keyboard backlight
    light_event2.value = 0; // light off -- sleep after timeout

    do {
        c = getopt(argc, argv, "e:ni:vql:k:");
        if (c == EOF)
            break;
        switch (c) {
        case 'e':
            eventdev = optarg;
            break;
        case 'n':
            gotkey = 0;
            break;
        case 'i':
            idle_time = atoi(optarg);
            idle_time_string = optarg;
            break;
        case 'v':
            verbose = 2;
            break;
        case 'q':
            verbose = 0;
            break;
        case 'l':
            lcd_light_time = atoi(optarg);
            break;
        case 'k':
            key_light_time = atoi(optarg);
            break;
        case '?':
            fprintf(stderr, "%s: invalid option -%c\n",
                argv[0], optopt);
            exit(1);
        }
    } while (1);
    if(optind  != argc) {
        fprintf(stderr,"%s [-e eventdev]\n", argv[0]);
        return 1;
    }

    eventfd = open(eventdev, O_RDWR | O_NONBLOCK);
    if(eventfd < 0) {
        fprintf(stderr, "could not open %s, %s\n", eventdev, strerror(errno));
        return 1;
    }
    if(key_light_time >= lcd_light_time) {
        lcd_light_time = key_light_time + 1;
        fprintf(stderr,"lcd bright backlight time must be longer than keyboard backlight time.\n"
            "Setting lcd bright backlight time to %ld seconds\n", lcd_light_time);
    }

    user_activity_fd = open(android_user_activity_dev, O_RDWR);
    if(user_activity_fd >= 0) {
        int auto_off_fd = open(android_autooff_dev, O_RDWR);
        write(auto_off_fd, idle_time_string, strlen(idle_time_string));
        close(auto_off_fd);
    }

    powerfd = open(android_sleepdev, O_RDWR);
    if(powerfd >= 0) {
        powerfd_is_sleep = 1;
        if(verbose > 0)
            printf("Using android sleep dev: %s\n", android_sleepdev);
    }
    else {
        powerfd_is_sleep = 0;
        powerfd = open(powerdev, O_RDWR);
        if(powerfd >= 0) {
            if(verbose > 0)
                printf("Using linux power dev: %s\n", powerdev);
        }
    }
    if(powerfd < 0) {
        fprintf(stderr, "could not open %s, %s\n", powerdev, strerror(errno));
        return 1;
    }

    notifyfd = inotify_init();
    if(notifyfd < 0) {
        fprintf(stderr, "inotify_init failed, %s\n", strerror(errno));
        return 1;
    }
    fcntl(notifyfd, F_SETFL, O_NONBLOCK | fcntl(notifyfd, F_GETFL));
    for(i = 0; i < ARRAY_SIZE(watched_files); i++) {
        watched_files[i].id = inotify_add_watch(notifyfd, watched_files[i].filename, IN_MODIFY);
        printf("Watching %s, id %d\n", watched_files[i].filename, watched_files[i].id);
    }

    acquire_partial_wake_lock_fd = open(android_acquire_partial_wake_lock_dev, O_RDWR);
    acquire_full_wake_lock_fd = open(android_acquire_full_wake_lock_dev, O_RDWR);
    release_wake_lock_fd = open(android_release_wake_lock_dev, O_RDWR);

    if(user_activity_fd >= 0) {
        idle_time = 60*60*24; // driver handles real timeout
    }
    if(gotkey) {
        tv.tv_sec = idle_time;
        tv.tv_usec = 0;
    }
    else {
        tv.tv_sec = 0;
        tv.tv_usec = 500000;
    }
    
    while(1) {
        FD_ZERO(&rfds);
        //FD_SET(0, &rfds);
        FD_SET(eventfd, &rfds);
        FD_SET(notifyfd, &rfds);
        res = select(((notifyfd > eventfd) ? notifyfd : eventfd) + 1, &rfds, NULL, NULL, &tv);
        if(res < 0) {
            fprintf(stderr, "select failed, %s\n", strerror(errno));
            return 1;
        }
        if(res == 0) {
            if(light_event2.value == 1)
                goto light2_off;
            if(light_event.value == 1)
                goto light_off;
            if(user_activity_fd < 0) {
                if(gotkey && verbose > 0)
                    printf("Idle - sleep\n");
                if(!gotkey && verbose > 1)
                    printf("Reenter sleep\n");
                goto sleep;
            }
            else {
                tv.tv_sec = 60*60*24;
                tv.tv_usec = 0;
            }
        }
        if(res > 0) {
            //if(FD_ISSET(0, &rfds)) {
            //  printf("goto data on stdin quit\n");
            //  return 0;
            //}
            if(FD_ISSET(notifyfd, &rfds)) {
                write(acquire_partial_wake_lock_fd, wakelockstring, sizeof(wakelockstring) - 1);
                if(handle_inotify_event(notifyfd) > 0) {
                    write(acquire_full_wake_lock_fd, wakelockstring, sizeof(wakelockstring) - 1);
                }
                write(release_wake_lock_fd, wakelockstring, sizeof(wakelockstring) - 1);
            }
            if(FD_ISSET(eventfd, &rfds)) {
                write(acquire_partial_wake_lock_fd, wakelockstring, sizeof(wakelockstring) - 1);
                res = read(eventfd, &event, sizeof(event));
                if(res < (int)sizeof(event)) {
                    fprintf(stderr, "could not get event\n");
                    write(release_wake_lock_fd, wakelockstring, sizeof(wakelockstring) - 1);
                    return 1;
                }
                if(event.type == EV_PWR && event.code == KEY_SLEEP) {
                    event_sleep = event.value;
                }
                if(event.type == EV_KEY || (event.type == EV_SW && event.code == SW_0 && event.value == 1)) {
                    gotkey = 1;
                    if(user_activity_fd >= 0) {
                        char buf[32];
                        int len;
                        len = sprintf(buf, "%ld%06lu000", event.time.tv_sec, event.time.tv_usec);
                        write(user_activity_fd, buf, len);
                    }
                    if(lcd_light_time | key_light_time) {
                        tv.tv_sec = key_light_time;
                        light_event.value = 1;
                        write(eventfd, &light_event, sizeof(light_event));
                        light_event2.value = 1;
                        write(eventfd, &light_event2, sizeof(light_event2));
                    }
                    else {
                        tv.tv_sec = idle_time;
                    }
                    tv.tv_usec = 0;
                    if(verbose > 1)
                        printf("got %s %s %d%s\n", event.type == EV_KEY ? "key" : "switch", event.value ? "down" : "up", event.code, event_sleep ? " from sleep" : "");
                    if(event.code == KEY_POWER) {
                        if(event.value == 0) {
                            int tmp_got_power_key_down = got_power_key_down;
                            got_power_key_down = 0;
                            if(tmp_got_power_key_down) {
                                // power key released
                                if(verbose > 0)
                                    printf("Power key released - sleep\n");
                                write(release_wake_lock_fd, wakelockstring, sizeof(wakelockstring) - 1);
                                goto sleep;
                            }
                        }
                        else if(event_sleep == 0) {
                            got_power_key_down = 1;
                            power_key_down_time = event.time;
                        }
                    }
                }
                if(event.type == EV_SW && event.code == SW_0 && event.value == 0) {
                    if(verbose > 0)
                        printf("Flip closed - sleep\n");
                    power_key_down_time = event.time;
                    write(release_wake_lock_fd, wakelockstring, sizeof(wakelockstring) - 1);
                    goto sleep;
                }
                write(release_wake_lock_fd, wakelockstring, sizeof(wakelockstring) - 1);
            }
        }
        if(0) {
light_off:
            light_event.value = 0;
            write(eventfd, &light_event, sizeof(light_event));
            tv.tv_sec = idle_time - lcd_light_time;
        }
        if(0) {
light2_off:
            light_event2.value = 0;
            write(eventfd, &light_event2, sizeof(light_event2));
            tv.tv_sec = lcd_light_time - key_light_time;
        }
        if(0) {
sleep:
            if(light_event.value == 1) {
                light_event.value = 0;
                write(eventfd, &light_event, sizeof(light_event));
                light_event2.value = 0;
                write(eventfd, &light_event2, sizeof(light_event2));
                tv.tv_sec = idle_time - lcd_light_time;
            }
            if(powerfd_is_sleep) {
                char buf[32];
                int len;
                len = sprintf(buf, "%ld%06lu000", power_key_down_time.tv_sec, power_key_down_time.tv_usec);
                write(powerfd, buf, len);
            }
            else
                write(powerfd, suspendstring, sizeof(suspendstring) - 1);
            gotkey = 0;
            tv.tv_sec = 0;
            tv.tv_usec = 500000;
        }
    }

    return 0;
}
