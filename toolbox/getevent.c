#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/inotify.h>
#include <sys/limits.h>
#include <sys/poll.h>
#include <linux/input.h>
#include <errno.h>

#include "getevent.h"

static struct pollfd *ufds;
static char **device_names;
static int nfds;

enum {
    PRINT_DEVICE_ERRORS     = 1U << 0,
    PRINT_DEVICE            = 1U << 1,
    PRINT_DEVICE_NAME       = 1U << 2,
    PRINT_DEVICE_INFO       = 1U << 3,
    PRINT_VERSION           = 1U << 4,
    PRINT_POSSIBLE_EVENTS   = 1U << 5,
    PRINT_INPUT_PROPS       = 1U << 6,

    PRINT_ALL_INFO          = (1U << 7) - 1,

    PRINT_LABELS            = 1U << 16,
};

static const char *get_label(const struct label *labels, int value)
{
    while(labels->name && value != labels->value) {
        labels++;
    }
    return labels->name;
}

static int print_input_props(int fd)
{
    uint8_t bits[INPUT_PROP_CNT / 8];
    int i, j;
    int res;
    int count;
    const char *bit_label;

    printf("  input props:\n");
    res = ioctl(fd, EVIOCGPROP(sizeof(bits)), bits);
    if(res < 0) {
        printf("    <not available\n");
        return 1;
    }
    count = 0;
    for(i = 0; i < res; i++) {
        for(j = 0; j < 8; j++) {
            if (bits[i] & 1 << j) {
                bit_label = get_label(input_prop_labels, i * 8 + j);
                if(bit_label)
                    printf("    %s\n", bit_label);
                else
                    printf("    %04x\n", i * 8 + j);
                count++;
            }
        }
    }
    if (!count)
        printf("    <none>\n");
    return 0;
}

static int print_possible_events(int fd, int print_flags)
{
    uint8_t *bits = NULL;
    ssize_t bits_size = 0;
    const char* label;
    int i, j, k;
    int res, res2;
    struct label* bit_labels;
    const char *bit_label;

    printf("  events:\n");
    for(i = EV_KEY; i <= EV_MAX; i++) { // skip EV_SYN since we cannot query its available codes
        int count = 0;
        while(1) {
            res = ioctl(fd, EVIOCGBIT(i, bits_size), bits);
            if(res < bits_size)
                break;
            bits_size = res + 16;
            bits = realloc(bits, bits_size * 2);
            if(bits == NULL) {
                fprintf(stderr, "failed to allocate buffer of size %d\n", (int)bits_size);
                return 1;
            }
        }
        res2 = 0;
        switch(i) {
            case EV_KEY:
                res2 = ioctl(fd, EVIOCGKEY(res), bits + bits_size);
                label = "KEY";
                bit_labels = key_labels;
                break;
            case EV_REL:
                label = "REL";
                bit_labels = rel_labels;
                break;
            case EV_ABS:
                label = "ABS";
                bit_labels = abs_labels;
                break;
            case EV_MSC:
                label = "MSC";
                bit_labels = msc_labels;
                break;
            case EV_LED:
                res2 = ioctl(fd, EVIOCGLED(res), bits + bits_size);
                label = "LED";
                bit_labels = led_labels;
                break;
            case EV_SND:
                res2 = ioctl(fd, EVIOCGSND(res), bits + bits_size);
                label = "SND";
                bit_labels = snd_labels;
                break;
            case EV_SW:
                res2 = ioctl(fd, EVIOCGSW(bits_size), bits + bits_size);
                label = "SW ";
                bit_labels = sw_labels;
                break;
            case EV_REP:
                label = "REP";
                bit_labels = rep_labels;
                break;
            case EV_FF:
                label = "FF ";
                bit_labels = ff_labels;
                break;
            case EV_PWR:
                label = "PWR";
                bit_labels = NULL;
                break;
            case EV_FF_STATUS:
                label = "FFS";
                bit_labels = ff_status_labels;
                break;
            default:
                res2 = 0;
                label = "???";
                bit_labels = NULL;
        }
        for(j = 0; j < res; j++) {
            for(k = 0; k < 8; k++)
                if(bits[j] & 1 << k) {
                    char down;
                    if(j < res2 && (bits[j + bits_size] & 1 << k))
                        down = '*';
                    else
                        down = ' ';
                    if(count == 0)
                        printf("    %s (%04x):", label, i);
                    else if((count & (print_flags & PRINT_LABELS ? 0x3 : 0x7)) == 0 || i == EV_ABS)
                        printf("\n               ");
                    if(bit_labels && (print_flags & PRINT_LABELS)) {
                        bit_label = get_label(bit_labels, j * 8 + k);
                        if(bit_label)
                            printf(" %.20s%c%*s", bit_label, down, 20 - strlen(bit_label), "");
                        else
                            printf(" %04x%c                ", j * 8 + k, down);
                    } else {
                        printf(" %04x%c", j * 8 + k, down);
                    }
                    if(i == EV_ABS) {
                        struct input_absinfo abs;
                        if(ioctl(fd, EVIOCGABS(j * 8 + k), &abs) == 0) {
                            printf(" : value %d, min %d, max %d, fuzz %d flat %d", abs.value, abs.minimum, abs.maximum, abs.fuzz, abs.flat);
                        }
                    }
                    count++;
                }
        }
        if(count)
            printf("\n");
    }
    free(bits);
    return 0;
}

static void print_event(int type, int code, int value, int print_flags)
{
    const char *type_label, *code_label, *value_label;

    if (print_flags & PRINT_LABELS) {
        type_label = get_label(ev_labels, type);
        code_label = NULL;
        value_label = NULL;

        switch(type) {
            case EV_SYN:
                code_label = get_label(syn_labels, code);
                break;
            case EV_KEY:
                code_label = get_label(key_labels, code);
                value_label = get_label(key_value_labels, value);
                break;
            case EV_REL:
                code_label = get_label(rel_labels, code);
                break;
            case EV_ABS:
                code_label = get_label(abs_labels, code);
                switch(code) {
                    case ABS_MT_TOOL_TYPE:
                        value_label = get_label(mt_tool_labels, value);
                }
                break;
            case EV_MSC:
                code_label = get_label(msc_labels, code);
                break;
            case EV_LED:
                code_label = get_label(led_labels, code);
                break;
            case EV_SND:
                code_label = get_label(snd_labels, code);
                break;
            case EV_SW:
                code_label = get_label(sw_labels, code);
                break;
            case EV_REP:
                code_label = get_label(rep_labels, code);
                break;
            case EV_FF:
                code_label = get_label(ff_labels, code);
                break;
            case EV_FF_STATUS:
                code_label = get_label(ff_status_labels, code);
                break;
        }

        if (type_label)
            printf("%-12.12s", type_label);
        else
            printf("%04x        ", type);
        if (code_label)
            printf(" %-20.20s", code_label);
        else
            printf(" %04x                ", code);
        if (value_label)
            printf(" %-20.20s", value_label);
        else
            printf(" %08x            ", value);
    } else {
        printf("%04x %04x %08x", type, code, value);
    }
}

static int open_device(const char *device, int print_flags)
{
    int version;
    int fd;
    struct pollfd *new_ufds;
    char **new_device_names;
    char name[80];
    char location[80];
    char idstr[80];
    struct input_id id;

    fd = open(device, O_RDWR);
    if(fd < 0) {
        if(print_flags & PRINT_DEVICE_ERRORS)
            fprintf(stderr, "could not open %s, %s\n", device, strerror(errno));
        return -1;
    }
    
    if(ioctl(fd, EVIOCGVERSION, &version)) {
        if(print_flags & PRINT_DEVICE_ERRORS)
            fprintf(stderr, "could not get driver version for %s, %s\n", device, strerror(errno));
        return -1;
    }
    if(ioctl(fd, EVIOCGID, &id)) {
        if(print_flags & PRINT_DEVICE_ERRORS)
            fprintf(stderr, "could not get driver id for %s, %s\n", device, strerror(errno));
        return -1;
    }
    name[sizeof(name) - 1] = '\0';
    location[sizeof(location) - 1] = '\0';
    idstr[sizeof(idstr) - 1] = '\0';
    if(ioctl(fd, EVIOCGNAME(sizeof(name) - 1), &name) < 1) {
        //fprintf(stderr, "could not get device name for %s, %s\n", device, strerror(errno));
        name[0] = '\0';
    }
    if(ioctl(fd, EVIOCGPHYS(sizeof(location) - 1), &location) < 1) {
        //fprintf(stderr, "could not get location for %s, %s\n", device, strerror(errno));
        location[0] = '\0';
    }
    if(ioctl(fd, EVIOCGUNIQ(sizeof(idstr) - 1), &idstr) < 1) {
        //fprintf(stderr, "could not get idstring for %s, %s\n", device, strerror(errno));
        idstr[0] = '\0';
    }

    new_ufds = realloc(ufds, sizeof(ufds[0]) * (nfds + 1));
    if(new_ufds == NULL) {
        fprintf(stderr, "out of memory\n");
        return -1;
    }
    ufds = new_ufds;
    new_device_names = realloc(device_names, sizeof(device_names[0]) * (nfds + 1));
    if(new_device_names == NULL) {
        fprintf(stderr, "out of memory\n");
        return -1;
    }
    device_names = new_device_names;

    if(print_flags & PRINT_DEVICE)
        printf("add device %d: %s\n", nfds, device);
    if(print_flags & PRINT_DEVICE_INFO)
        printf("  bus:      %04x\n"
               "  vendor    %04x\n"
               "  product   %04x\n"
               "  version   %04x\n",
               id.bustype, id.vendor, id.product, id.version);
    if(print_flags & PRINT_DEVICE_NAME)
        printf("  name:     \"%s\"\n", name);
    if(print_flags & PRINT_DEVICE_INFO)
        printf("  location: \"%s\"\n"
               "  id:       \"%s\"\n", location, idstr);
    if(print_flags & PRINT_VERSION)
        printf("  version:  %d.%d.%d\n",
               version >> 16, (version >> 8) & 0xff, version & 0xff);

    if(print_flags & PRINT_POSSIBLE_EVENTS) {
        print_possible_events(fd, print_flags);
    }

    if(print_flags & PRINT_INPUT_PROPS) {
        print_input_props(fd);
    }

    ufds[nfds].fd = fd;
    ufds[nfds].events = POLLIN;
    device_names[nfds] = strdup(device);
    nfds++;

    return 0;
}

int close_device(const char *device, int print_flags)
{
    int i;
    for(i = 1; i < nfds; i++) {
        if(strcmp(device_names[i], device) == 0) {
            int count = nfds - i - 1;
            if(print_flags & PRINT_DEVICE)
                printf("remove device %d: %s\n", i, device);
            free(device_names[i]);
            memmove(device_names + i, device_names + i + 1, sizeof(device_names[0]) * count);
            memmove(ufds + i, ufds + i + 1, sizeof(ufds[0]) * count);
            nfds--;
            return 0;
        }
    }
    if(print_flags & PRINT_DEVICE_ERRORS)
        fprintf(stderr, "remote device: %s not found\n", device);
    return -1;
}

static int read_notify(const char *dirname, int nfd, int print_flags)
{
    int res;
    char devname[PATH_MAX];
    char *filename;
    char event_buf[512];
    int event_size;
    int event_pos = 0;
    struct inotify_event *event;

    res = read(nfd, event_buf, sizeof(event_buf));
    if(res < (int)sizeof(*event)) {
        if(errno == EINTR)
            return 0;
        fprintf(stderr, "could not get event, %s\n", strerror(errno));
        return 1;
    }
    //printf("got %d bytes of event information\n", res);

    strcpy(devname, dirname);
    filename = devname + strlen(devname);
    *filename++ = '/';

    while(res >= (int)sizeof(*event)) {
        event = (struct inotify_event *)(event_buf + event_pos);
        //printf("%d: %08x \"%s\"\n", event->wd, event->mask, event->len ? event->name : "");
        if(event->len) {
            strcpy(filename, event->name);
            if(event->mask & IN_CREATE) {
                open_device(devname, print_flags);
            }
            else {
                close_device(devname, print_flags);
            }
        }
        event_size = sizeof(*event) + event->len;
        res -= event_size;
        event_pos += event_size;
    }
    return 0;
}

static int scan_dir(const char *dirname, int print_flags)
{
    char devname[PATH_MAX];
    char *filename;
    DIR *dir;
    struct dirent *de;
    dir = opendir(dirname);
    if(dir == NULL)
        return -1;
    strcpy(devname, dirname);
    filename = devname + strlen(devname);
    *filename++ = '/';
    while((de = readdir(dir))) {
        if(de->d_name[0] == '.' &&
           (de->d_name[1] == '\0' ||
            (de->d_name[1] == '.' && de->d_name[2] == '\0')))
            continue;
        strcpy(filename, de->d_name);
        open_device(devname, print_flags);
    }
    closedir(dir);
    return 0;
}

static void usage(int argc, char *argv[])
{
    fprintf(stderr, "Usage: %s [-t] [-n] [-s switchmask] [-S] [-v [mask]] [-p] [-i] [-l] [-q] [-c count] [-r] [device]\n", argv[0]);
    fprintf(stderr, "    -t: show time stamps\n");
    fprintf(stderr, "    -n: don't print newlines\n");
    fprintf(stderr, "    -s: print switch states for given bits\n");
    fprintf(stderr, "    -S: print all switch states\n");
    fprintf(stderr, "    -v: verbosity mask (errs=1, dev=2, name=4, info=8, vers=16, pos. events=32, props=64)\n");
    fprintf(stderr, "    -p: show possible events (errs, dev, name, pos. events)\n");
    fprintf(stderr, "    -i: show all device info and possible events\n");
    fprintf(stderr, "    -l: label event types and names in plain text\n");
    fprintf(stderr, "    -q: quiet (clear verbosity mask)\n");
    fprintf(stderr, "    -c: print given number of events then exit\n");
    fprintf(stderr, "    -r: print rate events are received\n");
}

int getevent_main(int argc, char *argv[])
{
    int c;
    int i;
    int res;
    int pollres;
    int get_time = 0;
    int print_device = 0;
    char *newline = "\n";
    uint16_t get_switch = 0;
    struct input_event event;
    int version;
    int print_flags = 0;
    int print_flags_set = 0;
    int dont_block = -1;
    int event_count = 0;
    int sync_rate = 0;
    int64_t last_sync_time = 0;
    const char *device = NULL;
    const char *device_path = "/dev/input";

    opterr = 0;
    do {
        c = getopt(argc, argv, "tns:Sv::pilqc:rh");
        if (c == EOF)
            break;
        switch (c) {
        case 't':
            get_time = 1;
            break;
        case 'n':
            newline = "";
            break;
        case 's':
            get_switch = strtoul(optarg, NULL, 0);
            if(dont_block == -1)
                dont_block = 1;
            break;
        case 'S':
            get_switch = ~0;
            if(dont_block == -1)
                dont_block = 1;
            break;
        case 'v':
            if(optarg)
                print_flags |= strtoul(optarg, NULL, 0);
            else
                print_flags |= PRINT_DEVICE | PRINT_DEVICE_NAME | PRINT_DEVICE_INFO | PRINT_VERSION;
            print_flags_set = 1;
            break;
        case 'p':
            print_flags |= PRINT_DEVICE_ERRORS | PRINT_DEVICE | PRINT_DEVICE_NAME | PRINT_POSSIBLE_EVENTS;
            print_flags_set = 1;
            if(dont_block == -1)
                dont_block = 1;
            break;
        case 'i':
            print_flags |= PRINT_ALL_INFO;
            print_flags_set = 1;
            if(dont_block == -1)
                dont_block = 1;
            break;
        case 'l':
            print_flags |= PRINT_LABELS;
            break;
        case 'q':
            print_flags_set = 1;
            break;
        case 'c':
            event_count = atoi(optarg);
            dont_block = 0;
            break;
        case 'r':
            sync_rate = 1;
            break;
        case '?':
            fprintf(stderr, "%s: invalid option -%c\n",
                argv[0], optopt);
        case 'h':
            usage(argc, argv);
            exit(1);
        }
    } while (1);
    if(dont_block == -1)
        dont_block = 0;

    if (optind + 1 == argc) {
        device = argv[optind];
        optind++;
    }
    if (optind != argc) {
        usage(argc, argv);
        exit(1);
    }
    nfds = 1;
    ufds = calloc(1, sizeof(ufds[0]));
    ufds[0].fd = inotify_init();
    ufds[0].events = POLLIN;
    if(device) {
        if(!print_flags_set)
            print_flags |= PRINT_DEVICE_ERRORS;
        res = open_device(device, print_flags);
        if(res < 0) {
            return 1;
        }
    } else {
        if(!print_flags_set)
            print_flags |= PRINT_DEVICE_ERRORS | PRINT_DEVICE | PRINT_DEVICE_NAME;
        print_device = 1;
		res = inotify_add_watch(ufds[0].fd, device_path, IN_DELETE | IN_CREATE);
        if(res < 0) {
            fprintf(stderr, "could not add watch for %s, %s\n", device_path, strerror(errno));
            return 1;
        }
        res = scan_dir(device_path, print_flags);
        if(res < 0) {
            fprintf(stderr, "scan dir failed for %s\n", device_path);
            return 1;
        }
    }

    if(get_switch) {
        for(i = 1; i < nfds; i++) {
            uint16_t sw;
            res = ioctl(ufds[i].fd, EVIOCGSW(1), &sw);
            if(res < 0) {
                fprintf(stderr, "could not get switch state, %s\n", strerror(errno));
                return 1;
            }
            sw &= get_switch;
            printf("%04x%s", sw, newline);
        }
    }

    if(dont_block)
        return 0;

    while(1) {
        pollres = poll(ufds, nfds, -1);
        //printf("poll %d, returned %d\n", nfds, pollres);
        if(ufds[0].revents & POLLIN) {
            read_notify(device_path, ufds[0].fd, print_flags);
        }
        for(i = 1; i < nfds; i++) {
            if(ufds[i].revents) {
                if(ufds[i].revents & POLLIN) {
                    res = read(ufds[i].fd, &event, sizeof(event));
                    if(res < (int)sizeof(event)) {
                        fprintf(stderr, "could not get event\n");
                        return 1;
                    }
                    if(get_time) {
                        printf("%ld-%ld: ", event.time.tv_sec, event.time.tv_usec);
                    }
                    if(print_device)
                        printf("%s: ", device_names[i]);
                    print_event(event.type, event.code, event.value, print_flags);
                    if(sync_rate && event.type == 0 && event.code == 0) {
                        int64_t now = event.time.tv_sec * 1000000LL + event.time.tv_usec;
                        if(last_sync_time)
                            printf(" rate %lld", 1000000LL / (now - last_sync_time));
                        last_sync_time = now;
                    }
                    printf("%s", newline);
                    if(event_count && --event_count == 0)
                        return 0;
                }
            }
        }
    }

    return 0;
}
