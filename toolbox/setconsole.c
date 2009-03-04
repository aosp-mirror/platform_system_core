#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <linux/kd.h>
#include <linux/vt.h>
#include <errno.h>
#include <pthread.h>

static int activate_thread_switch_vc;
static void *activate_thread(void *arg)
{
    int res;
    int fd = (int)arg;
    while(activate_thread_switch_vc >= 0) {
        do {
            res = ioctl(fd, VT_ACTIVATE, (void*)activate_thread_switch_vc);
        } while(res < 0 && errno == EINTR);
        if (res < 0) {
            fprintf(stderr, "ioctl( vcfd, VT_ACTIVATE, vtnum) failed, %d %d %s for %d\n", res, errno, strerror(errno), activate_thread_switch_vc);
        }
        if(activate_thread_switch_vc >= 0)
            sleep(1);
    }
    return NULL;
}


int setconsole_main(int argc, char *argv[])
{
    int c;
    int fd;
    int res;

    int mode = -1;
    int new_vc = 0;
    int close_vc = 0;
    int switch_vc = -1;
    int printvc = 0;
    char *ttydev = "/dev/tty0";

    do {
        c = getopt(argc, argv, "d:gtncv:poh");
        if (c == EOF)
            break;
        switch (c) {
        case 'd':
            ttydev = optarg;
            break;
        case 'g':
            if(mode == KD_TEXT) {
                fprintf(stderr, "%s: cannot specify both -g and -t\n", argv[0]);
                exit(1);
            }
            mode = KD_GRAPHICS;
            break;
        case 't':
            if(mode == KD_GRAPHICS) {
                fprintf(stderr, "%s: cannot specify both -g and -t\n", argv[0]);
                exit(1);
            }
            mode = KD_TEXT;
            break;
        case 'n':
            new_vc = 1;
            break;
        case 'c':
            close_vc = 1;
            break;
        case 'v':
            switch_vc = atoi(optarg);
            break;
        case 'p':
            printvc |= 1;
            break;
        case 'o':
            printvc |= 2;
            break;
        case 'h':
            fprintf(stderr, "%s [-d <dev>] [-v <vc>] [-gtncpoh]\n"
                    "  -d <dev>   Use <dev> instead of /dev/tty0\n"
                    "  -v <vc>    Switch to virtual console <vc>\n"
                    "  -g         Switch to graphics mode\n"
                    "  -t         Switch to text mode\n"
                    "  -n         Create and switch to new virtual console\n"
                    "  -c         Close unused virtual consoles\n"
                    "  -p         Print new virtual console\n"
                    "  -o         Print old virtual console\n"
                    "  -h         Print help\n", argv[0]);
            return -1;
        case '?':
            fprintf(stderr, "%s: invalid option -%c\n",
                argv[0], optopt);
            exit(1);
        }
    } while (1);
    if(mode == -1 && new_vc == 0 && close_vc == 0 && switch_vc == -1 && printvc == 0) {
        fprintf(stderr,"%s [-d <dev>] [-v <vc>] [-gtncpoh]\n", argv[0]);
        return -1;
    }

    fd = open(ttydev, O_RDWR | O_SYNC);
    if (fd < 0) {
        fprintf(stderr, "cannot open %s\n", ttydev);
        return -1;
    }

    if ((printvc && !new_vc) || (printvc & 2)) {
        struct vt_stat vs;

        res = ioctl(fd, VT_GETSTATE, &vs);
        if (res < 0) {
            fprintf(stderr, "ioctl(vcfd, VT_GETSTATE, &vs) failed, %d\n", res);
        }
        printf("%d\n", vs.v_active);
    }

    if (new_vc) {
        int vtnum;
        res = ioctl(fd, VT_OPENQRY, &vtnum);
        if (res < 0 || vtnum == -1) {
            fprintf(stderr, "ioctl(vcfd, VT_OPENQRY, &vtnum) failed, res %d, vtnum %d\n", res, vtnum);
        }
        switch_vc = vtnum;
    }
    if (switch_vc != -1) {
        pthread_t thread;
        pthread_attr_t attr;
        activate_thread_switch_vc = switch_vc;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        pthread_create(&thread, &attr, activate_thread, (void*)fd);
        
        do {
            res = ioctl(fd, VT_WAITACTIVE, (void*)switch_vc);
        } while(res < 0 && errno == EINTR);
        activate_thread_switch_vc = -1;
        if (res < 0) {
            fprintf(stderr, "ioctl( vcfd, VT_WAITACTIVE, vtnum) failed, %d %d %s for %d\n", res, errno, strerror(errno), switch_vc);
        }
        if(printvc & 1)
            printf("%d\n", switch_vc);

        close(fd);
        fd = open(ttydev, O_RDWR | O_SYNC);
        if (fd < 0) {
            fprintf(stderr, "cannot open %s\n", ttydev);
            return -1;
        }
    }
    if (close_vc) {
        res = ioctl(fd, VT_DISALLOCATE, 0);
        if (res < 0) {
            fprintf(stderr, "ioctl(vcfd, VT_DISALLOCATE, 0) failed, %d\n", res);
        }
    }
    if (mode != -1) {
        if (ioctl(fd, KDSETMODE, (void*)mode) < 0) {
            fprintf(stderr, "KDSETMODE %d failed\n", mode);
            return -1;
        }
    }
    return 0;
}
