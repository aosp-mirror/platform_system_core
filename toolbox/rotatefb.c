#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <errno.h>
#include <linux/fb.h>


int rotatefb_main(int argc, char *argv[])
{
    int c;
    char *fbdev = "/dev/graphics/fb0";
    int rotation = 0;
    int fd;
    int res;
    struct fb_var_screeninfo fbinfo;

    do {
        c = getopt(argc, argv, "d:");
        if (c == EOF)
            break;
        switch (c) {
        case 'd':
            fbdev = optarg;
            break;
        case '?':
            fprintf(stderr, "%s: invalid option -%c\n",
                argv[0], optopt);
            exit(1);
        }
    } while (1);

    if(optind + 1 != argc) {
        fprintf(stderr, "%s: specify rotation\n", argv[0]);
        exit(1);
    }
    rotation = atoi(argv[optind]);

    fd = open(fbdev, O_RDWR);
    if(fd < 0) {
        fprintf(stderr, "cannot open %s\n", fbdev);
        return 1;
    }

    res = ioctl(fd, FBIOGET_VSCREENINFO, &fbinfo);
    if(res < 0) {
        fprintf(stderr, "failed to get fbinfo: %s\n", strerror(errno));
        return 1;
    }
    if((fbinfo.rotate ^ rotation) & 1) {
        unsigned int xres = fbinfo.yres;
        fbinfo.yres = fbinfo.xres;
        fbinfo.xres = xres;
        fbinfo.xres_virtual = fbinfo.xres;
        fbinfo.yres_virtual = fbinfo.yres * 2;
        if(fbinfo.yoffset == xres)
            fbinfo.yoffset = fbinfo.yres;
    }
    fbinfo.rotate = rotation; 
    res = ioctl(fd, FBIOPUT_VSCREENINFO, &fbinfo);
    if(res < 0) {
        fprintf(stderr, "failed to set fbinfo: %s\n", strerror(errno));
        return 1;
    }

    return 0;
}
