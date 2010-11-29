#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <getopt.h>
#include <string.h>
#include <linux/kd.h>
#include <linux/vt.h>
#include <errno.h>
#include <pthread.h>
#include <sys/ioctl.h>

int ioctl_main(int argc, char *argv[])
{
    int c;
    int fd;
    int res;

    int read_only = 0;
    int length = -1;
    int arg_size = 4;
    int direct_arg = 0;
    uint32_t ioctl_nr;
    void *ioctl_args;
    uint8_t *ioctl_argp;
    uint8_t *ioctl_argp_save;
    int rem;

    do {
        c = getopt(argc, argv, "rdl:a:h");
        if (c == EOF)
            break;
        switch (c) {
        case 'r':
            read_only = 1;
            break;
        case 'd':
            direct_arg = 1;
            break;
        case 'l':
            length = strtol(optarg, NULL, 0);
            break;
        case 'a':
            arg_size = strtol(optarg, NULL, 0);
            break;
        case 'h':
            fprintf(stderr, "%s [-l <length>] [-a <argsize>] [-rdh] <device> <ioctlnr>\n"
                    "  -l <lenght>   Length of io buffer\n"
                    "  -a <argsize>  Size of each argument (1-8)\n"
                    "  -r            Open device in read only mode\n"
                    "  -d            Direct argument (no iobuffer)\n"
                    "  -h            Print help\n", argv[0]);
            return -1;
        case '?':
            fprintf(stderr, "%s: invalid option -%c\n",
                argv[0], optopt);
            exit(1);
        }
    } while (1);

    if(optind + 2 > argc) {
        fprintf(stderr, "%s: too few arguments\n", argv[0]);
        exit(1);
    }

    fd = open(argv[optind], O_RDWR | O_SYNC);
    if (fd < 0) {
        fprintf(stderr, "cannot open %s\n", argv[optind]);
        return 1;
    }
    optind++;
    
    ioctl_nr = strtol(argv[optind], NULL, 0);
    optind++;

    if(direct_arg) {
        arg_size = 4;
        length = 4;
    }

    if(length < 0) {
        length = (argc - optind) * arg_size;
    }
    if(length) {
        ioctl_args = calloc(1, length);

        ioctl_argp_save = ioctl_argp = ioctl_args;
        rem = length;
        while(optind < argc) {
            uint64_t tmp = strtoull(argv[optind], NULL, 0);
            if(rem < arg_size) {
                fprintf(stderr, "%s: too many arguments\n", argv[0]);
                exit(1);
            }
            memcpy(ioctl_argp, &tmp, arg_size);
            ioctl_argp += arg_size;
            rem -= arg_size;
            optind++;
        }
    }
    printf("sending ioctl 0x%x", ioctl_nr);
    rem = length;
    while(rem--) {
        printf(" 0x%02x", *ioctl_argp_save++);
    }
    printf("\n");

    if(direct_arg)
        res = ioctl(fd, ioctl_nr, *(uint32_t*)ioctl_args);
    else if(length)
        res = ioctl(fd, ioctl_nr, ioctl_args);
    else
        res = ioctl(fd, ioctl_nr, 0);
    if (res < 0) {
        fprintf(stderr, "ioctl 0x%x failed, %d\n", ioctl_nr, res);
        return 1;
    }
    if(length) {
        printf("return buf:");
        ioctl_argp = ioctl_args;
        rem = length;
        while(rem--) {
            printf(" %02x", *ioctl_argp++);
        }
        printf("\n");
    }
    return 0;
}
