#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>

int smd_main(int argc, char **argv)
{
    int fd, len, r, port = 0;
    char devname[32];
    argc--;
    argv++;

    if((argc > 0) && (argv[0][0] == '-')) {
        port = atoi(argv[0] + 1);
        argc--;
        argv++;
    }

    sprintf(devname,"/dev/smd%d",port);
    fd = open(devname, O_WRONLY);
    if(fd < 0) {
        fprintf(stderr,"failed to open smd0 - %s\n",
            strerror(errno));
        return -1;
    }
    while(argc > 0) {
        len = strlen(argv[0]);
        r = write(fd, argv[0], len);
        if(r != len) {
            fprintf(stderr,"failed to write smd0 (%d) %s\n",
                r, strerror(errno));
            return -1;
        }
        argc--;
        argv++;
        write(fd, argc ? " " : "\r", 1);
    }
    close(fd);
    return 0;       
}
