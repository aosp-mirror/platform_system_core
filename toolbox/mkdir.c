#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

static int usage()
{
    fprintf(stderr,"mkdir <target>\n");
    return -1;
}

int mkdir_main(int argc, char *argv[])
{
    int symbolic = 0;
    int ret;
    if(argc < 2) return usage();

    while(argc > 1) {
        argc--;
        argv++;
        ret = mkdir(argv[0], 0777);
        if(ret < 0) {
            fprintf(stderr, "mkdir failed for %s, %s\n", argv[0], strerror(errno));
            return ret;
        }
    }
    
    return 0;
}
