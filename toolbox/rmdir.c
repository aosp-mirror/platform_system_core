#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

static int usage()
{
    fprintf(stderr,"rmdir <directory>\n");
    return -1;
}

int rmdir_main(int argc, char *argv[])
{
    int symbolic = 0;
    int ret;
    if(argc < 2) return usage();

    while(argc > 1) {
        argc--;
        argv++;
        ret = rmdir(argv[0]);
        if(ret < 0) {
            fprintf(stderr, "rmdir failed for %s, %s\n", argv[0], strerror(errno));
            return ret;
        }
    }
    
    return 0;
}
