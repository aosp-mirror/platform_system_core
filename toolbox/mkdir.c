#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/limits.h>
#include <sys/stat.h>

static int usage()
{
    fprintf(stderr,"mkdir [OPTION] <target>\n");
    fprintf(stderr,"    --help           display usage and exit\n");
    fprintf(stderr,"    -p, --parents    create parent directories as needed\n");
    return -1;
}

int mkdir_main(int argc, char *argv[])
{
    int symbolic = 0;
    int ret;
    if(argc < 2 || strcmp(argv[1], "--help") == 0) {
        return usage();
    }

    int recursive = (strcmp(argv[1], "-p") == 0 ||
                     strcmp(argv[1], "--parents") == 0) ? 1 : 0;

    if(recursive && argc < 3) {
        // -p specified without a path
        return usage();
    }

    if(recursive) {
        argc--;
        argv++;
    }

    char currpath[PATH_MAX], *pathpiece;
    struct stat st;

    while(argc > 1) {
        argc--;
        argv++;
        if(recursive) {
            // reset path
            strcpy(currpath, "");
            // create the pieces of the path along the way
            pathpiece = strtok(argv[0], "/");
            if(argv[0][0] == '/') {
                // prepend / if needed
                strcat(currpath, "/");
            }
            while(pathpiece != NULL) {
                if(strlen(currpath) + strlen(pathpiece) + 2/*NUL and slash*/ > PATH_MAX) {
                    fprintf(stderr, "Invalid path specified: too long\n");
                    return 1;
                }
                strcat(currpath, pathpiece);
                strcat(currpath, "/");
                if(stat(currpath, &st) != 0) {
                    ret = mkdir(currpath, 0777);
                    if(ret < 0) {
                        fprintf(stderr, "mkdir failed for %s, %s\n", currpath, strerror(errno));
                        return ret;
                    }
                }
                pathpiece = strtok(NULL, "/");
            }
        } else {
            ret = mkdir(argv[0], 0777);
            if(ret < 0) {
                fprintf(stderr, "mkdir failed for %s, %s\n", argv[0], strerror(errno));
                return ret;
            }
        }
    }
    
    return 0;
}
