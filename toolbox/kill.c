#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <sys/types.h>
#include <signal.h>

int kill_main(int argc, char **argv)
{
    int sig = SIGTERM;
    int result = 0;
    
    argc--;
    argv++;

    if(argc >= 2 && argv[0][0] == '-'){
        sig = atoi(argv[0] + 1);
        argc--;
        argv++;
    }

    while(argc > 0){
        int pid = atoi(argv[0]);
        int err = kill(pid, sig);
        if (err < 0) {
            result = err;
            fprintf(stderr, "could not kill pid %d: %s\n", pid, strerror(errno));
        }
            
        argc--;
        argv++;
    }
    
    return result;
}
