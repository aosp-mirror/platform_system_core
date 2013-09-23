#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int nohup_main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s [-n] program args...\n", argv[0]);
        return EXIT_FAILURE;
    }
    signal(SIGHUP, SIG_IGN);
    argv++;
    if (strcmp(argv[0], "-n") == 0) {
        argv++;
        signal(SIGINT, SIG_IGN);
        signal(SIGSTOP, SIG_IGN);
        signal(SIGTTIN, SIG_IGN);
        signal(SIGTTOU, SIG_IGN);
        signal(SIGQUIT, SIG_IGN);
        signal(SIGTERM, SIG_IGN);
    }
    execvp(argv[0], argv);
    perror(argv[0]);
    return EXIT_FAILURE;
}
