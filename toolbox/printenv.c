#include <stdio.h>
#include <stdlib.h>

extern char** environ;

int printenv_main (int argc, char **argv)
{
    char** e;
    char* v;
    int i;
   
    if (argc == 1) {
        e = environ;
        while (*e) {
            printf("%s\n", *e);
            e++;
        }
    } else {
        for (i=1; i<argc; i++) {
            v = getenv(argv[i]);
            if (v) {
                printf("%s\n", v);
            }
        }
    }

    return 0;
}

