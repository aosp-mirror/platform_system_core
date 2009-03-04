#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

int exists_main(int argc, char *argv[])
{
    struct stat s;

    if(argc < 2) return 1;

    if(stat(argv[1], &s)) {
        return 1;
    } else {
        return 0;
    }
}
