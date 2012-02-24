#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <errno.h>
#include <selinux/selinux.h>

int load_policy_main(int argc, char **argv)
{
    int fd, rc, vers;
    struct stat sb;
    void *map;
    const char *path;

    if (argc != 2) {
        fprintf(stderr, "usage:  %s policy-file\n", argv[0]);
        exit(1);
    }

    path = argv[1];
    fd = open(path, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "Could not open %s:  %s\n", path, strerror(errno));
        exit(2);
    }

    if (fstat(fd, &sb) < 0) {
        fprintf(stderr, "Could not stat %s:  %s\n", path, strerror(errno));
        exit(3);
    }

    map = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map == MAP_FAILED) {
        fprintf(stderr, "Could not mmap %s:  %s\n", path, strerror(errno));
        exit(4);
    }

    rc = security_load_policy(map, sb.st_size);
    if (rc < 0) {
        fprintf(stderr, "Could not load %s:  %s\n", path, strerror(errno));
        exit(5);
    }
    munmap(map, sb.st_size);
    close(fd);
    exit(0);
}
