#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <md5.h>

/* When this was written, bionic's md5.h did not define this. */
#ifndef MD5_DIGEST_LENGTH
#define MD5_DIGEST_LENGTH 16
#endif

static int usage()
{
    fprintf(stderr,"md5 file ...\n");
    return -1;
}

static int do_md5(const char *path)
{
    unsigned int i;
    int fd;
    MD5_CTX md5_ctx;
    unsigned char md5[MD5_DIGEST_LENGTH];

    fd = open(path, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr,"could not open %s, %s\n", path, strerror(errno));
        return -1;
    }

    /* Note that bionic's MD5_* functions return void. */
    MD5_Init(&md5_ctx);

    while (1) {
        char buf[4096];
        ssize_t rlen;
        rlen = read(fd, buf, sizeof(buf));
        if (rlen == 0)
            break;
        else if (rlen < 0) {
            (void)close(fd);
            fprintf(stderr,"could not read %s, %s\n", path, strerror(errno));
            return -1;
        }
        MD5_Update(&md5_ctx, buf, rlen);
    }
    if (close(fd)) {
        fprintf(stderr,"could not close %s, %s\n", path, strerror(errno));
        return -1;
    }

    MD5_Final(md5, &md5_ctx);

    for (i = 0; i < (int)sizeof(md5); i++)
        printf("%02x", md5[i]);
    printf("  %s\n", path);

    return 0;
}

int md5_main(int argc, char *argv[])
{
    int i, ret = 0;

    if (argc < 2)
        return usage();

    /* loop over the file args */
    for (i = 1; i < argc; i++) {
        if (do_md5(argv[i]))
            ret = 1;
    }

    return ret;
}
