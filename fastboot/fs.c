#include "fastboot.h"
#include "make_ext4fs.h"
#include "make_f2fs.h"
#include "fs.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sparse/sparse.h>
#include <unistd.h>

#ifdef USE_MINGW
#include <fcntl.h>
#else
#include <sys/mman.h>
#endif



static int generate_ext4_image(int fd, long long partSize)
{
    make_ext4fs_sparse_fd(fd, partSize, NULL, NULL);

    return 0;
}

#ifdef USE_F2FS
static int generate_f2fs_image(int fd, long long partSize)
{
    return make_f2fs_sparse_fd(fd, partSize, NULL, NULL);
}
#endif

static const struct fs_generator {

    char *fs_type;  //must match what fastboot reports for partition type
    int (*generate)(int fd, long long partSize); //returns 0 or error value

} generators[] = {
    { "ext4", generate_ext4_image},
#ifdef USE_F2FS
    { "f2fs", generate_f2fs_image},
#endif
};

const struct fs_generator* fs_get_generator(const char *fs_type)
{
    unsigned i;

    for (i = 0; i < sizeof(generators) / sizeof(*generators); i++)
        if (!strcmp(generators[i].fs_type, fs_type))
            return generators + i;

    return NULL;
}

int fs_generator_generate(const struct fs_generator* gen, int tmpFileNo, long long partSize)
{
    return gen->generate(tmpFileNo, partSize);
}
