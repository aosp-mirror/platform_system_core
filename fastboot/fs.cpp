#include "fs.h"

#include "fastboot.h"
#include "make_f2fs.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <android-base/unique_fd.h>
#include <ext4_utils/make_ext4fs.h>
#include <sparse/sparse.h>

using android::base::unique_fd;

static int generate_ext4_image(const char* fileName, long long partSize, const std::string& initial_dir,
                                       unsigned eraseBlkSize, unsigned logicalBlkSize)
{
    unique_fd fd(open(fileName, O_CREAT | O_RDWR | O_TRUNC, S_IRUSR | S_IWUSR));
    if (fd == -1) {
        fprintf(stderr, "Unable to open output file for EXT4 filesystem: %s\n", strerror(errno));
        return -1;
    }
    if (initial_dir.empty()) {
        make_ext4fs_sparse_fd_align(fd, partSize, NULL, NULL, eraseBlkSize, logicalBlkSize);
    } else {
        make_ext4fs_sparse_fd_directory_align(fd, partSize, NULL, NULL, initial_dir.c_str(),
                                              eraseBlkSize, logicalBlkSize);
    }
    return 0;
}

#ifdef USE_F2FS
static int generate_f2fs_image(const char* fileName, long long partSize, const std::string& initial_dir,
                               unsigned /* unused */, unsigned /* unused */)
{
    if (!initial_dir.empty()) {
        fprintf(stderr, "Unable to set initial directory on F2FS filesystem: %s\n", strerror(errno));
        return -1;
    }
    unique_fd fd(open(fileName, O_CREAT | O_RDWR | O_TRUNC, S_IRUSR | S_IWUSR));
    if (fd == -1) {
        fprintf(stderr, "Unable to open output file for F2FS filesystem: %s\n", strerror(errno));
        return -1;
    }
    return make_f2fs_sparse_fd(fd, partSize, NULL, NULL);
}
#endif

static const struct fs_generator {
    const char* fs_type;  //must match what fastboot reports for partition type

    //returns 0 or error value
    int (*generate)(const char* fileName, long long partSize, const std::string& initial_dir,
                    unsigned eraseBlkSize, unsigned logicalBlkSize);

} generators[] = {
    { "ext4", generate_ext4_image},
#ifdef USE_F2FS
    { "f2fs", generate_f2fs_image},
#endif
};

const struct fs_generator* fs_get_generator(const std::string& fs_type) {
    for (size_t i = 0; i < sizeof(generators) / sizeof(*generators); i++) {
        if (fs_type == generators[i].fs_type) {
            return generators + i;
        }
    }
    return nullptr;
}

int fs_generator_generate(const struct fs_generator* gen, const char* fileName, long long partSize,
    const std::string& initial_dir, unsigned eraseBlkSize, unsigned logicalBlkSize)
{
    return gen->generate(fileName, partSize, initial_dir, eraseBlkSize, logicalBlkSize);
}
