#pragma once

#include <string>
#include <stdint.h>

struct fs_generator;

enum FS_OPTION {
    FS_OPT_CASEFOLD,
    FS_OPT_PROJID,
    FS_OPT_COMPRESS,
};

const struct fs_generator* fs_get_generator(const std::string& fs_type);
int fs_generator_generate(const struct fs_generator* gen, const char* fileName, long long partSize,
                          const std::string& initial_dir, unsigned eraseBlkSize = 0,
                          unsigned logicalBlkSize = 0, unsigned fsOptions = 0);
