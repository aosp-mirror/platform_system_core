#ifndef _FS_H_
#define _FS_H_

#include <stdint.h>

#if defined(__cplusplus)
extern "C" {
#endif

struct fs_generator;

const struct fs_generator* fs_get_generator(const char *fs_type);
int fs_generator_generate(const struct fs_generator* gen, int tmpFileNo, long long partSize);

#if defined(__cplusplus)
}
#endif

#endif

