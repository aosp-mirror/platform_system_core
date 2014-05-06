/* libs/diskconfig/diskutils.c
 *
 * Copyright 2008, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define LOG_TAG "diskutils"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include <log/log.h>

#include <diskconfig/diskconfig.h>

int
write_raw_image(const char *dst, const char *src, loff_t offset, int test)
{
    int dst_fd = -1;
    int src_fd = -1;
    uint8_t buffer[2048];
    ssize_t nr_bytes;
    ssize_t tmp;
    int done = 0;
    uint64_t total = 0;

    ALOGI("Writing RAW image '%s' to '%s' (offset=%llu)", src, dst, (unsigned long long)offset);
    if ((src_fd = open(src, O_RDONLY)) < 0) {
        ALOGE("Could not open %s for reading (errno=%d).", src, errno);
        goto fail;
    }

    if (!test) {
        if ((dst_fd = open(dst, O_RDWR)) < 0) {
            ALOGE("Could not open '%s' for read/write (errno=%d).", dst, errno);
            goto fail;
        }

        if (lseek64(dst_fd, offset, SEEK_SET) != offset) {
            ALOGE("Could not seek to offset %lld in %s.", (long long)offset, dst);
            goto fail;
        }
    }

    while (!done) {
        if ((nr_bytes = read(src_fd, buffer, sizeof(buffer))) < 0) {
            /* XXX: Should we not even bother with EINTR? */
            if (errno == EINTR)
                continue;
            ALOGE("Error (%d) while reading from '%s'", errno, src);
            goto fail;
        }

        if (!nr_bytes) {
            /* we're done. */
            done = 1;
            break;
        }

        total += nr_bytes;

        /* skip the write loop if we're testing */
        if (test)
            nr_bytes = 0;

        while (nr_bytes > 0) {
            if ((tmp = write(dst_fd, buffer, nr_bytes)) < 0) {
                /* XXX: Should we not even bother with EINTR? */
                if (errno == EINTR)
                    continue;
                ALOGE("Error (%d) while writing to '%s'", errno, dst);
                goto fail;
            }
            if (!tmp)
                continue;
            nr_bytes -= tmp;
        }
    }

    if (!done) {
        ALOGE("Exited read/write loop without setting flag! WTF?!");
        goto fail;
    }

    if (dst_fd >= 0)
        fsync(dst_fd);

    ALOGI("Wrote %" PRIu64 " bytes to %s @ %lld", total, dst, (long long)offset);

    close(src_fd);
    if (dst_fd >= 0)
        close(dst_fd);
    return 0;

fail:
    if (dst_fd >= 0)
        close(dst_fd);
    if (src_fd >= 0)
        close(src_fd);
    return 1;
}
