/*
 * Copyright (C) 2008 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Implementation of the user-space ashmem API for devices, which have our
 * ashmem-enabled kernel. See ashmem-sim.c for the "fake" tmp-based version,
 * used by the simulator.
 */

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <linux/ashmem.h>

#include <cutils/ashmem.h>

#define ASHMEM_DEVICE "/dev/ashmem"

/*
 * ashmem_create_region - creates a new ashmem region and returns the file
 * descriptor, or <0 on error
 *
 * `name' is an optional label to give the region (visible in /proc/pid/maps)
 * `size' is the size of the region, in page-aligned bytes
 */
int ashmem_create_region(const char *name, size_t size)
{
    int ret, save_errno;

    int fd = TEMP_FAILURE_RETRY(open(ASHMEM_DEVICE, O_RDWR));
    if (fd < 0) {
        return fd;
    }

    if (name) {
        char buf[ASHMEM_NAME_LEN] = {0};

        strlcpy(buf, name, sizeof(buf));
        ret = TEMP_FAILURE_RETRY(ioctl(fd, ASHMEM_SET_NAME, buf));
        if (ret < 0) {
            goto error;
        }
    }

    ret = TEMP_FAILURE_RETRY(ioctl(fd, ASHMEM_SET_SIZE, size));
    if (ret < 0) {
        goto error;
    }

    return fd;

error:
    save_errno = errno;
    close(fd);
    errno = save_errno;
    return ret;
}

int ashmem_set_prot_region(int fd, int prot)
{
    return TEMP_FAILURE_RETRY(ioctl(fd, ASHMEM_SET_PROT_MASK, prot));
}

int ashmem_pin_region(int fd, size_t offset, size_t len)
{
    struct ashmem_pin pin = { offset, len };
    return TEMP_FAILURE_RETRY(ioctl(fd, ASHMEM_PIN, &pin));
}

int ashmem_unpin_region(int fd, size_t offset, size_t len)
{
    struct ashmem_pin pin = { offset, len };
    return TEMP_FAILURE_RETRY(ioctl(fd, ASHMEM_UNPIN, &pin));
}

int ashmem_get_size_region(int fd)
{
    return TEMP_FAILURE_RETRY(ioctl(fd, ASHMEM_GET_SIZE, NULL));
}
