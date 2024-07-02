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

#include <cutils/ashmem.h>

/*
 * Implementation of the user-space ashmem API for the simulator, which lacks an
 * ashmem-enabled kernel. See ashmem-dev.c for the real ashmem-based version.  A
 * disk-backed temp file is the best option that is consistently supported
 * across all host platforms.
 */

#include <android-base/unique_fd.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <utils/Compat.h>
#include <memory>

using android::base::unique_fd;

static bool ashmem_validate_stat(int fd, struct stat* buf) {
    int result = fstat(fd, buf);
    if (result == -1) {
        return false;
    }

    // Check if this is an ashmem region. Since there's no such thing on the host,
    // we can't actually implement that. Check that it's at least a regular file.
    if (!S_ISREG(buf->st_mode)) {
        errno = ENOTTY;
        return false;
    }
    // In Win32, unlike Unix, the temp file is not unlinked immediately after
    // creation.
#if !defined(_WIN32)
    if (buf->st_nlink != 0) {
        errno = ENOTTY;
        return false;
    }
#endif
    return true;
}

int ashmem_valid(int fd) {
    struct stat buf;
    return ashmem_validate_stat(fd, &buf);
}

int ashmem_create_region(const char* /*ignored*/, size_t size) {
    // Files returned by tmpfile are automatically removed.
    std::unique_ptr<FILE, decltype(&fclose)> tmp(tmpfile(), &fclose);

    if (!tmp) {
        return -1;
    }
    int fd = fileno(tmp.get());
    if (fd == -1) {
        return -1;
    }
    unique_fd dupfd = unique_fd(dup(fd));
    if (dupfd == -1) {
        return -1;
    }
    if (TEMP_FAILURE_RETRY(ftruncate(dupfd, size)) == -1) {
        return -1;
    }
    return dupfd.release();
}

int ashmem_set_prot_region(int /*fd*/, int /*prot*/) {
    return 0;
}

int ashmem_pin_region(int /*fd*/, size_t /*offset*/, size_t /*len*/) {
    return 0 /*ASHMEM_NOT_PURGED*/;
}

int ashmem_unpin_region(int /*fd*/, size_t /*offset*/, size_t /*len*/) {
    return 0 /*ASHMEM_IS_UNPINNED*/;
}

int ashmem_get_size_region(int fd)
{
    struct stat buf;
    if (!ashmem_validate_stat(fd, &buf)) {
        return -1;
    }

    return buf.st_size;
}
