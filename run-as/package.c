/*
**
** Copyright 2010, The Android Open Source Project
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <private/android_filesystem_config.h>
#include "package.h"

/*
 *  WARNING WARNING WARNING WARNING
 *
 *  The following code runs as root on production devices, before
 *  the run-as command has dropped the uid/gid. Hence be very
 *  conservative and keep in mind the following:
 *
 *  - Performance does not matter here, clarity and safety of the code
 *    does however. Documentation is a must.
 *
 *  - Avoid calling C library functions with complex implementations
 *    like malloc() and printf(). You want to depend on simple system
 *    calls instead, which behaviour is not going to be altered in
 *    unpredictible ways by environment variables or system properties.
 *
 *  - Do not trust user input and/or the filesystem whenever possible.
 *
 */

/* The file containing the list of installed packages on the system */
#define PACKAGES_LIST_FILE  "/data/system/packages.list"

/* Copy 'srclen' string bytes from 'src' into buffer 'dst' of size 'dstlen'
 * This function always zero-terminate the destination buffer unless
 * 'dstlen' is 0, even in case of overflow.
 * Returns a pointer into the src string, leaving off where the copy
 * has stopped. The copy will stop when dstlen, srclen or a null
 * character on src has been reached.
 */
static const char*
string_copy(char* dst, size_t dstlen, const char* src, size_t srclen)
{
    const char* srcend = src + srclen;
    const char* dstend = dst + dstlen;

    if (dstlen == 0)
        return src;

    dstend--; /* make room for terminating zero */

    while (dst < dstend && src < srcend && *src != '\0')
        *dst++ = *src++;

    *dst = '\0'; /* zero-terminate result */
    return src;
}

/* Open 'filename' and map it into our address-space.
 * Returns buffer address, or NULL on error
 * On exit, *filesize will be set to the file's size, or 0 on error
 */
static void*
map_file(const char* filename, size_t* filesize)
{
    int  fd, ret, old_errno;
    struct stat  st;
    size_t  length = 0;
    void*   address = NULL;
    gid_t   oldegid;

    *filesize = 0;

    /*
     * Temporarily switch effective GID to allow us to read
     * the packages file
     */

    oldegid = getegid();
    if (setegid(AID_PACKAGE_INFO) < 0) {
        return NULL;
    }

    /* open the file for reading */
    fd = TEMP_FAILURE_RETRY(open(filename, O_RDONLY));
    if (fd < 0) {
        return NULL;
    }

    /* restore back to our old egid */
    if (setegid(oldegid) < 0) {
        goto EXIT;
    }

    /* get its size */
    ret = TEMP_FAILURE_RETRY(fstat(fd, &st));
    if (ret < 0)
        goto EXIT;

    /* Ensure that the file is owned by the system user */
    if ((st.st_uid != AID_SYSTEM) || (st.st_gid != AID_PACKAGE_INFO)) {
        goto EXIT;
    }

    /* Ensure that the file has sane permissions */
    if ((st.st_mode & S_IWOTH) != 0) {
        goto EXIT;
    }

    /* Ensure that the size is not ridiculously large */
    length = (size_t)st.st_size;
    if ((off_t)length != st.st_size) {
        errno = ENOMEM;
        goto EXIT;
    }

    /* Memory-map the file now */
    do {
        address = mmap(NULL, length, PROT_READ, MAP_PRIVATE, fd, 0);
    } while (address == MAP_FAILED && errno == EINTR);
    if (address == MAP_FAILED) {
        address = NULL;
        goto EXIT;
    }

    /* We're good, return size */
    *filesize = length;

EXIT:
    /* close the file, preserve old errno for better diagnostics */
    old_errno = errno;
    close(fd);
    errno = old_errno;

    return address;
}

/* unmap the file, but preserve errno */
static void
unmap_file(void*  address, size_t  size)
{
    int old_errno = errno;
    TEMP_FAILURE_RETRY(munmap(address, size));
    errno = old_errno;
}

/* Check that a given directory:
 * - exists
 * - is owned by a given uid/gid
 * - is a real directory, not a symlink
 * - isn't readable or writable by others
 *
 * Return 0 on success, or -1 on error.
 * errno is set to EINVAL in case of failed check.
 */
static int
check_directory_ownership(const char* path, uid_t uid)
{
    int ret;
    struct stat st;

    do {
        ret = lstat(path, &st);
    } while (ret < 0 && errno == EINTR);

    if (ret < 0)
        return -1;

    /* must be a real directory, not a symlink */
    if (!S_ISDIR(st.st_mode))
        goto BAD;

    /* must be owned by specific uid/gid */
    if (st.st_uid != uid || st.st_gid != uid)
        goto BAD;

    /* must not be readable or writable by others */
    if ((st.st_mode & (S_IROTH|S_IWOTH)) != 0)
        goto BAD;

    /* everything ok */
    return 0;

BAD:
    errno = EINVAL;
    return -1;
}

/* This function is used to check the data directory path for safety.
 * We check that every sub-directory is owned by the 'system' user
 * and exists and is not a symlink. We also check that the full directory
 * path is properly owned by the user ID.
 *
 * Return 0 on success, -1 on error.
 */
int
check_data_path(const char* dataPath, uid_t  uid)
{
    int  nn;

    /* the path should be absolute */
    if (dataPath[0] != '/') {
        errno = EINVAL;
        return -1;
    }

    /* look for all sub-paths, we do that by finding
     * directory separators in the input path and
     * checking each sub-path independently
     */
    for (nn = 1; dataPath[nn] != '\0'; nn++)
    {
        char subpath[PATH_MAX];

        /* skip non-separator characters */
        if (dataPath[nn] != '/')
            continue;

        /* handle trailing separator case */
        if (dataPath[nn+1] == '\0') {
            break;
        }

        /* found a separator, check that dataPath is not too long. */
        if (nn >= (int)(sizeof subpath)) {
            errno = EINVAL;
            return -1;
        }

        /* reject any '..' subpath */
        if (nn >= 3               &&
            dataPath[nn-3] == '/' &&
            dataPath[nn-2] == '.' &&
            dataPath[nn-1] == '.') {
            errno = EINVAL;
            return -1;
        }

        /* copy to 'subpath', then check ownership */
        memcpy(subpath, dataPath, nn);
        subpath[nn] = '\0';

        if (check_directory_ownership(subpath, AID_SYSTEM) < 0)
            return -1;
    }

    /* All sub-paths were checked, now verify that the full data
     * directory is owned by the application uid
     */
    if (check_directory_ownership(dataPath, uid) < 0)
        return -1;

    /* all clear */
    return 0;
}

/* Return TRUE iff a character is a space or tab */
static inline int
is_space(char c)
{
    return (c == ' ' || c == '\t');
}

/* Skip any space or tab character from 'p' until 'end' is reached.
 * Return new position.
 */
static const char*
skip_spaces(const char*  p, const char*  end)
{
    while (p < end && is_space(*p))
        p++;

    return p;
}

/* Skip any non-space and non-tab character from 'p' until 'end'.
 * Return new position.
 */
static const char*
skip_non_spaces(const char* p, const char* end)
{
    while (p < end && !is_space(*p))
        p++;

    return p;
}

/* Find the first occurence of 'ch' between 'p' and 'end'
 * Return its position, or 'end' if none is found.
 */
static const char*
find_first(const char* p, const char* end, char ch)
{
    while (p < end && *p != ch)
        p++;

    return p;
}

/* Check that the non-space string starting at 'p' and eventually
 * ending at 'end' equals 'name'. Return new position (after name)
 * on success, or NULL on failure.
 *
 * This function fails is 'name' is NULL, empty or contains any space.
 */
static const char*
compare_name(const char* p, const char* end, const char* name)
{
    /* 'name' must not be NULL or empty */
    if (name == NULL || name[0] == '\0' || p == end)
        return NULL;

    /* compare characters to those in 'name', excluding spaces */
    while (*name) {
        /* note, we don't check for *p == '\0' since
         * it will be caught in the next conditional.
         */
        if (p >= end || is_space(*p))
            goto BAD;

        if (*p != *name)
            goto BAD;

        p++;
        name++;
    }

    /* must be followed by end of line or space */
    if (p < end && !is_space(*p))
        goto BAD;

    return p;

BAD:
    return NULL;
}

/* Parse one or more whitespace characters starting from '*pp'
 * until 'end' is reached. Updates '*pp' on exit.
 *
 * Return 0 on success, -1 on failure.
 */
static int
parse_spaces(const char** pp, const char* end)
{
    const char* p = *pp;

    if (p >= end || !is_space(*p)) {
        errno = EINVAL;
        return -1;
    }
    p   = skip_spaces(p, end);
    *pp = p;
    return 0;
}

/* Parse a positive decimal number starting from '*pp' until 'end'
 * is reached. Adjust '*pp' on exit. Return decimal value or -1
 * in case of error.
 *
 * If the value is larger than INT_MAX, -1 will be returned,
 * and errno set to EOVERFLOW.
 *
 * If '*pp' does not start with a decimal digit, -1 is returned
 * and errno set to EINVAL.
 */
static int
parse_positive_decimal(const char** pp, const char* end)
{
    const char* p = *pp;
    int value = 0;
    int overflow = 0;

    if (p >= end || *p < '0' || *p > '9') {
        errno = EINVAL;
        return -1;
    }

    while (p < end) {
        int      ch = *p;
        unsigned d  = (unsigned)(ch - '0');
        int      val2;

        if (d >= 10U) /* d is unsigned, no lower bound check */
            break;

        val2 = value*10 + (int)d;
        if (val2 < value)
            overflow = 1;
        value = val2;
        p++;
    }
    *pp = p;

    if (overflow) {
        errno = EOVERFLOW;
        value = -1;
    }
    return value;
}

/* Read the system's package database and extract information about
 * 'pkgname'. Return 0 in case of success, or -1 in case of error.
 *
 * If the package is unknown, return -1 and set errno to ENOENT
 * If the package database is corrupted, return -1 and set errno to EINVAL
 */
int
get_package_info(const char* pkgName, uid_t userId, PackageInfo *info)
{
    char*        buffer;
    size_t       buffer_len;
    const char*  p;
    const char*  buffer_end;
    int          result = -1;

    info->uid          = 0;
    info->isDebuggable = 0;
    info->dataDir[0]   = '\0';
    info->seinfo[0]    = '\0';

    buffer = map_file(PACKAGES_LIST_FILE, &buffer_len);
    if (buffer == NULL)
        return -1;

    p          = buffer;
    buffer_end = buffer + buffer_len;

    /* expect the following format on each line of the control file:
     *
     *  <pkgName> <uid> <debugFlag> <dataDir> <seinfo>
     *
     * where:
     *  <pkgName>    is the package's name
     *  <uid>        is the application-specific user Id (decimal)
     *  <debugFlag>  is 1 if the package is debuggable, or 0 otherwise
     *  <dataDir>    is the path to the package's data directory (e.g. /data/data/com.example.foo)
     *  <seinfo>     is the seinfo label associated with the package
     *
     * The file is generated in com.android.server.PackageManagerService.Settings.writeLP()
     */

    while (p < buffer_end) {
        /* find end of current line and start of next one */
        const char*  end  = find_first(p, buffer_end, '\n');
        const char*  next = (end < buffer_end) ? end + 1 : buffer_end;
        const char*  q;
        int          uid, debugFlag;

        /* first field is the package name */
        p = compare_name(p, end, pkgName);
        if (p == NULL)
            goto NEXT_LINE;

        /* skip spaces */
        if (parse_spaces(&p, end) < 0)
            goto BAD_FORMAT;

        /* second field is the pid */
        uid = parse_positive_decimal(&p, end);
        if (uid < 0)
            return -1;

        info->uid = (uid_t) uid;

        /* skip spaces */
        if (parse_spaces(&p, end) < 0)
            goto BAD_FORMAT;

        /* third field is debug flag (0 or 1) */
        debugFlag = parse_positive_decimal(&p, end);
        switch (debugFlag) {
        case 0:
            info->isDebuggable = 0;
            break;
        case 1:
            info->isDebuggable = 1;
            break;
        default:
            goto BAD_FORMAT;
        }

        /* skip spaces */
        if (parse_spaces(&p, end) < 0)
            goto BAD_FORMAT;

        /* fourth field is data directory path and must not contain
         * spaces.
         */
        q = skip_non_spaces(p, end);
        if (q == p)
            goto BAD_FORMAT;

        /* If userId == 0 (i.e. user is device owner) we can use dataDir value
         * from packages.list, otherwise compose data directory as
         * /data/user/$uid/$packageId
         */
        if (userId == 0) {
            p = string_copy(info->dataDir, sizeof info->dataDir, p, q - p);
        } else {
            snprintf(info->dataDir,
                     sizeof info->dataDir,
                     "/data/user/%d/%s",
                     userId,
                     pkgName);
            p = q;
        }

        /* skip spaces */
        if (parse_spaces(&p, end) < 0)
            goto BAD_FORMAT;

        /* fifth field is the seinfo string */
        q = skip_non_spaces(p, end);
        if (q == p)
            goto BAD_FORMAT;

        string_copy(info->seinfo, sizeof info->seinfo, p, q - p);

        /* Ignore the rest */
        result = 0;
        goto EXIT;

    NEXT_LINE:
        p = next;
    }

    /* the package is unknown */
    errno = ENOENT;
    result = -1;
    goto EXIT;

BAD_FORMAT:
    errno = EINVAL;
    result = -1;

EXIT:
    unmap_file(buffer, buffer_len);
    return result;
}
