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
#include <unistd.h>
#include <sys/stat.h>
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

/* This should be large enough to hold the content of the package database file */
#define PACKAGES_LIST_BUFFER_SIZE  8192

/* Copy 'srclen' string bytes from 'src' into buffer 'dst' of size 'dstlen'
 * This function always zero-terminate the destination buffer unless
 * 'dstlen' is 0, even in case of overflow.
 */
static void
string_copy(char* dst, size_t dstlen, const char* src, size_t srclen)
{
    const char* srcend = src + srclen;
    const char* dstend = dst + dstlen;

    if (dstlen == 0)
        return;

    dstend--; /* make room for terminating zero */

    while (dst < dstend && src < srcend && *src != '\0')
        *dst++ = *src++;

    *dst = '\0'; /* zero-terminate result */
}

/* Read up to 'buffsize' bytes into 'buff' from the file
 * named 'filename'. Return byte length on success, or -1
 * on error.
 */
static int
read_file(const char* filename, char* buff, size_t buffsize)
{
    int  fd, len, old_errno;

    /* check the input buffer size */
    if (buffsize >= INT_MAX) {
        errno = EINVAL;
        return -1;
    }

    /* open the file for reading */
    do {
        fd = open(filename, O_RDONLY);
    } while (fd < 0 && errno == EINTR);

    if (fd < 0)
        return -1;

    /* read the content */
    do {
        len = read(fd, buff, buffsize);
    } while (len < 0 && errno == EINTR);

    /* close the file, preserve old errno for better diagnostics */
    old_errno = errno;
    close(fd);
    errno = old_errno;

    return len;
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

BAD:
    *pp = p;
    return -1;
}

/* Read the system's package database and extract information about
 * 'pkgname'. Return 0 in case of success, or -1 in case of error.
 *
 * If the package is unknown, return -1 and set errno to ENOENT
 * If the package database is corrupted, return -1 and set errno to EINVAL
 */
int
get_package_info(const char* pkgName, PackageInfo *info)
{
    static char  buffer[PACKAGES_LIST_BUFFER_SIZE];
    int          buffer_len;
    const char*  p;
    const char*  buffer_end;
    int          result;

    info->uid          = 0;
    info->isDebuggable = 0;
    info->dataDir[0]   = '\0';

    buffer_len = read_file(PACKAGES_LIST_FILE, buffer, sizeof buffer);
    if (buffer_len < 0)
        return -1;

    p          = buffer;
    buffer_end = buffer + buffer_len;

    /* expect the following format on each line of the control file:
     *
     *  <pkgName> <uid> <debugFlag> <dataDir>
     *
     * where:
     *  <pkgName>    is the package's name
     *  <uid>        is the application-specific user Id (decimal)
     *  <debugFlag>  is 1 if the package is debuggable, or 0 otherwise
     *  <dataDir>    is the path to the package's data directory (e.g. /data/data/com.example.foo)
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

        string_copy(info->dataDir, sizeof info->dataDir, p, q - p);

        /* Ignore the rest */
        return 0;

    NEXT_LINE:
        p = next;
    }

    /* the package is unknown */
    errno = ENOENT;
    return -1;

BAD_FORMAT:
    errno = EINVAL;
    return -1;
}
