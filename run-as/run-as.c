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

#define PROGNAME "run-as"
#define LOG_TAG  PROGNAME

#include <dirent.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/capability.h>
#include <sys/cdefs.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <private/android_filesystem_config.h>
#include <selinux/android.h>

#include "package.h"

/*
 *  WARNING WARNING WARNING WARNING
 *
 *  This program runs with CAP_SETUID and CAP_SETGID capabilities on Android
 *  production devices. Be very conservative when modifying it to avoid any
 *  serious security issue. Keep in mind the following:
 *
 *  - This program should only run for the 'root' or 'shell' users
 *
 *  - Avoid anything that is more complex than simple system calls
 *    until the uid/gid has been dropped to that of a normal user
 *    or you are sure to exit.
 *
 *    This avoids depending on environment variables, system properties
 *    and other external factors that may affect the C library in
 *    unpredictable ways.
 *
 *  - Do not trust user input and/or the filesystem whenever possible.
 *
 *  Read README.TXT for more details.
 *
 *
 *
 * The purpose of this program is to run a command as a specific
 * application user-id. Typical usage is:
 *
 *   run-as <package-name> <command> <args>
 *
 *  The 'run-as' binary is installed with CAP_SETUID and CAP_SETGID file
 *  capabilities, but will check the following:
 *
 *  - that it is invoked from the 'shell' or 'root' user (abort otherwise)
 *  - that '<package-name>' is the name of an installed and debuggable package
 *  - that the package's data directory is well-formed (see package.c)
 *
 *  If so, it will drop to the application's user id / group id, cd to the
 *  package's data directory, then run the command there.
 *
 *  NOTE: In the future it might not be possible to cd to the package's data
 *  directory under that package's user id / group id, in which case this
 *  utility will need to be changed accordingly.
 *
 *  This can be useful for a number of different things on production devices:
 *
 *  - Allow application developers to look at their own applicative data
 *    during development.
 *
 *  - Run the 'gdbserver' binary executable to allow native debugging
 */

__noreturn static void
panic(const char* format, ...)
{
    va_list args;
    int e = errno;

    fprintf(stderr, "%s: ", PROGNAME);
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
    exit(e ? -e : 1);
}

static void
usage(void)
{
    panic("Usage:\n    " PROGNAME " <package-name> [--user <uid>] <command> [<args>]\n");
}

int main(int argc, char **argv)
{
    const char* pkgname;
    uid_t myuid, uid, gid, userAppId = 0;
    int commandArgvOfs = 2, userId = 0;
    PackageInfo info;
    struct __user_cap_header_struct capheader;
    struct __user_cap_data_struct capdata[2];

    /* check arguments */
    if (argc < 2) {
        usage();
    }

    /* check userid of caller - must be 'shell' or 'root' */
    myuid = getuid();
    if (myuid != AID_SHELL && myuid != AID_ROOT) {
        panic("only 'shell' or 'root' users can run this program\n");
    }

    memset(&capheader, 0, sizeof(capheader));
    memset(&capdata, 0, sizeof(capdata));
    capheader.version = _LINUX_CAPABILITY_VERSION_3;
    capdata[CAP_TO_INDEX(CAP_SETUID)].effective |= CAP_TO_MASK(CAP_SETUID);
    capdata[CAP_TO_INDEX(CAP_SETGID)].effective |= CAP_TO_MASK(CAP_SETGID);
    capdata[CAP_TO_INDEX(CAP_SETUID)].permitted |= CAP_TO_MASK(CAP_SETUID);
    capdata[CAP_TO_INDEX(CAP_SETGID)].permitted |= CAP_TO_MASK(CAP_SETGID);

    if (capset(&capheader, &capdata[0]) < 0) {
        panic("Could not set capabilities: %s\n", strerror(errno));
    }

    pkgname = argv[1];

    /* get user_id from command line if provided */
    if ((argc >= 4) && !strcmp(argv[2], "--user")) {
        userId = atoi(argv[3]);
        if (userId < 0)
            panic("Negative user id %d is provided\n", userId);
        commandArgvOfs += 2;
    }

    /* retrieve package information from system (does setegid) */
    if (get_package_info(pkgname, userId, &info) < 0) {
        panic("Package '%s' is unknown\n", pkgname);
    }

    /* verify that user id is not too big. */
    if ((UID_MAX - info.uid) / AID_USER < (uid_t)userId) {
        panic("User id %d is too big\n", userId);
    }

    /* calculate user app ID. */
    userAppId = (AID_USER * userId) + info.uid;

    /* reject system packages */
    if (userAppId < AID_APP) {
        panic("Package '%s' is not an application\n", pkgname);
    }

    /* reject any non-debuggable package */
    if (!info.isDebuggable) {
        panic("Package '%s' is not debuggable\n", pkgname);
    }

    /* check that the data directory path is valid */
    if (check_data_path(info.dataDir, userAppId) < 0) {
        panic("Package '%s' has corrupt installation\n", pkgname);
    }

    /* Ensure that we change all real/effective/saved IDs at the
     * same time to avoid nasty surprises.
     */
    uid = gid = userAppId;
    if(setresgid(gid,gid,gid) || setresuid(uid,uid,uid)) {
        panic("Permission denied\n");
    }

    /* Required if caller has uid and gid all non-zero */
    memset(&capdata, 0, sizeof(capdata));
    if (capset(&capheader, &capdata[0]) < 0) {
        panic("Could not clear all capabilities: %s\n", strerror(errno));
    }

    if (selinux_android_setcontext(uid, 0, info.seinfo, pkgname) < 0) {
        panic("Could not set SELinux security context: %s\n", strerror(errno));
    }

    /* cd into the data directory */
    if (TEMP_FAILURE_RETRY(chdir(info.dataDir)) < 0) {
        panic("Could not cd to package's data directory: %s\n", strerror(errno));
    }

    /* User specified command for exec. */
    if ((argc >= commandArgvOfs + 1) &&
        (execvp(argv[commandArgvOfs], argv+commandArgvOfs) < 0)) {
        panic("exec failed for %s: %s\n", argv[commandArgvOfs], strerror(errno));
    }

    /* Default exec shell. */
    execlp("/system/bin/sh", "sh", NULL);

    panic("exec failed: %s\n", strerror(errno));
}
