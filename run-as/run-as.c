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

#define PROGNAME  "run-as"
#define LOG_TAG   PROGNAME

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <stdarg.h>

#include <selinux/android.h>
#include <private/android_filesystem_config.h>
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

static void
usage(void)
{
    const char*  str = "Usage: " PROGNAME " <package-name> <command> [<args>]\n\n";
    write(1, str, strlen(str));
    exit(1);
}


static void
panic(const char* format, ...)
{
    va_list args;

    fprintf(stderr, "%s: ", PROGNAME);
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
    exit(1);
}


int main(int argc, char **argv)
{
    const char* pkgname;
    int myuid, uid, gid;
    PackageInfo info;

    /* check arguments */
    if (argc < 2)
        usage();

    /* check userid of caller - must be 'shell' or 'root' */
    myuid = getuid();
    if (myuid != AID_SHELL && myuid != AID_ROOT) {
        panic("only 'shell' or 'root' users can run this program\n");
    }

    /* retrieve package information from system */
    pkgname = argv[1];
    if (get_package_info(pkgname, &info) < 0) {
        panic("Package '%s' is unknown\n", pkgname);
        return 1;
    }

    /* reject system packages */
    if (info.uid < AID_APP) {
        panic("Package '%s' is not an application\n", pkgname);
        return 1;
    }

    /* reject any non-debuggable package */
    if (!info.isDebuggable) {
        panic("Package '%s' is not debuggable\n", pkgname);
        return 1;
    }

    /* check that the data directory path is valid */
    if (check_data_path(info.dataDir, info.uid) < 0) {
        panic("Package '%s' has corrupt installation\n", pkgname);
        return 1;
    }

    /* Ensure that we change all real/effective/saved IDs at the
     * same time to avoid nasty surprises.
     */
    uid = gid = info.uid;
    if(setresgid(gid,gid,gid) || setresuid(uid,uid,uid)) {
        panic("Permission denied\n");
        return 1;
    }

    if (selinux_android_setcontext(uid, 0, info.seinfo, pkgname) < 0) {
        panic("Could not set SELinux security context:  %s\n", strerror(errno));
        return 1;
    }

    /* cd into the data directory */
    {
        int ret;
        do {
            ret = chdir(info.dataDir);
        } while (ret < 0 && errno == EINTR);

        if (ret < 0) {
            panic("Could not cd to package's data directory: %s\n", strerror(errno));
            return 1;
        }
    }

    /* User specified command for exec. */
    if (argc >= 3 ) {
        if (execvp(argv[2], argv+2) < 0) {
            panic("exec failed for %s Error:%s\n", argv[2], strerror(errno));
            return -errno;
        }
    }

    /* Default exec shell. */
    execlp("/system/bin/sh", "sh", NULL);

    panic("exec failed\n");
    return 1;
}
