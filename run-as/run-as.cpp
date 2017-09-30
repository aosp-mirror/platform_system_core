/*
 * Copyright (C) 2010 The Android Open Source Project
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

#include <errno.h>
#include <error.h>
#include <paths.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/capability.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <libminijail.h>
#include <scoped_minijail.h>

#include <packagelistparser/packagelistparser.h>
#include <private/android_filesystem_config.h>
#include <selinux/android.h>

// The purpose of this program is to run a command as a specific
// application user-id. Typical usage is:
//
//   run-as <package-name> <command> <args>
//
//  The 'run-as' binary is installed with CAP_SETUID and CAP_SETGID file
//  capabilities, but will check the following:
//
//  - that it is invoked from the 'shell' or 'root' user (abort otherwise)
//  - that '<package-name>' is the name of an installed and debuggable package
//  - that the package's data directory is well-formed
//
//  If so, it will drop to the application's user id / group id, cd to the
//  package's data directory, then run the command there.
//
//  This can be useful for a number of different things on production devices:
//
//  - Allow application developers to look at their own application data
//    during development.
//
//  - Run the 'gdbserver' binary executable to allow native debugging
//

static bool packagelist_parse_callback(pkg_info* this_package, void* userdata) {
  pkg_info* p = reinterpret_cast<pkg_info*>(userdata);
  if (strcmp(p->name, this_package->name) == 0) {
    *p = *this_package;
    return false; // Stop searching.
  }
  packagelist_free(this_package);
  return true; // Keep searching.
}

static bool check_directory(const char* path, uid_t uid) {
  struct stat st;
  if (TEMP_FAILURE_RETRY(lstat(path, &st)) == -1) return false;

  // /data/user/0 is a known safe symlink.
  if (strcmp("/data/user/0", path) == 0) return true;

  // Must be a real directory, not a symlink.
  if (!S_ISDIR(st.st_mode)) return false;

  // Must be owned by specific uid/gid.
  if (st.st_uid != uid || st.st_gid != uid) return false;

  // Must not be readable or writable by others.
  if ((st.st_mode & (S_IROTH|S_IWOTH)) != 0) return false;

  return true;
}

// This function is used to check the data directory path for safety.
// We check that every sub-directory is owned by the 'system' user
// and exists and is not a symlink. We also check that the full directory
// path is properly owned by the user ID.
static bool check_data_path(const char* data_path, uid_t uid) {
  // The path should be absolute.
  if (data_path[0] != '/') return false;

  // Look for all sub-paths, we do that by finding
  // directory separators in the input path and
  // checking each sub-path independently.
  for (int nn = 1; data_path[nn] != '\0'; nn++) {
    char subpath[PATH_MAX];

    /* skip non-separator characters */
    if (data_path[nn] != '/') continue;

    /* handle trailing separator case */
    if (data_path[nn+1] == '\0') break;

    /* found a separator, check that data_path is not too long. */
    if (nn >= (int)(sizeof subpath)) return false;

    /* reject any '..' subpath */
    if (nn >= 3               &&
        data_path[nn-3] == '/' &&
        data_path[nn-2] == '.' &&
        data_path[nn-1] == '.') {
      return false;
    }

    /* copy to 'subpath', then check ownership */
    memcpy(subpath, data_path, nn);
    subpath[nn] = '\0';

    if (!check_directory(subpath, AID_SYSTEM)) return false;
  }

  // All sub-paths were checked, now verify that the full data
  // directory is owned by the application uid.
  return check_directory(data_path, uid);
}

int main(int argc, char* argv[]) {
  // Check arguments.
  if (argc < 2) {
    error(1, 0, "usage: run-as <package-name> [--user <uid>] <command> [<args>]\n");
  }

  // This program runs with CAP_SETUID and CAP_SETGID capabilities on Android
  // production devices. Check user id of caller --- must be 'shell' or 'root'.
  if (getuid() != AID_SHELL && getuid() != AID_ROOT) {
    error(1, 0, "only 'shell' or 'root' users can run this program");
  }

  char* pkgname = argv[1];
  int cmd_argv_offset = 2;

  // Get user_id from command line if provided.
  int userId = 0;
  if ((argc >= 4) && !strcmp(argv[2], "--user")) {
    userId = atoi(argv[3]);
    if (userId < 0) error(1, 0, "negative user id: %d", userId);
    cmd_argv_offset += 2;
  }

  // Retrieve package information from system, switching egid so we can read the file.
  gid_t old_egid = getegid();
  if (setegid(AID_PACKAGE_INFO) == -1) error(1, errno, "setegid(AID_PACKAGE_INFO) failed");
  pkg_info info;
  memset(&info, 0, sizeof(info));
  info.name = pkgname;
  if (!packagelist_parse(packagelist_parse_callback, &info)) {
    error(1, errno, "packagelist_parse failed");
  }
  if (info.uid == 0) {
    error(1, 0, "unknown package: %s", pkgname);
  }
  if (setegid(old_egid) == -1) error(1, errno, "couldn't restore egid");

  // Verify that user id is not too big.
  if ((UID_MAX - info.uid) / AID_USER_OFFSET < (uid_t)userId) {
    error(1, 0, "user id too big: %d", userId);
  }

  // Calculate user app ID.
  uid_t userAppId = (AID_USER_OFFSET * userId) + info.uid;

  // Reject system packages.
  if (userAppId < AID_APP) {
    error(1, 0, "package not an application: %s", pkgname);
  }

  // Reject any non-debuggable package.
  if (!info.debuggable) {
    error(1, 0, "package not debuggable: %s", pkgname);
  }

  // Check that the data directory path is valid.
  if (!check_data_path(info.data_dir, userAppId)) {
    error(1, 0, "package has corrupt installation: %s", pkgname);
  }

  // Ensure that we change all real/effective/saved IDs at the
  // same time to avoid nasty surprises.
  uid_t uid = userAppId;
  uid_t gid = userAppId;
  ScopedMinijail j(minijail_new());
  minijail_change_uid(j.get(), uid);
  minijail_change_gid(j.get(), gid);
  minijail_keep_supplementary_gids(j.get());
  minijail_enter(j.get());

  if (selinux_android_setcontext(uid, 0, info.seinfo, pkgname) < 0) {
    error(1, errno, "couldn't set SELinux security context");
  }

  // cd into the data directory, and set $HOME correspondingly.
  if (TEMP_FAILURE_RETRY(chdir(info.data_dir)) == -1) {
    error(1, errno, "couldn't chdir to package's data directory");
  }
  setenv("HOME", info.data_dir, 1);

  // Reset parts of the environment, like su would.
  setenv("PATH", _PATH_DEFPATH, 1);
  unsetenv("IFS");

  // Set the user-specific parts for this user.
  passwd* pw = getpwuid(uid);
  setenv("LOGNAME", pw->pw_name, 1);
  setenv("SHELL", pw->pw_shell, 1);
  setenv("USER", pw->pw_name, 1);

  // User specified command for exec.
  if ((argc >= cmd_argv_offset + 1) &&
      (execvp(argv[cmd_argv_offset], argv+cmd_argv_offset) == -1)) {
    error(1, errno, "exec failed for %s", argv[cmd_argv_offset]);
  }

  // Default exec shell.
  execlp(_PATH_BSHELL, "sh", NULL);
  error(1, errno, "exec failed");
}
