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

#include <string>
#include <vector>

#include <libminijail.h>
#include <scoped_minijail.h>

#include <android-base/properties.h>
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
//  - that the ro.boot.disable_runas property is not set
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

static void check_directory(const char* path, uid_t uid) {
  struct stat st;
  if (TEMP_FAILURE_RETRY(lstat(path, &st)) == -1) {
    error(1, errno, "couldn't stat %s", path);
  }

  // Must be a real directory, not a symlink.
  if (!S_ISDIR(st.st_mode)) {
    error(1, 0, "%s not a directory: %o", path, st.st_mode);
  }

  // Must be owned by specific uid/gid.
  if (st.st_uid != uid || st.st_gid != uid) {
    error(1, 0, "%s has wrong owner: %d/%d, not %d", path, st.st_uid, st.st_gid, uid);
  }

  // Must not be readable or writable by others.
  if ((st.st_mode & (S_IROTH | S_IWOTH)) != 0) {
    error(1, 0, "%s readable or writable by others: %o", path, st.st_mode);
  }
}

// This function is used to check the data directory path for safety.
// We check that every sub-directory is owned by the 'system' user
// and exists and is not a symlink. We also check that the full directory
// path is properly owned by the user ID.
static void check_data_path(const char* package_name, const char* data_path, uid_t uid) {
  // The path should be absolute.
  if (data_path[0] != '/') {
    error(1, 0, "%s data path not absolute: %s", package_name, data_path);
  }

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
    if (nn >= (int)(sizeof subpath)) {
      error(1, 0, "%s data path too long: %s", package_name, data_path);
    }

    /* reject any '..' subpath */
    if (nn >= 3               &&
        data_path[nn-3] == '/' &&
        data_path[nn-2] == '.' &&
        data_path[nn-1] == '.') {
      error(1, 0, "%s contains '..': %s", package_name, data_path);
    }

    /* copy to 'subpath', then check ownership */
    memcpy(subpath, data_path, nn);
    subpath[nn] = '\0';

    check_directory(subpath, AID_SYSTEM);
  }

  // All sub-paths were checked, now verify that the full data
  // directory is owned by the application uid.
  check_directory(data_path, uid);
}

std::vector<gid_t> get_supplementary_gids(uid_t userAppId) {
  std::vector<gid_t> gids;
  int size = getgroups(0, &gids[0]);
  if (size < 0) {
    error(1, errno, "getgroups failed");
  }
  gids.resize(size);
  size = getgroups(size, &gids[0]);
  if (size != static_cast<int>(gids.size())) {
    error(1, errno, "getgroups failed");
  }
  // Profile guide compiled oat files (like /data/app/xxx/oat/arm64/base.odex) are not readable
  // worldwide (DEXOPT_PUBLIC flag isn't set). To support reading them (needed by simpleperf for
  // profiling), add shared app gid to supplementary groups.
  gid_t shared_app_gid = userAppId % AID_USER_OFFSET - AID_APP_START + AID_SHARED_GID_START;
  gids.push_back(shared_app_gid);
  return gids;
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

  // Some devices can disable running run-as, such as Chrome OS when running in
  // non-developer mode.
  if (android::base::GetBoolProperty("ro.boot.disable_runas", false)) {
    error(1, 0, "run-as is disabled from the kernel commandline");
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
  pkg_info info = {.name = pkgname};
  gid_t old_egid = getegid();
  if (setegid(AID_PACKAGE_INFO) == -1) error(1, errno, "setegid(AID_PACKAGE_INFO) failed");
  if (!packagelist_parse(packagelist_parse_callback, &info)) {
    error(1, errno, "packagelist_parse failed");
  }
  if (setegid(old_egid) == -1) error(1, errno, "couldn't restore egid");

  if (info.uid == 0) {
    error(1, 0, "unknown package: %s", pkgname);
  }

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

  // Ensure we have the right data path for the specific user.
  free(info.data_dir);
  if (asprintf(&info.data_dir, "/data/user/%d/%s", userId, pkgname) == -1) {
    error(1, errno, "asprintf failed");
  }

  // Check that the data directory path is valid.
  check_data_path(pkgname, info.data_dir, userAppId);

  // Ensure that we change all real/effective/saved IDs at the
  // same time to avoid nasty surprises.
  uid_t uid = userAppId;
  uid_t gid = userAppId;
  std::vector<gid_t> supplementary_gids = get_supplementary_gids(userAppId);
  ScopedMinijail j(minijail_new());
  minijail_change_uid(j.get(), uid);
  minijail_change_gid(j.get(), gid);
  minijail_set_supplementary_gids(j.get(), supplementary_gids.size(), supplementary_gids.data());
  minijail_enter(j.get());

  std::string seinfo = std::string(info.seinfo) + ":fromRunAs";
  if (selinux_android_setcontext(uid, 0, seinfo.c_str(), pkgname) < 0) {
    error(1, errno, "couldn't set SELinux security context '%s'", seinfo.c_str());
  }

  // cd into the data directory, and set $HOME correspondingly.
  if (TEMP_FAILURE_RETRY(chdir(info.data_dir)) == -1) {
    error(1, errno, "couldn't chdir to package's data directory '%s'", info.data_dir);
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
