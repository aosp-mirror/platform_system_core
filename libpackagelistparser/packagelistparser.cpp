/*
 * Copyright (C) 2019 The Android Open Source Project
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

#define LOG_TAG "packagelistparser"

#include <packagelistparser/packagelistparser.h>

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <sys/limits.h>

#include <memory>

#include <log/log.h>

static bool parse_gids(const char* path, size_t line_number, const char* gids, pkg_info* info) {
  // Nothing to do?
  if (!gids || !strcmp(gids, "none")) return true;

  // How much space do we need?
  info->gids.cnt = 1;
  for (const char* p = gids; *p; ++p) {
    if (*p == ',') ++info->gids.cnt;
  }

  // Allocate the space.
  info->gids.gids = new gid_t[info->gids.cnt];
  if (!info->gids.gids) return false;

  // And parse the individual gids.
  size_t i = 0;
  while (true) {
    char* end;
    unsigned long gid = strtoul(gids, &end, 10);
    if (gid > GID_MAX) {
      ALOGE("%s:%zu: gid %lu > GID_MAX", path, line_number, gid);
      return false;
    }

    if (i >= info->gids.cnt) return false;
    info->gids.gids[i++] = gid;

    if (*end == '\0') return true;
    if (*end != ',') return false;
    gids = end + 1;
  }
  return true;
}

static bool parse_line(const char* path, size_t line_number, const char* line, pkg_info* info) {
  unsigned long uid;
  int debuggable;
  char* gid_list;
  int profileable_from_shell = 0;

  int fields =
      sscanf(line, "%ms %lu %d %ms %ms %ms %d %ld", &info->name, &uid, &debuggable, &info->data_dir,
             &info->seinfo, &gid_list, &profileable_from_shell, &info->version_code);

  // Handle the more complicated gids field and free the temporary string.
  bool gids_okay = parse_gids(path, line_number, gid_list, info);
  free(gid_list);
  if (!gids_okay) return false;

  // Did we see enough fields to be getting on with?
  // The final fields are optional (and not usually present).
  if (fields < 6) {
    ALOGE("%s:%zu: too few fields in line", path, line_number);
    return false;
  }

  // Extra validation.
  if (uid > UID_MAX) {
    ALOGE("%s:%zu: uid %lu > UID_MAX", path, line_number, uid);
    return false;
  }
  info->uid = uid;

  // Integer to bool conversions.
  info->debuggable = debuggable;
  info->profileable_from_shell = profileable_from_shell;

  return true;
}

bool packagelist_parse_file(const char* path, bool (*callback)(pkg_info*, void*), void* user_data) {
  std::unique_ptr<FILE, decltype(&fclose)> fp(fopen(path, "re"), &fclose);
  if (!fp) {
    ALOGE("couldn't open '%s': %s", path, strerror(errno));
    return false;
  }

  size_t line_number = 0;
  char* line = nullptr;
  size_t allocated_length = 0;
  while (getline(&line, &allocated_length, fp.get()) > 0) {
    ++line_number;
    std::unique_ptr<pkg_info, decltype(&packagelist_free)> info(
        static_cast<pkg_info*>(calloc(1, sizeof(pkg_info))), &packagelist_free);
    if (!info) {
      ALOGE("%s:%zu: couldn't allocate pkg_info", path, line_number);
      return false;
    }

    if (!parse_line(path, line_number, line, info.get())) return false;

    if (!callback(info.release(), user_data)) break;
  }
  free(line);
  return true;
}

bool packagelist_parse(bool (*callback)(pkg_info*, void*), void* user_data) {
  return packagelist_parse_file("/data/system/packages.list", callback, user_data);
}

void packagelist_free(pkg_info* info) {
  if (!info) return;

  free(info->name);
  free(info->data_dir);
  free(info->seinfo);
  delete[] info->gids.gids;
  free(info);
}
