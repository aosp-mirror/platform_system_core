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

#pragma once

#include <stdbool.h>
#include <sys/types.h>

__BEGIN_DECLS

typedef struct gid_list {
  /** Number of gids. */
  size_t cnt;

  /** Array of gids. */
  gid_t* gids;
} gid_list;

typedef struct pkg_info {
  /** Package name like "com.android.blah". */
  char* name;

  /** Package uid like 10014. */
  uid_t uid;

  /** Package's AndroidManifest.xml debuggable flag. */
  bool debuggable;

  /** Package data directory like "/data/user/0/com.android.blah" */
  char* data_dir;

  /** Package SELinux info. */
  char* seinfo;

  /** Package's list of gids. */
  gid_list gids;

  /** Spare pointer for the caller to stash extra data off. */
  void* private_data;

  /** Package's AndroidManifest.xml profileable flag. */
  bool profileable_from_shell;

  /** Package's AndroidManifest.xml version code. */
  long version_code;
} pkg_info;

/**
 * Parses the system's default package list.
 * Invokes `callback` once for each package.
 * The callback owns the `pkg_info*` and should call packagelist_free().
 * The callback should return `false` to exit early or `true` to continue.
 */
bool packagelist_parse(bool (*callback)(pkg_info* info, void* user_data), void* user_data);

/**
 * Parses the given package list.
 * Invokes `callback` once for each package.
 * The callback owns the `pkg_info*` and should call packagelist_free().
 * The callback should return `false` to exit early or `true` to continue.
 */
bool packagelist_parse_file(const char* path, bool (*callback)(pkg_info* info, void* user_data),
                            void* user_data);

/** Frees the given `pkg_info`. */
void packagelist_free(pkg_info* info);

__END_DECLS
