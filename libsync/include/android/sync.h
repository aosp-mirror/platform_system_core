/*
 *  sync.h
 *
 *   Copyright 2012 Google, Inc
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#ifndef __SYS_CORE_SYNC_H
#define __SYS_CORE_SYNC_H

/* This file contains the legacy sync interface used by Android platform and
 * device code. The direct contents will be removed over time as code
 * transitions to using the updated interface in ndk/sync.h. When this file is
 * empty other than the ndk/sync.h include, that file will be renamed to
 * replace this one.
 *
 * New code should continue to include this file (#include <android/sync.h>)
 * instead of ndk/sync.h so the eventual rename is seamless, but should only
 * use the things declared in ndk/sync.h.
 *
 * This file used to be called sync/sync.h, but we renamed to that both the
 * platform and NDK call it android/sync.h. A symlink from the old name to this
 * one exists temporarily to avoid having to change all sync clients
 * simultaneously. It will be removed when they've been updated, and probably
 * after this change has been delivered to AOSP so that integrations don't
 * break builds.
 */

#include "../ndk/sync.h"

__BEGIN_DECLS

struct sync_fence_info_data {
 uint32_t len;
 char name[32];
 int32_t status;
 uint8_t pt_info[0];
};

struct sync_pt_info {
 uint32_t len;
 char obj_name[32];
 char driver_name[32];
 int32_t status;
 uint64_t timestamp_ns;
 uint8_t driver_data[0];
};

/* timeout in msecs */
int sync_wait(int fd, int timeout);
struct sync_fence_info_data *sync_fence_info(int fd);
struct sync_pt_info *sync_pt_info(struct sync_fence_info_data *info,
                                  struct sync_pt_info *itr);
void sync_fence_info_free(struct sync_fence_info_data *info);

__END_DECLS

#endif /* __SYS_CORE_SYNC_H */
