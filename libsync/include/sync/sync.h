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

#include <sys/cdefs.h>
#include <stdint.h>

#include <linux/types.h>

__BEGIN_DECLS

struct sync_legacy_merge_data {
 int32_t fd2;
 char name[32];
 int32_t fence;
};

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

#define SYNC_IOC_MAGIC		'>'

/**
 * DOC: SYNC_IOC_LEGACY_WAIT - wait for a fence to signal
 *
 * pass timeout in milliseconds.  Waits indefinitely timeout < 0.
 *
 * This is the legacy version of the Sync API before the de-stage that happened
 * on Linux kernel 4.7.
 */
#define SYNC_IOC_LEGACY_WAIT	_IOW(SYNC_IOC_MAGIC, 0, __s32)

/**
 * DOC: SYNC_IOC_MERGE - merge two fences
 *
 * Takes a struct sync_merge_data.  Creates a new fence containing copies of
 * the sync_pts in both the calling fd and sync_merge_data.fd2.  Returns the
 * new fence's fd in sync_merge_data.fence
 *
 * This is the legacy version of the Sync API before the de-stage that happened
 * on Linux kernel 4.7.
 */
#define SYNC_IOC_LEGACY_MERGE	_IOWR(SYNC_IOC_MAGIC, 1, \
	struct sync_legacy_merge_data)

/**
 * DOC: SYNC_IOC_LEGACY_FENCE_INFO - get detailed information on a fence
 *
 * Takes a struct sync_fence_info_data with extra space allocated for pt_info.
 * Caller should write the size of the buffer into len.  On return, len is
 * updated to reflect the total size of the sync_fence_info_data including
 * pt_info.
 *
 * pt_info is a buffer containing sync_pt_infos for every sync_pt in the fence.
 * To iterate over the sync_pt_infos, use the sync_pt_info.len field.
 *
 * This is the legacy version of the Sync API before the de-stage that happened
 * on Linux kernel 4.7.
 */
#define SYNC_IOC_LEGACY_FENCE_INFO	_IOWR(SYNC_IOC_MAGIC, 2,\
	struct sync_fence_info_data)

/* timeout in msecs */
int sync_wait(int fd, int timeout);
int sync_merge(const char *name, int fd1, int fd2);
struct sync_fence_info_data *sync_fence_info(int fd);
struct sync_pt_info *sync_pt_info(struct sync_fence_info_data *info,
                                  struct sync_pt_info *itr);
void sync_fence_info_free(struct sync_fence_info_data *info);

__END_DECLS

#endif /* __SYS_CORE_SYNC_H */
