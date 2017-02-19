/*
 * Copyright (C) 2016 The Android Open Source Project
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef __CORE_FS_MGR_AVB_OPS_H
#define __CORE_FS_MGR_AVB_OPS_H

#include <libavb/libavb.h>

#include "fs_mgr.h"

__BEGIN_DECLS

/* Allocates a "dummy" AvbOps instance solely for use in user-space.
 * Returns nullptr on OOM.
 *
 * It mainly provides read_from_partitions() for user-space to get
 * AvbSlotVerifyData.vbmeta_images[] and the caller MUST check their
 * integrity against the androidboot.vbmeta.{hash_alg, size, digest}
 * values from /proc/cmdline, e.g. verify_vbmeta_images()
 * in fs_mgr_avb.cpp.
 *
 * Other I/O operations are only required in boot loader so we set
 * them as dummy operations here.
 *  - Will allow any public key for signing.
 *  - returns 0 for any rollback index location.
 *  - returns device is unlocked regardless of the actual state.
 *  - returns a dummy guid for any partition.
 *
 * Frees with fs_mgr_dummy_avb_ops_free().
 */
AvbOps* fs_mgr_dummy_avb_ops_new(struct fstab* fstab);

/* Frees an AvbOps instance previously allocated with fs_mgr_avb_ops_new(). */
void fs_mgr_dummy_avb_ops_free(AvbOps* ops);

__END_DECLS

#endif /* __CORE_FS_MGR_AVB_OPS_H */
