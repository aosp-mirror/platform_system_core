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

#ifndef __CORE_FS_MGR_PRIV_AVB_OPS_H
#define __CORE_FS_MGR_PRIV_AVB_OPS_H

#include <map>
#include <string>

#include <libavb/libavb.h>

#include "fs_mgr.h"

// This class provides C++ bindings to interact with libavb, a small
// self-contained piece of code that's intended to be used in bootloaders.
// It mainly contains two functions:
//   - ReadFromPartition(): to read AVB metadata from a given partition.
//     It provides the implementation of AvbOps.read_from_partition() when
//     reading metadata through libavb.
//   - AvbSlotVerify(): the C++ binding of libavb->avb_slot_verify() to
//     read and verify the metadata and store it into the out_data parameter.
//     The caller MUST check the integrity of metadata against the
//     androidboot.vbmeta.{hash_alg, size, digest} values from /proc/cmdline.
//     e.g., see class FsManagerAvbVerifier for more details.
//
class FsManagerAvbOps {
  public:
    FsManagerAvbOps(const fstab& fstab);
    FsManagerAvbOps(std::map<std::string, std::string>&& by_name_symlink_map);

    static FsManagerAvbOps* GetInstanceFromAvbOps(AvbOps* ops) {
        return reinterpret_cast<FsManagerAvbOps*>(ops->user_data);
    }

    AvbIOResult ReadFromPartition(const char* partition, int64_t offset, size_t num_bytes,
                                  void* buffer, size_t* out_num_read);

    AvbSlotVerifyResult AvbSlotVerify(const std::string& ab_suffix, AvbSlotVerifyFlags flags,
                                      AvbSlotVerifyData** out_data);

  private:
    void InitializeAvbOps();

    AvbOps avb_ops_;
    std::map<std::string, std::string> by_name_symlink_map_;
};
#endif /* __CORE_FS_MGR_PRIV_AVB_OPS_H */
