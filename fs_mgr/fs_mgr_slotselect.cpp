/*
 * Copyright (C) 2015 The Android Open Source Project
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

#include <stdio.h>

#include "fs_mgr.h"
#include "fs_mgr_priv.h"

// Updates |fstab| for slot_suffix. Returns 0 on success, -1 on error.
int fs_mgr_update_for_slotselect(struct fstab *fstab)
{
    int n;
    int got_suffix = 0;
    std::string suffix;

    for (n = 0; n < fstab->num_entries; n++) {
        if (fstab->recs[n].fs_mgr_flags & MF_SLOTSELECT) {
            char *tmp;

            if (!got_suffix) {
                if (!fs_mgr_get_boot_config("slot_suffix", &suffix)) {
                  return -1;
                }
                got_suffix = 1;
            }

            if (asprintf(&tmp, "%s%s", fstab->recs[n].blk_device,
                         suffix.c_str()) > 0) {
                free(fstab->recs[n].blk_device);
                fstab->recs[n].blk_device = tmp;
            } else {
                return -1;
            }
        }
    }
    return 0;
}
