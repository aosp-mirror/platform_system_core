/*
 *  Copyright 2018 Google, Inc
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

#ifndef _LIBDM_DMTABLE_H_
#define _LIBDM_DMTABLE_H_

#include <stdint.h>

#include <memory>
#include <string>
#include <vector>

#include "dm_target.h"

namespace android {
namespace dm {

class DmTable {
  public:
    DmTable() : num_sectors_(0), readonly_(false) {}
    DmTable(DmTable&& other) = default;

    // Adds a target to the device mapper table for a range specified in the target object.
    // The function will return 'true' if the target was successfully added and doesn't overlap with
    // any of the existing targets in the table. Gaps are allowed. The final check, including
    // overlaps and gaps are done before loading the table. Returns 'false' on failure.
    bool AddTarget(std::unique_ptr<DmTarget>&& target);

    // Removes a target from the table for the range specified in the target object. Returns 'false'
    // if the target name doesn't match with the one in the table. Returns 'true' if target is
    // successfully removed.
    bool RemoveTarget(std::unique_ptr<DmTarget>&& target);

    // Adds a target, constructing it in-place for convenience. For example,
    //
    //   table.Emplace<DmTargetZero>(0, num_sectors);
    template <typename T, typename... Args>
    bool Emplace(Args&&... args) {
        return AddTarget(std::make_unique<T>(std::forward<Args>(args)...));
    }

    // Checks the table to make sure it is valid. i.e. Checks for range overlaps, range gaps
    // and returns 'true' if the table is ready to be loaded into kernel. Returns 'false' if the
    // table is malformed.
    bool valid() const;

    // Returns the total number of targets.
    size_t num_targets() const { return targets_.size(); }

    // Returns the total size represented by the table in terms of number of 512-byte sectors.
    // NOTE: This function will overlook if there are any gaps in the targets added in the table.
    uint64_t num_sectors() const;

    // Returns the string represntation of the table that is ready to be passed into the kernel
    // as part of the DM_TABLE_LOAD ioctl.
    std::string Serialize() const;

    void set_readonly(bool readonly) { readonly_ = readonly; }
    bool readonly() const { return readonly_; }

    DmTable& operator=(DmTable&& other) = default;

    ~DmTable() = default;

  private:
    // list of targets defined in this table sorted by
    // their start and end sectors.
    // Note: Overlapping targets MUST never be added in this list.
    std::vector<std::unique_ptr<DmTarget>> targets_;

    // Total size in terms of # of sectors, as calculated by looking at the last and the first
    // target in 'target_'.
    uint64_t num_sectors_;

    // True if the device should be read-only; false otherwise.
    bool readonly_;
};

}  // namespace dm
}  // namespace android

#endif /* _LIBDM_DMTABLE_H_ */
