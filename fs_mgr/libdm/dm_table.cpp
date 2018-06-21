/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include "libdm/dm_table.h"

#include <android-base/logging.h>
#include <android-base/macros.h>

namespace android {
namespace dm {

bool DmTable::AddTarget(std::unique_ptr<DmTarget>&& /* target */) {
    return true;
}

bool DmTable::RemoveTarget(std::unique_ptr<DmTarget>&& /* target */) {
    return true;
}

bool DmTable::valid() const {
    return true;
}

uint64_t DmTable::num_sectors() const {
    return valid() ? num_sectors_ : 0;
}

// Returns a string represnetation of the table that is ready to be passed
// down to the kernel for loading
//
// Implementation must verify there are no gaps in the table, table starts
// with sector == 0, and iterate over each target to get its table
// serialized.
std::string DmTable::Serialize() const {
    return "";
}

}  // namespace dm
}  // namespace android
