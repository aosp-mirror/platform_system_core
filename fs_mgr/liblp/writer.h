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

#ifndef LIBLP_WRITER_H
#define LIBLP_WRITER_H

#include <functional>
#include <string>

#include <liblp/liblp.h>

namespace android {
namespace fs_mgr {

// These variants are for testing only. The path-based functions should be used
// for actual operation, so that open() is called with the correct flags.
bool FlashPartitionTable(int fd, const LpMetadata& metadata, uint32_t slot_number);
bool UpdatePartitionTable(int fd, const LpMetadata& metadata, uint32_t slot_number);

bool UpdatePartitionTable(int fd, const LpMetadata& metadata, uint32_t slot_number,
                          const std::function<bool(int, const std::string&)>& writer);

// Helper function to serialize geometry and metadata to a normal file, for
// flashing or debugging.
bool WriteToImageFile(const char* file, const LpMetadata& metadata);
bool WriteToImageFile(int fd, const LpMetadata& metadata);

}  // namespace fs_mgr
}  // namespace android

#endif /* LIBLP_WRITER_H */
