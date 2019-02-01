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

#pragma once

#include <unwindstack/MapInfo.h>
#include <unwindstack/Maps.h>
#include <unwindstack/Unwinder.h>

class UnwinderMock : public unwindstack::Unwinder {
 public:
  UnwinderMock() : Unwinder(128, new unwindstack::Maps, nullptr) {}
  virtual ~UnwinderMock() { delete GetMaps(); }

  void MockAddMap(uint64_t start, uint64_t end, uint64_t offset, uint64_t flags, std::string name,
                  uint64_t load_bias) {
    GetMaps()->Add(start, end, offset, flags, name, load_bias);
  }

  void MockSetBuildID(uint64_t offset, const std::string& build_id) {
    unwindstack::MapInfo* map_info = GetMaps()->Find(offset);
    if (map_info != nullptr) {
      std::string* new_build_id = new std::string(build_id);
      map_info->build_id = reinterpret_cast<uintptr_t>(new_build_id);
    }
  }
};
