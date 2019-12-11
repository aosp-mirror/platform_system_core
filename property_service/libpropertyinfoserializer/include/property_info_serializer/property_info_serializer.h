//
// Copyright (C) 2017 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

#pragma once

#include <string>
#include <vector>

namespace android {
namespace properties {

struct PropertyInfoEntry {
  PropertyInfoEntry() {}
  template <typename T, typename U, typename V>
  PropertyInfoEntry(T&& name, U&& context, V&& type, bool exact_match)
      : name(std::forward<T>(name)),
        context(std::forward<U>(context)),
        type(std::forward<V>(type)),
        exact_match(exact_match) {}
  std::string name;
  std::string context;
  std::string type;
  bool exact_match;
};

bool BuildTrie(const std::vector<PropertyInfoEntry>& property_info,
               const std::string& default_context, const std::string& default_type,
               std::string* serialized_trie, std::string* error);

void ParsePropertyInfoFile(const std::string& file_contents, bool require_prefix_or_exact,
                           std::vector<PropertyInfoEntry>* property_infos,
                           std::vector<std::string>* errors);

}  // namespace properties
}  // namespace android
