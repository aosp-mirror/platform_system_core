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

#include "trie_builder.h"

#include <android-base/strings.h>

using android::base::Split;

namespace android {
namespace properties {

TrieBuilder::TrieBuilder(const std::string& default_context, const std::string& default_type)
    : builder_root_("root") {
  auto* context_pointer = StringPointerFromContainer(default_context, &contexts_);
  builder_root_.set_context(context_pointer);
  auto* type_pointer = StringPointerFromContainer(default_type, &types_);
  builder_root_.set_type(type_pointer);
}

bool TrieBuilder::AddToTrie(const std::string& name, const std::string& context,
                            const std::string& type, bool exact, std::string* error) {
  auto* context_pointer = StringPointerFromContainer(context, &contexts_);
  auto* type_pointer = StringPointerFromContainer(type, &types_);
  return AddToTrie(name, context_pointer, type_pointer, exact, error);
}

bool TrieBuilder::AddToTrie(const std::string& name, const std::string* context,
                            const std::string* type, bool exact, std::string* error) {
  TrieBuilderNode* current_node = &builder_root_;

  auto name_pieces = Split(name, ".");

  bool ends_with_dot = false;
  if (name_pieces.back().empty()) {
    ends_with_dot = true;
    name_pieces.pop_back();
  }

  // Move us to the final node that we care about, adding incremental nodes if necessary.
  while (name_pieces.size() > 1) {
    auto child = current_node->FindChild(name_pieces.front());
    if (child == nullptr) {
      child = current_node->AddChild(name_pieces.front());
    }
    if (child == nullptr) {
      *error = "Unable to allocate Trie node";
      return false;
    }
    current_node = child;
    name_pieces.erase(name_pieces.begin());
  }

  // Store our context based on what type of match it is.
  if (exact) {
    if (!current_node->AddExactMatchContext(name_pieces.front(), context, type)) {
      *error = "Duplicate exact match detected for '" + name + "'";
      return false;
    }
  } else if (!ends_with_dot) {
    if (!current_node->AddPrefixContext(name_pieces.front(), context, type)) {
      *error = "Duplicate prefix match detected for '" + name + "'";
      return false;
    }
  } else {
    auto child = current_node->FindChild(name_pieces.front());
    if (child == nullptr) {
      child = current_node->AddChild(name_pieces.front());
    }
    if (child == nullptr) {
      *error = "Unable to allocate Trie node";
      return false;
    }
    if (child->context() != nullptr || child->type() != nullptr) {
      *error = "Duplicate prefix match detected for '" + name + "'";
      return false;
    }
    child->set_context(context);
    child->set_type(type);
  }
  return true;
}

const std::string* TrieBuilder::StringPointerFromContainer(const std::string& string,
                                                           std::set<std::string>* container) {
  // Get a pointer to the string in a given set, such that we only ever serialize each string once.
  auto [iterator, _] = container->emplace(string);
  return &(*iterator);
}

}  // namespace properties
}  // namespace android
