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

#ifndef PROPERTY_INFO_SERIALIZER_TRIE_BUILDER_H
#define PROPERTY_INFO_SERIALIZER_TRIE_BUILDER_H

#include <memory>
#include <set>
#include <string>
#include <vector>

namespace android {
namespace properties {

struct PropertyEntryBuilder {
  PropertyEntryBuilder() : context(nullptr), type(nullptr) {}
  PropertyEntryBuilder(const std::string& name, const std::string* context, const std::string* type)
      : name(name), context(context), type(type) {}
  std::string name;
  const std::string* context;
  const std::string* type;
};

class TrieBuilderNode {
 public:
  TrieBuilderNode(const std::string& name) : property_entry_(name, nullptr, nullptr) {}

  TrieBuilderNode* FindChild(const std::string& name) {
    for (auto& child : children_) {
      if (child.name() == name) return &child;
    }
    return nullptr;
  }

  const TrieBuilderNode* FindChild(const std::string& name) const {
    for (const auto& child : children_) {
      if (child.name() == name) return &child;
    }
    return nullptr;
  }

  TrieBuilderNode* AddChild(const std::string& name) { return &children_.emplace_back(name); }

  bool AddPrefixContext(const std::string& prefix, const std::string* context,
                        const std::string* type) {
    if (std::find_if(prefixes_.begin(), prefixes_.end(),
                     [&prefix](const auto& t) { return t.name == prefix; }) != prefixes_.end()) {
      return false;
    }

    prefixes_.emplace_back(prefix, context, type);
    return true;
  }

  bool AddExactMatchContext(const std::string& exact_match, const std::string* context,
                            const std::string* type) {
    if (std::find_if(exact_matches_.begin(), exact_matches_.end(), [&exact_match](const auto& t) {
          return t.name == exact_match;
        }) != exact_matches_.end()) {
      return false;
    }

    exact_matches_.emplace_back(exact_match, context, type);
    return true;
  }

  const std::string& name() const { return property_entry_.name; }
  const std::string* context() const { return property_entry_.context; }
  void set_context(const std::string* context) { property_entry_.context = context; }
  const std::string* type() const { return property_entry_.type; }
  void set_type(const std::string* type) { property_entry_.type = type; }

  const PropertyEntryBuilder property_entry() const { return property_entry_; }

  const std::vector<TrieBuilderNode>& children() const { return children_; }
  const std::vector<PropertyEntryBuilder>& prefixes() const { return prefixes_; }
  const std::vector<PropertyEntryBuilder>& exact_matches() const { return exact_matches_; }

 private:
  PropertyEntryBuilder property_entry_;
  std::vector<TrieBuilderNode> children_;
  std::vector<PropertyEntryBuilder> prefixes_;
  std::vector<PropertyEntryBuilder> exact_matches_;
};

class TrieBuilder {
 public:
  TrieBuilder(const std::string& default_context, const std::string& default_type);
  bool AddToTrie(const std::string& name, const std::string& context, const std::string& type,
                 bool exact, std::string* error);

  const TrieBuilderNode builder_root() const { return builder_root_; }
  const std::set<std::string>& contexts() const { return contexts_; }
  const std::set<std::string>& types() const { return types_; }

 private:
  bool AddToTrie(const std::string& name, const std::string* context, const std::string* type,
                 bool exact, std::string* error);
  const std::string* StringPointerFromContainer(const std::string& string,
                                                std::set<std::string>* container);

  TrieBuilderNode builder_root_;
  std::set<std::string> contexts_;
  std::set<std::string> types_;
};

}  // namespace properties
}  // namespace android

#endif
