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

#include "trie_serializer.h"

namespace android {
namespace properties {

// Serialized strings contains:
// 1) A uint32_t count of elements in the below array
// 2) A sorted array of uint32_t offsets pointing to null terminated strings
// 3) Each of the null terminated strings themselves packed back to back
// This returns the offset into arena where the serialized strings start.
void TrieSerializer::SerializeStrings(const std::set<std::string>& strings) {
  arena_->AllocateAndWriteUint32(strings.size());

  // Allocate space for the array.
  uint32_t offset_array_offset = arena_->AllocateUint32Array(strings.size());

  // Write offset pointers and strings; these are already alphabetically sorted by virtue of being
  // in an std::set.
  auto it = strings.begin();
  for (unsigned int i = 0; i < strings.size(); ++i, ++it) {
    uint32_t string_offset = arena_->AllocateAndWriteString(*it);
    arena_->uint32_array(offset_array_offset)[i] = string_offset;
  }
}

uint32_t TrieSerializer::WritePropertyEntry(const PropertyEntryBuilder& property_entry) {
  uint32_t context_index = property_entry.context != nullptr && !property_entry.context->empty()
                               ? serialized_info()->FindContextIndex(property_entry.context->c_str())
                               : ~0u;
  uint32_t type_index = property_entry.type != nullptr && !property_entry.type->empty()
                            ? serialized_info()->FindTypeIndex(property_entry.type->c_str())
                            : ~0u;
  uint32_t offset;
  auto serialized_property_entry = arena_->AllocateObject<PropertyEntry>(&offset);
  serialized_property_entry->name_offset = arena_->AllocateAndWriteString(property_entry.name);
  serialized_property_entry->namelen = property_entry.name.size();
  serialized_property_entry->context_index = context_index;
  serialized_property_entry->type_index = type_index;
  return offset;
}

uint32_t TrieSerializer::WriteTrieNode(const TrieBuilderNode& builder_node) {
  uint32_t trie_offset;
  auto trie = arena_->AllocateObject<TrieNodeInternal>(&trie_offset);

  trie->property_entry = WritePropertyEntry(builder_node.property_entry());

  // Write prefix matches
  auto sorted_prefix_matches = builder_node.prefixes();
  // Prefixes are sorted by descending length
  std::sort(sorted_prefix_matches.begin(), sorted_prefix_matches.end(),
            [](const auto& lhs, const auto& rhs) { return lhs.name.size() > rhs.name.size(); });

  trie->num_prefixes = sorted_prefix_matches.size();

  uint32_t prefix_entries_array_offset = arena_->AllocateUint32Array(sorted_prefix_matches.size());
  trie->prefix_entries = prefix_entries_array_offset;

  for (unsigned int i = 0; i < sorted_prefix_matches.size(); ++i) {
    uint32_t property_entry_offset = WritePropertyEntry(sorted_prefix_matches[i]);
    arena_->uint32_array(prefix_entries_array_offset)[i] = property_entry_offset;
  }

  // Write exact matches
  auto sorted_exact_matches = builder_node.exact_matches();
  // Exact matches are sorted alphabetically
  std::sort(sorted_exact_matches.begin(), sorted_exact_matches.end(),
            [](const auto& lhs, const auto& rhs) { return lhs.name < rhs.name; });

  trie->num_exact_matches = sorted_exact_matches.size();

  uint32_t exact_match_entries_array_offset =
      arena_->AllocateUint32Array(sorted_exact_matches.size());
  trie->exact_match_entries = exact_match_entries_array_offset;

  for (unsigned int i = 0; i < sorted_exact_matches.size(); ++i) {
    uint32_t property_entry_offset = WritePropertyEntry(sorted_exact_matches[i]);
    arena_->uint32_array(exact_match_entries_array_offset)[i] = property_entry_offset;
  }

  // Write children
  auto sorted_children = builder_node.children();
  std::sort(sorted_children.begin(), sorted_children.end(),
            [](const auto& lhs, const auto& rhs) { return lhs.name() < rhs.name(); });

  trie->num_child_nodes = sorted_children.size();
  uint32_t children_offset_array_offset = arena_->AllocateUint32Array(sorted_children.size());
  trie->child_nodes = children_offset_array_offset;

  for (unsigned int i = 0; i < sorted_children.size(); ++i) {
    arena_->uint32_array(children_offset_array_offset)[i] = WriteTrieNode(sorted_children[i]);
  }
  return trie_offset;
}

TrieSerializer::TrieSerializer() {}

std::string TrieSerializer::SerializeTrie(const TrieBuilder& trie_builder) {
  arena_.reset(new TrieNodeArena());

  auto header = arena_->AllocateObject<PropertyInfoAreaHeader>(nullptr);
  header->current_version = 1;
  header->minimum_supported_version = 1;

  // Store where we're about to write the contexts.
  header->contexts_offset = arena_->size();
  SerializeStrings(trie_builder.contexts());

  // Store where we're about to write the types.
  header->types_offset = arena_->size();
  SerializeStrings(trie_builder.types());

  // We need to store size() up to this point now for Find*Offset() to work.
  header->size = arena_->size();

  uint32_t root_trie_offset = WriteTrieNode(trie_builder.builder_root());
  header->root_offset = root_trie_offset;

  // Record the real size now that we've written everything
  header->size = arena_->size();

  return arena_->truncated_data();
}

}  // namespace properties
}  // namespace android
