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

#include <gtest/gtest.h>

namespace android {
namespace properties {

TEST(propertyinfoserializer, BuildTrie_Simple) {
  auto trie_builder = TrieBuilder("default", "default_type");

  // Add test data to tree
  auto error = std::string();
  EXPECT_TRUE(trie_builder.AddToTrie("test.", "1st", "1st_type", false, &error));
  EXPECT_TRUE(trie_builder.AddToTrie("test.test", "2nd", "2nd_type", false, &error));
  EXPECT_TRUE(trie_builder.AddToTrie("test.test1", "3rd", "3rd_type", true, &error));
  EXPECT_TRUE(trie_builder.AddToTrie("test.test2", "3rd", "3rd_type", true, &error));
  EXPECT_TRUE(trie_builder.AddToTrie("test.test3", "3rd", "3rd_type", true, &error));
  EXPECT_TRUE(trie_builder.AddToTrie("this.is.a.long.string", "4th", "4th_type", true, &error));

  ASSERT_EQ(5U, trie_builder.contexts().size());
  ASSERT_EQ(5U, trie_builder.types().size());

  auto& builder_root = trie_builder.builder_root();

  // Check the root node
  EXPECT_EQ("root", builder_root.name());
  ASSERT_NE(nullptr, builder_root.context());
  EXPECT_EQ("default", *builder_root.context());
  ASSERT_NE(nullptr, builder_root.type());
  EXPECT_EQ("default_type", *builder_root.type());

  EXPECT_EQ(0U, builder_root.prefixes().size());
  EXPECT_EQ(0U, builder_root.exact_matches().size());

  ASSERT_EQ(2U, builder_root.children().size());

  // Check the 'test.' node
  auto* test_node = builder_root.FindChild("test");
  EXPECT_EQ("test", test_node->name());
  ASSERT_NE(nullptr, test_node->context());
  EXPECT_EQ("1st", *test_node->context());
  ASSERT_NE(nullptr, test_node->type());
  EXPECT_EQ("1st_type", *test_node->type());

  EXPECT_EQ(0U, test_node->children().size());
  EXPECT_EQ(1U, test_node->prefixes().size());
  {
    auto& property_entry = test_node->prefixes()[0];
    EXPECT_EQ("test", property_entry.name);
    ASSERT_NE(nullptr, property_entry.context);
    EXPECT_EQ("2nd", *property_entry.context);
    ASSERT_NE(nullptr, property_entry.type);
    EXPECT_EQ("2nd_type", *property_entry.type);
  }
  EXPECT_EQ(3U, test_node->exact_matches().size());
  EXPECT_EQ("test1", test_node->exact_matches()[0].name);
  EXPECT_EQ("test2", test_node->exact_matches()[1].name);
  EXPECT_EQ("test3", test_node->exact_matches()[2].name);

  ASSERT_NE(nullptr, test_node->exact_matches()[0].context);
  ASSERT_NE(nullptr, test_node->exact_matches()[1].context);
  ASSERT_NE(nullptr, test_node->exact_matches()[2].context);
  EXPECT_EQ("3rd", *test_node->exact_matches()[0].context);
  EXPECT_EQ("3rd", *test_node->exact_matches()[1].context);
  EXPECT_EQ("3rd", *test_node->exact_matches()[2].context);

  ASSERT_NE(nullptr, test_node->exact_matches()[0].type);
  ASSERT_NE(nullptr, test_node->exact_matches()[1].type);
  ASSERT_NE(nullptr, test_node->exact_matches()[2].type);
  EXPECT_EQ("3rd_type", *test_node->exact_matches()[0].type);
  EXPECT_EQ("3rd_type", *test_node->exact_matches()[1].type);
  EXPECT_EQ("3rd_type", *test_node->exact_matches()[2].type);

  // Check the long string node
  auto expect_empty_one_child = [](auto* node) {
    ASSERT_NE(nullptr, node);
    EXPECT_EQ(nullptr, node->context());
    EXPECT_EQ(nullptr, node->type());
    EXPECT_EQ(0U, node->prefixes().size());
    EXPECT_EQ(0U, node->exact_matches().size());
    EXPECT_EQ(1U, node->children().size());
  };

  // Start with 'this'
  auto* long_string_node = builder_root.FindChild("this");
  expect_empty_one_child(long_string_node);

  // Move to 'is'
  long_string_node = long_string_node->FindChild("is");
  expect_empty_one_child(long_string_node);

  // Move to 'a'
  long_string_node = long_string_node->FindChild("a");
  expect_empty_one_child(long_string_node);

  // Move to 'long'
  long_string_node = long_string_node->FindChild("long");
  EXPECT_EQ(0U, long_string_node->prefixes().size());
  EXPECT_EQ(1U, long_string_node->exact_matches().size());
  EXPECT_EQ(0U, long_string_node->children().size());

  {
    auto& property_entry = long_string_node->exact_matches()[0];
    EXPECT_EQ("string", property_entry.name);
    ASSERT_NE(nullptr, property_entry.context);
    EXPECT_EQ("4th", *property_entry.context);
    ASSERT_NE(nullptr, property_entry.type);
    EXPECT_EQ("4th_type", *property_entry.type);
  }
}

}  // namespace properties
}  // namespace android
