/*
 * Copyright (C) 2017 The Android Open Source Project
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

#include "persistent_properties.h"

#include <errno.h>

#include <android-base/test_utils.h>
#include <gtest/gtest.h>

#include "util.h"

using namespace std::string_literals;

namespace android {
namespace init {

TEST(persistent_properties, GeneratedContents) {
    const std::vector<std::pair<std::string, std::string>> persistent_properties = {
        {"persist.abc", ""},
        {"persist.def", "test_success"},
    };
    auto generated_contents = GenerateFileContents(persistent_properties);

    // Manually serialized contents below:
    std::string file_contents;
    // All values below are written and read as little endian.
    // Add magic value: 0x8495E0B4
    file_contents += "\xB4\xE0\x95\x84"s;
    // Add version: 1
    file_contents += "\x01\x00\x00\x00"s;
    // Add number of properties: 2
    file_contents += "\x02\x00\x00\x00"s;

    // Add first key: persist.abc
    file_contents += "\x0B\x00\x00\x00persist.abc"s;
    // Add first value: (empty string)
    file_contents += "\x00\x00\x00\x00"s;

    // Add second key: persist.def
    file_contents += "\x0B\x00\x00\x00persist.def"s;
    // Add second value: test_success
    file_contents += "\x0C\x00\x00\x00test_success"s;

    EXPECT_EQ(file_contents, generated_contents);
}

TEST(persistent_properties, EndToEnd) {
    TemporaryFile tf;
    ASSERT_TRUE(tf.fd != -1);
    persistent_property_filename = tf.path;

    std::vector<std::pair<std::string, std::string>> persistent_properties = {
        {"persist.sys.locale", "en-US"},
        {"persist.sys.timezone", "America/Los_Angeles"},
        {"persist.test.empty.value", ""},
        {"persist.test.new.line", "abc\n\n\nabc"},
        {"persist.test.numbers", "1234567890"},
        {"persist.test.non.ascii", "\x00\x01\x02\xFF\xFE\xFD\x7F\x8F\x9F"},
        // We don't currently allow for non-ascii keys for system properties, but this is a policy
        // decision, not a technical limitation.
        {"persist.\x00\x01\x02\xFF\xFE\xFD\x7F\x8F\x9F", "non-ascii-key"},
    };

    ASSERT_TRUE(WritePersistentPropertyFile(persistent_properties));

    auto read_back_properties = LoadPersistentProperties();
    EXPECT_EQ(persistent_properties, read_back_properties);
}

TEST(persistent_properties, BadMagic) {
    TemporaryFile tf;
    ASSERT_TRUE(tf.fd != -1);
    persistent_property_filename = tf.path;

    ASSERT_TRUE(WriteFile(tf.path, "ab"));

    auto read_back_properties = LoadPersistentPropertyFile();

    ASSERT_FALSE(read_back_properties);
    EXPECT_EQ(
        "Unable to parse persistent property file: Could not read magic value: Input buffer not "
        "large enough to read uint32_t",
        read_back_properties.error_string());

    ASSERT_TRUE(WriteFile(tf.path, "\xFF\xFF\xFF\xFF"));

    read_back_properties = LoadPersistentPropertyFile();

    ASSERT_FALSE(read_back_properties);
    EXPECT_EQ(
        "Unable to parse persistent property file: Magic value '0xffffffff' does not match "
        "expected value '0x8495e0b4'",
        read_back_properties.error_string());
}

TEST(persistent_properties, AddProperty) {
    TemporaryFile tf;
    ASSERT_TRUE(tf.fd != -1);
    persistent_property_filename = tf.path;

    std::vector<std::pair<std::string, std::string>> persistent_properties = {
        {"persist.sys.timezone", "America/Los_Angeles"},
    };
    ASSERT_TRUE(WritePersistentPropertyFile(persistent_properties));

    WritePersistentProperty("persist.sys.locale", "pt-BR");

    std::vector<std::pair<std::string, std::string>> persistent_properties_expected = {
        {"persist.sys.timezone", "America/Los_Angeles"},
        {"persist.sys.locale", "pt-BR"},
    };

    auto read_back_properties = LoadPersistentProperties();
    EXPECT_EQ(persistent_properties_expected, read_back_properties);
}

TEST(persistent_properties, UpdateProperty) {
    TemporaryFile tf;
    ASSERT_TRUE(tf.fd != -1);
    persistent_property_filename = tf.path;

    std::vector<std::pair<std::string, std::string>> persistent_properties = {
        {"persist.sys.locale", "en-US"},
        {"persist.sys.timezone", "America/Los_Angeles"},
    };
    ASSERT_TRUE(WritePersistentPropertyFile(persistent_properties));

    WritePersistentProperty("persist.sys.locale", "pt-BR");

    std::vector<std::pair<std::string, std::string>> persistent_properties_expected = {
        {"persist.sys.locale", "pt-BR"},
        {"persist.sys.timezone", "America/Los_Angeles"},
    };

    auto read_back_properties = LoadPersistentProperties();
    EXPECT_EQ(persistent_properties_expected, read_back_properties);
}

TEST(persistent_properties, UpdatePropertyBadParse) {
    TemporaryFile tf;
    ASSERT_TRUE(tf.fd != -1);
    persistent_property_filename = tf.path;

    ASSERT_TRUE(WriteFile(tf.path, "ab"));

    WritePersistentProperty("persist.sys.locale", "pt-BR");

    auto read_back_properties = LoadPersistentProperties();
    EXPECT_GT(read_back_properties.size(), 0U);

    auto it = std::find_if(
        read_back_properties.begin(), read_back_properties.end(), [](const auto& entry) {
            return entry.first == "persist.sys.locale" && entry.second == "pt-BR";
        });
    EXPECT_FALSE(it == read_back_properties.end());
}

}  // namespace init
}  // namespace android
