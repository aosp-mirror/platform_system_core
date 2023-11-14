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

#include <vector>

#include <android-base/file.h>
#include <gtest/gtest.h>

#include "util.h"

using namespace std::string_literals;

namespace android {
namespace init {

PersistentProperties VectorToPersistentProperties(
    const std::vector<std::pair<std::string, std::string>>& input_properties) {
    PersistentProperties persistent_properties;

    for (const auto& [name, value] : input_properties) {
        auto persistent_property_record = persistent_properties.add_properties();
        persistent_property_record->set_name(name);
        persistent_property_record->set_value(value);
    }

    return persistent_properties;
}

void CheckPropertiesEqual(std::vector<std::pair<std::string, std::string>> expected,
                          const PersistentProperties& persistent_properties) {
    for (const auto& persistent_property_record : persistent_properties.properties()) {
        auto it = std::find_if(expected.begin(), expected.end(),
                               [persistent_property_record](const auto& entry) {
                                   return entry.first == persistent_property_record.name() &&
                                          entry.second == persistent_property_record.value();
                               });
        ASSERT_TRUE(it != expected.end())
            << "Found unexpected property (" << persistent_property_record.name() << ", "
            << persistent_property_record.value() << ")";
        expected.erase(it);
    }
    auto joiner = [](const std::vector<std::pair<std::string, std::string>>& vector) {
        std::string result;
        for (const auto& [name, value] : vector) {
            result += " (" + name + ", " + value + ")";
        }
        return result;
    };
    EXPECT_TRUE(expected.empty()) << "Did not find expected properties:" << joiner(expected);
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
        // We don't currently allow for non-ascii names for system properties, but this is a policy
        // decision, not a technical limitation.
        {"persist.\x00\x01\x02\xFF\xFE\xFD\x7F\x8F\x9F", "non-ascii-name"},
    };

    ASSERT_RESULT_OK(
            WritePersistentPropertyFile(VectorToPersistentProperties(persistent_properties)));

    auto read_back_properties = LoadPersistentProperties();
    CheckPropertiesEqual(persistent_properties, read_back_properties);
}

TEST(persistent_properties, AddProperty) {
    TemporaryFile tf;
    ASSERT_TRUE(tf.fd != -1);
    persistent_property_filename = tf.path;

    std::vector<std::pair<std::string, std::string>> persistent_properties = {
        {"persist.sys.timezone", "America/Los_Angeles"},
    };
    ASSERT_RESULT_OK(
            WritePersistentPropertyFile(VectorToPersistentProperties(persistent_properties)));

    WritePersistentProperty("persist.sys.locale", "pt-BR");

    std::vector<std::pair<std::string, std::string>> persistent_properties_expected = {
        {"persist.sys.timezone", "America/Los_Angeles"},
        {"persist.sys.locale", "pt-BR"},
    };

    auto read_back_properties = LoadPersistentProperties();
    CheckPropertiesEqual(persistent_properties_expected, read_back_properties);
}

TEST(persistent_properties, UpdateProperty) {
    TemporaryFile tf;
    ASSERT_TRUE(tf.fd != -1);
    persistent_property_filename = tf.path;

    std::vector<std::pair<std::string, std::string>> persistent_properties = {
        {"persist.sys.locale", "en-US"},
        {"persist.sys.timezone", "America/Los_Angeles"},
    };
    ASSERT_RESULT_OK(
            WritePersistentPropertyFile(VectorToPersistentProperties(persistent_properties)));

    WritePersistentProperty("persist.sys.locale", "pt-BR");

    std::vector<std::pair<std::string, std::string>> persistent_properties_expected = {
        {"persist.sys.locale", "pt-BR"},
        {"persist.sys.timezone", "America/Los_Angeles"},
    };

    auto read_back_properties = LoadPersistentProperties();
    CheckPropertiesEqual(persistent_properties_expected, read_back_properties);
}

TEST(persistent_properties, UpdatePropertyBadParse) {
    TemporaryFile tf;
    ASSERT_TRUE(tf.fd != -1);
    persistent_property_filename = tf.path;

    ASSERT_RESULT_OK(WriteFile(tf.path, "ab"));

    WritePersistentProperty("persist.sys.locale", "pt-BR");

    auto read_back_properties = LoadPersistentProperties();
    EXPECT_GT(read_back_properties.properties().size(), 0);

    auto it =
        std::find_if(read_back_properties.properties().begin(),
                     read_back_properties.properties().end(), [](const auto& entry) {
                         return entry.name() == "persist.sys.locale" && entry.value() == "pt-BR";
                     });
    EXPECT_FALSE(it == read_back_properties.properties().end());
}

TEST(persistent_properties, RejectNonPersistProperty) {
    TemporaryFile tf;
    ASSERT_TRUE(tf.fd != -1);
    persistent_property_filename = tf.path;

    WritePersistentProperty("notpersist.sys.locale", "pt-BR");

    auto read_back_properties = LoadPersistentProperties();
    EXPECT_EQ(read_back_properties.properties().size(), 0);

    WritePersistentProperty("persist.sys.locale", "pt-BR");

    read_back_properties = LoadPersistentProperties();
    EXPECT_GT(read_back_properties.properties().size(), 0);

    auto it = std::find_if(read_back_properties.properties().begin(),
                           read_back_properties.properties().end(), [](const auto& entry) {
                               return entry.name() == "persist.sys.locale" &&
                                      entry.value() == "pt-BR";
                           });
    EXPECT_FALSE(it == read_back_properties.properties().end());
}

TEST(persistent_properties, StagedPersistProperty) {
    TemporaryFile tf;
    ASSERT_TRUE(tf.fd != -1);
    persistent_property_filename = tf.path;

    std::vector<std::pair<std::string, std::string>> persistent_properties = {
        {"persist.sys.locale", "en-US"},
        {"next_boot.persist.test.numbers", "54321"},
        {"persist.sys.timezone", "America/Los_Angeles"},
        {"persist.test.numbers", "12345"},
        {"next_boot.persist.test.extra", "abc"},
    };

    ASSERT_RESULT_OK(
            WritePersistentPropertyFile(VectorToPersistentProperties(persistent_properties)));

    std::vector<std::pair<std::string, std::string>> expected_persistent_properties = {
        {"persist.sys.locale", "en-US"},
        {"persist.sys.timezone", "America/Los_Angeles"},
        {"persist.test.numbers", "54321"},
        {"persist.test.extra", "abc"},
    };

    // lock down that staged props are applied
    auto first_read_back_properties = LoadPersistentProperties();
    CheckPropertiesEqual(expected_persistent_properties, first_read_back_properties);

    // lock down that other props are not overwritten
    auto second_read_back_properties = LoadPersistentProperties();
    CheckPropertiesEqual(expected_persistent_properties, second_read_back_properties);
}

}  // namespace init
}  // namespace android
