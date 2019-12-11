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

#include <property_info_serializer/property_info_serializer.h>

#include <android-base/strings.h>

#include "space_tokenizer.h"

using android::base::Join;
using android::base::Split;
using android::base::StartsWith;
using android::base::Trim;

namespace android {
namespace properties {

namespace {

bool IsTypeValid(const std::vector<std::string>& type_strings) {
  if (type_strings.empty()) {
    return false;
  }

  // There must be at least one string following 'enum'
  if (type_strings[0] == "enum") {
    return type_strings.size() > 1;
  }

  // There should not be any string following any other types.
  if (type_strings.size() != 1) {
    return false;
  }

  // Check that the type matches one of remaining valid types.
  static const char* const no_parameter_types[] = {"string", "bool",   "int",
                                                   "uint",   "double", "size"};
  for (const auto& type : no_parameter_types) {
    if (type_strings[0] == type) {
      return true;
    }
  }
  return false;
}

bool ParsePropertyInfoLine(const std::string& line, bool require_prefix_or_exact,
                           PropertyInfoEntry* out, std::string* error) {
  auto tokenizer = SpaceTokenizer(line);

  auto property = tokenizer.GetNext();
  if (property.empty()) {
    *error = "Did not find a property entry in '" + line + "'";
    return false;
  }

  auto context = tokenizer.GetNext();
  if (context.empty()) {
    *error = "Did not find a context entry in '" + line + "'";
    return false;
  }

  // It is not an error to not find exact_match or a type, as older files will not contain them.
  auto match_operation = tokenizer.GetNext();
  // We reformat type to be space deliminated regardless of the input whitespace for easier storage
  // and subsequent parsing.
  auto type_strings = std::vector<std::string>{};
  auto type = tokenizer.GetNext();
  while (!type.empty()) {
    type_strings.emplace_back(type);
    type = tokenizer.GetNext();
  }

  bool exact_match = false;
  if (match_operation == "exact") {
    exact_match = true;
  } else if (match_operation != "prefix" && match_operation != "" && require_prefix_or_exact) {
    *error = "Match operation '" + match_operation +
             "' is not valid: must be either 'prefix' or 'exact'";
    return false;
  }

  if (!type_strings.empty() && !IsTypeValid(type_strings)) {
    *error = "Type '" + Join(type_strings, " ") + "' is not valid";
    return false;
  }

  *out = {property, context, Join(type_strings, " "), exact_match};
  return true;
}

}  // namespace

void ParsePropertyInfoFile(const std::string& file_contents, bool require_prefix_or_exact,
                           std::vector<PropertyInfoEntry>* property_infos,
                           std::vector<std::string>* errors) {
  // Do not clear property_infos to allow this function to be called on multiple files, with
  // their results concatenated.
  errors->clear();

  for (const auto& line : Split(file_contents, "\n")) {
    auto trimmed_line = Trim(line);
    if (trimmed_line.empty() || StartsWith(trimmed_line, "#")) {
      continue;
    }

    auto property_info_entry = PropertyInfoEntry{};
    auto parse_error = std::string{};
    if (!ParsePropertyInfoLine(trimmed_line, require_prefix_or_exact, &property_info_entry,
                               &parse_error)) {
      errors->emplace_back(parse_error);
      continue;
    }

    property_infos->emplace_back(property_info_entry);
  }
}

}  // namespace properties
}  // namespace android
