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

#ifndef BASE_STRINGS_H
#define BASE_STRINGS_H

#include <sstream>
#include <string>
#include <vector>

namespace android {
namespace base {

// Splits a string into a vector of strings.
//
// The string is split at each occurrence of a character in delimiters.
//
// The empty string is not a valid delimiter list.
std::vector<std::string> Split(const std::string& s,
                               const std::string& delimiters);

// Trims whitespace off both ends of the given string.
std::string Trim(const std::string& s);

// Joins a container of things into a single string, using the given separator.
template <typename ContainerT>
std::string Join(const ContainerT& things, char separator) {
  if (things.empty()) {
    return "";
  }

  std::ostringstream result;
  result << *things.begin();
  for (auto it = std::next(things.begin()); it != things.end(); ++it) {
    result << separator << *it;
  }
  return result.str();
}

// We instantiate the common cases in strings.cpp.
extern template std::string Join(const std::vector<std::string>&, char);
extern template std::string Join(const std::vector<const char*>&, char);

// Tests whether 's' starts with 'prefix'.
bool StartsWith(const std::string& s, const char* prefix);

// Tests whether 's' ends with 'suffix'.
bool EndsWith(const std::string& s, const char* suffix);

}  // namespace base
}  // namespace android

#endif  // BASE_STRINGS_H
