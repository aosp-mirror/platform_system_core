/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include <gtest/gtest.h>

size_t convertPrintable(char* p, const char* message, size_t messageLen);

TEST(liblog, convertPrintable_ascii) {
  auto input = "easy string, output same";
  auto output_size = convertPrintable(nullptr, input, strlen(input));
  EXPECT_EQ(output_size, strlen(input));

  char output[output_size];

  output_size = convertPrintable(output, input, strlen(input));
  EXPECT_EQ(output_size, strlen(input));
  EXPECT_STREQ(input, output);
}

TEST(liblog, convertPrintable_escapes) {
  // Note that \t is not escaped.
  auto input = "escape\a\b\t\v\f\r\\";
  auto expected_output = "escape\\a\\b\t\\v\\f\\r\\\\";
  auto output_size = convertPrintable(nullptr, input, strlen(input));
  EXPECT_EQ(output_size, strlen(expected_output));

  char output[output_size];

  output_size = convertPrintable(output, input, strlen(input));
  EXPECT_EQ(output_size, strlen(expected_output));
  EXPECT_STREQ(expected_output, output);
}

TEST(liblog, convertPrintable_validutf8) {
  auto input = u8"¢ह€𐍈";
  auto output_size = convertPrintable(nullptr, input, strlen(input));
  EXPECT_EQ(output_size, strlen(input));

  char output[output_size];

  output_size = convertPrintable(output, input, strlen(input));
  EXPECT_EQ(output_size, strlen(input));
  EXPECT_STREQ(input, output);
}

TEST(liblog, convertPrintable_invalidutf8) {
  auto input = "\x80\xC2\x01\xE0\xA4\x06\xE0\x06\xF0\x90\x8D\x06\xF0\x90\x06\xF0\x0E";
  auto expected_output =
      "\\x80\\xC2\\x01\\xE0\\xA4\\x06\\xE0\\x06\\xF0\\x90\\x8D\\x06\\xF0\\x90\\x06\\xF0\\x0E";
  auto output_size = convertPrintable(nullptr, input, strlen(input));
  EXPECT_EQ(output_size, strlen(expected_output));

  char output[output_size];

  output_size = convertPrintable(output, input, strlen(input));
  EXPECT_EQ(output_size, strlen(expected_output));
  EXPECT_STREQ(expected_output, output);
}

TEST(liblog, convertPrintable_mixed) {
  auto input =
      u8"\x80\xC2¢ह€𐍈\x01\xE0\xA4\x06¢ह€𐍈\xE0\x06\a\b\xF0\x90¢ह€𐍈\x8D\x06\xF0\t\t\x90\x06\xF0\x0E";
  auto expected_output =
      u8"\\x80\\xC2¢ह€𐍈\\x01\\xE0\\xA4\\x06¢ह€𐍈\\xE0\\x06\\a\\b\\xF0\\x90¢ह€𐍈\\x8D\\x06\\xF0\t\t"
      u8"\\x90\\x06\\xF0\\x0E";
  auto output_size = convertPrintable(nullptr, input, strlen(input));
  EXPECT_EQ(output_size, strlen(expected_output));

  char output[output_size];

  output_size = convertPrintable(output, input, strlen(input));
  EXPECT_EQ(output_size, strlen(expected_output));
  EXPECT_STREQ(expected_output, output);
}
