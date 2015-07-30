// Copyright (C) 2015 The Android Open Source Project
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

#include "tokenizer.h"

#include <errno.h>
#include <gtest/gtest.h>

#include <string>

namespace init {

#define SETUP_TEST(test_data)  \
  std::string data(test_data); \
  Tokenizer tokenizer(data);   \
  ASSERT_EQ(Tokenizer::TOK_START, tokenizer.current().type)

#define ASSERT_TEXT_TOKEN(test_text)              \
  ASSERT_TRUE(tokenizer.Next());                  \
  ASSERT_EQ(test_text, tokenizer.current().text); \
  ASSERT_EQ(Tokenizer::TOK_TEXT, tokenizer.current().type)

#define ASSERT_NEWLINE_TOKEN()   \
  ASSERT_TRUE(tokenizer.Next()); \
  ASSERT_EQ(Tokenizer::TOK_NEWLINE, tokenizer.current().type)

TEST(Tokenizer, Empty) {
  SETUP_TEST("");
  ASSERT_FALSE(tokenizer.Next());
}

TEST(Tokenizer, Simple) {
  SETUP_TEST("test");
  ASSERT_TEXT_TOKEN("test");
  ASSERT_FALSE(tokenizer.Next());
}

TEST(Tokenizer, LeadingWhiteSpace) {
  SETUP_TEST(" \t  \r  test");
  ASSERT_TEXT_TOKEN("test");
  ASSERT_FALSE(tokenizer.Next());
}

TEST(Tokenizer, TrailingWhiteSpace) {
  SETUP_TEST("test \t  \r  ");
  ASSERT_TEXT_TOKEN("test");
  ASSERT_FALSE(tokenizer.Next());
}

TEST(Tokenizer, WhiteSpace) {
  SETUP_TEST(" \t  \r  test \t  \r  ");
  ASSERT_TEXT_TOKEN("test");

  ASSERT_FALSE(tokenizer.Next());
}

TEST(Tokenizer, TwoTokens) {
  SETUP_TEST("  foo   bar ");
  ASSERT_TEXT_TOKEN("foo");
  ASSERT_TEXT_TOKEN("bar");

  ASSERT_FALSE(tokenizer.Next());
}

TEST(Tokenizer, MultiToken) {
  SETUP_TEST("one two three four five");
  ASSERT_TEXT_TOKEN("one");
  ASSERT_TEXT_TOKEN("two");
  ASSERT_TEXT_TOKEN("three");
  ASSERT_TEXT_TOKEN("four");
  ASSERT_TEXT_TOKEN("five");

  ASSERT_FALSE(tokenizer.Next());
}

TEST(Tokenizer, NewLine) {
  SETUP_TEST("\n");
  ASSERT_NEWLINE_TOKEN();

  ASSERT_FALSE(tokenizer.Next());
}

TEST(Tokenizer, TextNewLine) {
  SETUP_TEST("test\n");
  ASSERT_TEXT_TOKEN("test");
  ASSERT_NEWLINE_TOKEN();

  ASSERT_FALSE(tokenizer.Next());
}

TEST(Tokenizer, MultiTextNewLine) {
  SETUP_TEST("one\ntwo\nthree\n");
  ASSERT_TEXT_TOKEN("one");
  ASSERT_NEWLINE_TOKEN();
  ASSERT_TEXT_TOKEN("two");
  ASSERT_NEWLINE_TOKEN();
  ASSERT_TEXT_TOKEN("three");
  ASSERT_NEWLINE_TOKEN();

  ASSERT_FALSE(tokenizer.Next());
}

TEST(Tokenizer, MultiTextNewLineNoLineEnding) {
  SETUP_TEST("one\ntwo\nthree");
  ASSERT_TEXT_TOKEN("one");
  ASSERT_NEWLINE_TOKEN();
  ASSERT_TEXT_TOKEN("two");
  ASSERT_NEWLINE_TOKEN();
  ASSERT_TEXT_TOKEN("three");

  ASSERT_FALSE(tokenizer.Next());
}

TEST(Tokenizer, Comment) {
  SETUP_TEST("#test");
  ASSERT_FALSE(tokenizer.Next());
}

TEST(Tokenizer, CommentWhiteSpace) {
  SETUP_TEST(" \t  \r  #test \t  \r  ");
  ASSERT_FALSE(tokenizer.Next());
}

TEST(Tokenizer, CommentNewLine) {
  SETUP_TEST(" #test   \n");
  ASSERT_NEWLINE_TOKEN();
  ASSERT_FALSE(tokenizer.Next());
}

TEST(Tokenizer, CommentTwoNewLine) {
  SETUP_TEST(" #test   \n#test");
  ASSERT_NEWLINE_TOKEN();
  ASSERT_FALSE(tokenizer.Next());
}

TEST(Tokenizer, CommentWithText) {
  SETUP_TEST("foo bar #test");
  ASSERT_TEXT_TOKEN("foo");
  ASSERT_TEXT_TOKEN("bar");
  ASSERT_FALSE(tokenizer.Next());
}

TEST(Tokenizer, CommentWithTextNoSpace) {
  SETUP_TEST("foo bar#test");
  ASSERT_TEXT_TOKEN("foo");
  ASSERT_TEXT_TOKEN("bar");
  ASSERT_FALSE(tokenizer.Next());
}

TEST(Tokenizer, CommentWithTextLineFeed) {
  SETUP_TEST("foo bar #test\n");
  ASSERT_TEXT_TOKEN("foo");
  ASSERT_TEXT_TOKEN("bar");
  ASSERT_NEWLINE_TOKEN();
  ASSERT_FALSE(tokenizer.Next());
}

TEST(Tokenizer, CommentWithMultiTextLineFeed) {
  SETUP_TEST("#blah\nfoo bar #test\n#blah");
  ASSERT_NEWLINE_TOKEN();
  ASSERT_TEXT_TOKEN("foo");
  ASSERT_TEXT_TOKEN("bar");
  ASSERT_NEWLINE_TOKEN();
  ASSERT_FALSE(tokenizer.Next());
}

TEST(Tokenizer, SimpleEscaped) {
  SETUP_TEST("fo\\no bar");
  ASSERT_TEXT_TOKEN("fo\\no");
  ASSERT_TEXT_TOKEN("bar");
  ASSERT_FALSE(tokenizer.Next());
}

TEST(Tokenizer, EscapedLineContNoLineFeed) {
  SETUP_TEST("fo\\no bar \\ hello");
  ASSERT_TEXT_TOKEN("fo\\no");
  ASSERT_TEXT_TOKEN("bar");
  ASSERT_FALSE(tokenizer.Next());
}

TEST(Tokenizer, EscapedLineContLineFeed) {
  SETUP_TEST("fo\\no bar \\ hello\n");
  ASSERT_TEXT_TOKEN("fo\\no");
  ASSERT_TEXT_TOKEN("bar");
  ASSERT_FALSE(tokenizer.Next());
}

TEST(Tokenizer, EscapedLineCont) {
  SETUP_TEST("fo\\no bar \\\ntest");
  ASSERT_TEXT_TOKEN("fo\\no");
  ASSERT_TEXT_TOKEN("bar");
  ASSERT_TEXT_TOKEN("test");
  ASSERT_FALSE(tokenizer.Next());
}

TEST(Tokenizer, EscapedLineContWithBadChars) {
  SETUP_TEST("fo\\no bar \\bad bad bad\ntest");
  ASSERT_TEXT_TOKEN("fo\\no");
  ASSERT_TEXT_TOKEN("bar");
  ASSERT_TEXT_TOKEN("test");
  ASSERT_FALSE(tokenizer.Next());
}

TEST(Tokenizer, SimpleQuotes) {
  SETUP_TEST("foo \"single token\" bar");
  ASSERT_TEXT_TOKEN("foo");
  ASSERT_TEXT_TOKEN("single token");
  ASSERT_TEXT_TOKEN("bar");
  ASSERT_FALSE(tokenizer.Next());
}

TEST(Tokenizer, BadQuotes) {
  SETUP_TEST("foo \"single token");
  ASSERT_TEXT_TOKEN("foo");
  ASSERT_TEXT_TOKEN("single token");
  ASSERT_FALSE(tokenizer.Next());
}

}  // namespace init
