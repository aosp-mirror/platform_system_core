//
// Copyright (C) 2018 The Android Open Source Project
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

#include "tokenizer.h"

#include <string>
#include <vector>

#include <gtest/gtest.h>

namespace android {
namespace init {

namespace {

void RunTest(const std::string& data, const std::vector<std::vector<std::string>>& expected_tokens) {
    auto data_copy = std::string{data};
    data_copy.push_back('\n');  // TODO: fix tokenizer
    data_copy.push_back('\0');

    parse_state state;
    state.line = 0;
    state.ptr = data_copy.data();
    state.nexttoken = 0;

    std::vector<std::string> current_line;
    std::vector<std::vector<std::string>> tokens;

    while (true) {
        switch (next_token(&state)) {
            case T_EOF:
                EXPECT_EQ(expected_tokens, tokens) << data;
                return;
            case T_NEWLINE:
                tokens.emplace_back(std::move(current_line));
                break;
            case T_TEXT:
                current_line.emplace_back(state.text);
                break;
        }
    }
}

}  // namespace

TEST(tokenizer, null) {
    RunTest("", {{}});
}

TEST(tokenizer, simple_oneline) {
    RunTest("one two\tthree\rfour", {{"one", "two", "three", "four"}});
}

TEST(tokenizer, simple_multiline) {
    RunTest("1 2 3\n4 5 6\n7 8 9", {{"1", "2", "3"}, {"4", "5", "6"}, {"7", "8", "9"}});
}

TEST(tokenizer, preceding_space) {
    // Preceding spaces are ignored.
    RunTest("    1 2 3\n\t\t\t\t4 5 6\n\r\r\r\r7 8 9",
            {{"1", "2", "3"}, {"4", "5", "6"}, {"7", "8", "9"}});
}

TEST(tokenizer, comments) {
    // Entirely commented lines still produce a T_NEWLINE token for tracking line count.
    RunTest("1 2 3\n#4 5 6\n7 8 9", {{"1", "2", "3"}, {}, {"7", "8", "9"}});

    RunTest("#1 2 3\n4 5 6\n7 8 9", {{}, {"4", "5", "6"}, {"7", "8", "9"}});

    RunTest("1 2 3\n4 5 6\n#7 8 9", {{"1", "2", "3"}, {"4", "5", "6"}, {}});

    RunTest("1 2 #3\n4 #5 6\n#7 8 9", {{"1", "2"}, {"4"}, {}});
}

TEST(tokenizer, control_chars) {
    // Literal \n, \r, \t, and \\ produce the control characters \n, \r, \t, and \\ respectively.
    // Literal \? produces ? for all other character '?'

    RunTest(R"(1 token\ntoken 2)", {{"1", "token\ntoken", "2"}});
    RunTest(R"(1 token\rtoken 2)", {{"1", "token\rtoken", "2"}});
    RunTest(R"(1 token\ttoken 2)", {{"1", "token\ttoken", "2"}});
    RunTest(R"(1 token\\token 2)", {{"1", "token\\token", "2"}});
    RunTest(R"(1 token\btoken 2)", {{"1", "tokenbtoken", "2"}});

    RunTest(R"(1 token\n 2)", {{"1", "token\n", "2"}});
    RunTest(R"(1 token\r 2)", {{"1", "token\r", "2"}});
    RunTest(R"(1 token\t 2)", {{"1", "token\t", "2"}});
    RunTest(R"(1 token\\ 2)", {{"1", "token\\", "2"}});
    RunTest(R"(1 token\b 2)", {{"1", "tokenb", "2"}});

    RunTest(R"(1 \ntoken 2)", {{"1", "\ntoken", "2"}});
    RunTest(R"(1 \rtoken 2)", {{"1", "\rtoken", "2"}});
    RunTest(R"(1 \ttoken 2)", {{"1", "\ttoken", "2"}});
    RunTest(R"(1 \\token 2)", {{"1", "\\token", "2"}});
    RunTest(R"(1 \btoken 2)", {{"1", "btoken", "2"}});

    RunTest(R"(1 \n 2)", {{"1", "\n", "2"}});
    RunTest(R"(1 \r 2)", {{"1", "\r", "2"}});
    RunTest(R"(1 \t 2)", {{"1", "\t", "2"}});
    RunTest(R"(1 \\ 2)", {{"1", "\\", "2"}});
    RunTest(R"(1 \b 2)", {{"1", "b", "2"}});
}

TEST(tokenizer, cr_lf) {
    // \ before \n, \r, or \r\n is interpreted as a line continuation
    // Extra whitespace on the next line is eaten, except \r unlike in the above tests.

    RunTest("lf\\\ncont", {{"lfcont"}});
    RunTest("lf\\\n    \t\t\t\tcont", {{"lfcont"}});

    RunTest("crlf\\\r\ncont", {{"crlfcont"}});
    RunTest("crlf\\\r\n    \t\t\t\tcont", {{"crlfcont"}});

    RunTest("cr\\\rcont", {{"crcont"}});

    RunTest("lfspace \\\ncont", {{"lfspace", "cont"}});
    RunTest("lfspace \\\n    \t\t\t\tcont", {{"lfspace", "cont"}});

    RunTest("crlfspace \\\r\ncont", {{"crlfspace", "cont"}});
    RunTest("crlfspace \\\r\n    \t\t\t\tcont", {{"crlfspace", "cont"}});

    RunTest("crspace \\\rcont", {{"crspace", "cont"}});
}

TEST(tokenizer, quoted) {
    RunTest("\"quoted simple string\"", {{"quoted simple string"}});

    // Unterminated quotes just return T_EOF without any T_NEWLINE.
    RunTest("\"unterminated quoted string", {});

    RunTest("\"1 2 3\"\n \"unterminated quoted string", {{"1 2 3"}});

    // Escaping quotes is not allowed and are treated as an unterminated quoted string.
    RunTest("\"quoted escaped quote\\\"\"", {});
    RunTest("\"quoted escaped\\\" quote\"", {});
    RunTest("\"\\\"quoted escaped quote\"", {});

    RunTest("\"quoted control characters \\n \\r \\t \\\\ \\b \\\r \\\n \r \n\"",
            {{"quoted control characters \\n \\r \\t \\\\ \\b \\\r \\\n \r \n"}});

    RunTest("\"quoted simple string\" \"second quoted string\"",
            {{"quoted simple string", "second quoted string"}});

    RunTest("\"# comment quoted string\"", {{"# comment quoted string"}});

    RunTest("\"Adjacent \"\"quoted strings\"", {{"Adjacent quoted strings"}});
}

}  // namespace init
}  // namespace android
