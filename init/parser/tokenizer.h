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

#ifndef _INIT_PARSER_TOKENIZER_H
#define _INIT_PARSER_TOKENIZER_H

#include <string>

namespace init {

// Used to tokenize a std::string.
// Call Next() to advance through each token until it returns false,
// indicating there are no more tokens left in the string.
// The current token can be accessed with current(), which returns
// a Token.
// Supported tokens are:
// TOK_START - Next() has yet to be called
// TOK_END - At the end of string
// TOK_NEWLINE - The end of a line denoted by \n.
// TOK_TEXT - A word.
// Comments are denoted with '#' and the tokenizer will ignore
// the rest of the line.
// Double quotes can be used to insert whitespace into words.
// A backslash at the end of a line denotes continuation and
// a TOK_NEWLINE will not be generated for that line.
class Tokenizer {
 public:
  explicit Tokenizer(const std::string& data);
  ~Tokenizer();

  enum TokenType { TOK_START, TOK_END, TOK_NEWLINE, TOK_TEXT };
  struct Token {
    TokenType type;
    std::string text;
  };

  // Returns the curret token.
  const Token& current();

  // Move to the next token, returns false at the end of input.
  bool Next();

 private:
  void GetData();
  void AdvChar();
  void AdvText();
  void AdvUntil(char x);
  void AdvWhiteSpace();
  void StartText();
  void EndText();

  const std::string& data_;
  Token current_;

  bool eof_;
  size_t pos_;
  char cur_char_;
  size_t tok_start_;
};

}  // namespace init

#endif
