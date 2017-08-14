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

#ifndef _INIT_IMPORT_PARSER_H
#define _INIT_IMPORT_PARSER_H

#include <string>
#include <vector>

#include "parser.h"

namespace android {
namespace init {

class ImportParser : public SectionParser {
  public:
    ImportParser(Parser* parser) : parser_(parser) {}
    Result<Success> ParseSection(std::vector<std::string>&& args, const std::string& filename,
                                 int line) override;
    void EndFile() override;

  private:
    Parser* parser_;
    // Store filename for later error reporting.
    std::string filename_;
    // Vector of imports and their line numbers for later error reporting.
    std::vector<std::pair<std::string, int>> imports_;
};

}  // namespace init
}  // namespace android

#endif
