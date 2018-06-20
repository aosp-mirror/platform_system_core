/*
 * Copyright (C) 2010 The Android Open Source Project
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

#ifndef _INIT_PARSER_H_
#define _INIT_PARSER_H_

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "result.h"

//  SectionParser is an interface that can parse a given 'section' in init.
//
//  You can implement up to 4 functions below, with ParseSection being mandatory. The first two
//  functions return Result<Success> indicating if they have an error. It will be reported along
//  with the filename and line number of where the error occurred.
//
//  1) ParseSection
//    This function is called when a section is first encountered.
//
//  2) ParseLineSection
//    This function is called on each subsequent line until the next section is encountered.
//
//  3) EndSection
//    This function is called either when a new section is found or at the end of the file.
//    It indicates that parsing of the current section is complete and any relevant objects should
//    be committed.
//
//  4) EndFile
//    This function is called at the end of the file.
//    It indicates that the parsing has completed and any relevant objects should be committed.

namespace android {
namespace init {

class SectionParser {
  public:
    virtual ~SectionParser() {}
    virtual Result<Success> ParseSection(std::vector<std::string>&& args,
                                         const std::string& filename, int line) = 0;
    virtual Result<Success> ParseLineSection(std::vector<std::string>&&, int) { return Success(); };
    virtual Result<Success> EndSection() { return Success(); };
    virtual void EndFile(){};
};

class Parser {
  public:
    //  LineCallback is the type for callbacks that can parse a line starting with a given prefix.
    //
    //  They take the form of bool Callback(std::vector<std::string>&& args, std::string* err)
    //
    //  Similar to ParseSection() and ParseLineSection(), this function returns bool with false
    //  indicating a failure and has an std::string* err parameter into which an error string can
    //  be written.
    using LineCallback = std::function<Result<Success>(std::vector<std::string>&&)>;

    Parser();

    bool ParseConfig(const std::string& path);
    void AddSectionParser(const std::string& name, std::unique_ptr<SectionParser> parser);
    void AddSingleLineParser(const std::string& prefix, LineCallback callback);

    // Host init verifier check file permissions.
    bool ParseConfigFileInsecure(const std::string& path);

    size_t parse_error_count() const { return parse_error_count_; }

  private:
    void ParseData(const std::string& filename, std::string* data);
    bool ParseConfigFile(const std::string& path);
    bool ParseConfigDir(const std::string& path);

    std::map<std::string, std::unique_ptr<SectionParser>> section_parsers_;
    std::vector<std::pair<std::string, LineCallback>> line_callbacks_;
    size_t parse_error_count_ = 0;
};

}  // namespace init
}  // namespace android

#endif
