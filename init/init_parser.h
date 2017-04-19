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

#ifndef _INIT_INIT_PARSER_H_
#define _INIT_INIT_PARSER_H_

#include <map>
#include <memory>
#include <string>
#include <vector>

//  SectionParser is an interface that can parse a given 'section' in init.
//
//  You can implement up to 4 functions below, with ParseSection() being mandatory.
//  The first two function return bool with false indicating a failure and has a std::string* err
//  parameter into which an error string can be written.  It will be reported along with the
//  filename and line number of where the error occurred.
//
//  1) bool ParseSection(std::vector<std::string>&& args, const std::string& filename,
//                       int line, std::string* err)
//    This function is called when a section is first encountered.
//
//  2) bool ParseLineSection(std::vector<std::string>&& args, int line, std::string* err)
//    This function is called on each subsequent line until the next section is encountered.
//
//  3) bool EndSection()
//    This function is called either when a new section is found or at the end of the file.
//    It indicates that parsing of the current section is complete and any relevant objects should
//    be committed.
//
//  4) bool EndFile()
//    This function is called at the end of the file.
//    It indicates that the parsing has completed and any relevant objects should be committed.

class SectionParser {
  public:
    virtual ~SectionParser() {}
    virtual bool ParseSection(std::vector<std::string>&& args, const std::string& filename,
                              int line, std::string* err) = 0;
    virtual bool ParseLineSection(std::vector<std::string>&&, int, std::string*) { return true; };
    virtual void EndSection(){};
    virtual void EndFile(){};
};

class Parser {
  public:
    static Parser& GetInstance();

    // Exposed for testing
    Parser();

    bool ParseConfig(const std::string& path);
    void AddSectionParser(const std::string& name,
                          std::unique_ptr<SectionParser> parser);

    void set_is_system_etc_init_loaded(bool loaded) {
        is_system_etc_init_loaded_ = loaded;
    }
    void set_is_vendor_etc_init_loaded(bool loaded) {
        is_vendor_etc_init_loaded_ = loaded;
    }
    void set_is_odm_etc_init_loaded(bool loaded) {
        is_odm_etc_init_loaded_ = loaded;
    }
    bool is_system_etc_init_loaded() { return is_system_etc_init_loaded_; }
    bool is_vendor_etc_init_loaded() { return is_vendor_etc_init_loaded_; }
    bool is_odm_etc_init_loaded() { return is_odm_etc_init_loaded_; }

  private:
    void ParseData(const std::string& filename, const std::string& data);
    bool ParseConfigFile(const std::string& path);
    bool ParseConfigDir(const std::string& path);

    std::map<std::string, std::unique_ptr<SectionParser>> section_parsers_;
    bool is_system_etc_init_loaded_ = false;
    bool is_vendor_etc_init_loaded_ = false;
    bool is_odm_etc_init_loaded_ = false;
};

#endif
