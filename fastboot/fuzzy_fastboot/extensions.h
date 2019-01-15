/*
 * Copyright (C) 2018 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#pragma once

#include <regex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace fastboot {
namespace extension {

enum Expect { OKAY = 0, FAIL, DATA };

static const std::unordered_map<std::string, Expect> CMD_EXPECTS = {
        {"okay", OKAY},
        {"fail", FAIL},
        {"data", DATA},
};

static const std::unordered_map<Expect, std::string> EXPECTS_STR = {
        {OKAY, "okay"},
        {FAIL, "fail"},
        {DATA, "data"},
};

struct Configuration {
    struct GetVar {
        std::string regex_str;
        std::regex regex;
        int line_num;

        // So gtest can print me
        friend ::std::ostream& operator<<(::std::ostream& os, const GetVar& self) {
            return os << "<regex='" << self.regex_str << "' line_num=" << self.line_num << ">";
        }
    };
    struct PartitionInfo {
        enum TestConfig { NO = 0, NO_WRITES, YES };
        bool hashable;
        bool slots;   // Does it have slots
        bool parsed;  // Does the bootloader do parsing on the img?
        TestConfig test;

        // So gtest can print me
        friend ::std::ostream& operator<<(::std::ostream& os, const PartitionInfo& pinfo) {
            return os << "<hashable=" << pinfo.hashable << " slots=" << pinfo.slots
                      << " parsed=" << pinfo.parsed << ">";
        }
    };

    struct PackedInfoTest {
        Expect expect;  // Does it have slots
        std::string packed_img;
        std::string unpacked_dir;

        // So gtest can print me
        friend ::std::ostream& operator<<(::std::ostream& os, const PackedInfoTest& pinfo) {
            return os << "<"
                      << "expect=" << EXPECTS_STR.at(pinfo.expect)
                      << " packed_img=" << pinfo.packed_img
                      << " unpacked_dir=" << pinfo.unpacked_dir << ">";
        }
    };

    struct PackedInfo {
        bool slots;  // Does it have slots
        std::unordered_set<std::string> children;
        std::vector<PackedInfoTest> tests;
    };

    struct CommandTest {
        std::string name;
        int line_num;
        std::string arg;
        Expect expect;
        std::string regex_str;
        std::regex regex;
        std::string input;
        std::string output;
        std::string validator;

        // So gtest can print me
        friend ::std::ostream& operator<<(::std::ostream& os, const CommandTest& self) {
            return os << "test: " << self.name << " (line: " << self.line_num << ")";
        }
    };

    struct OemCommand {
        bool restricted;  // Does device need to be unlocked?
        std::vector<CommandTest> tests;
    };

    std::unordered_map<std::string, GetVar> getvars;
    std::unordered_map<std::string, PartitionInfo> partitions;
    std::unordered_map<std::string, PackedInfo> packed;
    std::unordered_map<std::string, OemCommand> oem;

    std::string checksum;
    std::string checksum_parser;
};

bool ParseXml(const std::string& file, Configuration* config);

}  // namespace extension
}  // namespace fastboot
