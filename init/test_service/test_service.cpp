// Copyright (C) 2016 The Android Open Source Project
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

#include <unistd.h>

#include <map>
#include <sstream>
#include <string>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/strings.h>

void Usage(char* argv[]) {
    printf("Usage: %s <status field> <value> [<status field> <value>]*\n", argv[0]);
    printf("E.g.: $ %s Uid \"1000 1000 1000 1000\"\n", argv[0]);
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        Usage(argv);
        LOG(FATAL) << "no status field requested";
    }
    if (argc % 2 == 0) {
        // Since |argc| counts argv[0], if |argc| is odd, then the number of
        // command-line arguments is even.
        Usage(argv);
        LOG(FATAL) << "need even number of command-line arguments";
    }

    std::string status;
    bool res = android::base::ReadFileToString("/proc/self/status", &status, true);
    if (!res) {
        PLOG(FATAL) << "could not read /proc/self/status";
    }

    std::map<std::string, std::string> fields;
    std::vector<std::string> lines = android::base::Split(status, "\n");
    for (const auto& line : lines) {
        std::vector<std::string> tokens = android::base::Split(line, ":");
        if (tokens.size() >= 2) {
            std::string field = tokens[0];
            std::string value = android::base::Trim(tokens[1]);
            if (field.length() > 0) {
                fields[field] = value;
            }
        }
    }

    bool test_fails = false;
    for (size_t i = 1; i < static_cast<size_t>(argc); i = i + 2) {
        std::string expected_value = argv[i + 1];
        auto f = fields.find(argv[i]);
        if (f != fields.end()) {
            if (f->second != expected_value) {
                LOG(ERROR) << "field '" << argv[i] << "' expected '" << expected_value
                           << "', actual '" << f->second << "'";
                test_fails = true;
            }
        } else {
            LOG(WARNING) << "could not find field '" << argv[i] << "'";
        }
    }

    return test_fails ? 1 : 0;
}
