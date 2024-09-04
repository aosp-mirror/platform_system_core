/*
 * Copyright (C) 2022 The Android Open Source Project
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

#include <fuzzer/FuzzedDataProvider.h>
#include <import_parser.h>
#include <rlimit_parser.h>

using namespace android;
using namespace android::init;

const std::vector<std::string> kValidInputs[] = {
        {"", "cpu", "10", "10"}, {"", "RLIM_CPU", "10", "10"},  {"", "12", "unlimited", "10"},
        {"", "13", "-1", "10"},  {"", "14", "10", "unlimited"}, {"", "15", "10", "-1"},
};

const std::string kValidPaths[] = {
        "/system/etc/init/hw/init.rc",
        "/system/etc/init",
};

const int32_t kMaxBytes = 256;

class InitParserFuzzer {
  public:
    InitParserFuzzer(const uint8_t* data, size_t size) : fdp_(data, size){};
    void Process();

  private:
    void InvokeParser();
    void InvokeLimitParser();

    FuzzedDataProvider fdp_;
};

void InitParserFuzzer::InvokeLimitParser() {
    if (fdp_.ConsumeBool()) {
        std::vector<std::string> input;
        input.push_back("");
        input.push_back(fdp_.ConsumeRandomLengthString(kMaxBytes));
        input.push_back(fdp_.ConsumeRandomLengthString(kMaxBytes));
        input.push_back(fdp_.ConsumeRandomLengthString(kMaxBytes));
        ParseRlimit(input);
    } else {
        ParseRlimit(fdp_.PickValueInArray(kValidInputs));
    }
}

void InitParserFuzzer::InvokeParser() {
    Parser parser;
    std::string name = fdp_.ConsumeBool() ? fdp_.ConsumeRandomLengthString(kMaxBytes) : "import";
    parser.AddSectionParser(name, std::make_unique<ImportParser>(&parser));
    std::string path = fdp_.ConsumeBool() ? fdp_.PickValueInArray(kValidPaths)
                                          : fdp_.ConsumeRandomLengthString(kMaxBytes);
    parser.ParseConfig(path);
    parser.ParseConfigFileInsecure(path, false /* follow_symlinks */);
}

void InitParserFuzzer::Process() {
    while (fdp_.remaining_bytes()) {
        auto invoke_parser_fuzzer = fdp_.PickValueInArray<const std::function<void()>>({
                [&]() { InvokeParser(); },
                [&]() { InvokeLimitParser(); },
        });
        invoke_parser_fuzzer();
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    InitParserFuzzer init_parser_fuzzer(data, size);
    init_parser_fuzzer.Process();
    return 0;
}
