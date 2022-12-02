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
#include <hidl/metadata.h>
#include <import_parser.h>
#include <interface_utils.h>
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
const std::string kValidInterfaces = "android.frameworks.vr.composer@2.0::IVrComposerClient";

class InitParserFuzzer {
  public:
    InitParserFuzzer(const uint8_t* data, size_t size) : fdp_(data, size){};
    void Process();

  private:
    void InvokeParser();
    void InvokeLimitParser();
    void InvokeInterfaceUtils();
    InterfaceInheritanceHierarchyMap GenerateHierarchyMap();
    std::vector<HidlInterfaceMetadata> GenerateInterfaceMetadata();

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

std::vector<HidlInterfaceMetadata> InitParserFuzzer::GenerateInterfaceMetadata() {
    std::vector<HidlInterfaceMetadata> random_interface;
    for (size_t idx = 0; idx < fdp_.ConsumeIntegral<size_t>(); ++idx) {
        HidlInterfaceMetadata metadata;
        metadata.name = fdp_.ConsumeRandomLengthString(kMaxBytes);
        for (size_t idx1 = 0; idx1 < fdp_.ConsumeIntegral<size_t>(); ++idx1) {
            metadata.inherited.push_back(fdp_.ConsumeRandomLengthString(kMaxBytes));
        }
        random_interface.push_back(metadata);
    }
    return random_interface;
}

InterfaceInheritanceHierarchyMap InitParserFuzzer::GenerateHierarchyMap() {
    InterfaceInheritanceHierarchyMap result;
    std::vector<HidlInterfaceMetadata> random_interface;
    if (fdp_.ConsumeBool()) {
        random_interface = GenerateInterfaceMetadata();
    } else {
        random_interface = HidlInterfaceMetadata::all();
    }

    for (const HidlInterfaceMetadata& iface : random_interface) {
        std::set<FQName> inherited_interfaces;
        for (const std::string& intf : iface.inherited) {
            FQName fqname;
            (void)fqname.setTo(intf);
            inherited_interfaces.insert(fqname);
        }
        FQName fqname;
        (void)fqname.setTo(iface.name);
        result[fqname] = inherited_interfaces;
    }
    return result;
}

void InitParserFuzzer::InvokeInterfaceUtils() {
    InterfaceInheritanceHierarchyMap hierarchy_map = GenerateHierarchyMap();
    SetKnownInterfaces(hierarchy_map);
    IsKnownInterface(fdp_.ConsumeRandomLengthString(kMaxBytes));
    std::set<std::string> interface_set;
    for (size_t idx = 0; idx < fdp_.ConsumeIntegral<size_t>(); ++idx) {
        auto set_interface_values = fdp_.PickValueInArray<const std::function<void()>>({
                [&]() {
                    interface_set.insert(("aidl/" + fdp_.ConsumeRandomLengthString(kMaxBytes)));
                },
                [&]() { interface_set.insert(fdp_.ConsumeRandomLengthString(kMaxBytes)); },
                [&]() { interface_set.insert(kValidInterfaces); },
        });
        set_interface_values();
    }
    CheckInterfaceInheritanceHierarchy(interface_set, hierarchy_map);
}

void InitParserFuzzer::InvokeParser() {
    Parser parser;
    std::string name = fdp_.ConsumeBool() ? fdp_.ConsumeRandomLengthString(kMaxBytes) : "import";
    parser.AddSectionParser(name, std::make_unique<ImportParser>(&parser));
    std::string path = fdp_.ConsumeBool() ? fdp_.PickValueInArray(kValidPaths)
                                          : fdp_.ConsumeRandomLengthString(kMaxBytes);
    parser.ParseConfig(path);
    parser.ParseConfigFileInsecure(path);
}

void InitParserFuzzer::Process() {
    while (fdp_.remaining_bytes()) {
        auto invoke_parser_fuzzer = fdp_.PickValueInArray<const std::function<void()>>({
                [&]() { InvokeParser(); },
                [&]() { InvokeInterfaceUtils(); },
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
