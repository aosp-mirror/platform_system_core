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
#include <persistent_properties.h>
#include <property_type.h>
#include <sys/stat.h>
#include <fstream>
#include "fuzzer/FuzzedDataProvider.h"

using namespace android;
using namespace android::init;
using android::init::persistent_property_filename;

const std::string kTempDir = "/data/local/tmp/";
const std::string kFuzzerPropertyFile = kTempDir + "persistent_properties";
constexpr int32_t kMaxPropertyLength = 10;
const std::string kPrefix = "persist.";
const std::string kPropertyName = kPrefix + "sys.timezone";
const std::string kPropertyValue = "America/Los_Angeles";
const std::string kLegacyPropertyFile = "/data/property/persist.properties";
const std::string kSizeSuffix[3] = {"g", "k", "m"};
constexpr int32_t kMinNumStrings = 1;
constexpr int32_t kMaxNumStrings = 10;

enum PropertyType { STRING, BOOL, INT, UINT, DOUBLE, SIZE, ENUM, RANDOM, kMaxValue = RANDOM };

class InitPropertyFuzzer {
  public:
    InitPropertyFuzzer(const uint8_t* data, size_t size) : fdp_(data, size){};
    void process();

  private:
    void InvokeCheckType();
    void InvokeWritePersistentProperty();
    void RemoveFiles();
    void CreateFuzzerPropertyFile(const std::string property_file);
    FuzzedDataProvider fdp_;
};

void InitPropertyFuzzer::InvokeCheckType() {
    std::string property_type;
    std::string value;
    int type = fdp_.ConsumeEnum<PropertyType>();
    switch (type) {
        case STRING:
            value = fdp_.ConsumeRandomLengthString(kMaxPropertyLength);
            property_type = "string";
            break;
        case BOOL:
            value = fdp_.ConsumeBool();
            property_type = "bool";
            break;
        case INT:
            value = fdp_.ConsumeIntegral<int>();
            property_type = "int";
            break;
        case UINT:
            value = fdp_.ConsumeIntegral<uint_t>();
            property_type = "uint";
            break;
        case DOUBLE:
            value = fdp_.ConsumeFloatingPoint<double>();
            property_type = "double";
            break;
        case SIZE:
            value = fdp_.ConsumeIntegral<uint_t>();
            value = value.append(fdp_.PickValueInArray(kSizeSuffix));
            property_type = "size";
            break;
        case ENUM:
            value = fdp_.ConsumeIntegral<uint_t>();
            property_type = "enum";
            break;
        case RANDOM:
            value = fdp_.ConsumeRandomLengthString(kMaxPropertyLength);
            property_type = fdp_.ConsumeRandomLengthString(kMaxPropertyLength);
            break;
    }

    CheckType(property_type, value);
}

void InitPropertyFuzzer::InvokeWritePersistentProperty() {
    if (fdp_.ConsumeBool()) {
        WritePersistentProperty(kPropertyName, kPropertyValue);
    } else {
        WritePersistentProperty((kPrefix + fdp_.ConsumeRandomLengthString(kMaxPropertyLength)),
                                fdp_.ConsumeRandomLengthString(kMaxPropertyLength));
    }
}

void InitPropertyFuzzer::RemoveFiles() {
    remove(kFuzzerPropertyFile.c_str());
    remove(kLegacyPropertyFile.c_str());
}

void InitPropertyFuzzer::CreateFuzzerPropertyFile(const std::string property_file) {
    std::ofstream out;
    out.open(property_file, std::ios::binary | std::ofstream::trunc);
    chmod(property_file.c_str(), S_IRWXU);
    const int32_t numStrings = fdp_.ConsumeIntegralInRange(kMinNumStrings, kMaxNumStrings);
    for (int32_t i = 0; i < numStrings; ++i) {
        out << fdp_.ConsumeRandomLengthString(kMaxPropertyLength) << "\n";
    }
    out.close();
}

void InitPropertyFuzzer::process() {
    persistent_property_filename = kFuzzerPropertyFile;
    /* Property and legacy files are created using createFuzzerPropertyFile() and */
    /* are used in the below APIs. Hence createFuzzerPropertyFile() is not a part */
    /* of the lambda construct. */
    CreateFuzzerPropertyFile(kFuzzerPropertyFile);
    CreateFuzzerPropertyFile(kLegacyPropertyFile);
    auto property_type = fdp_.PickValueInArray<const std::function<void()>>({
            [&]() { InvokeCheckType(); },
            [&]() { InvokeWritePersistentProperty(); },
            [&]() { LoadPersistentProperties(); },
    });
    property_type();
    RemoveFiles();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    InitPropertyFuzzer initPropertyFuzzer(data, size);
    initPropertyFuzzer.process();
    return 0;
}
