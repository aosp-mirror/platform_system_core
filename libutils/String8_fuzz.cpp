/*
 * Copyright 2020 The Android Open Source Project
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
#include <functional>
#include <iostream>

#include "fuzzer/FuzzedDataProvider.h"
#include "utils/String8.h"

static constexpr int MAX_STRING_BYTES = 256;
static constexpr uint8_t MAX_OPERATIONS = 50;

std::vector<std::function<void(FuzzedDataProvider&, android::String8, android::String8)>>
        operations = {

                // Bytes and size
                [](FuzzedDataProvider&, android::String8 str1, android::String8) -> void {
                    str1.bytes();
                },
                [](FuzzedDataProvider&, android::String8 str1, android::String8) -> void {
                    str1.isEmpty();
                },
                [](FuzzedDataProvider&, android::String8 str1, android::String8) -> void {
                    str1.length();
                },
                [](FuzzedDataProvider&, android::String8 str1, android::String8) -> void {
                    str1.size();
                },

                // Casing
                [](FuzzedDataProvider&, android::String8 str1, android::String8) -> void {
                    str1.toUpper();
                },
                [](FuzzedDataProvider&, android::String8 str1, android::String8) -> void {
                    str1.toLower();
                },

                [](FuzzedDataProvider&, android::String8 str1, android::String8 str2) -> void {
                    str1.removeAll(str2.c_str());
                },
                [](FuzzedDataProvider&, android::String8 str1, android::String8 str2) -> void {
                    str1.compare(str2);
                },

                // Append and format
                [](FuzzedDataProvider&, android::String8 str1, android::String8 str2) -> void {
                    str1.append(str2);
                },
                [](FuzzedDataProvider&, android::String8 str1, android::String8 str2) -> void {
                    str1.appendFormat(str1.c_str(), str2.c_str());
                },
                [](FuzzedDataProvider&, android::String8 str1, android::String8 str2) -> void {
                    str1.format(str1.c_str(), str2.c_str());
                },

                // Find operation
                [](FuzzedDataProvider& dataProvider, android::String8 str1,
                   android::String8) -> void {
                    // We need to get a value from our fuzzer here.
                    int start_index = dataProvider.ConsumeIntegralInRange<int>(0, str1.size());
                    str1.find(str1.c_str(), start_index);
                },

                // Path handling
                [](FuzzedDataProvider&, android::String8 str1, android::String8) -> void {
                    str1.getBasePath();
                },
                [](FuzzedDataProvider&, android::String8 str1, android::String8) -> void {
                    str1.getPathExtension();
                },
                [](FuzzedDataProvider&, android::String8 str1, android::String8) -> void {
                    str1.getPathLeaf();
                },
                [](FuzzedDataProvider&, android::String8 str1, android::String8) -> void {
                    str1.getPathDir();
                },
                [](FuzzedDataProvider&, android::String8 str1, android::String8) -> void {
                    str1.convertToResPath();
                },
                [](FuzzedDataProvider&, android::String8 str1, android::String8) -> void {
                    android::String8 path_out_str = android::String8();
                    str1.walkPath(&path_out_str);
                    path_out_str.clear();
                },
                [](FuzzedDataProvider& dataProvider, android::String8 str1,
                   android::String8) -> void {
                    str1.setPathName(dataProvider.ConsumeBytesWithTerminator<char>(5).data());
                },
                [](FuzzedDataProvider& dataProvider, android::String8 str1,
                   android::String8) -> void {
                    str1.appendPath(dataProvider.ConsumeBytesWithTerminator<char>(5).data());
                },
};

void callFunc(uint8_t index, FuzzedDataProvider& dataProvider, android::String8 str1,
              android::String8 str2) {
    operations[index](dataProvider, str1, str2);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    FuzzedDataProvider dataProvider(data, size);
    // Generate vector lengths
    const size_t kVecOneLen = dataProvider.ConsumeIntegralInRange<size_t>(1, MAX_STRING_BYTES);
    const size_t kVecTwoLen = dataProvider.ConsumeIntegralInRange<size_t>(1, MAX_STRING_BYTES);
    // Populate vectors
    std::vector<char> vec = dataProvider.ConsumeBytesWithTerminator<char>(kVecOneLen);
    std::vector<char> vec_two = dataProvider.ConsumeBytesWithTerminator<char>(kVecTwoLen);
    // Create UTF-8 pointers
    android::String8 str_one_utf8 = android::String8(vec.data());
    android::String8 str_two_utf8 = android::String8(vec_two.data());

    // Run operations against strings
    int opsRun = 0;
    while (dataProvider.remaining_bytes() > 0 && opsRun++ < MAX_OPERATIONS) {
        uint8_t op = dataProvider.ConsumeIntegralInRange<uint8_t>(0, operations.size() - 1);
        callFunc(op, dataProvider, str_one_utf8, str_two_utf8);
    }

    // Just to be extra sure these can be freed, we're going to explicitly clear
    // them
    str_one_utf8.clear();
    str_two_utf8.clear();
    return 0;
}
