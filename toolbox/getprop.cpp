//
// Copyright (C) 2017 The Android Open Source Project
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
//

#include <getopt.h>
#include <sys/system_properties.h>

#include <iostream>
#include <string>
#include <vector>

#include <android-base/properties.h>
#include <property_info_parser/property_info_parser.h>

using android::base::GetProperty;
using android::properties::PropertyInfoAreaFile;

PropertyInfoAreaFile property_info_file;

enum class ResultType {
    Value,
    Context,
    Type,
};

void PrintAllProperties(ResultType result_type) {
    std::vector<std::pair<std::string, std::string>> properties;
    __system_property_foreach(
        [](const prop_info* pi, void* cookie) {
            __system_property_read_callback(
                pi,
                [](void* cookie, const char* name, const char* value, unsigned) {
                    auto properties =
                        reinterpret_cast<std::vector<std::pair<std::string, std::string>>*>(cookie);
                    properties->emplace_back(name, value);
                },
                cookie);
        },
        &properties);

    std::sort(properties.begin(), properties.end());

    if (result_type != ResultType::Value) {
        for (auto& [name, value] : properties) {
            const char* context = nullptr;
            const char* type = nullptr;
            property_info_file->GetPropertyInfo(name.c_str(), &context, &type);
            if (result_type == ResultType::Context) {
                value = context;
            } else {
                value = type;
            }
        }
    }

    for (const auto& [name, value] : properties) {
        std::cout << "[" << name << "]: [" << value << "]" << std::endl;
    }
}

void PrintProperty(const char* name, const char* default_value, ResultType result_type) {
    switch (result_type) {
        case ResultType::Value:
            std::cout << GetProperty(name, default_value) << std::endl;
            break;
        case ResultType::Context: {
            const char* context = nullptr;
            property_info_file->GetPropertyInfo(name, &context, nullptr);
            std::cout << context << std::endl;
            break;
        }
        case ResultType::Type: {
            const char* type = nullptr;
            property_info_file->GetPropertyInfo(name, nullptr, &type);
            std::cout << type << std::endl;
            break;
        }
    }
}

extern "C" int getprop_main(int argc, char** argv) {
    auto result_type = ResultType::Value;

    while (true) {
        static const struct option long_options[] = {
            {"help", no_argument, nullptr, 'h'},
            {nullptr, 0, nullptr, 0},
        };

        int arg = getopt_long(argc, argv, "TZ", long_options, nullptr);

        if (arg == -1) {
            break;
        }

        switch (arg) {
            case 'h':
                std::cout << "usage: getprop [-TZ] [NAME [DEFAULT]]\n"
                             "\n"
                             "Gets an Android system property, or lists them all.\n"
                             "\n"
                             "-T\tShow property types instead of values\n"
                             "-Z\tShow property contexts instead of values\n"
                          << std::endl;
                return 0;
            case 'T':
                if (result_type != ResultType::Value) {
                    std::cerr << "Only one of -T or -Z may be specified" << std::endl;
                    return -1;
                }
                result_type = ResultType::Type;
                break;
            case 'Z':
                if (result_type != ResultType::Value) {
                    std::cerr << "Only one of -T or -Z may be specified" << std::endl;
                    return -1;
                }
                result_type = ResultType::Context;
                break;
            case '?':
                return -1;
            default:
                std::cerr << "getprop: getopt returned invalid result: " << arg << std::endl;
                return -1;
        }
    }

    if (result_type != ResultType::Value) {
        property_info_file.LoadDefaultPath();
        if (!property_info_file) {
            std::cerr << "Unable to load property info file" << std::endl;
            return -1;
        }
    }

    if (optind >= argc) {
        PrintAllProperties(result_type);
        return 0;
    }

    if (optind < argc - 2) {
        std::cerr << "getprop: Max 2 arguments (see \"getprop --help\")" << std::endl;
        return -1;
    }

    PrintProperty(argv[optind], (optind == argc - 1) ? "" : argv[optind + 1], result_type);

    return 0;
}
