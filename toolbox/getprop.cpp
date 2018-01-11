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

void PrintAllProperties(bool print_property_context) {
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

    if (print_property_context) {
        for (auto& [name, value] : properties) {
            const char* context = nullptr;
            property_info_file->GetPropertyInfo(name.c_str(), &context, nullptr);
            value = context;
        }
    }

    for (const auto& [name, value] : properties) {
        std::cout << "[" << name << "]: [" << value << "]" << std::endl;
    }
}

void PrintProperty(const char* name, const char* default_value, bool print_property_context) {
    if (print_property_context) {
        const char* context = nullptr;
        property_info_file->GetPropertyInfo(name, &context, nullptr);
        std::cout << context << std::endl;
    } else {
        std::cout << GetProperty(name, default_value) << std::endl;
    }
}

extern "C" int getprop_main(int argc, char** argv) {
    bool print_property_context = false;

    while (true) {
        static const struct option long_options[] = {
            {"help", no_argument, nullptr, 'h'},
            {nullptr, 0, nullptr, 0},
        };

        int arg = getopt_long(argc, argv, "Z", long_options, nullptr);

        if (arg == -1) {
            break;
        }

        switch (arg) {
            case 'h':
                std::cout << "usage: getprop [-Z] [NAME [DEFAULT]]\n\n"
                             "Gets an Android system property, or lists them all.\n"
                             "Use -Z to return the property context instead of the property value\n"
                          << std::endl;
                return 0;
            case 'Z':
                print_property_context = true;
                break;
            case '?':
                return -1;
            default:
                std::cerr << "getprop: getopt returned invalid result: " << arg << std::endl;
                return -1;
        }
    }

    if (print_property_context) {
        property_info_file.LoadDefaultPath();
        if (!property_info_file) {
            std::cerr << "Unable to load property info file" << std::endl;
            return -1;
        }
    }

    if (optind >= argc) {
        PrintAllProperties(print_property_context);
        return 0;
    }

    if (optind < argc - 2) {
        std::cerr << "getprop: Max 2 arguments (see \"getprop --help\")" << std::endl;
        return -1;
    }

    PrintProperty(argv[optind], (optind == argc - 1) ? "" : argv[optind + 1],
                  print_property_context);

    return 0;
}
