/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include <ctype.h>
#include <stdlib.h>
#include <sys/system_properties.h>

#include <iostream>

#include <android-base/properties.h>
#include <android-base/strings.h>

using android::base::SetProperty;
using android::base::StartsWith;

extern "C" int setprop_main(int argc, char** argv) {
    if (argc != 3) {
        std::cout << "usage: setprop NAME VALUE\n"
                     "\n"
                     "Sets an Android system property."
                  << std::endl;
        return EXIT_FAILURE;
    }

    auto name = std::string{argv[1]};
    auto value = std::string{argv[2]};

    // SetProperty() doesn't tell us why it failed, and actually can't recognize most failures, so
    // we duplicate some of init's checks here to help the user.

    if (name.front() == '.' || name.back() == '.') {
        std::cerr << "Property names must not start or end with a '.'" << std::endl;
        return EXIT_FAILURE;
    }

    if (name.find("..") != std::string::npos) {
        std::cerr << "'..' is not allowed in a property name" << std::endl;
        return EXIT_FAILURE;
    }

    for (const auto& c : name) {
        if (!isalnum(c) && !strchr(":@_.-", c)) {
            std::cerr << "Invalid character '" << c << "' in name '" << name << "'" << std::endl;
            return EXIT_FAILURE;
        }
    }

    if (value.size() >= PROP_VALUE_MAX && !StartsWith(value, "ro.")) {
        std::cerr << "Value '" << value << "' is too long, " << value.size()
                  << " bytes vs a max of " << PROP_VALUE_MAX << std::endl;
        return EXIT_FAILURE;
    }

    if (mbstowcs(nullptr, value.data(), 0) == static_cast<std::size_t>(-1)) {
        std::cerr << "Value '" << value << "' is not a UTF8 encoded string" << std::endl;
        return EXIT_FAILURE;
    }

    if (!SetProperty(name, value)) {
        std::cerr << "Failed to set property '" << name << "' to '" << value
                  << "'.\nSee dmesg for error reason." << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}