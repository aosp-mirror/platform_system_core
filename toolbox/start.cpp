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

#include <stdlib.h>
#include <unistd.h>

#include <iostream>
#include <string>
#include <vector>

#include <android-base/properties.h>

using android::base::GetProperty;
using android::base::SetProperty;
using namespace std::literals;

static void ControlService(bool start, const std::string& service) {
    if (!android::base::SetProperty(start ? "ctl.start" : "ctl.stop", service)) {
        std::cerr << "Unable to " << (start ? "start" : "stop") << " service '" << service
                  << "'\nSee dmesg for error reason." << std::endl;
        exit(EXIT_FAILURE);
    }
}

static void ControlDefaultServices(bool start) {
    std::vector<std::string> services = {
        "netd",
        "surfaceflinger",
        "audioserver",
        "zygote",
    };

    // Only start zygote_secondary if not single arch.
    std::string zygote_configuration = GetProperty("ro.zygote", "");
    if (zygote_configuration != "zygote32" && zygote_configuration != "zygote64") {
        services.emplace_back("zygote_secondary");
    }

    if (start) {
        for (const auto& service : services) {
            ControlService(true, service);
        }
    } else {
        for (auto it = services.crbegin(); it != services.crend(); ++it) {
            ControlService(false, *it);
        }
    }
}

static int StartStop(int argc, char** argv, bool start) {
    if (getuid()) {
        std::cerr << "Must be root" << std::endl;
        return EXIT_FAILURE;
    }

    if (argc == 1) {
        ControlDefaultServices(start);
    }

    if (argc == 2 && argv[1] == "--help"s) {
        std::cout << "usage: " << (start ? "start" : "stop")
                  << " [SERVICE...]\n"
                     "\n"
                  << (start ? "Starts" : "Stops")
                  << " the given system service, or netd/surfaceflinger/zygotes." << std::endl;
        return EXIT_SUCCESS;
    }

    for (int i = 1; i < argc; ++i) {
        ControlService(start, argv[i]);
    }
    return EXIT_SUCCESS;
}

extern "C" int start_main(int argc, char** argv) {
    return StartStop(argc, argv, true);
}

extern "C" int stop_main(int argc, char** argv) {
    return StartStop(argc, argv, false);
}
