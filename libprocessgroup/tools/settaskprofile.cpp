/*
 * Copyright (C) 2021 The Android Open Source Project
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

#include <iostream>

#include <processgroup/processgroup.h>

[[noreturn]] static void usage(int exit_status) {
    std::cerr << "Usage: " << getprogname() << " <tid> <profile> [... profileN]" << std::endl
              << "    tid      Thread ID to apply the profiles to." << std::endl
              << "    profile  Name of the profile to apply." << std::endl
              << "Applies listed profiles to the thread with specified ID." << std::endl
              << "Profiles are applied in the order specified in the command line." << std::endl
              << "If applying a profile fails, remaining profiles are ignored." << std::endl;
    exit(exit_status);
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        usage(EXIT_FAILURE);
    }

    int tid = atoi(argv[1]);
    if (tid == 0) {
        std::cerr << "Invalid thread id" << std::endl;
        exit(EXIT_FAILURE);
    }

    for (int i = 2; i < argc; i++) {
        if (!SetTaskProfiles(tid, {argv[i]})) {
            std::cerr << "Failed to apply " << argv[i] << " profile" << std::endl;
            exit(EXIT_FAILURE);
        }
        std::cout << "Profile " << argv[i] << " is applied successfully!" << std::endl;
    }

    return 0;
}
