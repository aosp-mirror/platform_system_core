/*
 * Copyright (C) 2016 The Android Open Source Project
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

#include <string>

#include <android-base/strings.h>

#include "bugreport.h"
#include "commandline.h"
#include "file_sync_service.h"

static constexpr char BUGZ_OK_PREFIX[] = "OK:";
static constexpr char BUGZ_FAIL_PREFIX[] = "FAIL:";

int Bugreport::DoIt(TransportType transport_type, const char* serial, int argc, const char** argv) {
    if (argc == 1) return SendShellCommand(transport_type, serial, "bugreport", false);
    if (argc != 2) return usage();

    // Zipped bugreport option - will call 'bugreportz', which prints the location
    // of the generated
    // file, then pull it to the destination file provided by the user.
    std::string dest_file = argv[1];
    if (!android::base::EndsWith(argv[1], ".zip")) {
        // TODO: use a case-insensitive comparison (like EndsWithIgnoreCase
        dest_file += ".zip";
    }
    std::string output;

    fprintf(stderr,
            "Bugreport is in progress and it could take minutes to complete.\n"
            "Please be patient and do not cancel or disconnect your device until "
            "it completes.\n");
    int status = SendShellCommand(transport_type, serial, "bugreportz", false, &output, nullptr);
    if (status != 0 || output.empty()) return status;
    output = android::base::Trim(output);

    if (android::base::StartsWith(output, BUGZ_OK_PREFIX)) {
        const char* zip_file = &output[strlen(BUGZ_OK_PREFIX)];
        std::vector<const char*> srcs{zip_file};
        status = DoSyncPull(srcs, dest_file.c_str(), true, dest_file.c_str()) ? 0 : 1;
        if (status != 0) {
            fprintf(stderr, "Could not copy file '%s' to '%s'\n", zip_file, dest_file.c_str());
        }
        return status;
    }
    if (android::base::StartsWith(output, BUGZ_FAIL_PREFIX)) {
        const char* error_message = &output[strlen(BUGZ_FAIL_PREFIX)];
        fprintf(stderr, "Device failed to take a zipped bugreport: %s\n", error_message);
        return -1;
    }
    fprintf(stderr,
            "Unexpected string (%s) returned by bugreportz, "
            "device probably does not support it\n",
            output.c_str());
    return -1;
}

int Bugreport::SendShellCommand(TransportType transport_type, const char* serial,
                                const std::string& command, bool disable_shell_protocol,
                                std::string* output, std::string* err) {
    return send_shell_command(transport_type, serial, command, disable_shell_protocol, output, err);
}

bool Bugreport::DoSyncPull(const std::vector<const char*>& srcs, const char* dst, bool copy_attrs,
                           const char* name) {
    return do_sync_pull(srcs, dst, copy_attrs, name);
}
