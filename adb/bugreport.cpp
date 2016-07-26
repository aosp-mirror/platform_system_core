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
#include "file_sync_service.h"

static constexpr char BUGZ_OK_PREFIX[] = "OK:";
static constexpr char BUGZ_FAIL_PREFIX[] = "FAIL:";

// Custom callback used to handle the output of zipped bugreports.
class BugreportStandardStreamsCallback : public StandardStreamsCallbackInterface {
  public:
    BugreportStandardStreamsCallback(const std::string& dest_file, Bugreport* br)
        : br_(br), dest_file_(dest_file), stdout_str_() {
    }

    void OnStdout(const char* buffer, int length) {
        std::string output;
        OnStream(&output, stdout, buffer, length);
        stdout_str_.append(output);
    }

    void OnStderr(const char* buffer, int length) {
        OnStream(nullptr, stderr, buffer, length);
    }

    int Done(int unused_) {
        int status = -1;
        std::string output = android::base::Trim(stdout_str_);
        if (android::base::StartsWith(output, BUGZ_OK_PREFIX)) {
            const char* zip_file = &output[strlen(BUGZ_OK_PREFIX)];
            std::vector<const char*> srcs{zip_file};
            status = br_->DoSyncPull(srcs, dest_file_.c_str(), true, dest_file_.c_str()) ? 0 : 1;
            if (status != 0) {
                fprintf(stderr, "Could not copy file '%s' to '%s'\n", zip_file, dest_file_.c_str());
            }
        } else if (android::base::StartsWith(output, BUGZ_FAIL_PREFIX)) {
            const char* error_message = &output[strlen(BUGZ_FAIL_PREFIX)];
            fprintf(stderr, "Device failed to take a zipped bugreport: %s\n", error_message);
        } else {
            fprintf(stderr,
                    "Unexpected string (%s) returned by bugreportz, "
                    "device probably does not support it\n",
                    output.c_str());
        }

        return status;
    }

  private:
    Bugreport* br_;
    const std::string dest_file_;
    std::string stdout_str_;

    DISALLOW_COPY_AND_ASSIGN(BugreportStandardStreamsCallback);
};

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
    fprintf(stderr,
            "Bugreport is in progress and it could take minutes to complete.\n"
            "Please be patient and do not cancel or disconnect your device until "
            "it completes.\n");
    BugreportStandardStreamsCallback bugz_callback(dest_file, this);
    return SendShellCommand(transport_type, serial, "bugreportz", false, &bugz_callback);
}

int Bugreport::SendShellCommand(TransportType transport_type, const char* serial,
                                const std::string& command, bool disable_shell_protocol,
                                StandardStreamsCallbackInterface* callback) {
    return send_shell_command(transport_type, serial, command, disable_shell_protocol, callback);
}

bool Bugreport::DoSyncPull(const std::vector<const char*>& srcs, const char* dst, bool copy_attrs,
                           const char* name) {
    return do_sync_pull(srcs, dst, copy_attrs, name);
}
