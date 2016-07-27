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
static constexpr char BUGZ_PROGRESS_PREFIX[] = "PROGRESS:";
static constexpr char BUGZ_PROGRESS_SEPARATOR[] = "/";

// Custom callback used to handle the output of zipped bugreports.
class BugreportStandardStreamsCallback : public StandardStreamsCallbackInterface {
  public:
    BugreportStandardStreamsCallback(const std::string& dest_file, bool show_progress, Bugreport* br)
        : br_(br), dest_file_(dest_file), show_progress_(show_progress), status_(-1), line_() {
    }

    void OnStdout(const char* buffer, int length) {
        for (int i = 0; i < length; i++) {
            char c = buffer[i];
            if (c == '\n') {
                ProcessLine(line_);
                line_.clear();
            } else {
                line_.append(1, c);
            }
        }
    }

    void OnStderr(const char* buffer, int length) {
        OnStream(nullptr, stderr, buffer, length);
    }
    int Done(int unused_) {
        // Process remaining line, if any...
        ProcessLine(line_);
        // ..then return.
        return status_;
    }

  private:
    void ProcessLine(const std::string& line) {
        if (line.empty()) return;

        if (android::base::StartsWith(line, BUGZ_OK_PREFIX)) {
            if (show_progress_) {
                // Make sure pull message doesn't conflict with generation message.
                br_->UpdateProgress(dest_file_, 100, 100, true);
            }

            const char* zip_file = &line[strlen(BUGZ_OK_PREFIX)];
            std::vector<const char*> srcs{zip_file};
            status_ = br_->DoSyncPull(srcs, dest_file_.c_str(), true, dest_file_.c_str()) ? 0 : 1;
            if (status_ != 0) {
                fprintf(stderr, "Could not copy file '%s' to '%s'\n", zip_file, dest_file_.c_str());
            }
        } else if (android::base::StartsWith(line, BUGZ_FAIL_PREFIX)) {
            const char* error_message = &line[strlen(BUGZ_FAIL_PREFIX)];
            fprintf(stderr, "Device failed to take a zipped bugreport: %s\n", error_message);
            status_ = -1;
        } else if (show_progress_ && android::base::StartsWith(line, BUGZ_PROGRESS_PREFIX)) {
            // progress_line should have the following format:
            //
            // BUGZ_PROGRESS_PREFIX:PROGRESS/TOTAL
            //
            size_t idx1 = line.rfind(BUGZ_PROGRESS_PREFIX) + strlen(BUGZ_PROGRESS_PREFIX);
            size_t idx2 = line.rfind(BUGZ_PROGRESS_SEPARATOR);
            int progress = std::stoi(line.substr(idx1, (idx2 - idx1)));
            int total = std::stoi(line.substr(idx2 + 1));
            br_->UpdateProgress(dest_file_, progress, total);
        } else {
            fprintf(stderr,
                    "WARNING: unexpected line (%s) returned by bugreportz, "
                    "device probably does not support zipped bugreports.\n"
                    "Try 'adb bugreport' instead.",
                    line.c_str());
        }
    }

    Bugreport* br_;
    const std::string dest_file_;
    bool show_progress_;
    int status_;

    // Temporary buffer containing the characters read since the last newline
    // (\n).
    std::string line_;

    DISALLOW_COPY_AND_ASSIGN(BugreportStandardStreamsCallback);
};

// Implemented in commandline.cpp
int usage();

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

    // Gets bugreportz version.
    std::string bugz_stderr;
    DefaultStandardStreamsCallback version_callback(nullptr, &bugz_stderr);
    int status = SendShellCommand(transport_type, serial, "bugreportz -v", false, &version_callback);

    if (status != 0) {
        fprintf(stderr,
                "Failed to get bugreportz version: 'bugreport -v' returned '%s' "
                "(code %d)."
                "\nIf the device does not support it, try running 'adb bugreport' "
                "to get a "
                "flat-file bugreport.",
                bugz_stderr.c_str(), status);
        return status;
    }
    std::string bugz_version = android::base::Trim(bugz_stderr);

    bool show_progress = true;
    std::string bugz_command = "bugreportz -p";
    if (bugz_version == "1.0") {
        // 1.0 does not support progress notifications, so print a disclaimer
        // message instead.
        fprintf(stderr,
                "Bugreport is in progress and it could take minutes to complete.\n"
                "Please be patient and do not cancel or disconnect your device "
                "until it completes."
                "\n");
        show_progress = false;
        bugz_command = "bugreportz";
    }
    BugreportStandardStreamsCallback bugz_callback(dest_file, show_progress, this);
    return SendShellCommand(transport_type, serial, bugz_command, false, &bugz_callback);
}

void Bugreport::UpdateProgress(const std::string& file_name, int progress, int total,
                               bool keep_info_line) {
    int progress_percentage = (progress * 100 / total);
    line_printer_.Print(android::base::StringPrintf("[%3d%%] generating %s", progress_percentage,
                                                    file_name.c_str()),
                        LinePrinter::INFO);
    if (keep_info_line) {
        line_printer_.KeepInfoLine();
    }
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
