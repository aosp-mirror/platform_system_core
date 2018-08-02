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

#define TRACE_TAG ADB

#include "sysdeps.h"

#include "bugreport.h"

#include <string>
#include <vector>

#include <android-base/file.h>
#include <android-base/strings.h>

#include "adb_utils.h"
#include "client/file_sync_client.h"

static constexpr char BUGZ_BEGIN_PREFIX[] = "BEGIN:";
static constexpr char BUGZ_PROGRESS_PREFIX[] = "PROGRESS:";
static constexpr char BUGZ_PROGRESS_SEPARATOR[] = "/";
static constexpr char BUGZ_OK_PREFIX[] = "OK:";
static constexpr char BUGZ_FAIL_PREFIX[] = "FAIL:";

// Custom callback used to handle the output of zipped bugreports.
class BugreportStandardStreamsCallback : public StandardStreamsCallbackInterface {
  public:
    BugreportStandardStreamsCallback(const std::string& dest_dir, const std::string& dest_file,
                                     bool show_progress, Bugreport* br)
        : br_(br),
          src_file_(),
          dest_dir_(dest_dir),
          dest_file_(dest_file),
          line_message_(),
          invalid_lines_(),
          show_progress_(show_progress),
          status_(0),
          line_(),
          last_progress_percentage_(0) {
        SetLineMessage("generating");
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
        // Process remaining line, if any.
        ProcessLine(line_);

        // Warn about invalid lines, if any.
        if (!invalid_lines_.empty()) {
            fprintf(stderr,
                    "WARNING: bugreportz generated %zu line(s) with unknown commands, "
                    "device might not support zipped bugreports:\n",
                    invalid_lines_.size());
            for (const auto& line : invalid_lines_) {
                fprintf(stderr, "\t%s\n", line.c_str());
            }
            fprintf(stderr,
                    "If the zipped bugreport was not generated, try 'adb bugreport' instead.\n");
        }

        // Pull the generated bug report.
        if (status_ == 0) {
            if (src_file_.empty()) {
                fprintf(stderr, "bugreportz did not return a '%s' or '%s' line\n", BUGZ_OK_PREFIX,
                        BUGZ_FAIL_PREFIX);
                return -1;
            }
            std::string destination;
            if (dest_dir_.empty()) {
                destination = dest_file_;
            } else {
                destination = android::base::StringPrintf("%s%c%s", dest_dir_.c_str(),
                                                          OS_PATH_SEPARATOR, dest_file_.c_str());
            }
            std::vector<const char*> srcs{src_file_.c_str()};
            SetLineMessage("pulling");
            status_ =
                br_->DoSyncPull(srcs, destination.c_str(), false, line_message_.c_str()) ? 0 : 1;
            if (status_ != 0) {
                fprintf(stderr,
                        "Bug report finished but could not be copied to '%s'.\n"
                        "Try to run 'adb pull %s <directory>'\n"
                        "to copy it to a directory that can be written.\n",
                        destination.c_str(), src_file_.c_str());
            }
        }
        return status_;
    }

  private:
    void SetLineMessage(const std::string& action) {
        line_message_ = action + " " + android::base::Basename(dest_file_);
    }

    void SetSrcFile(const std::string path) {
        src_file_ = path;
        if (!dest_dir_.empty()) {
            // Only uses device-provided name when user passed a directory.
            dest_file_ = android::base::Basename(path);
            SetLineMessage("generating");
        }
    }

    void ProcessLine(const std::string& line) {
        if (line.empty()) return;

        if (android::base::StartsWith(line, BUGZ_BEGIN_PREFIX)) {
            SetSrcFile(&line[strlen(BUGZ_BEGIN_PREFIX)]);
        } else if (android::base::StartsWith(line, BUGZ_OK_PREFIX)) {
            SetSrcFile(&line[strlen(BUGZ_OK_PREFIX)]);
        } else if (android::base::StartsWith(line, BUGZ_FAIL_PREFIX)) {
            const char* error_message = &line[strlen(BUGZ_FAIL_PREFIX)];
            fprintf(stderr, "adb: device failed to take a zipped bugreport: %s\n", error_message);
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
            int progress_percentage = (progress * 100 / total);
            if (progress_percentage != 0 && progress_percentage <= last_progress_percentage_) {
                // Ignore.
                return;
            }
            last_progress_percentage_ = progress_percentage;
            br_->UpdateProgress(line_message_, progress_percentage);
        } else {
            invalid_lines_.push_back(line);
        }
    }

    Bugreport* br_;

    // Path of bugreport on device.
    std::string src_file_;

    // Bugreport destination on host, depending on argument passed on constructor:
    // - if argument is a directory, dest_dir_ is set with it and dest_file_ will be the name
    //   of the bugreport reported by the device.
    // - if argument is empty, dest_dir is set as the current directory and dest_file_ will be the
    //   name of the bugreport reported by the device.
    // - otherwise, dest_dir_ is not set and dest_file_ is set with the value passed on constructor.
    std::string dest_dir_, dest_file_;

    // Message displayed on LinePrinter, it's updated every time the destination above change.
    std::string line_message_;

    // Lines sent by bugreportz that contain invalid commands; will be displayed at the end.
    std::vector<std::string> invalid_lines_;

    // Whether PROGRESS_LINES should be interpreted as progress.
    bool show_progress_;

    // Overall process of the operation, as returned by Done().
    int status_;

    // Temporary buffer containing the characters read since the last newline (\n).
    std::string line_;

    // Last displayed progress.
    // Since dumpstate progress can recede, only forward progress should be displayed
    int last_progress_percentage_;

    DISALLOW_COPY_AND_ASSIGN(BugreportStandardStreamsCallback);
};

int Bugreport::DoIt(int argc, const char** argv) {
    if (argc > 2) return syntax_error("adb bugreport [PATH]");

    // Gets bugreportz version.
    std::string bugz_stdout, bugz_stderr;
    DefaultStandardStreamsCallback version_callback(&bugz_stdout, &bugz_stderr);
    int status = SendShellCommand("bugreportz -v", false, &version_callback);
    std::string bugz_version = android::base::Trim(bugz_stderr);
    std::string bugz_output = android::base::Trim(bugz_stdout);

    if (status != 0 || bugz_version.empty()) {
        D("'bugreportz' -v results: status=%d, stdout='%s', stderr='%s'", status,
          bugz_output.c_str(), bugz_version.c_str());
        if (argc == 1) {
            // Device does not support bugreportz: if called as 'adb bugreport', just falls out to
            // the flat-file version.
            fprintf(stderr,
                    "Failed to get bugreportz version, which is only available on devices "
                    "running Android 7.0 or later.\nTrying a plain-text bug report instead.\n");
            return SendShellCommand("bugreport", false);
        }

        // But if user explicitly asked for a zipped bug report, fails instead (otherwise calling
        // 'bugreport' would generate a lot of output the user might not be prepared to handle).
        fprintf(stderr,
                "Failed to get bugreportz version: 'bugreportz -v' returned '%s' (code %d).\n"
                "If the device does not run Android 7.0 or above, try 'adb bugreport' instead.\n",
                bugz_output.c_str(), status);
        return status != 0 ? status : -1;
    }

    std::string dest_file, dest_dir;

    if (argc == 1) {
        // No args - use current directory
        if (!getcwd(&dest_dir)) {
            perror("adb: getcwd failed");
            return 1;
        }
    } else {
        // Check whether argument is a directory or file
        if (directory_exists(argv[1])) {
            dest_dir = argv[1];
        } else {
            dest_file = argv[1];
        }
    }

    if (dest_file.empty()) {
        // Uses a default value until device provides the proper name
        dest_file = "bugreport.zip";
    } else {
        if (!android::base::EndsWithIgnoreCase(dest_file, ".zip")) {
            dest_file += ".zip";
        }
    }

    bool show_progress = true;
    std::string bugz_command = "bugreportz -p";
    if (bugz_version == "1.0") {
        // 1.0 does not support progress notifications, so print a disclaimer
        // message instead.
        fprintf(stderr,
                "Bugreport is in progress and it could take minutes to complete.\n"
                "Please be patient and do not cancel or disconnect your device "
                "until it completes.\n");
        show_progress = false;
        bugz_command = "bugreportz";
    }
    BugreportStandardStreamsCallback bugz_callback(dest_dir, dest_file, show_progress, this);
    return SendShellCommand(bugz_command, false, &bugz_callback);
}

void Bugreport::UpdateProgress(const std::string& message, int progress_percentage) {
    line_printer_.Print(
        android::base::StringPrintf("[%3d%%] %s", progress_percentage, message.c_str()),
        LinePrinter::INFO);
}

int Bugreport::SendShellCommand(const std::string& command, bool disable_shell_protocol,
                                StandardStreamsCallbackInterface* callback) {
    return send_shell_command(command, disable_shell_protocol, callback);
}

bool Bugreport::DoSyncPull(const std::vector<const char*>& srcs, const char* dst, bool copy_attrs,
                           const char* name) {
    return do_sync_pull(srcs, dst, copy_attrs, name);
}
