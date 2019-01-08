/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include "adb.h"
#include "adb_io.h"
#include "shell_service.h"

#include "cmd.h"

#include <sys/wait.h>

namespace {

class AdbFdTextOutput : public android::TextOutput {
  public:
    explicit AdbFdTextOutput(int fd) : mFD(fd) {}

  private:
    android::status_t print(const char* txt, size_t len) override {
        return WriteFdExactly(mFD, txt, len) ? android::OK : -errno;
    }
    void moveIndent(int delta) override { /*not implemented*/
    }

    void pushBundle() override { /*not implemented*/
    }
    void popBundle() override { /*not implemented*/
    }

  private:
    int mFD;
};

std::vector<std::string_view> parseCmdArgs(std::string_view args) {
    std::vector<std::string_view> argv;

    char delim = ABB_ARG_DELIMETER;
    size_t size = args.size();
    size_t base = 0;
    while (base < size) {
        size_t found;
        for (found = base; found < size && args[found] && args[found] != delim; ++found)
            ;
        if (found > base) {
            argv.emplace_back(args.substr(base, found - base));
        }
        base = found + 1;
    }

    return argv;
}

}  // namespace

static int execCmd(std::string_view args, int in, int out, int err) {
    AdbFdTextOutput oin(out);
    AdbFdTextOutput oerr(err);
    return cmdMain(parseCmdArgs(args), oin, oerr, in, out, err, RunMode::kLibrary);
}

int main(int argc, char* const argv[]) {
    signal(SIGPIPE, SIG_IGN);

    int fd = STDIN_FILENO;
    std::string data;
    while (true) {
        std::string error;
        if (!ReadProtocolString(fd, &data, &error)) {
            PLOG(ERROR) << "Failed to read message: " << error;
            break;
        }

        auto result = StartCommandInProcess(std::move(data), &execCmd);
        if (!SendFileDescriptor(fd, result)) {
            PLOG(ERROR) << "Failed to send an inprocess fd for command: " << data;
            break;
        }
    }
}
