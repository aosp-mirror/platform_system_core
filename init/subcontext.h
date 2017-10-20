/*
 * Copyright (C) 2017 The Android Open Source Project
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

#ifndef _INIT_SUBCONTEXT_H
#define _INIT_SUBCONTEXT_H

#include <signal.h>

#include <string>
#include <vector>

#include <android-base/unique_fd.h>

#include "builtins.h"

namespace android {
namespace init {

extern const std::string kInitContext;
extern const std::string kVendorContext;

class Subcontext {
  public:
    Subcontext(std::string path_prefix, std::string context)
        : path_prefix_(std::move(path_prefix)), context_(std::move(context)) {
        Fork();
    }

    Result<Success> Execute(const std::vector<std::string>& command);
    void Restart();

    const std::string& path_prefix() const { return path_prefix_; }
    const std::string& context() const { return context_; }
    pid_t pid() const { return pid_; }

  private:
    void Fork();

    std::string path_prefix_;
    std::string context_;
    pid_t pid_;
    android::base::unique_fd socket_;
};

// For testing, to kill the subcontext after the test has completed.
class SubcontextKiller {
  public:
    SubcontextKiller(const Subcontext& subcontext) : subcontext_(subcontext) {}
    ~SubcontextKiller() {
        if (subcontext_.pid() > 0) {
            kill(subcontext_.pid(), SIGTERM);
            kill(subcontext_.pid(), SIGKILL);
        }
    }

  private:
    const Subcontext& subcontext_;
};

int SubcontextMain(int argc, char** argv, const KeywordFunctionMap* function_map);
std::vector<Subcontext>* InitializeSubcontexts();
bool SubcontextChildReap(pid_t pid);

}  // namespace init
}  // namespace android

#endif
