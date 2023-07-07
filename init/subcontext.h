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

#pragma once

#include <signal.h>

#include <string>
#include <vector>

#include <android-base/unique_fd.h>

#include "builtins.h"
#include "result.h"
#include "system/core/init/subcontext.pb.h"

namespace android {
namespace init {

static constexpr const char kInitContext[] = "u:r:init:s0";
static constexpr const char kVendorContext[] = "u:r:vendor_init:s0";
static constexpr const char kTestContext[] = "test-test-test";

class Subcontext {
  public:
    Subcontext(std::vector<std::string> path_prefixes, std::string_view context, bool host = false)
        : path_prefixes_(std::move(path_prefixes)),
          context_(context.begin(), context.end()),
          pid_(0) {
        if (!host) {
            Fork();
        }
    }

    Result<void> Execute(const std::vector<std::string>& args);
    Result<std::vector<std::string>> ExpandArgs(const std::vector<std::string>& args);
    void Restart();
    bool PathMatchesSubcontext(const std::string& path) const;
    void SetApexList(std::vector<std::string>&& apex_list);

    const std::string& context() const { return context_; }
    pid_t pid() const { return pid_; }

  private:
    void Fork();
    Result<SubcontextReply> TransmitMessage(const SubcontextCommand& subcontext_command);

    std::vector<std::string> path_prefixes_;
    std::vector<std::string> apex_list_;
    std::string context_;
    pid_t pid_;
    android::base::unique_fd socket_;
};

int SubcontextMain(int argc, char** argv, const BuiltinFunctionMap* function_map);
void InitializeSubcontext();
void InitializeHostSubcontext(std::vector<std::string> vendor_prefixes);
Subcontext* GetSubcontext();
bool SubcontextChildReap(pid_t pid);
void SubcontextTerminate();

}  // namespace init
}  // namespace android
