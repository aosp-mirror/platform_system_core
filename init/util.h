/*
 * Copyright (C) 2010 The Android Open Source Project
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

#ifndef _INIT_UTIL_H_
#define _INIT_UTIL_H_

#include <sys/stat.h>
#include <sys/types.h>

#include <chrono>
#include <functional>
#include <ostream>
#include <string>

#include <android-base/chrono_utils.h>
#include <selinux/label.h>

#include "result.h"

#define COLDBOOT_DONE "/dev/.coldboot_done"

using android::base::boot_clock;
using namespace std::chrono_literals;

namespace android {
namespace init {

int CreateSocket(const char* name, int type, bool passcred, mode_t perm, uid_t uid, gid_t gid,
                 const char* socketcon);

Result<std::string> ReadFile(const std::string& path);
Result<Success> WriteFile(const std::string& path, const std::string& content);

Result<uid_t> DecodeUid(const std::string& name);

bool mkdir_recursive(const std::string& pathname, mode_t mode);
int wait_for_file(const char *filename, std::chrono::nanoseconds timeout);
void import_kernel_cmdline(bool in_qemu,
                           const std::function<void(const std::string&, const std::string&, bool)>&);
bool make_dir(const std::string& path, mode_t mode);
bool is_dir(const char* pathname);
bool expand_props(const std::string& src, std::string* dst);

// Returns the platform's Android DT directory as specified in the kernel cmdline.
// If the platform does not configure a custom DT path, returns the standard one (based in procfs).
const std::string& get_android_dt_dir();
// Reads or compares the content of device tree file under the platform's Android DT directory.
bool read_android_dt_file(const std::string& sub_path, std::string* dt_content);
bool is_android_dt_value_expected(const std::string& sub_path, const std::string& expected_content);

bool IsLegalPropertyName(const std::string& name);

void InitKernelLogging(char** argv, std::function<void(const char*)> abort_function);
bool IsRecoveryMode();
}  // namespace init
}  // namespace android

#endif
