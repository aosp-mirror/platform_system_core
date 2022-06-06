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

#include <stdarg.h>

#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <sparse/sparse.h>

#include "fastboot_device.h"

static void LogSparseVerboseMessage(const char* fmt, ...) {
    std::string message;

    va_list ap;
    va_start(ap, fmt);
    android::base::StringAppendV(&message, fmt, ap);
    va_end(ap);

    LOG(ERROR) << "libsparse message: " << message;
}

int main(int /*argc*/, char* argv[]) {
    android::base::InitLogging(argv, &android::base::KernelLogger);

    sparse_print_verbose = LogSparseVerboseMessage;

    while (true) {
        FastbootDevice device;
        device.ExecuteCommands();
    }
}
