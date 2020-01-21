/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include "liblog_symbols.h"

#if defined(__ANDROID__) && !defined(NO_LIBLOG_DLSYM)
#include <dlfcn.h>
#endif

namespace android {
namespace base {

#if defined(__ANDROID__) && !defined(NO_LIBLOG_DLSYM)

const std::optional<LibLogFunctions>& GetLibLogFunctions() {
  static std::optional<LibLogFunctions> liblog_functions = []() -> std::optional<LibLogFunctions> {
    void* liblog_handle = dlopen("liblog.so", RTLD_NOW);
    if (liblog_handle == nullptr) {
      return {};
    }

    LibLogFunctions real_liblog_functions = {};

#define DLSYM(name)                                                                   \
  real_liblog_functions.name =                                                        \
      reinterpret_cast<decltype(LibLogFunctions::name)>(dlsym(liblog_handle, #name)); \
  if (real_liblog_functions.name == nullptr) {                                        \
    return {};                                                                        \
  }

    DLSYM(__android_log_set_logger)
    DLSYM(__android_log_write_logger_data)
    DLSYM(__android_log_logd_logger)
    DLSYM(__android_log_stderr_logger)
    DLSYM(__android_log_set_aborter)
    DLSYM(__android_log_call_aborter)
    DLSYM(__android_log_default_aborter)
    DLSYM(__android_log_set_minimum_priority);
    DLSYM(__android_log_get_minimum_priority);
#undef DLSYM

    return real_liblog_functions;
  }();

  return liblog_functions;
}

#else

const std::optional<LibLogFunctions>& GetLibLogFunctions() {
  static std::optional<LibLogFunctions> liblog_functions = []() -> std::optional<LibLogFunctions> {
    return LibLogFunctions{
        .__android_log_set_logger = __android_log_set_logger,
        .__android_log_write_logger_data = __android_log_write_logger_data,
        .__android_log_logd_logger = __android_log_logd_logger,
        .__android_log_stderr_logger = __android_log_stderr_logger,
        .__android_log_set_aborter = __android_log_set_aborter,
        .__android_log_call_aborter = __android_log_call_aborter,
        .__android_log_default_aborter = __android_log_default_aborter,
        .__android_log_set_minimum_priority = __android_log_set_minimum_priority,
        .__android_log_get_minimum_priority = __android_log_get_minimum_priority,
    };
  }();
  return liblog_functions;
}

#endif

}  // namespace base
}  // namespace android
