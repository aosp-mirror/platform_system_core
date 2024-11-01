/*
 * Copyright (C) 2024 The Android Open Source Project
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

#include <string>
#include <vector>

#include "android-base/unique_fd.h"

class BacktraceFrame;

class Symbolizer {
  android::base::unique_fd in_fd, out_fd;

  std::string read_response();

 public:
  bool Start(const std::vector<std::string>& debug_file_directories);

  struct Frame {
    std::string function_name, file;
    uint64_t line, column;
  };

  std::vector<Frame> SymbolizeCode(std::string path, uint64_t rel_pc);
};

void symbolize_backtrace_frame(const BacktraceFrame& frame, Symbolizer& sym);
