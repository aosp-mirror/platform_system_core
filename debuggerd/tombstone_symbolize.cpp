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

#include "tombstone_symbolize.h"

#include <fcntl.h>
#include <inttypes.h>
#include <unistd.h>

#include <string>
#include <vector>

#include "android-base/stringprintf.h"
#include "android-base/unique_fd.h"

#include "tombstone.pb.h"

using android::base::StringPrintf;
using android::base::unique_fd;

bool Symbolizer::Start(const std::vector<std::string>& debug_file_directories) {
  unique_fd parent_in, parent_out, child_in, child_out;
  if (!Pipe(&parent_in, &child_out) || !Pipe(&child_in, &parent_out)) {
    return false;
  }

  std::vector<const char *> args;
  args.push_back("llvm-symbolizer");
  for (const std::string &dir : debug_file_directories) {
    args.push_back("--debug-file-directory");
    args.push_back(dir.c_str());
  }
  args.push_back(0);

  int pid = fork();
  if (pid == -1) {
    return false;
  } else if (pid == 0) {
    parent_in.reset();
    parent_out.reset();

    dup2(child_in.get(), STDIN_FILENO);
    dup2(child_out.get(), STDOUT_FILENO);

    execvp("llvm-symbolizer", const_cast<char *const *>(args.data()));

    fprintf(stderr, "unable to start llvm-symbolizer: %s\n", strerror(errno));
    _exit(1);
  } else {
    child_in.reset();
    child_out.reset();

    // TODO: Check that llvm-symbolizer started up successfully.
    // There used to be an easy way to do this, but it was removed in:
    // https://github.com/llvm/llvm-project/commit/1792852f86dc75efa1f44d46b1a0daf386d64afa

    in_fd = std::move(parent_in);
    out_fd = std::move(parent_out);
    return true;
  }
}

std::string Symbolizer::read_response() {
  std::string resp;

  while (resp.size() < 2 || resp[resp.size() - 2] != '\n' || resp[resp.size() - 1] != '\n') {
    char buf[4096];
    ssize_t size = read(in_fd, buf, 4096);
    if (size <= 0) {
      return "";
    }
    resp.append(buf, size);
  }

  return resp;
}

std::vector<Symbolizer::Frame> Symbolizer::SymbolizeCode(std::string path, uint64_t rel_pc) {
  std::string request = StringPrintf("CODE %s 0x%" PRIx64 "\n", path.c_str(), rel_pc);
  if (write(out_fd, request.c_str(), request.size()) != static_cast<ssize_t>(request.size())) {
    return {};
  }

  std::string response = read_response();
  if (response.empty()) {
    return {};
  }

  std::vector<Symbolizer::Frame> frames;

  size_t frame_start = 0;
  while (frame_start < response.size() - 1) {
    Symbolizer::Frame frame;

    size_t second_line_start = response.find('\n', frame_start) + 1;
    if (second_line_start == std::string::npos + 1) {
      return {};
    }

    size_t third_line_start = response.find('\n', second_line_start) + 1;
    if (third_line_start == std::string::npos + 1) {
      return {};
    }

    frame.function_name = response.substr(frame_start, second_line_start - frame_start - 1);

    size_t column_number_start = response.rfind(':', third_line_start);
    if (column_number_start == std::string::npos) {
      return {};
    }

    size_t line_number_start = response.rfind(':', column_number_start - 1);
    if (line_number_start == std::string::npos) {
      return {};
    }

    frame.file = response.substr(second_line_start, line_number_start - second_line_start);

    errno = 0;
    frame.line = strtoull(response.c_str() + line_number_start + 1, 0, 10);
    frame.column = strtoull(response.c_str() + column_number_start + 1, 0, 10);
    if (errno != 0) {
      return {};
    }

    frames.push_back(frame);

    frame_start = third_line_start;
  }

  if (frames.size() == 1 && frames[0].file == "??") {
    return {};
  }

  return frames;
}

void symbolize_backtrace_frame(const BacktraceFrame& frame, Symbolizer& sym) {
  if (frame.build_id().empty()) {
    return;
  }

  for (Symbolizer::Frame f : sym.SymbolizeCode("BUILDID:" + frame.build_id(), frame.rel_pc())) {
    printf("          %s:%" PRId64 ":%" PRId64 " (%s)\n", f.file.c_str(), f.line, f.column,
           f.function_name.c_str());
  }
}
