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

#include <err.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <unistd.h>

#include <string>
#include <vector>

#include <android-base/unique_fd.h>
#include <libdebuggerd/tombstone_proto_to_text.h>

#include "tombstone.pb.h"
#include "tombstone_symbolize.h"

using android::base::unique_fd;

[[noreturn]] void usage(bool error) {
  fprintf(stderr, "usage: pbtombstone [OPTION] TOMBSTONE.PB\n");
  fprintf(stderr, "Convert a protobuf tombstone to text.\n");
  fprintf(stderr, "Arguments:\n");
  fprintf(stderr, "  -h, --help                   print this message\n");
  fprintf(stderr, "  --debug-file-directory PATH  specify the path to a symbols directory\n");
  exit(error);
}

int main(int argc, char* argv[]) {
  std::vector<std::string> debug_file_directories;
  static struct option long_options[] = {
      {"debug-file-directory", required_argument, 0, 0},
      {"help", no_argument, 0, 'h'},
      {},
  };
  int c;
  while ((c = getopt_long(argc, argv, "h", long_options, 0)) != -1) {
    switch (c) {
      case 0:
        debug_file_directories.push_back(optarg);
        break;

      case 'h':
        usage(false);
        break;
    }
  }

  if (optind != argc-1) {
    usage(true);
  }

  unique_fd fd(open(argv[optind], O_RDONLY | O_CLOEXEC));
  if (fd == -1) {
    err(1, "failed to open tombstone '%s'", argv[1]);
  }

  Tombstone tombstone;
  if (!tombstone.ParseFromFileDescriptor(fd.get())) {
    err(1, "failed to parse tombstone");
  }

  Symbolizer sym;
  sym.Start(debug_file_directories);
  bool result = tombstone_proto_to_text(
      tombstone, [](const std::string& line, bool) { printf("%s\n", line.c_str()); },
      [&](const BacktraceFrame& frame) { symbolize_backtrace_frame(frame, sym); });

  if (!result) {
    errx(1, "tombstone was malformed");
  }

  return 0;
}
