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

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <string>

#include <demangle.h>

extern "C" char* __cxa_demangle(const char*, char*, size_t*, int*);

void usage(const char* prog_name) {
  printf("Usage: %s [-c] <NAME_TO_DEMANGLE>\n", prog_name);
  printf("  -c\n");
  printf("    Compare the results of __cxa_demangle against the current\n");
  printf("    demangler.\n");
}

std::string DemangleWithCxa(const char* name) {
  const char* cxa_demangle = __cxa_demangle(name, nullptr, nullptr, nullptr);

  if (cxa_demangle == nullptr) {
    return name;
  }

  // The format of our demangler is slightly different from the cxa demangler
  // so modify the cxa demangler output. Specifically, for templates, remove
  // the spaces between '>' and '>'.
  std::string demangled_str;
  for (size_t i = 0; i < strlen(cxa_demangle); i++) {
    if (i > 2 && cxa_demangle[i] == '>' && std::isspace(cxa_demangle[i - 1]) &&
        cxa_demangle[i - 2] == '>') {
      demangled_str.resize(demangled_str.size() - 1);
    }
    demangled_str += cxa_demangle[i];
  }
  return demangled_str;
}

int main(int argc, char** argv) {
#ifdef __BIONIC__
  const char* prog_name = getprogname();
#else
  const char* prog_name = argv[0];
#endif

  bool compare = false;
  int opt_char;
  while ((opt_char = getopt(argc, argv, "c")) != -1) {
    if (opt_char == 'c') {
      compare = true;
    } else {
      usage(prog_name);
      return 1;
    }
  }
  if (optind >= argc || argc - optind != 1) {
    printf("Must supply a single argument.\n\n");
    usage(prog_name);
    return 1;
  }
  const char* name = argv[optind];

  std::string demangled_name = demangle(name);

  printf("%s\n", demangled_name.c_str());

  if (compare) {
    std::string cxa_demangle_str(DemangleWithCxa(name));

    if (cxa_demangle_str != demangled_name) {
      printf("Mismatch\n");
      printf("cxa demangle: %s\n", cxa_demangle_str.c_str());
      return 1;
    } else {
      printf("Match\n");
    }
  }
  return 0;
}
