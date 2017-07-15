/*
 * Copyright (C) 2016 The Android Open Source Project
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

#include <elf.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <unwindstack/Elf.h>
#include <unwindstack/Log.h>
#include <unwindstack/Memory.h>

int main(int argc, char** argv) {
  if (argc != 2) {
    printf("Need to pass the name of an elf file to the program.\n");
    return 1;
  }

  struct stat st;
  if (stat(argv[1], &st) == -1) {
    printf("Cannot stat %s: %s\n", argv[1], strerror(errno));
    return 1;
  }
  if (!S_ISREG(st.st_mode)) {
    printf("%s is not a regular file.\n", argv[1]);
    return 1;
  }

  // Send all log messages to stdout.
  unwindstack::log_to_stdout(true);

  unwindstack::MemoryFileAtOffset* memory = new unwindstack::MemoryFileAtOffset;
  if (!memory->Init(argv[1], 0)) {
    printf("Failed to init\n");
    return 1;
  }

  unwindstack::Elf elf(memory);
  if (!elf.Init() || !elf.valid()) {
    printf("%s is not a valid elf file.\n", argv[1]);
    return 1;
  }

  switch (elf.machine_type()) {
    case EM_ARM:
      printf("ABI: arm\n");
      break;
    case EM_AARCH64:
      printf("ABI: arm64\n");
      break;
    case EM_386:
      printf("ABI: x86\n");
      break;
    case EM_X86_64:
      printf("ABI: x86_64\n");
      break;
    default:
      printf("ABI: unknown\n");
      return 1;
  }

  // This is a crude way to get the symbols in order.
  std::string name;
  uint64_t load_bias = elf.interface()->load_bias();
  for (const auto& entry : elf.interface()->pt_loads()) {
    uint64_t start = entry.second.offset + load_bias;
    uint64_t end = entry.second.table_size + load_bias;
    for (uint64_t addr = start; addr < end; addr += 4) {
      std::string cur_name;
      uint64_t func_offset;
      if (elf.GetFunctionName(addr, &cur_name, &func_offset)) {
        if (cur_name != name) {
          printf("<0x%" PRIx64 "> Function: %s\n", addr - func_offset, cur_name.c_str());
        }
        name = cur_name;
      }
    }
  }

  return 0;
}
