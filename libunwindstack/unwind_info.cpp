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
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "ArmExidx.h"
#include "Elf.h"
#include "ElfInterface.h"
#include "ElfInterfaceArm.h"
#include "Log.h"

void DumpArm(ElfInterfaceArm* interface) {
  if (interface == nullptr) {
    printf("No ARM Unwind Information.\n\n");
    return;
  }

  printf("ARM Unwind Information:\n");
  for (const auto& entry : interface->pt_loads()) {
    uint64_t load_bias = entry.second.table_offset;
    printf(" PC Range 0x%" PRIx64 " - 0x%" PRIx64 "\n", entry.second.offset + load_bias,
           entry.second.table_size + load_bias);
    for (auto addr : *interface) {
      std::string name;
      printf("  PC 0x%" PRIx64, addr + load_bias);
      uint64_t func_offset;
      if (interface->GetFunctionName(addr + load_bias + 1, &name, &func_offset) && !name.empty()) {
        printf(" <%s>", name.c_str());
      }
      printf("\n");
      uint64_t entry;
      if (!interface->FindEntry(addr + load_bias, &entry)) {
        printf("    Cannot find entry for address.\n");
        continue;
      }
      ArmExidx arm(nullptr, interface->memory(), nullptr);
      arm.set_log(true);
      arm.set_log_skip_execution(true);
      arm.set_log_indent(2);
      if (!arm.ExtractEntryData(entry)) {
        if (arm.status() != ARM_STATUS_NO_UNWIND) {
          printf("    Error trying to extract data.\n");
        }
        continue;
      }
      if (arm.data()->size() > 0) {
        if (!arm.Eval() && arm.status() != ARM_STATUS_NO_UNWIND) {
          printf("      Error trying to evaluate dwarf data.\n");
        }
      }
    }
  }
  printf("\n");
}

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
  if (S_ISDIR(st.st_mode)) {
    printf("%s is a directory.\n", argv[1]);
    return 1;
  }

  // Send all log messages to stdout.
  log_to_stdout(true);

  MemoryFileAtOffset* memory = new MemoryFileAtOffset;
  if (!memory->Init(argv[1], 0)) {
    // Initializatation failed.
    printf("Failed to init\n");
    return 1;
  }

  Elf elf(memory);
  if (!elf.Init() || !elf.valid()) {
    printf("%s is not a valid elf file.\n", argv[1]);
    return 1;
  }

  ElfInterface* interface = elf.interface();
  if (elf.machine_type() == EM_ARM) {
    DumpArm(reinterpret_cast<ElfInterfaceArm*>(interface));
    printf("\n");
  }

  return 0;
}
