// SPDX-License-Identifier: Apache-2.0

#include <stddef.h>
#include <stdint.h>

#include <ziparchive/zip_archive.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  ZipArchiveHandle handle = nullptr;
  OpenArchiveFromMemory(data, size, "fuzz", &handle);
  CloseArchive(handle);
  return 0;
}
