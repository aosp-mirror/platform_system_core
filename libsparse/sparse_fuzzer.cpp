#include "include/sparse/sparse.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 2 * sizeof(wchar_t)) return 0;

  int64_t blocksize = 4096;
  struct sparse_file* file = sparse_file_new(size, blocksize);
  if (!file) {
    return 0;
  }

  unsigned int block = 1;
  sparse_file_add_data(file, &data, size, block);
  sparse_file_destroy(file);
  return 0;
}
