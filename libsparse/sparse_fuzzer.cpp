#include "include/sparse/sparse.h"

static volatile int count;

int WriteCallback(void* priv  __attribute__((__unused__)), const void* data, size_t len) {
  if (!data) {
    return 0;
  }
  if (len == 0) {
    return 0;
  }

  const char* p = (const char*)data;
  // Just to make sure the data is accessible
  // We only check the head and tail to save time
  count += *p;
  count += *(p+len-1);
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  struct sparse_file* file = sparse_file_import_buf((char*)data, size, true, false);
  if (!file) {
      return 0;
  }
  int32_t result = sparse_file_callback(file, false, false, WriteCallback, nullptr);
  sparse_file_destroy(file);
  return result;
}
