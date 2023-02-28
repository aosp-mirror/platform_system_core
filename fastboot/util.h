#pragma once

#include <inttypes.h>
#include <stdlib.h>

#include <string>
#include <vector>

#include <android-base/logging.h>
#include <android-base/result.h>
#include <android-base/unique_fd.h>
#include <bootimg.h>
#include <liblp/liblp.h>
#include <sparse/sparse.h>

using android::base::ErrnoError;
using android::base::Error;
using android::base::Result;
using android::base::ResultError;

template <typename T, typename U>
inline T Expect(Result<T, U> r) {
    if (r.ok()) {
        return r.value();
    }

    LOG(FATAL) << r.error().message();

    return r.value();
}

using SparsePtr = std::unique_ptr<sparse_file, decltype(&sparse_file_destroy)>;

/* util stuff */
double now();
void set_verbose();

// These printf-like functions are implemented in terms of vsnprintf, so they
// use the same attribute for compile-time format string checking.
void die(const char* fmt, ...) __attribute__((__noreturn__))
__attribute__((__format__(__printf__, 1, 2)));

void verbose(const char* fmt, ...) __attribute__((__format__(__printf__, 1, 2)));

void die(const std::string& str) __attribute__((__noreturn__));

bool should_flash_in_userspace(const android::fs_mgr::LpMetadata& metadata,
                               const std::string& partition_name);
bool is_sparse_file(android::base::borrowed_fd fd);
int64_t get_file_size(android::base::borrowed_fd fd);

class ImageSource {
  public:
    virtual ~ImageSource(){};
    virtual bool ReadFile(const std::string& name, std::vector<char>* out) const = 0;
    virtual android::base::unique_fd OpenFile(const std::string& name) const = 0;
};
