/*
 * Copyright (C) 2010 The Android Open Source Project
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

#ifndef _INIT_UTIL_H_
#define _INIT_UTIL_H_

#include <sys/stat.h>
#include <sys/types.h>

#include <chrono>
#include <functional>
#include <ostream>
#include <string>

#include <android-base/chrono_utils.h>

#define COLDBOOT_DONE "/dev/.coldboot_done"

using android::base::boot_clock;
using namespace std::chrono_literals;

int create_socket(const char *name, int type, mode_t perm,
                  uid_t uid, gid_t gid, const char *socketcon);

bool read_file(const std::string& path, std::string* content);
bool write_file(const std::string& path, const std::string& content);

class Timer {
  public:
    Timer() : start_(boot_clock::now()) {}

    double duration_s() const {
        typedef std::chrono::duration<double> double_duration;
        return std::chrono::duration_cast<double_duration>(boot_clock::now() - start_).count();
    }

    int64_t duration_ms() const {
        return std::chrono::duration_cast<std::chrono::milliseconds>(boot_clock::now() - start_)
            .count();
    }

  private:
    android::base::boot_clock::time_point start_;
};

std::ostream& operator<<(std::ostream& os, const Timer& t);

unsigned int decode_uid(const char *s);

int mkdir_recursive(const std::string& pathname, mode_t mode);
int wait_for_file(const char *filename, std::chrono::nanoseconds timeout);
void import_kernel_cmdline(bool in_qemu,
                           const std::function<void(const std::string&, const std::string&, bool)>&);
int make_dir(const char *path, mode_t mode);
int restorecon(const char *pathname, int flags = 0);
std::string bytes_to_hex(const uint8_t *bytes, size_t bytes_len);
bool is_dir(const char* pathname);
bool expand_props(const std::string& src, std::string* dst);

void panic() __attribute__((__noreturn__));

#endif
