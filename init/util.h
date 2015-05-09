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

#include <string>
#include <functional>

#define ARRAY_SIZE(x) (sizeof(x)/sizeof(x[0]))

#define COLDBOOT_DONE "/dev/.coldboot_done"

int mtd_name_to_number(const char *name);
int create_socket(const char *name, int type, mode_t perm,
                  uid_t uid, gid_t gid, const char *socketcon);

bool read_file(const char* path, std::string* content);
int write_file(const char* path, const char* content);

time_t gettime();
uint64_t gettime_ns();

class Timer {
 public:
  Timer() : t0(gettime_ns()) {
  }

  double duration() {
    return static_cast<double>(gettime_ns() - t0) / 1000000000.0;
  }

 private:
  uint64_t t0;
};

unsigned int decode_uid(const char *s);

int mkdir_recursive(const char *pathname, mode_t mode);
void sanitize(char *p);
void make_link_init(const char *oldpath, const char *newpath);
void remove_link(const char *oldpath, const char *newpath);
int wait_for_file(const char *filename, int timeout);
void open_devnull_stdio(void);
void import_kernel_cmdline(bool in_qemu, std::function<void(char*,bool)>);
int make_dir(const char *path, mode_t mode);
int restorecon(const char *pathname);
int restorecon_recursive(const char *pathname);
std::string bytes_to_hex(const uint8_t *bytes, size_t bytes_len);
#endif
