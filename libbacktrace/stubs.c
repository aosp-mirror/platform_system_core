/*
 * Copyright (C) 2013 The Android Open Source Project
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

#define LOG_TAG "libbacktrace"

#include <cutils/log.h>
#include <backtrace/backtrace.h>

bool backtrace_get_data(backtrace_t* backtrace, pid_t tid) {
  ALOGW("backtrace_get_data: unsupported architecture.\n");
  return true;
}

void backtrace_free_data(backtrace_t* backtrace) {
  ALOGW("backtrace_free_data: unsupported architecture.\n");
}

bool backtrace_read_word(const backtrace_t* backtrace, uintptr_t ptr,
                         uint32_t* out_value) {
  ALOGW("backtrace_read_word: unsupported architecture.\n");
  return false;
}

const char *backtrace_get_map_info(const backtrace_t* backtrace,
    uintptr_t pc, uintptr_t* start_pc) {
  ALOGW("backtrace_get_map_info: unsupported architecture.\n");
  return NULL;
}

char* backtrace_get_proc_name(const backtrace_t* backtrace, uintptr_t pc,
    uintptr_t* offset) {
  ALOGW("backtrace_get_proc_name: unsupported architecture.\n");
  return NULL;
}

void backtrace_format_frame_data(
    const backtrace_frame_data_t* frame, size_t frame_num, char *buf, size_t buf_size) {
  ALOGW("backtrace_format_frame_data: unsupported architecture.\n");
  buf[0] = '\0';
}
