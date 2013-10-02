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

#include <errno.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <inttypes.h>

#include <log/log.h>
#include <backtrace/backtrace.h>

#include "common.h"

bool backtrace_read_word(const backtrace_t* backtrace, uintptr_t ptr,
                         uint32_t* out_value) {
  if (ptr & 3) {
    ALOGW("backtrace_read_word: invalid pointer %p", (void*)ptr);
    *out_value = (uint32_t)-1;
    return false;
  }

  // Check if reading from the current process, or a different process.
  if (backtrace->tid < 0) {
    const backtrace_map_info_t* map_info = backtrace_find_map_info(backtrace->map_info_list, ptr);
    if (map_info && map_info->is_readable) {
      *out_value = *(uint32_t*)ptr;
      return true;
    } else {
      ALOGW("backtrace_read_word: pointer %p not in a readbale map", (void*)ptr);
      *out_value = (uint32_t)-1;
      return false;
    }
  } else {
#if defined(__APPLE__)
    ALOGW("read_word: MacOS does not support reading from another pid.\n");
    return false;
#else
    // ptrace() returns -1 and sets errno when the operation fails.
    // To disambiguate -1 from a valid result, we clear errno beforehand.
    errno = 0;
    *out_value = ptrace(PTRACE_PEEKTEXT, backtrace->tid, (void*)ptr, NULL);
    if (*out_value == (uint32_t)-1 && errno) {
      ALOGW("try_get_word: invalid pointer 0x%08x reading from tid %d, "
            "ptrace() errno=%d", ptr, backtrace->tid, errno);
      return false;
    }
    return true;
  }
#endif
}

const char *backtrace_get_map_info(
    const backtrace_t* backtrace, uintptr_t pc, uintptr_t* start_pc) {
  const backtrace_map_info_t* map_info = backtrace_find_map_info(backtrace->map_info_list, pc);
  if (map_info) {
    if (start_pc) {
      *start_pc = map_info->start;
    }
    return map_info->name;
  }
  return NULL;
}

void backtrace_format_frame_data(
    const backtrace_frame_data_t* frame, size_t frame_num, char *buf, size_t buf_size) {
  uintptr_t relative_pc;
  const char* map_name;
  if (frame->map_name) {
    map_name = frame->map_name;
  } else {
    map_name = "<unknown>";
  }
  if (frame->map_offset) {
    relative_pc = frame->map_offset;
  } else {
    relative_pc = frame->pc;
  }
  if (frame->proc_name && frame->proc_offset) {
    snprintf(buf, buf_size, "#%02zu pc %0*" PRIxPTR "  %s (%s+%" PRIuPTR ")",
             frame_num, (int)sizeof(uintptr_t)*2, relative_pc, map_name,
             frame->proc_name, frame->proc_offset);
  } else if (frame->proc_name) {
    snprintf(buf, buf_size, "#%02zu pc %0*" PRIxPTR "  %s (%s)", frame_num,
             (int)sizeof(uintptr_t)*2, relative_pc, map_name, frame->proc_name);
  } else {
    snprintf(buf, buf_size, "#%02zu pc %0*" PRIxPTR "  %s", frame_num,
             (int)sizeof(uintptr_t)*2, relative_pc, map_name);
  }
}

void free_frame_data(backtrace_t* backtrace) {
  for (size_t i = 0; i < backtrace->num_frames; i++) {
    if (backtrace->frames[i].proc_name) {
      free(backtrace->frames[i].proc_name);
    }
  }
  backtrace->num_frames = 0;
}
