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

#include <sys/ptrace.h>
#include <string.h>

#include <log/log.h>
#include <backtrace/backtrace.h>

#include <libunwind.h>
#include <libunwind-ptrace.h>

#include "common.h"
#include "demangle.h"

typedef struct {
  unw_addr_space_t addr_space;
  struct UPT_info* upt_info;
} backtrace_private_t;

static bool remote_get_frames(backtrace_t* backtrace) {
  backtrace_private_t* data = (backtrace_private_t*)backtrace->private_data;
  unw_cursor_t cursor;
  int ret = unw_init_remote(&cursor, data->addr_space, data->upt_info);
  if (ret < 0) {
    ALOGW("remote_get_frames: unw_init_remote failed %d\n", ret);
    return false;
  }

  backtrace_frame_data_t* frame;
  bool returnValue = true;
  backtrace->num_frames = 0;
  uintptr_t map_start;
  unw_word_t value;
  do {
    frame = &backtrace->frames[backtrace->num_frames];
    frame->stack_size = 0;
    frame->map_name = NULL;
    frame->map_offset = 0;
    frame->proc_name = NULL;
    frame->proc_offset = 0;

    ret = unw_get_reg(&cursor, UNW_REG_IP, &value);
    if (ret < 0) {
      ALOGW("remote_get_frames: Failed to read IP %d\n", ret);
      returnValue = false;
      break;
    }
    frame->pc = (uintptr_t)value;
    ret = unw_get_reg(&cursor, UNW_REG_SP, &value);
    if (ret < 0) {
      ALOGW("remote_get_frames: Failed to read SP %d\n", ret);
      returnValue = false;
      break;
    }
    frame->sp = (uintptr_t)value;

    if (backtrace->num_frames) {
      backtrace_frame_data_t* prev = &backtrace->frames[backtrace->num_frames-1];
      prev->stack_size = frame->sp - prev->sp;
    }

    frame->proc_name = backtrace_get_proc_name(backtrace, frame->pc, &frame->proc_offset);

    frame->map_name = backtrace_get_map_info(backtrace, frame->pc, &map_start);
    if (frame->map_name) {
      frame->map_offset = frame->pc - map_start;
    }

    backtrace->num_frames++;
    ret = unw_step (&cursor);
  } while (ret > 0 && backtrace->num_frames < MAX_BACKTRACE_FRAMES);

  return returnValue;
}

bool remote_get_data(backtrace_t* backtrace) {
  backtrace_private_t* data = (backtrace_private_t*)malloc(sizeof(backtrace_private_t));
  if (!data) {
    ALOGW("remote_get_data: Failed to allocate memory.\n");
    backtrace_free_data(backtrace);
    return false;
  }
  data->addr_space = NULL;
  data->upt_info = NULL;

  backtrace->private_data = data;
  data->addr_space = unw_create_addr_space(&_UPT_accessors, 0);
  if (!data->addr_space) {
    ALOGW("remote_get_data: Failed to create unw address space.\n");
    backtrace_free_data(backtrace);
    return false;
  }

  data->upt_info = _UPT_create(backtrace->tid);
  if (!data->upt_info) {
    ALOGW("remote_get_data: Failed to create upt info.\n");
    backtrace_free_data(backtrace);
    return false;
  }

  if (!remote_get_frames(backtrace)) {
    backtrace_free_data(backtrace);
    return false;
  }

  return true;
}

void remote_free_data(backtrace_t* backtrace) {
  if (backtrace->private_data) {
    backtrace_private_t* data = (backtrace_private_t*)backtrace->private_data;
    if (data->upt_info) {
      _UPT_destroy(data->upt_info);
      data->upt_info = NULL;
    }
    if (data->addr_space) {
      unw_destroy_addr_space(data->addr_space);
    }

    free(backtrace->private_data);
    backtrace->private_data = NULL;
  }
}

char* remote_get_proc_name(const backtrace_t* backtrace, uintptr_t pc,
                           uintptr_t* offset) {
  backtrace_private_t* data = (backtrace_private_t*)backtrace->private_data;
  char buf[512];

  *offset = 0;
  unw_word_t value;
  if (unw_get_proc_name_by_ip(data->addr_space, pc, buf, sizeof(buf), &value,
                              data->upt_info) >= 0 && buf[0] != '\0') {
    *offset = (uintptr_t)value;
    char* symbol = demangle_symbol_name(buf);
    if (!symbol) {
      symbol = strdup(buf);
    }
    return symbol;
  }
  return NULL;
}
