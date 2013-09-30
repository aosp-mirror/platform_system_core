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

#include <string.h>

#include <cutils/log.h>
#include <backtrace/backtrace.h>

#define UNW_LOCAL_ONLY
#include <libunwind.h>
#include <libunwind-ptrace.h>

#include "common.h"
#include "demangle.h"

static bool local_get_frames(backtrace_t* backtrace) {
  unw_context_t* context = (unw_context_t*)backtrace->private_data;
  unw_cursor_t cursor;

  int ret = unw_getcontext(context);
  if (ret < 0) {
    ALOGW("local_get_frames: unw_getcontext failed %d\n", ret);
    return false;
  }

  ret = unw_init_local(&cursor, context);
  if (ret < 0) {
    ALOGW("local_get_frames: unw_init_local failed %d\n", ret);
    return false;
  }

  backtrace_frame_data_t* frame;
  bool returnValue = true;
  backtrace->num_frames = 0;
  uintptr_t map_start;
  do {
    frame = &backtrace->frames[backtrace->num_frames];
    frame->stack_size = 0;
    frame->map_name = NULL;
    frame->map_offset = 0;
    frame->proc_name = NULL;
    frame->proc_offset = 0;

    ret = unw_get_reg(&cursor, UNW_REG_IP, &frame->pc);
    if (ret < 0) {
      ALOGW("get_frames: Failed to read IP %d\n", ret);
      returnValue = false;
      break;
    }
    ret = unw_get_reg(&cursor, UNW_REG_SP, &frame->sp);
    if (ret < 0) {
      ALOGW("get_frames: Failed to read IP %d\n", ret);
      returnValue = false;
      break;
    }
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

bool local_get_data(backtrace_t* backtrace) {
  unw_context_t *context = (unw_context_t*)malloc(sizeof(unw_context_t));
  backtrace->private_data = context;

  if (!local_get_frames(backtrace)) {
    backtrace_free_data(backtrace);
    return false;
  }

  return true;
}

void local_free_data(backtrace_t* backtrace) {
  if (backtrace->private_data) {
    free(backtrace->private_data);
    backtrace->private_data = NULL;
  }
}

char* local_get_proc_name(const backtrace_t* backtrace, uintptr_t pc,
                          uintptr_t* offset) {
  unw_context_t* context = (unw_context_t*)backtrace->private_data;
  char buf[512];

  if (unw_get_proc_name_by_ip(unw_local_addr_space, pc, buf, sizeof(buf),
                              offset, context) >= 0 && buf[0] != '\0') {
    char* symbol = demangle_symbol_name(buf);
    if (!symbol) {
      symbol = strdup(buf);
    }
    return symbol;
  }
  return NULL;
}
