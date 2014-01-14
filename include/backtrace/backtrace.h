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

#ifndef _BACKTRACE_H
#define _BACKTRACE_H

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

__BEGIN_DECLS

// When the pid to be traced is set to this value, then trace the current
// process. If the tid value is not BACKTRACE_NO_TID, then the specified
// thread from the current process will be traced.
#define BACKTRACE_CURRENT_PROCESS -1
// When the tid to be traced is set to this value, then trace the specified
// current thread of the specified pid.
#define BACKTRACE_CURRENT_THREAD -1

#define MAX_BACKTRACE_FRAMES 64

typedef struct backtrace_map_info {
  struct backtrace_map_info* next;
  uintptr_t start;
  uintptr_t end;
  bool is_readable;
  bool is_writable;
  bool is_executable;
  char name[];
} backtrace_map_info_t;

typedef struct {
  size_t num;             /* The current fame number. */
  uintptr_t pc;           /* The absolute pc. */
  uintptr_t sp;           /* The top of the stack. */
  size_t stack_size;      /* The size of the stack, zero indicate an unknown stack size. */
  const char* map_name;   /* The name of the map to which this pc belongs, NULL indicates the pc doesn't belong to a known map. */
  uintptr_t map_offset;   /* pc relative to the start of the map, only valid if map_name is not NULL. */
  char* func_name;        /* The function name associated with this pc, NULL if not found. */
  uintptr_t func_offset;  /* pc relative to the start of the function, only valid if func_name is not NULL. */
} backtrace_frame_data_t;

typedef struct {
  backtrace_frame_data_t frames[MAX_BACKTRACE_FRAMES];
  size_t num_frames;

  pid_t pid;
  pid_t tid;
  backtrace_map_info_t* map_info_list;
} backtrace_t;

typedef struct {
  void* data;
  const backtrace_t* backtrace;
} backtrace_context_t;

/* Create a context for the backtrace data and gather the backtrace.
 * If pid < 0, then gather the backtrace for the current process.
 */
bool backtrace_create_context(
    backtrace_context_t* context, pid_t pid, pid_t tid, size_t num_ignore_frames);

/* The same as backtrace_create_context, except that it is assumed that
 * the pid map has already been acquired and the caller will handle freeing
 * the map data.
 */
bool backtrace_create_context_with_map(
    backtrace_context_t* context, pid_t pid, pid_t tid, size_t num_ignore_frames,
    backtrace_map_info_t* map_info);

/* Gather the backtrace data for a pthread instead of a process. */
bool backtrace_create_thread_context(
    backtrace_context_t* context, pid_t tid, size_t num_ignore_frames);

/* Free any memory allocated during the context create. */
void backtrace_destroy_context(backtrace_context_t* context);

/* Read data at a specific address for a process. */
bool backtrace_read_word(
    const backtrace_context_t* context, uintptr_t ptr, uint32_t* value);

/* Get information about the map name associated with a pc. If NULL is
 * returned, then map_start is not set.
 */
const char* backtrace_get_map_name(
    const backtrace_context_t* context, uintptr_t pc, uintptr_t* map_start);

/* Get the function name and offset given the pc. If NULL is returned,
 * then func_offset is not set. The returned string is allocated using
 * malloc and must be freed by the caller.
 */
char* backtrace_get_func_name(
    const backtrace_context_t* context, uintptr_t pc, uintptr_t* func_offset);

/* Loads memory map from /proc/<pid>/maps. If pid < 0, then load the memory
 * map for the current process.
 */
backtrace_map_info_t* backtrace_create_map_info_list(pid_t pid);

/* Frees memory associated with the map list. */
void backtrace_destroy_map_info_list(backtrace_map_info_t* map_info_list);

/* Finds the memory map that contains the specified pc. */
const backtrace_map_info_t* backtrace_find_map_info(
    const backtrace_map_info_t* map_info_list, uintptr_t pc);

/* Create a formatted line of backtrace information for a single frame. */
void backtrace_format_frame_data(
    const backtrace_context_t* context, size_t frame_num, char* buf,
    size_t buf_size);

/* Get the backtrace data structure associated with the context. */
const backtrace_t* backtrace_get_data(backtrace_context_t* context);

__END_DECLS

#endif /* _BACKTRACE_H */
