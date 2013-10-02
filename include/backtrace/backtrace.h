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

#include <sys/types.h>
#include <stdbool.h>
#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

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
  uintptr_t pc;           /* The absolute pc. */
  uintptr_t sp;           /* The top of the stack. */
  size_t stack_size;      /* The size of the stack, zero indicate an unknown stack size. */
  const char* map_name;   /* The name of the map to which this pc belongs, NULL indicates the pc doesn't belong to a known map. */
  uintptr_t map_offset;   /* pc relative to the start of the map, only valid if map_name is not NULL. */
  char* proc_name;        /* The function name associated with this pc, NULL if not found. */
  uintptr_t proc_offset;  /* pc relative to the start of the procedure, only valid if proc_name is not NULL. */
} backtrace_frame_data_t;

typedef struct {
  backtrace_frame_data_t frames[MAX_BACKTRACE_FRAMES];
  size_t num_frames;

  pid_t tid;
  backtrace_map_info_t* map_info_list;
  void* private_data;
} backtrace_t;

/* Gather the backtrace data for tid and fill in the backtrace structure.
 * If tid < 0, then gather the backtrace for the current thread.
 */
bool backtrace_get_data(backtrace_t* backtrace, pid_t tid);

/* Free any memory associated with the backtrace structure. */
void backtrace_free_data(backtrace_t* backtrace);

/* Read data at a specific address for a process. */
bool backtrace_read_word(
    const backtrace_t* backtrace, uintptr_t ptr, uint32_t* value);

/* Get information about the map associated with a pc. If NULL is
 * returned, then map_start is not set.
 */
const char* backtrace_get_map_info(
    const backtrace_t* backtrace, uintptr_t pc, uintptr_t* map_start);

/* Get the procedure name and offest given the pc. If NULL is returned,
 * then proc_offset is not set. The returned string is allocated using
 * malloc and must be freed by the caller.
 */
char* backtrace_get_proc_name(
    const backtrace_t* backtrace, uintptr_t pc, uintptr_t* proc_offset);

/* Loads memory map from /proc/<tid>/maps. If tid < 0, then load the memory
 * map for the current process.
 */
backtrace_map_info_t* backtrace_create_map_info_list(pid_t tid);

/* Frees memory associated with the map list. */
void backtrace_destroy_map_info_list(backtrace_map_info_t* map_info_list);

/* Finds the memory map that contains the specified pc. */
const backtrace_map_info_t* backtrace_find_map_info(
    const backtrace_map_info_t* map_info_list, uintptr_t pc);

/* Create a formatted line of backtrace information for a single frame. */
void backtrace_format_frame_data(
    const backtrace_frame_data_t* frame, size_t frame_num, char *buf, size_t buf_size);

#ifdef __cplusplus
}
#endif

#endif /* _BACKTRACE_H */
