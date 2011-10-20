/*
 * Copyright (C) 2011 The Android Open Source Project
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

/* Process memory map. */

#ifndef _CORKSCREW_MAP_INFO_H
#define _CORKSCREW_MAP_INFO_H

#include <sys/types.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct map_info {
    struct map_info* next;
    uintptr_t start;
    uintptr_t end;
    bool is_executable;
    void* data; // arbitrary data associated with the map by the user, initially NULL
    char name[];
} map_info_t;

/* Loads memory map from /proc/<tid>/maps. */
map_info_t* load_map_info_list(pid_t tid);

/* Frees memory map. */
void free_map_info_list(map_info_t* milist);

/* Finds the memory map that contains the specified address. */
const map_info_t* find_map_info(const map_info_t* milist, uintptr_t addr);

/* Gets the memory map for this process.  (result is cached) */
const map_info_t* my_map_info_list();

#ifdef __cplusplus
}
#endif

#endif // _CORKSCREW_MAP_INFO_H
