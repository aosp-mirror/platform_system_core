/*
 * Copyright (C) 2019, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif
/*
 * Metadata for registering a stats_pull_atom_callback.
 * All fields are optional, and defaults will be used for unspecified fields.
 */
typedef struct pull_atom_metadata {
    int64_t cool_down_ns;
    int64_t timeout_ns;
    int32_t* additive_fields;
    int32_t additive_fields_size;
} pull_atom_metadata;

typedef struct pulled_stats_event_list pulled_stats_event_list;

typedef bool (*stats_pull_atom_callback_t)(int32_t atom_tag, pulled_stats_event_list* data,
                                           const void* cookie);

struct stats_event* add_stats_event_to_pull_data(pulled_stats_event_list* pull_data);
void register_stats_pull_atom_callback(int32_t atom_tag, stats_pull_atom_callback_t* callback,
                                       pull_atom_metadata* metadata, void* cookie);

#ifdef __cplusplus
}
#endif
