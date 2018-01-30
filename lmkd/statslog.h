/*
 *  Copyright 2018 Google, Inc
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#pragma once

#include <sys/cdefs.h>
__BEGIN_DECLS

/**
 * Logs the change in LMKD state which is used as start/stop boundaries for logging
 * LMK_KILL_OCCURRED event.
 * Code: LMK_STATE_CHANGED = 54
 */
int
stats_write_lmk_state_changed(android_log_context ctx, int32_t code, int32_t state);

/**
 * Logs the event when LMKD kills a process to reduce memory pressure.
 * Code: LMK_KILL_OCCURRED = 51
 */
int
stats_write_lmk_kill_occurred(android_log_context ctx, int32_t code, int32_t uid,
                              char const* process_name, int32_t oom_score, int64_t pgfault,
                              int64_t pgmajfault, int64_t rss_in_bytes, int64_t cache_in_bytes,
                              int64_t swap_in_bytes);
__END_DECLS
