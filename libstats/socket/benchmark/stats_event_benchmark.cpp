/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include "benchmark/benchmark.h"
#include "stats_event.h"

static struct stats_event* constructStatsEvent() {
    struct stats_event* event = stats_event_obtain();
    stats_event_set_atom_id(event, 100);

    // randomly sample atom size
    for (int i = 0; i < rand() % 800; i++) {
        stats_event_write_int32(event, i);
    }

    return event;
}

static void BM_stats_event_truncate_buffer(benchmark::State& state) {
    while (state.KeepRunning()) {
        struct stats_event* event = constructStatsEvent();
        stats_event_build(event);
        stats_event_write(event);
        stats_event_release(event);
    }
}

BENCHMARK(BM_stats_event_truncate_buffer);

static void BM_stats_event_full_buffer(benchmark::State& state) {
    while (state.KeepRunning()) {
        struct stats_event* event = constructStatsEvent();
        stats_event_truncate_buffer(event, false);
        stats_event_build(event);
        stats_event_write(event);
        stats_event_release(event);
    }
}

BENCHMARK(BM_stats_event_full_buffer);
