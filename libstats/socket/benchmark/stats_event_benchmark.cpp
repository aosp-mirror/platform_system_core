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

static AStatsEvent* constructStatsEvent() {
    AStatsEvent* event = AStatsEvent_obtain();
    AStatsEvent_setAtomId(event, 100);

    // randomly sample atom size
    int numElements = rand() % 800;
    for (int i = 0; i < numElements; i++) {
        AStatsEvent_writeInt32(event, i);
    }

    return event;
}

static void BM_stats_event_truncate_buffer(benchmark::State& state) {
    while (state.KeepRunning()) {
        AStatsEvent* event = constructStatsEvent();
        AStatsEvent_build(event);
        AStatsEvent_write(event);
        AStatsEvent_release(event);
    }
}

BENCHMARK(BM_stats_event_truncate_buffer);

static void BM_stats_event_full_buffer(benchmark::State& state) {
    while (state.KeepRunning()) {
        AStatsEvent* event = constructStatsEvent();
        AStatsEvent_truncateBuffer(event, false);
        AStatsEvent_build(event);
        AStatsEvent_write(event);
        AStatsEvent_release(event);
    }
}

BENCHMARK(BM_stats_event_full_buffer);
