/*
 * Copyright (C) 2017 The Android Open Source Project
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

#include "logwrap/logwrap.h"

#include <android-base/logging.h>
#include <benchmark/benchmark.h>

static void BM_android_fork_execvp_ext(benchmark::State& state) {
    const char* argv[] = {"/system/bin/echo", "hello", "world"};
    const int argc = 3;
    while (state.KeepRunning()) {
        int rc = android_fork_execvp_ext(
            argc, (char**)argv, NULL /* status */, false /* ignore_int_quit */, LOG_NONE,
            false /* abbreviated */, NULL /* file_path */, NULL /* opts */, 0 /* opts_len */);
        CHECK_EQ(0, rc);
    }
}
BENCHMARK(BM_android_fork_execvp_ext);

BENCHMARK_MAIN();
