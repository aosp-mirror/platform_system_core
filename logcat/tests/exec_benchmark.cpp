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

#include <stdio.h>

#include <android-base/file.h>
#include <benchmark/benchmark.h>
#include <log/logcat.h>

// Dump the statistics and report results

static void logcat_popen_libc(benchmark::State& state, const char* cmd) {
    while (state.KeepRunning()) {
        FILE* fp = popen(cmd, "r");
        std::string ret;
        android::base::ReadFdToString(fileno(fp), &ret);
        pclose(fp);
    }
}

static void BM_logcat_stat_popen_libc(benchmark::State& state) {
    logcat_popen_libc(state, "logcat -b all -S");
}
BENCHMARK(BM_logcat_stat_popen_libc);

static void logcat_popen_liblogcat(benchmark::State& state, const char* cmd) {
    while (state.KeepRunning()) {
        android_logcat_context ctx;
        FILE* fp = android_logcat_popen(&ctx, cmd);
        std::string ret;
        android::base::ReadFdToString(fileno(fp), &ret);
        android_logcat_pclose(&ctx, fp);
    }
}

static void BM_logcat_stat_popen_liblogcat(benchmark::State& state) {
    logcat_popen_liblogcat(state, "logcat -b all -S");
}
BENCHMARK(BM_logcat_stat_popen_liblogcat);

static void logcat_system_libc(benchmark::State& state, const char* cmd) {
    while (state.KeepRunning()) {
        system(cmd);
    }
}

static void BM_logcat_stat_system_libc(benchmark::State& state) {
    logcat_system_libc(state, "logcat -b all -S >/dev/null 2>/dev/null");
}
BENCHMARK(BM_logcat_stat_system_libc);

static void logcat_system_liblogcat(benchmark::State& state, const char* cmd) {
    while (state.KeepRunning()) {
        android_logcat_system(cmd);
    }
}

static void BM_logcat_stat_system_liblogcat(benchmark::State& state) {
    logcat_system_liblogcat(state, "logcat -b all -S >/dev/null 2>/dev/null");
}
BENCHMARK(BM_logcat_stat_system_liblogcat);

// Dump the logs and report results

static void BM_logcat_dump_popen_libc(benchmark::State& state) {
    logcat_popen_libc(state, "logcat -b all -d");
}
BENCHMARK(BM_logcat_dump_popen_libc);

static void BM_logcat_dump_popen_liblogcat(benchmark::State& state) {
    logcat_popen_liblogcat(state, "logcat -b all -d");
}
BENCHMARK(BM_logcat_dump_popen_liblogcat);

static void BM_logcat_dump_system_libc(benchmark::State& state) {
    logcat_system_libc(state, "logcat -b all -d >/dev/null 2>/dev/null");
}
BENCHMARK(BM_logcat_dump_system_libc);

static void BM_logcat_dump_system_liblogcat(benchmark::State& state) {
    logcat_system_liblogcat(state, "logcat -b all -d >/dev/null 2>/dev/null");
}
BENCHMARK(BM_logcat_dump_system_liblogcat);
