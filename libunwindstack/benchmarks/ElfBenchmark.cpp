/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include <err.h>
#include <malloc.h>
#include <stdint.h>

#include <string>

#include <benchmark/benchmark.h>

#include <unwindstack/Elf.h>
#include <unwindstack/Memory.h>

#include "Utils.h"

static void BenchmarkElfCreate(benchmark::State& state, const std::string& elf_file) {
#if defined(__BIONIC__)
  uint64_t rss_bytes = 0;
#endif
  uint64_t alloc_bytes = 0;
  for (auto _ : state) {
    state.PauseTiming();
#if defined(__BIONIC__)
    mallopt(M_PURGE, 0);
    uint64_t rss_bytes_before = 0;
    GatherRss(&rss_bytes_before);
#endif
    uint64_t alloc_bytes_before = mallinfo().uordblks;
    auto file_memory = unwindstack::Memory::CreateFileMemory(elf_file, 0);
    state.ResumeTiming();

    unwindstack::Elf elf(file_memory.release());
    if (!elf.Init() || !elf.valid()) {
      errx(1, "Internal Error: Cannot open elf.");
    }

    state.PauseTiming();
#if defined(__BIONIC__)
    mallopt(M_PURGE, 0);
#endif
    alloc_bytes += mallinfo().uordblks - alloc_bytes_before;
#if defined(__BIONIC__)
    GatherRss(&rss_bytes);
    rss_bytes -= rss_bytes_before;
#endif
    state.ResumeTiming();
  }

#if defined(__BIONIC__)
  state.counters["RSS_BYTES"] = rss_bytes / static_cast<double>(state.iterations());
#endif
  state.counters["ALLOCATED_BYTES"] = alloc_bytes / static_cast<double>(state.iterations());
}

void BM_elf_create(benchmark::State& state) {
  BenchmarkElfCreate(state, GetElfFile());
}
BENCHMARK(BM_elf_create);

void BM_elf_create_compressed(benchmark::State& state) {
  BenchmarkElfCreate(state, GetCompressedElfFile());
}
BENCHMARK(BM_elf_create_compressed);
