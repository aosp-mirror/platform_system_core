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
#include <stdint.h>

#include <string>

#include <android-base/file.h>
#include <android-base/stringprintf.h>

#include <benchmark/benchmark.h>

#include <unwindstack/Maps.h>

class BenchmarkLocalUpdatableMaps : public unwindstack::LocalUpdatableMaps {
 public:
  BenchmarkLocalUpdatableMaps() : unwindstack::LocalUpdatableMaps() {}
  virtual ~BenchmarkLocalUpdatableMaps() = default;

  const std::string GetMapsFile() const override { return maps_file_; }

  void BenchmarkSetMapsFile(const std::string& maps_file) { maps_file_ = maps_file; }

 private:
  std::string maps_file_;
};

constexpr size_t kNumMaps = 10000;

static void CreateInitialMap(const char* filename) {
  std::string maps;
  for (size_t i = 0; i < kNumMaps; i += 2) {
    maps += android::base::StringPrintf("%zu-%zu r-xp 0000 00:00 0 name%zu\n", i * 1000,
                                        (i + 1) * 1000, i);
  }
  if (!android::base::WriteStringToFile(maps, filename)) {
    errx(1, "WriteStringToFile failed");
  }
}

static void CreateReparseMap(const char* filename) {
  std::string maps;
  for (size_t i = 0; i < kNumMaps; i++) {
    maps += android::base::StringPrintf("%zu-%zu r-xp 0000 00:00 0 name%zu\n", i * 2000,
                                        (i + 1) * 2000, 2 * i);
  }
  if (!android::base::WriteStringToFile(maps, filename)) {
    errx(1, "WriteStringToFile failed");
  }
}

void BM_local_updatable_maps_reparse(benchmark::State& state) {
  TemporaryFile initial_map;
  CreateInitialMap(initial_map.path);

  TemporaryFile reparse_map;
  CreateReparseMap(reparse_map.path);

  for (auto _ : state) {
    BenchmarkLocalUpdatableMaps maps;
    maps.BenchmarkSetMapsFile(initial_map.path);
    if (!maps.Reparse()) {
      errx(1, "Internal Error: reparse of initial maps filed.");
    }
    if (maps.Total() != (kNumMaps / 2)) {
      errx(1, "Internal Error: Incorrect total number of maps %zu, expected %zu.", maps.Total(),
           kNumMaps / 2);
    }
    maps.BenchmarkSetMapsFile(reparse_map.path);
    if (!maps.Reparse()) {
      errx(1, "Internal Error: reparse of second set of maps filed.");
    }
    if (maps.Total() != kNumMaps) {
      errx(1, "Internal Error: Incorrect total number of maps %zu, expected %zu.", maps.Total(),
           kNumMaps);
    }
  }
}
BENCHMARK(BM_local_updatable_maps_reparse);
