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

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <tuple>
#include <vector>

#include <android-base/test_utils.h>
#include <benchmark/benchmark.h>
#include <ziparchive/zip_archive.h>
#include <ziparchive/zip_archive_stream_entry.h>
#include <ziparchive/zip_writer.h>

static TemporaryFile* CreateZip() {
  TemporaryFile* result = new TemporaryFile;
  FILE* fp = fdopen(result->fd, "w");

  ZipWriter writer(fp);
  std::string lastName = "file";
  for (size_t i = 0; i < 1000; i++) {
    // Make file names longer and longer.
    lastName = lastName + std::to_string(i);
    writer.StartEntry(lastName.c_str(), ZipWriter::kCompress);
    writer.WriteBytes("helo", 4);
    writer.FinishEntry();
  }
  writer.Finish();
  fclose(fp);

  return result;
}

static void FindEntry_no_match(benchmark::State& state) {
  // Create a temporary zip archive.
  std::unique_ptr<TemporaryFile> temp_file(CreateZip());
  ZipArchiveHandle handle;
  ZipEntry data;

  // In order to walk through all file names in the archive, look for a name
  // that does not exist in the archive.
  ZipString name("thisFileNameDoesNotExist");

  // Start the benchmark.
  while (state.KeepRunning()) {
    OpenArchive(temp_file->path, &handle);
    FindEntry(handle, name, &data);
    CloseArchive(handle);
  }
}
BENCHMARK(FindEntry_no_match);

static void Iterate_all_files(benchmark::State& state) {
  std::unique_ptr<TemporaryFile> temp_file(CreateZip());
  ZipArchiveHandle handle;
  void* iteration_cookie;
  ZipEntry data;
  ZipString name;

  while (state.KeepRunning()) {
    OpenArchive(temp_file->path, &handle);
    StartIteration(handle, &iteration_cookie, nullptr, nullptr);
    while (Next(iteration_cookie, &data, &name) == 0) {
    }
    EndIteration(iteration_cookie);
    CloseArchive(handle);
  }
}
BENCHMARK(Iterate_all_files);

BENCHMARK_MAIN();
