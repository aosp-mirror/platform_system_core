/*
 * Copyright (C) 2013 The Android Open Source Project
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

#include "ziparchive/zip_archive.h"

#include <stdio.h>
#include <gtest/gtest.h>

TEST(ziparchive, open) {
  // Ignore this test, it's just a simple test involving
  // the framework jar.
  ZipArchiveHandle handle;
  void* iterationCookie;

  ASSERT_EQ(0, OpenArchive("/sdcard/test.jar", &handle));
  ASSERT_EQ(0, StartIteration(handle, &iterationCookie, NULL));

  ZipEntry data;
  ZipEntryName name;
  int ctr = 0;
  while (Next(iterationCookie, &data, &name) == 0) {
    printf("Found %.*s\n", name.name_length, name.name);
    ctr++;
  }

  ASSERT_EQ(2245, ctr);

  ASSERT_EQ(0, FindEntry(handle, "java/sql/Clob.class", &data));
  ASSERT_EQ(-1, FindEntry(handle, "java/sql/Slob.class", &data));

  CloseArchive(&handle);
}

