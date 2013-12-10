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

#include "getopt.h"
#include <stdio.h>
#include <gtest/gtest.h>

static std::string test_data_dir;

static const std::string kValidZip = "valid.zip";

static const uint8_t kATxtContents[] = {
  'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
  'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
  '\n'
};

static const uint8_t kBTxtContents[] = {
  'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
  '\n'
};

static int32_t OpenArchiveWrapper(const std::string& name,
                                  ZipArchiveHandle* handle) {
  const std::string abs_path = test_data_dir + "/" + name;
  return OpenArchive(abs_path.c_str(), handle);
}

static void AssertNameEquals(const std::string& name_str,
                             const ZipEntryName& name) {
  ASSERT_EQ(name_str.size(), name.name_length);
  ASSERT_EQ(0, memcmp(name_str.c_str(), name.name, name.name_length));
}

TEST(ziparchive, Open) {
  ZipArchiveHandle handle;
  ASSERT_EQ(0, OpenArchiveWrapper(kValidZip, &handle));

  CloseArchive(handle);
}

TEST(ziparchive, Iteration) {
  ZipArchiveHandle handle;
  ASSERT_EQ(0, OpenArchiveWrapper(kValidZip, &handle));

  void* iteration_cookie;
  ASSERT_EQ(0, StartIteration(handle, &iteration_cookie, NULL));

  ZipEntry data;
  ZipEntryName name;

  // b/c.txt
  ASSERT_EQ(0, Next(iteration_cookie, &data, &name));
  AssertNameEquals("b/c.txt", name);

  // b/d.txt
  ASSERT_EQ(0, Next(iteration_cookie, &data, &name));
  AssertNameEquals("b/d.txt", name);

  // a.txt
  ASSERT_EQ(0, Next(iteration_cookie, &data, &name));
  AssertNameEquals("a.txt", name);

  // b.txt
  ASSERT_EQ(0, Next(iteration_cookie, &data, &name));
  AssertNameEquals("b.txt", name);

  // b/
  ASSERT_EQ(0, Next(iteration_cookie, &data, &name));
  AssertNameEquals("b/", name);

  // End of iteration.
  ASSERT_EQ(-1, Next(iteration_cookie, &data, &name));

  CloseArchive(handle);
}

TEST(ziparchive, FindEntry) {
  ZipArchiveHandle handle;
  ASSERT_EQ(0, OpenArchiveWrapper(kValidZip, &handle));

  ZipEntry data;
  ASSERT_EQ(0, FindEntry(handle, "a.txt", &data));

  // Known facts about a.txt, from zipinfo -v.
  ASSERT_EQ(63, data.offset);
  ASSERT_EQ(kCompressDeflated, data.method);
  ASSERT_EQ(static_cast<uint32_t>(17), data.uncompressed_length);
  ASSERT_EQ(static_cast<uint32_t>(13), data.compressed_length);
  ASSERT_EQ(0x950821c5, data.crc32);

  // An entry that doesn't exist. Should be a negative return code.
  ASSERT_LT(FindEntry(handle, "nonexistent.txt", &data), 0);

  CloseArchive(handle);
}

TEST(ziparchive, ExtractToMemory) {
  ZipArchiveHandle handle;
  ASSERT_EQ(0, OpenArchiveWrapper(kValidZip, &handle));

  // An entry that's deflated.
  ZipEntry data;
  ASSERT_EQ(0, FindEntry(handle, "a.txt", &data));
  const uint32_t a_size = data.uncompressed_length;
  ASSERT_EQ(a_size, sizeof(kATxtContents));
  uint8_t* buffer = new uint8_t[a_size];
  ASSERT_EQ(0, ExtractToMemory(handle, &data, buffer, a_size));
  ASSERT_EQ(0, memcmp(buffer, kATxtContents, a_size));
  delete[] buffer;

  // An entry that's stored.
  ASSERT_EQ(0, FindEntry(handle, "b.txt", &data));
  const uint32_t b_size = data.uncompressed_length;
  ASSERT_EQ(b_size, sizeof(kBTxtContents));
  buffer = new uint8_t[b_size];
  ASSERT_EQ(0, ExtractToMemory(handle, &data, buffer, b_size));
  ASSERT_EQ(0, memcmp(buffer, kBTxtContents, b_size));
  delete[] buffer;

  CloseArchive(handle);
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);

  static struct option options[] = {
    { "test_data_dir", required_argument, NULL, 't' },
    { NULL, 0, NULL, 0 }
  };

  while (true) {
    int option_index;
    const int c = getopt_long_only(argc, argv, "", options, &option_index);
    if (c == -1) {
      break;
    }

    if (c == 't') {
      test_data_dir = optarg;
    }
  }

  if (test_data_dir.size() == 0) {
    printf("Test data flag (--test_data_dir) required\n\n");
    return -1;
  }

  if (test_data_dir[0] != '/') {
    printf("Test data must be an absolute path, was %s\n\n",
           test_data_dir.c_str());
    return -2;
  }

  return RUN_ALL_TESTS();
}

