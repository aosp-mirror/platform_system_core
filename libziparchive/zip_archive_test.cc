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

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <unistd.h>
#include <vector>

#include <base/file.h>
#include <gtest/gtest.h>

static std::string test_data_dir;

static const std::string kMissingZip = "missing.zip";
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

static const uint16_t kATxtNameLength = 5;
static const uint16_t kBTxtNameLength = 5;
static const uint16_t kNonexistentTxtNameLength = 15;
static const uint16_t kEmptyTxtNameLength = 9;

static const uint8_t kATxtName[kATxtNameLength] = {
  'a', '.', 't', 'x', 't'
};

static const uint8_t kBTxtName[kBTxtNameLength] = {
  'b', '.', 't', 'x', 't'
};

static const uint8_t kNonexistentTxtName[kNonexistentTxtNameLength] = {
  'n', 'o', 'n', 'e', 'x', 'i', 's', 't', 'e', 'n', 't', '.', 't', 'x' ,'t'
};

static const uint8_t kEmptyTxtName[kEmptyTxtNameLength] = {
  'e', 'm', 'p', 't', 'y', '.', 't', 'x', 't'
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

TEST(ziparchive, OpenMissing) {
  ZipArchiveHandle handle;
  ASSERT_NE(0, OpenArchiveWrapper(kMissingZip, &handle));

  // Confirm the file descriptor is not going to be mistaken for a valid one.
  ASSERT_EQ(-1, GetFileDescriptor(handle));
}

TEST(ziparchive, OpenAssumeFdOwnership) {
  int fd = open((test_data_dir + "/" + kValidZip).c_str(), O_RDONLY);
  ASSERT_NE(-1, fd);
  ZipArchiveHandle handle;
  ASSERT_EQ(0, OpenArchiveFd(fd, "OpenWithAssumeFdOwnership", &handle));
  CloseArchive(handle);
  ASSERT_EQ(-1, lseek(fd, 0, SEEK_SET));
  ASSERT_EQ(EBADF, errno);
}

TEST(ziparchive, OpenDoNotAssumeFdOwnership) {
  int fd = open((test_data_dir + "/" + kValidZip).c_str(), O_RDONLY);
  ASSERT_NE(-1, fd);
  ZipArchiveHandle handle;
  ASSERT_EQ(0, OpenArchiveFd(fd, "OpenWithAssumeFdOwnership", &handle, false));
  CloseArchive(handle);
  ASSERT_EQ(0, lseek(fd, 0, SEEK_SET));
  close(fd);
}

TEST(ziparchive, Iteration) {
  ZipArchiveHandle handle;
  ASSERT_EQ(0, OpenArchiveWrapper(kValidZip, &handle));

  void* iteration_cookie;
  ASSERT_EQ(0, StartIteration(handle, &iteration_cookie, NULL, NULL));

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

TEST(ziparchive, IterationWithPrefix) {
  ZipArchiveHandle handle;
  ASSERT_EQ(0, OpenArchiveWrapper(kValidZip, &handle));

  void* iteration_cookie;
  ZipEntryName prefix("b/");
  ASSERT_EQ(0, StartIteration(handle, &iteration_cookie, &prefix, NULL));

  ZipEntry data;
  ZipEntryName name;

  // b/c.txt
  ASSERT_EQ(0, Next(iteration_cookie, &data, &name));
  AssertNameEquals("b/c.txt", name);

  // b/d.txt
  ASSERT_EQ(0, Next(iteration_cookie, &data, &name));
  AssertNameEquals("b/d.txt", name);

  // b/
  ASSERT_EQ(0, Next(iteration_cookie, &data, &name));
  AssertNameEquals("b/", name);

  // End of iteration.
  ASSERT_EQ(-1, Next(iteration_cookie, &data, &name));

  CloseArchive(handle);
}

TEST(ziparchive, IterationWithSuffix) {
  ZipArchiveHandle handle;
  ASSERT_EQ(0, OpenArchiveWrapper(kValidZip, &handle));

  void* iteration_cookie;
  ZipEntryName suffix(".txt");
  ASSERT_EQ(0, StartIteration(handle, &iteration_cookie, NULL, &suffix));

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

  // End of iteration.
  ASSERT_EQ(-1, Next(iteration_cookie, &data, &name));

  CloseArchive(handle);
}

TEST(ziparchive, IterationWithPrefixAndSuffix) {
  ZipArchiveHandle handle;
  ASSERT_EQ(0, OpenArchiveWrapper(kValidZip, &handle));

  void* iteration_cookie;
  ZipEntryName prefix("b");
  ZipEntryName suffix(".txt");
  ASSERT_EQ(0, StartIteration(handle, &iteration_cookie, &prefix, &suffix));

  ZipEntry data;
  ZipEntryName name;

  // b/c.txt
  ASSERT_EQ(0, Next(iteration_cookie, &data, &name));
  AssertNameEquals("b/c.txt", name);

  // b/d.txt
  ASSERT_EQ(0, Next(iteration_cookie, &data, &name));
  AssertNameEquals("b/d.txt", name);

  // b.txt
  ASSERT_EQ(0, Next(iteration_cookie, &data, &name));
  AssertNameEquals("b.txt", name);

  // End of iteration.
  ASSERT_EQ(-1, Next(iteration_cookie, &data, &name));

  CloseArchive(handle);
}

TEST(ziparchive, IterationWithBadPrefixAndSuffix) {
  ZipArchiveHandle handle;
  ASSERT_EQ(0, OpenArchiveWrapper(kValidZip, &handle));

  void* iteration_cookie;
  ZipEntryName prefix("x");
  ZipEntryName suffix("y");
  ASSERT_EQ(0, StartIteration(handle, &iteration_cookie, &prefix, &suffix));

  ZipEntry data;
  ZipEntryName name;

  // End of iteration.
  ASSERT_EQ(-1, Next(iteration_cookie, &data, &name));

  CloseArchive(handle);
}

TEST(ziparchive, FindEntry) {
  ZipArchiveHandle handle;
  ASSERT_EQ(0, OpenArchiveWrapper(kValidZip, &handle));

  ZipEntry data;
  ZipEntryName name;
  name.name = kATxtName;
  name.name_length = kATxtNameLength;
  ASSERT_EQ(0, FindEntry(handle, name, &data));

  // Known facts about a.txt, from zipinfo -v.
  ASSERT_EQ(63, data.offset);
  ASSERT_EQ(kCompressDeflated, data.method);
  ASSERT_EQ(static_cast<uint32_t>(17), data.uncompressed_length);
  ASSERT_EQ(static_cast<uint32_t>(13), data.compressed_length);
  ASSERT_EQ(0x950821c5, data.crc32);

  // An entry that doesn't exist. Should be a negative return code.
  ZipEntryName absent_name;
  absent_name.name = kNonexistentTxtName;
  absent_name.name_length = kNonexistentTxtNameLength;
  ASSERT_LT(FindEntry(handle, absent_name, &data), 0);

  CloseArchive(handle);
}

TEST(ziparchive, TestInvalidDeclaredLength) {
  ZipArchiveHandle handle;
  ASSERT_EQ(0, OpenArchiveWrapper("declaredlength.zip", &handle));

  void* iteration_cookie;
  ASSERT_EQ(0, StartIteration(handle, &iteration_cookie, NULL));

  ZipEntryName name;
  ZipEntry data;

  ASSERT_EQ(Next(iteration_cookie, &data, &name), 0);
  ASSERT_EQ(Next(iteration_cookie, &data, &name), 0);

  CloseArchive(handle);
}

TEST(ziparchive, ExtractToMemory) {
  ZipArchiveHandle handle;
  ASSERT_EQ(0, OpenArchiveWrapper(kValidZip, &handle));

  // An entry that's deflated.
  ZipEntry data;
  ZipEntryName a_name;
  a_name.name = kATxtName;
  a_name.name_length = kATxtNameLength;
  ASSERT_EQ(0, FindEntry(handle, a_name, &data));
  const uint32_t a_size = data.uncompressed_length;
  ASSERT_EQ(a_size, sizeof(kATxtContents));
  uint8_t* buffer = new uint8_t[a_size];
  ASSERT_EQ(0, ExtractToMemory(handle, &data, buffer, a_size));
  ASSERT_EQ(0, memcmp(buffer, kATxtContents, a_size));
  delete[] buffer;

  // An entry that's stored.
  ZipEntryName b_name;
  b_name.name = kBTxtName;
  b_name.name_length = kBTxtNameLength;
  ASSERT_EQ(0, FindEntry(handle, b_name, &data));
  const uint32_t b_size = data.uncompressed_length;
  ASSERT_EQ(b_size, sizeof(kBTxtContents));
  buffer = new uint8_t[b_size];
  ASSERT_EQ(0, ExtractToMemory(handle, &data, buffer, b_size));
  ASSERT_EQ(0, memcmp(buffer, kBTxtContents, b_size));
  delete[] buffer;

  CloseArchive(handle);
}

static const uint32_t kEmptyEntriesZip[] = {
      0x04034b50, 0x0000000a, 0x63600000, 0x00004438, 0x00000000, 0x00000000,
      0x00090000, 0x6d65001c, 0x2e797470, 0x55747874, 0x03000954, 0x52e25c13,
      0x52e25c24, 0x000b7875, 0x42890401, 0x88040000, 0x50000013, 0x1e02014b,
      0x00000a03, 0x60000000, 0x00443863, 0x00000000, 0x00000000, 0x09000000,
      0x00001800, 0x00000000, 0xa0000000, 0x00000081, 0x706d6500, 0x742e7974,
      0x54557478, 0x13030005, 0x7552e25c, 0x01000b78, 0x00428904, 0x13880400,
      0x4b500000, 0x00000605, 0x00010000, 0x004f0001, 0x00430000, 0x00000000 };

// This is a zip file containing a single entry (ab.txt) that contains
// 90072 repetitions of the string "ab\n" and has an uncompressed length
// of 270216 bytes.
static const uint16_t kAbZip[] = {
  0x4b50, 0x0403, 0x0014, 0x0000, 0x0008, 0x51d2, 0x4698, 0xc4b0,
  0x2cda, 0x011b, 0x0000, 0x1f88, 0x0004, 0x0006, 0x001c, 0x6261,
  0x742e, 0x7478, 0x5455, 0x0009, 0x7c03, 0x3a09, 0x7c55, 0x3a09,
  0x7555, 0x0b78, 0x0100, 0x8904, 0x0042, 0x0400, 0x1388, 0x0000,
  0xc2ed, 0x0d31, 0x0000, 0x030c, 0x7fa0, 0x3b2e, 0x22ff, 0xa2aa,
  0x841f, 0x45fc, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555,
  0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555,
  0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555,
  0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555,
  0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555,
  0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555,
  0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555,
  0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555,
  0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555,
  0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555,
  0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555,
  0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555,
  0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555,
  0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555,
  0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555,
  0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555, 0x5555,
  0x5555, 0x5555, 0x5555, 0x5555, 0xdd55, 0x502c, 0x014b, 0x1e02,
  0x1403, 0x0000, 0x0800, 0xd200, 0x9851, 0xb046, 0xdac4, 0x1b2c,
  0x0001, 0x8800, 0x041f, 0x0600, 0x1800, 0x0000, 0x0000, 0x0100,
  0x0000, 0xa000, 0x0081, 0x0000, 0x6100, 0x2e62, 0x7874, 0x5574,
  0x0554, 0x0300, 0x097c, 0x553a, 0x7875, 0x000b, 0x0401, 0x4289,
  0x0000, 0x8804, 0x0013, 0x5000, 0x054b, 0x0006, 0x0000, 0x0100,
  0x0100, 0x4c00, 0x0000, 0x5b00, 0x0001, 0x0000, 0x0000
};

static const uint8_t kAbTxtName[] = { 'a', 'b', '.', 't', 'x', 't' };
static const uint16_t kAbTxtNameLength = sizeof(kAbTxtName);
static const size_t kAbUncompressedSize = 270216;

static int make_temporary_file(const char* file_name_pattern) {
  char full_path[1024];
  // Account for differences between the host and the target.
  //
  // TODO: Maybe reuse bionic/tests/TemporaryFile.h.
  snprintf(full_path, sizeof(full_path), "/data/local/tmp/%s", file_name_pattern);
  int fd = mkstemp(full_path);
  if (fd == -1) {
    snprintf(full_path, sizeof(full_path), "/tmp/%s", file_name_pattern);
    fd = mkstemp(full_path);
  }

  return fd;
}

TEST(ziparchive, EmptyEntries) {
  char temp_file_pattern[] = "empty_entries_test_XXXXXX";
  int fd = make_temporary_file(temp_file_pattern);
  ASSERT_NE(-1, fd);
  const ssize_t file_size = sizeof(kEmptyEntriesZip);
  ASSERT_EQ(file_size, TEMP_FAILURE_RETRY(write(fd, kEmptyEntriesZip, file_size)));

  ZipArchiveHandle handle;
  ASSERT_EQ(0, OpenArchiveFd(fd, "EmptyEntriesTest", &handle));

  ZipEntry entry;
  ZipEntryName empty_name;
  empty_name.name = kEmptyTxtName;
  empty_name.name_length = kEmptyTxtNameLength;
  ASSERT_EQ(0, FindEntry(handle, empty_name, &entry));
  ASSERT_EQ(static_cast<uint32_t>(0), entry.uncompressed_length);
  uint8_t buffer[1];
  ASSERT_EQ(0, ExtractToMemory(handle, &entry, buffer, 1));

  char output_file_pattern[] = "empty_entries_output_XXXXXX";
  int output_fd = make_temporary_file(output_file_pattern);
  ASSERT_NE(-1, output_fd);
  ASSERT_EQ(0, ExtractEntryToFile(handle, &entry, output_fd));

  struct stat stat_buf;
  ASSERT_EQ(0, fstat(output_fd, &stat_buf));
  ASSERT_EQ(0, stat_buf.st_size);

  close(fd);
  close(output_fd);
}

TEST(ziparchive, EntryLargerThan32K) {
  char temp_file_pattern[] = "entry_larger_than_32k_test_XXXXXX";
  int fd = make_temporary_file(temp_file_pattern);
  ASSERT_NE(-1, fd);
  ASSERT_TRUE(android::base::WriteFully(fd, reinterpret_cast<const uint8_t*>(kAbZip),
                         sizeof(kAbZip) - 1));
  ZipArchiveHandle handle;
  ASSERT_EQ(0, OpenArchiveFd(fd, "EntryLargerThan32KTest", &handle));

  ZipEntry entry;
  ZipEntryName ab_name;
  ab_name.name = kAbTxtName;
  ab_name.name_length = kAbTxtNameLength;
  ASSERT_EQ(0, FindEntry(handle, ab_name, &entry));
  ASSERT_EQ(kAbUncompressedSize, entry.uncompressed_length);

  // Extract the entry to memory.
  std::vector<uint8_t> buffer(kAbUncompressedSize);
  ASSERT_EQ(0, ExtractToMemory(handle, &entry, &buffer[0], buffer.size()));

  // Extract the entry to a file.
  char output_file_pattern[] = "entry_larger_than_32k_test_output_XXXXXX";
  int output_fd = make_temporary_file(output_file_pattern);
  ASSERT_NE(-1, output_fd);
  ASSERT_EQ(0, ExtractEntryToFile(handle, &entry, output_fd));

  // Make sure the extracted file size is as expected.
  struct stat stat_buf;
  ASSERT_EQ(0, fstat(output_fd, &stat_buf));
  ASSERT_EQ(kAbUncompressedSize, static_cast<size_t>(stat_buf.st_size));

  // Read the file back to a buffer and make sure the contents are
  // the same as the memory buffer we extracted directly to.
  std::vector<uint8_t> file_contents(kAbUncompressedSize);
  ASSERT_EQ(0, lseek64(output_fd, 0, SEEK_SET));
  ASSERT_TRUE(android::base::ReadFully(output_fd, &file_contents[0], file_contents.size()));
  ASSERT_EQ(file_contents, buffer);

  for (int i = 0; i < 90072; ++i) {
    const uint8_t* line = &file_contents[0] + (3 * i);
    ASSERT_EQ('a', line[0]);
    ASSERT_EQ('b', line[1]);
    ASSERT_EQ('\n', line[2]);
  }

  close(fd);
  close(output_fd);
}

TEST(ziparchive, TrailerAfterEOCD) {
  char temp_file_pattern[] = "trailer_after_eocd_test_XXXXXX";
  int fd = make_temporary_file(temp_file_pattern);
  ASSERT_NE(-1, fd);

  // Create a file with 8 bytes of random garbage.
  static const uint8_t trailer[] = { 'A' ,'n', 'd', 'r', 'o', 'i', 'd', 'z' };
  const ssize_t file_size = sizeof(kEmptyEntriesZip);
  const ssize_t trailer_size = sizeof(trailer);
  ASSERT_EQ(file_size, TEMP_FAILURE_RETRY(write(fd, kEmptyEntriesZip, file_size)));
  ASSERT_EQ(trailer_size, TEMP_FAILURE_RETRY(write(fd, trailer, trailer_size)));

  ZipArchiveHandle handle;
  ASSERT_GT(0, OpenArchiveFd(fd, "EmptyEntriesTest", &handle));
}

TEST(ziparchive, ExtractToFile) {
  char kTempFilePattern[] = "zip_archive_input_XXXXXX";
  int fd = make_temporary_file(kTempFilePattern);
  ASSERT_NE(-1, fd);
  const uint8_t data[8] = { '1', '2', '3', '4', '5', '6', '7', '8' };
  const ssize_t data_size = sizeof(data);

  ASSERT_EQ(data_size, TEMP_FAILURE_RETRY(write(fd, data, data_size)));

  ZipArchiveHandle handle;
  ASSERT_EQ(0, OpenArchiveWrapper(kValidZip, &handle));

  ZipEntry entry;
  ZipEntryName name;
  name.name = kATxtName;
  name.name_length = kATxtNameLength;
  ASSERT_EQ(0, FindEntry(handle, name, &entry));
  ASSERT_EQ(0, ExtractEntryToFile(handle, &entry, fd));


  // Assert that the first 8 bytes of the file haven't been clobbered.
  uint8_t read_buffer[data_size];
  ASSERT_EQ(0, lseek64(fd, 0, SEEK_SET));
  ASSERT_EQ(data_size, TEMP_FAILURE_RETRY(read(fd, read_buffer, data_size)));
  ASSERT_EQ(0, memcmp(read_buffer, data, data_size));

  // Assert that the remainder of the file contains the incompressed data.
  std::vector<uint8_t> uncompressed_data(entry.uncompressed_length);
  ASSERT_EQ(static_cast<ssize_t>(entry.uncompressed_length),
            TEMP_FAILURE_RETRY(
                read(fd, &uncompressed_data[0], entry.uncompressed_length)));
  ASSERT_EQ(0, memcmp(&uncompressed_data[0], kATxtContents,
                      sizeof(kATxtContents)));

  // Assert that the total length of the file is sane
  ASSERT_EQ(data_size + static_cast<ssize_t>(sizeof(kATxtContents)),
            lseek64(fd, 0, SEEK_END));

  close(fd);
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
