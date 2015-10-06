/*
 * Copyright (C) 2015 The Android Open Source Project
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
#include "ziparchive/zip_writer.h"

#include <base/test_utils.h>
#include <gtest/gtest.h>
#include <memory>

struct zipwriter : public ::testing::Test {
  TemporaryFile* temp_file_;
  int fd_;
  FILE* file_;

  void SetUp() override {
    temp_file_ = new TemporaryFile();
    fd_ = temp_file_->fd;
    file_ = fdopen(fd_, "w");
    ASSERT_NE(file_, nullptr);
  }

  void TearDown() override {
    fclose(file_);
    delete temp_file_;
  }
};

TEST_F(zipwriter, WriteUncompressedZipWithOneFile) {
  ZipWriter writer(file_);

  const char* expected = "hello";

  ASSERT_EQ(writer.StartEntry("file.txt", 0), 0);
  ASSERT_EQ(writer.WriteBytes("he", 2), 0);
  ASSERT_EQ(writer.WriteBytes("llo", 3), 0);
  ASSERT_EQ(writer.FinishEntry(), 0);
  ASSERT_EQ(writer.Finish(), 0);

  ASSERT_GE(lseek(fd_, 0, SEEK_SET), 0);

  ZipArchiveHandle handle;
  ASSERT_EQ(OpenArchiveFd(fd_, "temp", &handle, false), 0);

  ZipEntry data;
  ASSERT_EQ(FindEntry(handle, ZipString("file.txt"), &data), 0);
  EXPECT_EQ(data.compressed_length, strlen(expected));
  EXPECT_EQ(data.uncompressed_length, strlen(expected));
  EXPECT_EQ(data.method, kCompressStored);

  char buffer[6];
  EXPECT_EQ(ExtractToMemory(handle, &data, reinterpret_cast<uint8_t*>(&buffer), sizeof(buffer)),
            0);
  buffer[5] = 0;

  EXPECT_STREQ(expected, buffer);

  CloseArchive(handle);
}

TEST_F(zipwriter, WriteUncompressedZipWithMultipleFiles) {
  ZipWriter writer(file_);

  ASSERT_EQ(writer.StartEntry("file.txt", 0), 0);
  ASSERT_EQ(writer.WriteBytes("he", 2), 0);
  ASSERT_EQ(writer.FinishEntry(), 0);

  ASSERT_EQ(writer.StartEntry("file/file.txt", 0), 0);
  ASSERT_EQ(writer.WriteBytes("llo", 3), 0);
  ASSERT_EQ(writer.FinishEntry(), 0);

  ASSERT_EQ(writer.StartEntry("file/file2.txt", 0), 0);
  ASSERT_EQ(writer.FinishEntry(), 0);

  ASSERT_EQ(writer.Finish(), 0);

  ASSERT_GE(lseek(fd_, 0, SEEK_SET), 0);

  ZipArchiveHandle handle;
  ASSERT_EQ(OpenArchiveFd(fd_, "temp", &handle, false), 0);

  char buffer[4];
  ZipEntry data;

  ASSERT_EQ(FindEntry(handle, ZipString("file.txt"), &data), 0);
  EXPECT_EQ(data.method, kCompressStored);
  EXPECT_EQ(data.compressed_length, 2u);
  EXPECT_EQ(data.uncompressed_length, 2u);
  ASSERT_EQ(ExtractToMemory(handle, &data, reinterpret_cast<uint8_t*>(buffer), arraysize(buffer)),
            0);
  buffer[2] = 0;
  EXPECT_STREQ("he", buffer);

  ASSERT_EQ(FindEntry(handle, ZipString("file/file.txt"), &data), 0);
  EXPECT_EQ(data.method, kCompressStored);
  EXPECT_EQ(data.compressed_length, 3u);
  EXPECT_EQ(data.uncompressed_length, 3u);
  ASSERT_EQ(ExtractToMemory(handle, &data, reinterpret_cast<uint8_t*>(buffer), arraysize(buffer)),
            0);
  buffer[3] = 0;
  EXPECT_STREQ("llo", buffer);

  ASSERT_EQ(FindEntry(handle, ZipString("file/file2.txt"), &data), 0);
  EXPECT_EQ(data.method, kCompressStored);
  EXPECT_EQ(data.compressed_length, 0u);
  EXPECT_EQ(data.uncompressed_length, 0u);

  CloseArchive(handle);
}

TEST_F(zipwriter, WriteUncompressedZipWithAlignedFile) {
  ZipWriter writer(file_);

  ASSERT_EQ(writer.StartEntry("align.txt", ZipWriter::kAlign32), 0);
  ASSERT_EQ(writer.WriteBytes("he", 2), 0);
  ASSERT_EQ(writer.FinishEntry(), 0);
  ASSERT_EQ(writer.Finish(), 0);

  ASSERT_GE(lseek(fd_, 0, SEEK_SET), 0);

  ZipArchiveHandle handle;
  ASSERT_EQ(OpenArchiveFd(fd_, "temp", &handle, false), 0);

  ZipEntry data;
  ASSERT_EQ(FindEntry(handle, ZipString("align.txt"), &data), 0);
  EXPECT_EQ(data.offset & 0x03, 0);
}
