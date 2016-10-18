/*
 * Copyright (C) 2008 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef LIBZIPARCHIVE_ZIPARCHIVE_PRIVATE_H_
#define LIBZIPARCHIVE_ZIPARCHIVE_PRIVATE_H_

#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#include <memory>
#include <vector>

#include <utils/FileMap.h>
#include <ziparchive/zip_archive.h>

class MappedZipFile {
 public:
  explicit MappedZipFile(const int fd) :
    has_fd_(true),
    fd_(fd),
    base_ptr_(nullptr),
    data_length_(0),
    read_pos_(0) {}

  explicit MappedZipFile(void* address, size_t length) :
    has_fd_(false),
    fd_(-1),
    base_ptr_(address),
    data_length_(static_cast<off64_t>(length)),
    read_pos_(0) {}

  bool HasFd() const {return has_fd_;}

  int GetFileDescriptor() const;

  void* GetBasePtr() const;

  off64_t GetFileLength() const;

  bool SeekToOffset(off64_t offset);

  bool ReadData(uint8_t* buffer, size_t read_amount);

  bool ReadAtOffset(uint8_t* buf, size_t len, off64_t off);

 private:
  // If has_fd_ is true, fd is valid and we'll read contents of a zip archive
  // from the file. Otherwise, we're opening the archive from a memory mapped
  // file. In that case, base_ptr_ points to the start of the memory region and
  // data_length_ defines the file length.
  const bool has_fd_;

  const int fd_;

  void* const base_ptr_;
  const off64_t data_length_;
  // read_pos_ is the offset to the base_ptr_ where we read data from.
  size_t read_pos_;
};

class CentralDirectory {
 public:
  CentralDirectory(void) :
    base_ptr_(nullptr),
    length_(0) {}

  const uint8_t* GetBasePtr() const {return base_ptr_;}

  size_t GetMapLength() const {return length_;}

  void Initialize(void* map_base_ptr, off64_t cd_start_offset, size_t cd_size);

 private:
  const uint8_t* base_ptr_;
  size_t length_;
};

struct ZipArchive {
  // open Zip archive
  mutable MappedZipFile mapped_zip;
  const bool close_file;

  // mapped central directory area
  off64_t directory_offset;
  CentralDirectory central_directory;
  std::unique_ptr<android::FileMap> directory_map;

  // number of entries in the Zip archive
  uint16_t num_entries;

  // We know how many entries are in the Zip archive, so we can have a
  // fixed-size hash table. We define a load factor of 0.75 and over
  // allocate so the maximum number entries can never be higher than
  // ((4 * UINT16_MAX) / 3 + 1) which can safely fit into a uint32_t.
  uint32_t hash_table_size;
  ZipString* hash_table;

  ZipArchive(const int fd, bool assume_ownership) :
    mapped_zip(fd),
    close_file(assume_ownership),
    directory_offset(0),
    central_directory(),
    directory_map(new android::FileMap()),
    num_entries(0),
    hash_table_size(0),
    hash_table(nullptr) {}

  ZipArchive(void* address, size_t length) :
    mapped_zip(address, length),
    close_file(false),
    directory_offset(0),
    central_directory(),
    directory_map(new android::FileMap()),
    num_entries(0),
    hash_table_size(0),
    hash_table(nullptr) {}

  ~ZipArchive() {
    if (close_file && mapped_zip.GetFileDescriptor() >= 0) {
      close(mapped_zip.GetFileDescriptor());
    }

    free(hash_table);
  }

  bool InitializeCentralDirectory(const char* debug_file_name, off64_t cd_start_offset,
                                  size_t cd_size);

};

#endif  // LIBZIPARCHIVE_ZIPARCHIVE_PRIVATE_H_
