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

#pragma once

#include <ziparchive/zip_archive.h>

#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#include <memory>
#include <utility>
#include <vector>

#include "android-base/macros.h"
#include "android-base/mapped_file.h"
#include "zip_cd_entry_map.h"
#include "zip_error.h"

class MappedZipFile {
 public:
  explicit MappedZipFile(const int fd)
      : has_fd_(true), fd_(fd), fd_offset_(0), base_ptr_(nullptr), data_length_(-1) {}

  explicit MappedZipFile(const int fd, off64_t length, off64_t offset)
      : has_fd_(true), fd_(fd), fd_offset_(offset), base_ptr_(nullptr), data_length_(length) {}

  explicit MappedZipFile(const void* address, size_t length)
      : has_fd_(false), fd_(-1), fd_offset_(0), base_ptr_(address),
        data_length_(static_cast<off64_t>(length)) {}

  bool HasFd() const { return has_fd_; }

  int GetFileDescriptor() const;

  const void* GetBasePtr() const;

  off64_t GetFileOffset() const;

  off64_t GetFileLength() const;

  bool ReadAtOffset(uint8_t* buf, size_t len, off64_t off) const;

 private:
  // If has_fd_ is true, fd is valid and we'll read contents of a zip archive
  // from the file. Otherwise, we're opening the archive from a memory mapped
  // file. In that case, base_ptr_ points to the start of the memory region and
  // data_length_ defines the file length.
  const bool has_fd_;

  const int fd_;
  const off64_t fd_offset_;

  const void* const base_ptr_;
  mutable off64_t data_length_;
};

class CentralDirectory {
 public:
  CentralDirectory(void) : base_ptr_(nullptr), length_(0) {}

  const uint8_t* GetBasePtr() const { return base_ptr_; }

  size_t GetMapLength() const { return length_; }

  void Initialize(const void* map_base_ptr, off64_t cd_start_offset, size_t cd_size);

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
  std::unique_ptr<android::base::MappedFile> directory_map;

  // number of entries in the Zip archive
  uint16_t num_entries;
  std::unique_ptr<CdEntryMapInterface> cd_entry_map;

  ZipArchive(MappedZipFile&& map, bool assume_ownership);
  ZipArchive(const void* address, size_t length);
  ~ZipArchive();

  bool InitializeCentralDirectory(off64_t cd_start_offset, size_t cd_size);
};
