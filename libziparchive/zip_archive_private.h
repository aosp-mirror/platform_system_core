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

#include <map>
#include <memory>
#include <utility>
#include <vector>

#include "android-base/macros.h"
#include "android-base/mapped_file.h"

static const char* kErrorMessages[] = {
    "Success",
    "Iteration ended",
    "Zlib error",
    "Invalid file",
    "Invalid handle",
    "Duplicate entries in archive",
    "Empty archive",
    "Entry not found",
    "Invalid offset",
    "Inconsistent information",
    "Invalid entry name",
    "I/O error",
    "File mapping failed",
    "Allocation failed",
};

enum ZipError : int32_t {
  kSuccess = 0,

  kIterationEnd = -1,

  // We encountered a Zlib error when inflating a stream from this file.
  // Usually indicates file corruption.
  kZlibError = -2,

  // The input file cannot be processed as a zip archive. Usually because
  // it's too small, too large or does not have a valid signature.
  kInvalidFile = -3,

  // An invalid iteration / ziparchive handle was passed in as an input
  // argument.
  kInvalidHandle = -4,

  // The zip archive contained two (or possibly more) entries with the same
  // name.
  kDuplicateEntry = -5,

  // The zip archive contains no entries.
  kEmptyArchive = -6,

  // The specified entry was not found in the archive.
  kEntryNotFound = -7,

  // The zip archive contained an invalid local file header pointer.
  kInvalidOffset = -8,

  // The zip archive contained inconsistent entry information. This could
  // be because the central directory & local file header did not agree, or
  // if the actual uncompressed length or crc32 do not match their declared
  // values.
  kInconsistentInformation = -9,

  // An invalid entry name was encountered.
  kInvalidEntryName = -10,

  // An I/O related system call (read, lseek, ftruncate, map) failed.
  kIoError = -11,

  // We were not able to mmap the central directory or entry contents.
  kMmapFailed = -12,

  // An allocation failed.
  kAllocationFailed = -13,

  kLastErrorCode = kAllocationFailed,
};

class MappedZipFile {
 public:
  explicit MappedZipFile(const int fd)
      : has_fd_(true), fd_(fd), base_ptr_(nullptr), data_length_(0) {}

  explicit MappedZipFile(const void* address, size_t length)
      : has_fd_(false), fd_(-1), base_ptr_(address), data_length_(static_cast<off64_t>(length)) {}

  bool HasFd() const { return has_fd_; }

  int GetFileDescriptor() const;

  const void* GetBasePtr() const;

  off64_t GetFileLength() const;

  bool ReadAtOffset(uint8_t* buf, size_t len, off64_t off) const;

 private:
  // If has_fd_ is true, fd is valid and we'll read contents of a zip archive
  // from the file. Otherwise, we're opening the archive from a memory mapped
  // file. In that case, base_ptr_ points to the start of the memory region and
  // data_length_ defines the file length.
  const bool has_fd_;

  const int fd_;

  const void* const base_ptr_;
  const off64_t data_length_;
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

// This class is the interface of the central directory entries map. The map
// helps to locate a particular cd entry based on the filename.
class CdEntryMapInterface {
 public:
  virtual ~CdEntryMapInterface() = default;
  // Adds an entry to the map. The |name| should internally points to the
  // filename field of a cd entry. And |start| points to the beginning of the
  // central directory. Returns 0 on success.
  virtual ZipError AddToMap(std::string_view name, const uint8_t* start) = 0;
  // For the zip entry |entryName|, finds the offset of its filename field in
  // the central directory. Returns a pair of [status, offset]. The value of
  // the status is 0 on success.
  virtual std::pair<ZipError, uint64_t> GetCdEntryOffset(std::string_view name,
                                                         const uint8_t* cd_start) const = 0;
  // Resets the iterator to the beginning of the map.
  virtual void ResetIteration() = 0;
  // Returns the [name, cd offset] of the current element. Also increments the
  // iterator to points to the next element. Returns an empty pair we have read
  // past boundary.
  virtual std::pair<std::string_view, uint64_t> Next(const uint8_t* cd_start) = 0;
};

/**
 * More space efficient string representation of strings in an mmaped zipped
 * file than std::string_view. Using std::string_view as an entry in the
 * ZipArchive hash table wastes space. std::string_view stores a pointer to a
 * string (on 64 bit, 8 bytes) and the length to read from that pointer,
 * 2 bytes. Because of alignment, the structure consumes 16 bytes, wasting
 * 6 bytes.
 *
 * ZipStringOffset stores a 4 byte offset from a fixed location in the memory
 * mapped file instead of the entire address, consuming 8 bytes with alignment.
 */
struct ZipStringOffset {
  uint32_t name_offset;
  uint16_t name_length;

  const std::string_view ToStringView(const uint8_t* start) const {
    return std::string_view{reinterpret_cast<const char*>(start + name_offset), name_length};
  }
};

// This implementation of CdEntryMap uses an array hash table. It uses less
// memory than std::map; and it's used as the default implementation for zip
// archives without zip64 extension.
class CdEntryMapZip32 : public CdEntryMapInterface {
 public:
  static std::unique_ptr<CdEntryMapInterface> Create(uint16_t num_entries);

  ZipError AddToMap(std::string_view name, const uint8_t* start) override;
  std::pair<ZipError, uint64_t> GetCdEntryOffset(std::string_view name,
                                                 const uint8_t* cd_start) const override;
  void ResetIteration() override;
  std::pair<std::string_view, uint64_t> Next(const uint8_t* cd_start) override;

 private:
  explicit CdEntryMapZip32(uint16_t num_entries);

  // We know how many entries are in the Zip archive, so we can have a
  // fixed-size hash table. We define a load factor of 0.75 and over
  // allocate so the maximum number entries can never be higher than
  // ((4 * UINT16_MAX) / 3 + 1) which can safely fit into a uint32_t.
  uint32_t hash_table_size_{0};
  std::unique_ptr<ZipStringOffset[], decltype(&free)> hash_table_{nullptr, free};

  // The position of element for the current iteration.
  uint32_t current_position_{0};
};

// This implementation of CdEntryMap uses a std::map
class CdEntryMapZip64 : public CdEntryMapInterface {
 public:
  static std::unique_ptr<CdEntryMapInterface> Create();

  ZipError AddToMap(std::string_view name, const uint8_t* start) override;
  std::pair<ZipError, uint64_t> GetCdEntryOffset(std::string_view name,
                                                 const uint8_t* cd_start) const override;
  void ResetIteration() override;
  std::pair<std::string_view, uint64_t> Next(const uint8_t* cd_start) override;

 private:
  CdEntryMapZip64() = default;

  std::map<std::string_view, uint64_t> entry_table_;

  std::map<std::string_view, uint64_t>::iterator iterator_;
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

  ZipArchive(const int fd, bool assume_ownership);
  ZipArchive(const void* address, size_t length);
  ~ZipArchive();

  bool InitializeCentralDirectory(off64_t cd_start_offset, size_t cd_size);
};
