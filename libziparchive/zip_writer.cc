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

#include "entry_name_utils-inl.h"
#include "zip_archive_common.h"
#include "ziparchive/zip_writer.h"

#include <cassert>
#include <cstdio>
#include <memory>
#include <zlib.h>

/* Zip compression methods we support */
enum {
  kCompressStored     = 0,        // no compression
  kCompressDeflated   = 8,        // standard deflate
};

// No error, operation completed successfully.
static const int32_t kNoError = 0;

// The ZipWriter is in a bad state.
static const int32_t kInvalidState = -1;

// There was an IO error while writing to disk.
static const int32_t kIoError = -2;

// The zip entry name was invalid.
static const int32_t kInvalidEntryName = -3;

static const char* sErrorCodes[] = {
    "Invalid state",
    "IO error",
    "Invalid entry name",
};

const char* ZipWriter::ErrorCodeString(int32_t error_code) {
  if (error_code < 0 && (-error_code) < static_cast<int32_t>(arraysize(sErrorCodes))) {
    return sErrorCodes[-error_code];
  }
  return nullptr;
}

ZipWriter::ZipWriter(FILE* f) : file_(f), current_offset_(0), state_(State::kWritingZip) {
}

ZipWriter::ZipWriter(ZipWriter&& writer) : file_(writer.file_),
                                           current_offset_(writer.current_offset_),
                                           state_(writer.state_),
                                           files_(std::move(writer.files_)) {
  writer.file_ = nullptr;
  writer.state_ = State::kError;
}

ZipWriter& ZipWriter::operator=(ZipWriter&& writer) {
  file_ = writer.file_;
  current_offset_ = writer.current_offset_;
  state_ = writer.state_;
  files_ = std::move(writer.files_);
  writer.file_ = nullptr;
  writer.state_ = State::kError;
  return *this;
}

int32_t ZipWriter::HandleError(int32_t error_code) {
  state_ = State::kError;
  return error_code;
}

int32_t ZipWriter::StartEntry(const char* path, size_t flags) {
  return StartEntryWithTime(path, flags, time_t());
}

static void ExtractTimeAndDate(time_t when, uint16_t* out_time, uint16_t* out_date) {
  /* round up to an even number of seconds */
  when = static_cast<time_t>((static_cast<unsigned long>(when) + 1) & (~1));

  struct tm* ptm;
#if !defined(_WIN32)
    struct tm tm_result;
    ptm = localtime_r(&when, &tm_result);
#else
    ptm = localtime(&when);
#endif

  int year = ptm->tm_year;
  if (year < 80) {
    year = 80;
  }

  *out_date = (year - 80) << 9 | (ptm->tm_mon + 1) << 5 | ptm->tm_mday;
  *out_time = ptm->tm_hour << 11 | ptm->tm_min << 5 | ptm->tm_sec >> 1;
}

int32_t ZipWriter::StartEntryWithTime(const char* path, size_t flags, time_t time) {
  if (state_ != State::kWritingZip) {
    return kInvalidState;
  }

  FileInfo fileInfo = {};
  fileInfo.path = std::string(path);
  fileInfo.local_file_header_offset = current_offset_;

  if (!IsValidEntryName(reinterpret_cast<const uint8_t*>(fileInfo.path.data()),
                       fileInfo.path.size())) {
    return kInvalidEntryName;
  }

  LocalFileHeader header = {};
  header.lfh_signature = LocalFileHeader::kSignature;

  // Set this flag to denote that a DataDescriptor struct will appear after the data,
  // containing the crc and size fields.
  header.gpb_flags |= kGPBDDFlagMask;

  // For now, ignore the ZipWriter::kCompress flag.
  fileInfo.compression_method = kCompressStored;
  header.compression_method = fileInfo.compression_method;

  ExtractTimeAndDate(time, &fileInfo.last_mod_time, &fileInfo.last_mod_date);
  header.last_mod_time = fileInfo.last_mod_time;
  header.last_mod_date = fileInfo.last_mod_date;

  header.file_name_length = fileInfo.path.size();

  off64_t offset = current_offset_ + sizeof(header) + fileInfo.path.size();
  if ((flags & ZipWriter::kAlign32) && (offset & 0x03)) {
    // Pad the extra field so the data will be aligned.
    uint16_t padding = 4 - (offset % 4);
    header.extra_field_length = padding;
    offset += padding;
  }

  if (fwrite(&header, sizeof(header), 1, file_) != 1) {
    return HandleError(kIoError);
  }

  if (fwrite(path, sizeof(*path), fileInfo.path.size(), file_) != fileInfo.path.size()) {
    return HandleError(kIoError);
  }

  if (fwrite("\0\0\0", 1, header.extra_field_length, file_) != header.extra_field_length) {
    return HandleError(kIoError);
  }

  files_.emplace_back(std::move(fileInfo));

  current_offset_ = offset;
  state_ = State::kWritingEntry;
  return kNoError;
}

int32_t ZipWriter::WriteBytes(const void* data, size_t len) {
  if (state_ != State::kWritingEntry) {
    return HandleError(kInvalidState);
  }

  FileInfo& currentFile = files_.back();
  if (currentFile.compression_method & kCompressDeflated) {
    // TODO(adamlesinski): Implement compression using zlib deflate.
    assert(false);
  } else {
    if (fwrite(data, 1, len, file_) != len) {
      return HandleError(kIoError);
    }
    currentFile.crc32 = crc32(currentFile.crc32, reinterpret_cast<const Bytef*>(data), len);
    currentFile.compressed_size += len;
    current_offset_ += len;
  }

  currentFile.uncompressed_size += len;
  return kNoError;
}

int32_t ZipWriter::FinishEntry() {
  if (state_ != State::kWritingEntry) {
    return kInvalidState;
  }

  const uint32_t sig = DataDescriptor::kOptSignature;
  if (fwrite(&sig, sizeof(sig), 1, file_) != 1) {
    state_ = State::kError;
    return kIoError;
  }

  FileInfo& currentFile = files_.back();
  DataDescriptor dd = {};
  dd.crc32 = currentFile.crc32;
  dd.compressed_size = currentFile.compressed_size;
  dd.uncompressed_size = currentFile.uncompressed_size;
  if (fwrite(&dd, sizeof(dd), 1, file_) != 1) {
    return HandleError(kIoError);
  }

  current_offset_ += sizeof(DataDescriptor::kOptSignature) + sizeof(dd);
  state_ = State::kWritingZip;
  return kNoError;
}

int32_t ZipWriter::Finish() {
  if (state_ != State::kWritingZip) {
    return kInvalidState;
  }

  off64_t startOfCdr = current_offset_;
  for (FileInfo& file : files_) {
    CentralDirectoryRecord cdr = {};
    cdr.record_signature = CentralDirectoryRecord::kSignature;
    cdr.gpb_flags |= kGPBDDFlagMask;
    cdr.compression_method = file.compression_method;
    cdr.last_mod_time = file.last_mod_time;
    cdr.last_mod_date = file.last_mod_date;
    cdr.crc32 = file.crc32;
    cdr.compressed_size = file.compressed_size;
    cdr.uncompressed_size = file.uncompressed_size;
    cdr.file_name_length = file.path.size();
    cdr.local_file_header_offset = file.local_file_header_offset;
    if (fwrite(&cdr, sizeof(cdr), 1, file_) != 1) {
      return HandleError(kIoError);
    }

    if (fwrite(file.path.data(), 1, file.path.size(), file_) != file.path.size()) {
      return HandleError(kIoError);
    }

    current_offset_ += sizeof(cdr) + file.path.size();
  }

  EocdRecord er = {};
  er.eocd_signature = EocdRecord::kSignature;
  er.disk_num = 1;
  er.cd_start_disk = 1;
  er.num_records_on_disk = files_.size();
  er.num_records = files_.size();
  er.cd_size = current_offset_ - startOfCdr;
  er.cd_start_offset = startOfCdr;

  if (fwrite(&er, sizeof(er), 1, file_) != 1) {
    return HandleError(kIoError);
  }

  if (fflush(file_) != 0) {
    return HandleError(kIoError);
  }

  current_offset_ += sizeof(er);
  state_ = State::kDone;
  return kNoError;
}
