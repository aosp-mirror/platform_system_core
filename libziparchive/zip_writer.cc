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

#include "ziparchive/zip_writer.h"

#include <sys/param.h>
#include <sys/stat.h>
#include <zlib.h>
#include <cstdio>
#define DEF_MEM_LEVEL 8  // normally in zutil.h?

#include <memory>
#include <vector>

#include "android-base/logging.h"

#include "entry_name_utils-inl.h"
#include "zip_archive_common.h"

#undef powerof2
#define powerof2(x)                                               \
  ({                                                              \
    __typeof__(x) _x = (x);                                       \
    __typeof__(x) _x2;                                            \
    __builtin_add_overflow(_x, -1, &_x2) ? 1 : ((_x2 & _x) == 0); \
  })

/* Zip compression methods we support */
enum {
  kCompressStored = 0,    // no compression
  kCompressDeflated = 8,  // standard deflate
};

// Size of the output buffer used for compression.
static const size_t kBufSize = 32768u;

// No error, operation completed successfully.
static const int32_t kNoError = 0;

// The ZipWriter is in a bad state.
static const int32_t kInvalidState = -1;

// There was an IO error while writing to disk.
static const int32_t kIoError = -2;

// The zip entry name was invalid.
static const int32_t kInvalidEntryName = -3;

// An error occurred in zlib.
static const int32_t kZlibError = -4;

// The start aligned function was called with the aligned flag.
static const int32_t kInvalidAlign32Flag = -5;

// The alignment parameter is not a power of 2.
static const int32_t kInvalidAlignment = -6;

static const char* sErrorCodes[] = {
    "Invalid state", "IO error", "Invalid entry name", "Zlib error",
};

const char* ZipWriter::ErrorCodeString(int32_t error_code) {
  if (error_code < 0 && (-error_code) < static_cast<int32_t>(arraysize(sErrorCodes))) {
    return sErrorCodes[-error_code];
  }
  return nullptr;
}

static void DeleteZStream(z_stream* stream) {
  deflateEnd(stream);
  delete stream;
}

ZipWriter::ZipWriter(FILE* f)
    : file_(f),
      seekable_(false),
      current_offset_(0),
      state_(State::kWritingZip),
      z_stream_(nullptr, DeleteZStream),
      buffer_(kBufSize) {
  // Check if the file is seekable (regular file). If fstat fails, that's fine, subsequent calls
  // will fail as well.
  struct stat file_stats;
  if (fstat(fileno(f), &file_stats) == 0) {
    seekable_ = S_ISREG(file_stats.st_mode);
  }
}

ZipWriter::ZipWriter(ZipWriter&& writer) noexcept
    : file_(writer.file_),
      seekable_(writer.seekable_),
      current_offset_(writer.current_offset_),
      state_(writer.state_),
      files_(std::move(writer.files_)),
      z_stream_(std::move(writer.z_stream_)),
      buffer_(std::move(writer.buffer_)) {
  writer.file_ = nullptr;
  writer.state_ = State::kError;
}

ZipWriter& ZipWriter::operator=(ZipWriter&& writer) noexcept {
  file_ = writer.file_;
  seekable_ = writer.seekable_;
  current_offset_ = writer.current_offset_;
  state_ = writer.state_;
  files_ = std::move(writer.files_);
  z_stream_ = std::move(writer.z_stream_);
  buffer_ = std::move(writer.buffer_);
  writer.file_ = nullptr;
  writer.state_ = State::kError;
  return *this;
}

int32_t ZipWriter::HandleError(int32_t error_code) {
  state_ = State::kError;
  z_stream_.reset();
  return error_code;
}

int32_t ZipWriter::StartEntry(std::string_view path, size_t flags) {
  uint32_t alignment = 0;
  if (flags & kAlign32) {
    flags &= ~kAlign32;
    alignment = 4;
  }
  return StartAlignedEntryWithTime(path, flags, time_t(), alignment);
}

int32_t ZipWriter::StartAlignedEntry(std::string_view path, size_t flags, uint32_t alignment) {
  return StartAlignedEntryWithTime(path, flags, time_t(), alignment);
}

int32_t ZipWriter::StartEntryWithTime(std::string_view path, size_t flags, time_t time) {
  uint32_t alignment = 0;
  if (flags & kAlign32) {
    flags &= ~kAlign32;
    alignment = 4;
  }
  return StartAlignedEntryWithTime(path, flags, time, alignment);
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

  *out_date = static_cast<uint16_t>((year - 80) << 9 | (ptm->tm_mon + 1) << 5 | ptm->tm_mday);
  *out_time = static_cast<uint16_t>(ptm->tm_hour << 11 | ptm->tm_min << 5 | ptm->tm_sec >> 1);
}

static void CopyFromFileEntry(const ZipWriter::FileEntry& src, bool use_data_descriptor,
                              LocalFileHeader* dst) {
  dst->lfh_signature = LocalFileHeader::kSignature;
  if (use_data_descriptor) {
    // Set this flag to denote that a DataDescriptor struct will appear after the data,
    // containing the crc and size fields.
    dst->gpb_flags |= kGPBDDFlagMask;

    // The size and crc fields must be 0.
    dst->compressed_size = 0u;
    dst->uncompressed_size = 0u;
    dst->crc32 = 0u;
  } else {
    dst->compressed_size = src.compressed_size;
    dst->uncompressed_size = src.uncompressed_size;
    dst->crc32 = src.crc32;
  }
  dst->compression_method = src.compression_method;
  dst->last_mod_time = src.last_mod_time;
  dst->last_mod_date = src.last_mod_date;
  DCHECK_LE(src.path.size(), std::numeric_limits<uint16_t>::max());
  dst->file_name_length = static_cast<uint16_t>(src.path.size());
  dst->extra_field_length = src.padding_length;
}

int32_t ZipWriter::StartAlignedEntryWithTime(std::string_view path, size_t flags, time_t time,
                                             uint32_t alignment) {
  if (state_ != State::kWritingZip) {
    return kInvalidState;
  }

  // Can only have 16535 entries because of zip records.
  if (files_.size() == std::numeric_limits<uint16_t>::max()) {
    return HandleError(kIoError);
  }

  if (flags & kAlign32) {
    return kInvalidAlign32Flag;
  }

  if (powerof2(alignment) == 0) {
    return kInvalidAlignment;
  }
  if (alignment > std::numeric_limits<uint16_t>::max()) {
    return kInvalidAlignment;
  }

  FileEntry file_entry = {};
  file_entry.local_file_header_offset = current_offset_;
  file_entry.path = path;
  // No support for larger than 4GB files.
  if (file_entry.local_file_header_offset > std::numeric_limits<uint32_t>::max()) {
    return HandleError(kIoError);
  }

  if (!IsValidEntryName(reinterpret_cast<const uint8_t*>(file_entry.path.data()),
                        file_entry.path.size())) {
    return kInvalidEntryName;
  }

  if (flags & ZipWriter::kCompress) {
    file_entry.compression_method = kCompressDeflated;

    int32_t result = PrepareDeflate();
    if (result != kNoError) {
      return result;
    }
  } else {
    file_entry.compression_method = kCompressStored;
  }

  ExtractTimeAndDate(time, &file_entry.last_mod_time, &file_entry.last_mod_date);

  off_t offset = current_offset_ + sizeof(LocalFileHeader) + file_entry.path.size();
  // prepare a pre-zeroed memory page in case when we need to pad some aligned data.
  static constexpr auto kPageSize = 4096;
  static constexpr char kSmallZeroPadding[kPageSize] = {};
  // use this buffer if our preallocated one is too small
  std::vector<char> zero_padding_big;
  const char* zero_padding = nullptr;

  if (alignment != 0 && (offset & (alignment - 1))) {
    // Pad the extra field so the data will be aligned.
    uint16_t padding = static_cast<uint16_t>(alignment - (offset % alignment));
    file_entry.padding_length = padding;
    offset += padding;
    if (padding <= std::size(kSmallZeroPadding)) {
        zero_padding = kSmallZeroPadding;
    } else {
        zero_padding_big.resize(padding, 0);
        zero_padding = zero_padding_big.data();
    }
  }

  LocalFileHeader header = {};
  // Always start expecting a data descriptor. When the data has finished being written,
  // if it is possible to seek back, the GPB flag will reset and the sizes written.
  CopyFromFileEntry(file_entry, true /*use_data_descriptor*/, &header);

  if (fwrite(&header, sizeof(header), 1, file_) != 1) {
    return HandleError(kIoError);
  }

  if (fwrite(path.data(), 1, path.size(), file_) != path.size()) {
    return HandleError(kIoError);
  }

  if (file_entry.padding_length != 0 && fwrite(zero_padding, 1, file_entry.padding_length,
                                               file_) != file_entry.padding_length) {
    return HandleError(kIoError);
  }

  current_file_entry_ = std::move(file_entry);
  current_offset_ = offset;
  state_ = State::kWritingEntry;
  return kNoError;
}

int32_t ZipWriter::DiscardLastEntry() {
  if (state_ != State::kWritingZip || files_.empty()) {
    return kInvalidState;
  }

  FileEntry& last_entry = files_.back();
  current_offset_ = last_entry.local_file_header_offset;
  if (fseeko(file_, current_offset_, SEEK_SET) != 0) {
    return HandleError(kIoError);
  }
  files_.pop_back();
  return kNoError;
}

int32_t ZipWriter::GetLastEntry(FileEntry* out_entry) {
  CHECK(out_entry != nullptr);

  if (files_.empty()) {
    return kInvalidState;
  }
  *out_entry = files_.back();
  return kNoError;
}

int32_t ZipWriter::PrepareDeflate() {
  CHECK(state_ == State::kWritingZip);

  // Initialize the z_stream for compression.
  z_stream_ = std::unique_ptr<z_stream, void (*)(z_stream*)>(new z_stream(), DeleteZStream);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
  int zerr = deflateInit2(z_stream_.get(), Z_BEST_COMPRESSION, Z_DEFLATED, -MAX_WBITS,
                          DEF_MEM_LEVEL, Z_DEFAULT_STRATEGY);
#pragma GCC diagnostic pop

  if (zerr != Z_OK) {
    if (zerr == Z_VERSION_ERROR) {
      LOG(ERROR) << "Installed zlib is not compatible with linked version (" << ZLIB_VERSION << ")";
      return HandleError(kZlibError);
    } else {
      LOG(ERROR) << "deflateInit2 failed (zerr=" << zerr << ")";
      return HandleError(kZlibError);
    }
  }

  z_stream_->next_out = buffer_.data();
  DCHECK_EQ(buffer_.size(), kBufSize);
  z_stream_->avail_out = static_cast<uint32_t>(buffer_.size());
  return kNoError;
}

int32_t ZipWriter::WriteBytes(const void* data, size_t len) {
  if (state_ != State::kWritingEntry) {
    return HandleError(kInvalidState);
  }
  // Need to be able to mark down data correctly.
  if (len + static_cast<uint64_t>(current_file_entry_.uncompressed_size) >
      std::numeric_limits<uint32_t>::max()) {
    return HandleError(kIoError);
  }
  uint32_t len32 = static_cast<uint32_t>(len);

  int32_t result = kNoError;
  if (current_file_entry_.compression_method & kCompressDeflated) {
    result = CompressBytes(&current_file_entry_, data, len32);
  } else {
    result = StoreBytes(&current_file_entry_, data, len32);
  }

  if (result != kNoError) {
    return result;
  }

  current_file_entry_.crc32 = static_cast<uint32_t>(
      crc32(current_file_entry_.crc32, reinterpret_cast<const Bytef*>(data), len32));
  current_file_entry_.uncompressed_size += len32;
  return kNoError;
}

int32_t ZipWriter::StoreBytes(FileEntry* file, const void* data, uint32_t len) {
  CHECK(state_ == State::kWritingEntry);

  if (fwrite(data, 1, len, file_) != len) {
    return HandleError(kIoError);
  }
  file->compressed_size += len;
  current_offset_ += len;
  return kNoError;
}

int32_t ZipWriter::CompressBytes(FileEntry* file, const void* data, uint32_t len) {
  CHECK(state_ == State::kWritingEntry);
  CHECK(z_stream_);
  CHECK(z_stream_->next_out != nullptr);
  CHECK(z_stream_->avail_out != 0);

  // Prepare the input.
  z_stream_->next_in = reinterpret_cast<const uint8_t*>(data);
  z_stream_->avail_in = len;

  while (z_stream_->avail_in > 0) {
    // We have more data to compress.
    int zerr = deflate(z_stream_.get(), Z_NO_FLUSH);
    if (zerr != Z_OK) {
      return HandleError(kZlibError);
    }

    if (z_stream_->avail_out == 0) {
      // The output is full, let's write it to disk.
      size_t write_bytes = z_stream_->next_out - buffer_.data();
      if (fwrite(buffer_.data(), 1, write_bytes, file_) != write_bytes) {
        return HandleError(kIoError);
      }
      file->compressed_size += write_bytes;
      current_offset_ += write_bytes;

      // Reset the output buffer for the next input.
      z_stream_->next_out = buffer_.data();
      DCHECK_EQ(buffer_.size(), kBufSize);
      z_stream_->avail_out = static_cast<uint32_t>(buffer_.size());
    }
  }
  return kNoError;
}

int32_t ZipWriter::FlushCompressedBytes(FileEntry* file) {
  CHECK(state_ == State::kWritingEntry);
  CHECK(z_stream_);
  CHECK(z_stream_->next_out != nullptr);
  CHECK(z_stream_->avail_out != 0);

  // Keep deflating while there isn't enough space in the buffer to
  // to complete the compress.
  int zerr;
  while ((zerr = deflate(z_stream_.get(), Z_FINISH)) == Z_OK) {
    CHECK(z_stream_->avail_out == 0);
    size_t write_bytes = z_stream_->next_out - buffer_.data();
    if (fwrite(buffer_.data(), 1, write_bytes, file_) != write_bytes) {
      return HandleError(kIoError);
    }
    file->compressed_size += write_bytes;
    current_offset_ += write_bytes;

    z_stream_->next_out = buffer_.data();
    DCHECK_EQ(buffer_.size(), kBufSize);
    z_stream_->avail_out = static_cast<uint32_t>(buffer_.size());
  }
  if (zerr != Z_STREAM_END) {
    return HandleError(kZlibError);
  }

  size_t write_bytes = z_stream_->next_out - buffer_.data();
  if (write_bytes != 0) {
    if (fwrite(buffer_.data(), 1, write_bytes, file_) != write_bytes) {
      return HandleError(kIoError);
    }
    file->compressed_size += write_bytes;
    current_offset_ += write_bytes;
  }
  z_stream_.reset();
  return kNoError;
}

bool ZipWriter::ShouldUseDataDescriptor() const {
  // Only use a trailing "data descriptor" if the output isn't seekable.
  return !seekable_;
}

int32_t ZipWriter::FinishEntry() {
  if (state_ != State::kWritingEntry) {
    return kInvalidState;
  }

  if (current_file_entry_.compression_method & kCompressDeflated) {
    int32_t result = FlushCompressedBytes(&current_file_entry_);
    if (result != kNoError) {
      return result;
    }
  }

  if (ShouldUseDataDescriptor()) {
    // Some versions of ZIP don't allow STORED data to have a trailing DataDescriptor.
    // If this file is not seekable, or if the data is compressed, write a DataDescriptor.
    const uint32_t sig = DataDescriptor::kOptSignature;
    if (fwrite(&sig, sizeof(sig), 1, file_) != 1) {
      return HandleError(kIoError);
    }

    DataDescriptor dd = {};
    dd.crc32 = current_file_entry_.crc32;
    dd.compressed_size = current_file_entry_.compressed_size;
    dd.uncompressed_size = current_file_entry_.uncompressed_size;
    if (fwrite(&dd, sizeof(dd), 1, file_) != 1) {
      return HandleError(kIoError);
    }
    current_offset_ += sizeof(DataDescriptor::kOptSignature) + sizeof(dd);
  } else {
    // Seek back to the header and rewrite to include the size.
    if (fseeko(file_, current_file_entry_.local_file_header_offset, SEEK_SET) != 0) {
      return HandleError(kIoError);
    }

    LocalFileHeader header = {};
    CopyFromFileEntry(current_file_entry_, false /*use_data_descriptor*/, &header);

    if (fwrite(&header, sizeof(header), 1, file_) != 1) {
      return HandleError(kIoError);
    }

    if (fseeko(file_, current_offset_, SEEK_SET) != 0) {
      return HandleError(kIoError);
    }
  }

  files_.emplace_back(std::move(current_file_entry_));
  state_ = State::kWritingZip;
  return kNoError;
}

int32_t ZipWriter::Finish() {
  if (state_ != State::kWritingZip) {
    return kInvalidState;
  }

  off_t startOfCdr = current_offset_;
  for (FileEntry& file : files_) {
    CentralDirectoryRecord cdr = {};
    cdr.record_signature = CentralDirectoryRecord::kSignature;
    if (ShouldUseDataDescriptor()) {
      cdr.gpb_flags |= kGPBDDFlagMask;
    }
    cdr.compression_method = file.compression_method;
    cdr.last_mod_time = file.last_mod_time;
    cdr.last_mod_date = file.last_mod_date;
    cdr.crc32 = file.crc32;
    cdr.compressed_size = file.compressed_size;
    cdr.uncompressed_size = file.uncompressed_size;
    // Checked in IsValidEntryName.
    DCHECK_LE(file.path.size(), std::numeric_limits<uint16_t>::max());
    cdr.file_name_length = static_cast<uint16_t>(file.path.size());
    // Checked in StartAlignedEntryWithTime.
    DCHECK_LE(file.local_file_header_offset, std::numeric_limits<uint32_t>::max());
    cdr.local_file_header_offset = static_cast<uint32_t>(file.local_file_header_offset);
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
  er.disk_num = 0;
  er.cd_start_disk = 0;
  // Checked when adding entries.
  DCHECK_LE(files_.size(), std::numeric_limits<uint16_t>::max());
  er.num_records_on_disk = static_cast<uint16_t>(files_.size());
  er.num_records = static_cast<uint16_t>(files_.size());
  if (current_offset_ > std::numeric_limits<uint32_t>::max()) {
    return HandleError(kIoError);
  }
  er.cd_size = static_cast<uint32_t>(current_offset_ - startOfCdr);
  er.cd_start_offset = static_cast<uint32_t>(startOfCdr);

  if (fwrite(&er, sizeof(er), 1, file_) != 1) {
    return HandleError(kIoError);
  }

  current_offset_ += sizeof(er);

  // Since we can BackUp() and potentially finish writing at an offset less than one we had
  // already written at, we must truncate the file.

  if (ftruncate(fileno(file_), current_offset_) != 0) {
    return HandleError(kIoError);
  }

  if (fflush(file_) != 0) {
    return HandleError(kIoError);
  }

  state_ = State::kDone;
  return kNoError;
}
