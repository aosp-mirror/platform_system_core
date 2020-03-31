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

#ifndef LIBZIPARCHIVE_ZIPARCHIVECOMMON_H_
#define LIBZIPARCHIVE_ZIPARCHIVECOMMON_H_

#include "android-base/macros.h"

#include <inttypes.h>

#include <optional>

// The "end of central directory" (EOCD) record. Each archive
// contains exactly once such record which appears at the end of
// the archive. It contains archive wide information like the
// number of entries in the archive and the offset to the central
// directory of the offset.
struct EocdRecord {
  static const uint32_t kSignature = 0x06054b50;

  // End of central directory signature, should always be
  // |kSignature|.
  uint32_t eocd_signature;
  // The number of the current "disk", i.e, the "disk" that this
  // central directory is on.
  //
  // This implementation assumes that each archive spans a single
  // disk only. i.e, that disk_num == 1.
  uint16_t disk_num;
  // The disk where the central directory starts.
  //
  // This implementation assumes that each archive spans a single
  // disk only. i.e, that cd_start_disk == 1.
  uint16_t cd_start_disk;
  // The number of central directory records on this disk.
  //
  // This implementation assumes that each archive spans a single
  // disk only. i.e, that num_records_on_disk == num_records.
  uint16_t num_records_on_disk;
  // The total number of central directory records.
  uint16_t num_records;
  // The size of the central directory (in bytes).
  uint32_t cd_size;
  // The offset of the start of the central directory, relative
  // to the start of the file.
  uint32_t cd_start_offset;
  // Length of the central directory comment.
  uint16_t comment_length;

 private:
  EocdRecord() = default;
  DISALLOW_COPY_AND_ASSIGN(EocdRecord);
} __attribute__((packed));

// A structure representing the fixed length fields for a single
// record in the central directory of the archive. In addition to
// the fixed length fields listed here, each central directory
// record contains a variable length "file_name" and "extra_field"
// whose lengths are given by |file_name_length| and |extra_field_length|
// respectively.
struct CentralDirectoryRecord {
  static const uint32_t kSignature = 0x02014b50;

  // The start of record signature. Must be |kSignature|.
  uint32_t record_signature;
  // Source tool version. Top byte gives source OS.
  uint16_t version_made_by;
  // Tool version. Ignored by this implementation.
  uint16_t version_needed;
  // The "general purpose bit flags" for this entry. The only
  // flag value that we currently check for is the "data descriptor"
  // flag.
  uint16_t gpb_flags;
  // The compression method for this entry, one of |kCompressStored|
  // and |kCompressDeflated|.
  uint16_t compression_method;
  // The file modification time and date for this entry.
  uint16_t last_mod_time;
  uint16_t last_mod_date;
  // The CRC-32 checksum for this entry.
  uint32_t crc32;
  // The compressed size (in bytes) of this entry.
  uint32_t compressed_size;
  // The uncompressed size (in bytes) of this entry.
  uint32_t uncompressed_size;
  // The length of the entry file name in bytes. The file name
  // will appear immediately after this record.
  uint16_t file_name_length;
  // The length of the extra field info (in bytes). This data
  // will appear immediately after the entry file name.
  uint16_t extra_field_length;
  // The length of the entry comment (in bytes). This data will
  // appear immediately after the extra field.
  uint16_t comment_length;
  // The start disk for this entry. Ignored by this implementation).
  uint16_t file_start_disk;
  // File attributes. Ignored by this implementation.
  uint16_t internal_file_attributes;
  // File attributes. For archives created on Unix, the top bits are the mode.
  uint32_t external_file_attributes;
  // The offset to the local file header for this entry, from the
  // beginning of this archive.
  uint32_t local_file_header_offset;

 private:
  CentralDirectoryRecord() = default;
  DISALLOW_COPY_AND_ASSIGN(CentralDirectoryRecord);
} __attribute__((packed));

// The local file header for a given entry. This duplicates information
// present in the central directory of the archive. It is an error for
// the information here to be different from the central directory
// information for a given entry.
struct LocalFileHeader {
  static const uint32_t kSignature = 0x04034b50;

  // The local file header signature, must be |kSignature|.
  uint32_t lfh_signature;
  // Tool version. Ignored by this implementation.
  uint16_t version_needed;
  // The "general purpose bit flags" for this entry. The only
  // flag value that we currently check for is the "data descriptor"
  // flag.
  uint16_t gpb_flags;
  // The compression method for this entry, one of |kCompressStored|
  // and |kCompressDeflated|.
  uint16_t compression_method;
  // The file modification time and date for this entry.
  uint16_t last_mod_time;
  uint16_t last_mod_date;
  // The CRC-32 checksum for this entry.
  uint32_t crc32;
  // The compressed size (in bytes) of this entry.
  uint32_t compressed_size;
  // The uncompressed size (in bytes) of this entry.
  uint32_t uncompressed_size;
  // The length of the entry file name in bytes. The file name
  // will appear immediately after this record.
  uint16_t file_name_length;
  // The length of the extra field info (in bytes). This data
  // will appear immediately after the entry file name.
  uint16_t extra_field_length;

 private:
  LocalFileHeader() = default;
  DISALLOW_COPY_AND_ASSIGN(LocalFileHeader);
} __attribute__((packed));

struct DataDescriptor {
  // The *optional* data descriptor start signature.
  static const uint32_t kOptSignature = 0x08074b50;

  // CRC-32 checksum of the entry.
  uint32_t crc32;

  // For ZIP64 format archives, the compressed and uncompressed sizes are 8
  // bytes each. Also, the ZIP64 format MAY be used regardless of the size
  // of a file.  When extracting, if the zip64 extended information extra field
  // is present for the file the compressed and uncompressed sizes will be 8
  // byte values.

  // Compressed size of the entry, the field can be either 4 bytes or 8 bytes
  // in the zip file.
  uint64_t compressed_size;
  // Uncompressed size of the entry, the field can be either 4 bytes or 8 bytes
  // in the zip file.
  uint64_t uncompressed_size;

 private:
  DataDescriptor() = default;
  DISALLOW_COPY_AND_ASSIGN(DataDescriptor);
};

// The zip64 end of central directory locator helps to find the zip64 EOCD.
struct Zip64EocdLocator {
  static constexpr uint32_t kSignature = 0x07064b50;

  // The signature of zip64 eocd locator, must be |kSignature|
  uint32_t locator_signature;
  // The start disk of the zip64 eocd. This implementation assumes that each
  // archive spans a single disk only.
  uint32_t eocd_start_disk;
  // The offset offset of the zip64 end of central directory record.
  uint64_t zip64_eocd_offset;
  // The total number of disks. This implementation assumes that each archive
  // spans a single disk only.
  uint32_t num_of_disks;

 private:
  Zip64EocdLocator() = default;
  DISALLOW_COPY_AND_ASSIGN(Zip64EocdLocator);
} __attribute__((packed));

// The optional zip64 EOCD. If one of the fields in the end of central directory
// record is too small to hold required data, the field SHOULD be  set to -1
// (0xFFFF or 0xFFFFFFFF) and the ZIP64 format record SHOULD be created.
struct Zip64EocdRecord {
  static constexpr uint32_t kSignature = 0x06064b50;

  // The signature of zip64 eocd record, must be |kSignature|
  uint32_t record_signature;
  // Size of zip64 end of central directory record. It SHOULD be the size of the
  // remaining record and SHOULD NOT include the leading 12 bytes.
  uint64_t record_size;
  // The version of the tool that make this archive.
  uint16_t version_made_by;
  // Tool version needed to extract this archive.
  uint16_t version_needed;
  // Number of this disk.
  uint32_t disk_num;
  // Number of the disk with the start of the central directory.
  uint32_t cd_start_disk;
  // Total number of entries in the central directory on this disk.
  // This implementation assumes that each archive spans a single
  // disk only. i.e, that num_records_on_disk == num_records.
  uint64_t num_records_on_disk;
  // The total number of central directory records.
  uint64_t num_records;
  // The size of the central directory in bytes.
  uint64_t cd_size;
  // The offset of the start of the central directory, relative to the start of
  // the file.
  uint64_t cd_start_offset;

 private:
  Zip64EocdRecord() = default;
  DISALLOW_COPY_AND_ASSIGN(Zip64EocdRecord);
} __attribute__((packed));

// The possible contents of the Zip64 Extended Information Extra Field. It may appear in
// the 'extra' field of a central directory record or local file header. The order of
// the fields in the zip64 extended information record is fixed, but the fields MUST
// only appear if the corresponding local or central directory record field is set to
// 0xFFFF or 0xFFFFFFFF. And this entry in the Local header MUST include BOTH original
// and compressed file size fields.
struct Zip64ExtendedInfo {
  static constexpr uint16_t kHeaderId = 0x0001;
  // The header tag for this 'extra' block, should be |kHeaderId|.
  uint16_t header_id;
  // The size in bytes of the remaining data (excluding the top 4 bytes).
  uint16_t data_size;
  // Size in bytes of the uncompressed file.
  std::optional<uint64_t> uncompressed_file_size;
  // Size in bytes of the compressed file.
  std::optional<uint64_t> compressed_file_size;
  // Local file header offset relative to the start of the zip file.
  std::optional<uint64_t> local_header_offset;

  // This implementation assumes that each archive spans a single disk only. So
  // the disk_number is not used.
  // uint32_t disk_num;
 private:
  Zip64ExtendedInfo() = default;
  DISALLOW_COPY_AND_ASSIGN(Zip64ExtendedInfo);
};

// mask value that signifies that the entry has a DD
static const uint32_t kGPBDDFlagMask = 0x0008;

// The maximum size of a central directory or a file
// comment in bytes.
static const uint32_t kMaxCommentLen = 65535;

#endif /* LIBZIPARCHIVE_ZIPARCHIVECOMMON_H_ */
